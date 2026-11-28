//! Lifecycle controls for one local child. This module is the child's sole waiter.
#![cfg(any(target_os = "macos", target_os = "linux"))]

use crate::app::LensApp;
use eframe::egui;
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Running,
    Paused,
    Exited(ExitStatus),
    OwnershipLost,
}

#[derive(Default)]
pub(crate) struct NativeDebugger {
    session: Option<NativeSession>,
    consent_for: Weak<crate::loader::Binary>,
    args: String,
    environment: String,
    working_directory: String,
    start_paused: bool,
}

struct NativeSession {
    child: Child,
    program: PathBuf,
    state: State,
    traced: bool,
    output: Arc<Mutex<String>>,
    stop_reason: Option<String>,
}

fn capture_output<R: Read + Send + 'static>(mut reader: R, output: Arc<Mutex<String>>, label: &'static str) {
    const MAX_OUTPUT_BYTES: usize = 64 * 1024;
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        let mut first_chunk = true;
        loop {
            let count = match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            let mut output = output.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if first_chunk {
                output.push_str(label);
                output.push('\n');
                first_chunk = false;
            }
            output.push_str(&String::from_utf8_lossy(&buffer[..count]));
            if output.len() > MAX_OUTPUT_BYTES {
                let excess = output.len() - MAX_OUTPUT_BYTES;
                let boundary = output.char_indices().find(|(index, _)| *index >= excess).map(|(index, _)| index).unwrap_or(output.len());
                output.drain(..boundary);
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn trace_me() -> io::Result<()> {
    // SAFETY: PTRACE_TRACEME is called only in the freshly spawned child.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            0,
        )
    } == -1
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn trace_me() -> io::Result<()> {
    // SAFETY: PT_TRACE_ME is called only in the freshly spawned child.
    if unsafe { libc::ptrace(libc::PT_TRACE_ME, 0, std::ptr::null_mut(), 0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn trace_continue(pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: this session owns the traced child PID and it is stopped.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    } == -1
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn trace_continue(pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: address 1 means continue from the child's current instruction.
    if unsafe { libc::ptrace(libc::PT_CONTINUE, pid, 1_usize as *mut libc::c_char, 0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn trace_step(pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: this session owns the stopped traced child PID.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SINGLESTEP,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    } == -1
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn trace_step(pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: address 1 means step the stopped traced child from its current instruction.
    if unsafe { libc::ptrace(libc::PT_STEP, pid, 1_usize as *mut libc::c_char, 0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl NativeSession {
    fn launch(
        program: &Path,
        args: &[OsString],
        environment: &[(OsString, OsString)],
        working_directory: Option<&Path>,
        start_paused: bool,
    ) -> io::Result<Self> {
        // Resolve even a bare filename against the current directory, bypassing PATH lookup.
        let program = std::path::absolute(program)?;
        let mut command = Command::new(&program);
        command
            .args(args)
            .envs(environment.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(directory) = working_directory {
            command.current_dir(directory);
        }
        if start_paused {
            // SAFETY: the trace-me request is a single syscall in the child.
            // The kernel stops it after exec and before the first target instruction.
            unsafe {
                command.pre_exec(trace_me);
            }
        }
        let mut child = command.spawn()?;
        let output = Arc::new(Mutex::new(String::new()));
        if let Some(stdout) = child.stdout.take() {
            capture_output(stdout, Arc::clone(&output), "[stdout]");
        }
        if let Some(stderr) = child.stderr.take() {
            capture_output(stderr, Arc::clone(&output), "[stderr]");
        }
        let mut session = Self {
            child,
            program,
            state: State::Running,
            traced: start_paused,
            output,
            stop_reason: None,
        };
        if start_paused {
            session.wait_for_initial_stop()?;
        }
        Ok(session)
    }

    fn live(&self) -> bool {
        matches!(self.state, State::Running | State::Paused)
    }

    fn wait_for_initial_stop(&mut self) -> io::Result<()> {
        let mut status = 0;
        loop {
            // SAFETY: this session owns the spawned child and a writable status word.
            let result = unsafe {
                libc::waitpid(self.child.id() as libc::pid_t, &mut status, libc::WUNTRACED)
            };
            if result > 0 {
                if libc::WIFSTOPPED(status) {
                    self.state = State::Paused;
                    let signal = libc::WSTOPSIG(status);
                    let name = match signal {
                        libc::SIGTRAP => "SIGTRAP",
                        libc::SIGSTOP => "SIGSTOP",
                        libc::SIGSEGV => "SIGSEGV",
                        libc::SIGILL => "SIGILL",
                        libc::SIGABRT => "SIGABRT",
                        libc::SIGFPE => "SIGFPE",
                        _ => "signal",
                    };
                    self.stop_reason = Some(format!("{name} ({signal})"));
                    return Ok(());
                }
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.state = State::Exited(ExitStatus::from_raw(status));
                    return Ok(());
                }
                continue;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }

    fn poll(&mut self) -> io::Result<()> {
        if !self.live() {
            return Ok(());
        }
        let flags = libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED;
        let mut status = 0;
        loop {
            // SAFETY: a positive PID from spawn and a writable status word.
            let result =
                unsafe { libc::waitpid(self.child.id() as libc::pid_t, &mut status, flags) };
            if result == 0 {
                return Ok(());
            }
            if result > 0 {
                if libc::WIFSTOPPED(status) {
                    self.state = State::Paused;
                } else if libc::WIFCONTINUED(status) {
                    self.state = State::Running;
                } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.state = State::Exited(ExitStatus::from_raw(status));
                }
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                // The PID can be reused once reaped. Disable all further signals.
                self.state = State::OwnershipLost;
            }
            return Err(error);
        }
    }

    fn signal(&mut self, signal: libc::c_int) -> io::Result<()> {
        self.poll()?;
        if !self.live() {
            return Ok(());
        }
        // SAFETY: only this session reaps the child. Even if it exits after poll,
        // its positive PID stays reserved until we collect its exit status.
        if unsafe { libc::kill(self.child.id() as libc::pid_t, signal) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            self.poll()?;
            if !self.live() {
                return Ok(());
            }
        }
        Err(error)
    }

    fn pause(&mut self) -> io::Result<()> {
        self.signal(libc::SIGSTOP)
    }

    fn resume(&mut self) -> io::Result<()> {
        self.poll()?;
        if !self.live() {
            return Ok(());
        }
        if self.traced && self.state == State::Paused {
            trace_continue(self.child.id() as libc::pid_t)?;
            self.state = State::Running;
            Ok(())
        } else {
            self.signal(libc::SIGCONT)
        }
    }

    fn step(&mut self) -> io::Result<()> {
        self.poll()?;
        if !self.live() || !self.traced || self.state != State::Paused {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "single-step requires a paused native trace session"));
        }
        trace_step(self.child.id() as libc::pid_t)?;
        self.state = State::Running;
        self.wait_for_initial_stop()
    }

    fn terminate(&mut self) -> io::Result<()> {
        self.signal(libc::SIGKILL)
    }
}

fn parse_arguments(input: &str) -> Result<Vec<OsString>, &'static str> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            started = true;
        } else if ch == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
        } else if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else {
                current.push(ch);
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
            started = true;
        } else if ch.is_whitespace() {
            if started {
                args.push(OsString::from(std::mem::take(&mut current)));
                started = false;
            }
        } else {
            current.push(ch);
            started = true;
        }
    }
    if escaped {
        return Err("Argument list ends with an incomplete escape.");
    }
    if quote.is_some() {
        return Err("Argument list has an unclosed quote.");
    }
    if started {
        args.push(OsString::from(current));
    }
    Ok(args)
}

fn parse_environment(input: &str) -> Result<Vec<(OsString, OsString)>, &'static str> {
    input
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let Some((key, value)) = line.split_once('=') else {
                return Err("Environment entries must use KEY=VALUE format.");
            };
            if key.is_empty() || key.contains('\0') || key.contains('=') || value.contains('\0') {
                return Err("Environment names cannot be empty or contain '='; names and values cannot contain NUL characters.");
            }
            Ok((OsString::from(key), OsString::from(value)))
        })
        .collect()
}

impl Drop for NativeSession {
    fn drop(&mut self) {
        // SIGKILL also works on a paused child. Wait only if we still own it.
        if self.terminate().is_ok() && self.live() {
            let _ = self.child.wait();
        }
    }
}

impl LensApp {
    /// Render at the top of the debugger window. True means the native session owns the pane.
    pub(crate) fn native_session_ui(&mut self, ui: &mut egui::Ui) -> bool {
        if self.dbg.is_some() {
            self.native_debugger.consent_for = Weak::new();
            return false;
        }
        let Some(session) = &mut self.native_debugger.session else {
            let Some(bin) = self.loaded().map(|loaded| Arc::clone(&loaded.bin)) else {
                self.native_debugger.consent_for = Weak::new();
                return false;
            };
            // Identity belongs to this load, even if the next file has the same path.
            let current = Arc::downgrade(&bin);
            let mut confirmed = self.native_debugger.consent_for.ptr_eq(&current);
            let launch = ui.collapsing("Native local child", |ui| {
                ui.label(format!("Run {} as a local child process.", bin.path));
                ui.horizontal(|ui| {
                    ui.label("Arguments");
                    ui.text_edit_singleline(&mut self.native_debugger.args)
                        .on_hover_text("Space-separated arguments; single or double quotes group a value. Arguments are passed directly, without a shell.");
                });
                ui.label("Environment (one KEY=VALUE per line)");
                ui.add(egui::TextEdit::multiline(&mut self.native_debugger.environment).desired_rows(3))
                    .on_hover_text("Entries are passed directly to the child process. Values are not expanded by a shell.");
                ui.horizontal(|ui| {
                    ui.label("Working directory");
                    ui.text_edit_singleline(&mut self.native_debugger.working_directory)
                        .on_hover_text("Optional directory used to resolve relative paths in the child process.");
                });
                ui.checkbox(&mut self.native_debugger.start_paused, "Stop at program entry")
                    .on_hover_text("Stop the child before it begins executing the selected program.");
                ui.checkbox(&mut confirmed, "I understand, run it and capture local output");
                ui.add_enabled(confirmed, egui::Button::new("Launch local child"))
                    .clicked()
            });
            self.native_debugger.consent_for = if confirmed { current } else { Weak::new() };
            if confirmed && launch.body_returned == Some(true) {
                self.native_debugger.consent_for = Weak::new();
                let args = parse_arguments(&self.native_debugger.args);
                let environment = parse_environment(&self.native_debugger.environment);
                match args.and_then(|args| environment.map(|environment| (args, environment))) {
                    Ok((args, environment)) => match NativeSession::launch(
                        Path::new(&bin.path),
                        &args,
                        &environment,
                        (!self.native_debugger.working_directory.is_empty()).then(|| Path::new(&self.native_debugger.working_directory)),
                        self.native_debugger.start_paused,
                    ) {
                        Ok(session) => self.native_debugger.session = Some(session),
                        Err(error) => {
                            self.modal_message("Couldn't launch local child", error.to_string())
                        }
                    },
                    Err(error) => {
                        self.modal_message("Couldn't launch local child", error.to_string())
                    }
                }
            }
            return self.native_debugger.session.is_some();
        };

        let mut result = session.poll();
        ui.label(format!("Local child · {}", session.program.display()));
        let output = session.output.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        if !output.is_empty() {
            ui.horizontal(|ui| {
                ui.label("Child output (last 64 KiB)");
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(output.clone());
                }
                if ui.small_button("Clear").clicked() {
                    session.output.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
                }
            });
            egui::ScrollArea::vertical().id_salt("native-child-output").max_height(120.0).stick_to_bottom(true).show(ui, |ui| {
                ui.monospace(output);
            });
        }
        match session.state {
            State::Running | State::Paused => {
                let paused = session.state == State::Paused;
                if let Some(reason) = &session.stop_reason {
                    ui.label(format!("Last stop: {reason}"));
                }
                ui.horizontal(|ui| {
                    ui.label(if paused { "Paused" } else { "Running" });
                    if paused && session.traced && ui.button("Step instruction").clicked() {
                        result = session.step();
                    }
                    if paused && ui.button("Resume").clicked() {
                        result = session.resume();
                    }
                    if !paused && ui.button("Pause").clicked() {
                        result = session.pause();
                    }
                    if ui.button("Terminate child").clicked() {
                        result = session.terminate();
                    }
                });
                ui.ctx().request_repaint_after(Duration::from_millis(100));
            }
            State::Exited(status) => {
                ui.label(format!("Exited ({status})"));
            }
            State::OwnershipLost => {
                ui.label("Child status unavailable.");
            }
        }
        if let Err(error) = result {
            ui.label(format!("Child process error: {error}"));
        }
        if !session.live() && ui.button("Dismiss").clicked() {
            self.native_debugger.session = None;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn sleeper() -> NativeSession {
        NativeSession::launch(Path::new("/bin/sleep"), &[OsString::from("60")], &[], None, false).unwrap()
    }

    fn await_state(session: &mut NativeSession, expected: State) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            session.poll().unwrap();
            if session.state == expected {
                return;
            }
            assert!(Instant::now() < deadline, "last state: {:?}", session.state);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn observes_stop_continue_and_forced_exit() {
        let mut child = sleeper();
        child.pause().unwrap();
        await_state(&mut child, State::Paused);
        child.resume().unwrap();
        await_state(&mut child, State::Running);
        child.terminate().unwrap();
        await_state(
            &mut child,
            State::Exited(ExitStatus::from_raw(libc::SIGKILL)),
        );
    }

    #[test]
    fn preserves_natural_exit_across_late_controls() {
        let args = [OsString::from("-c"), OsString::from("exit 7")];
        let mut child = NativeSession::launch(Path::new("/bin/sh"), &args, &[], None, false).unwrap();
        let status = State::Exited(ExitStatus::from_raw(7 << 8));
        await_state(&mut child, status);
        child.pause().unwrap();
        child.resume().unwrap();
        child.terminate().unwrap();
        assert_eq!(child.state, status);
    }

    #[test]
    fn dropping_paused_child_reaps_only_that_child() {
        let mut sibling = sleeper();
        let mut child = sleeper();
        child.pause().unwrap();
        await_state(&mut child, State::Paused);
        let pid = child.child.id() as libc::pid_t;
        drop(child);
        // SAFETY: query just the former child's PID, without blocking or sending a signal.
        let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        let error = io::Error::last_os_error();
        assert_eq!(result, -1);
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        sibling.poll().unwrap();
        assert_eq!(sibling.state, State::Running);
    }
}
