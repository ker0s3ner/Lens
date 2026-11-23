//! Debugger front-end. Lens drives `lldb` (installed with Xcode's command line tools): it launches the
//! program, sets breakpoints at addresses from the listing, steps, and shows registers, stack and
//! backtrace next to the code. Any other lldb command can be typed into the console, including
//! `gdb-remote host:port` to debug firmware in an emulator or on a board.

use crate::app::{Action, LensApp, State};
use eframe::egui::{self, FontId, RichText, ScrollArea, TextEdit};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};

const DONE: &str = "@@LENS_PROMPT@@";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunState {
    Starting,
    Stopped,
    Running,
    Exited,
}

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Plain,
    Launch,
    Slide,
    Resume,
    Regs,
    Stack,
    Bt,
    Pc,
    Bp(u64),
    Watch(String),
}

struct Req {
    kind: Kind,
    cmd: String,
}

pub struct Dbg {
    child: Child,
    stdin: File,
    rx: Receiver<String>,
    buf: Vec<String>,
    queue: VecDeque<Req>,
    inflight: Option<Kind>,
    ready: bool,
    last_cmd: String,
    pub state: RunState,
    pub slide: u64,
    pub pc: Option<u64>,
    pub regs: Vec<(String, String)>,
    pub stack: Vec<String>,
    pub bt: Vec<String>,
    pub watch_values: HashMap<String, String>,
    watch_exprs: Vec<String>,
    pub console: Vec<String>,
    bp_ids: HashMap<u64, u32>,
    bp_conditions: HashMap<u64, String>,
    pending_bps: Vec<u64>,
}

#[derive(Default)]
pub struct DbgUi {
    pub open: bool,
    pub args: String,
    pub remote: String,
    pub confirm: bool,
    pub input: String,
    pub follow: bool,
    pub watches: Vec<String>,
    pub new_watch: String,
    pub condition: String,
    pub condition_addr: Option<u64>,
}

impl Drop for Dbg {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"process kill\nquit\n");
        let _ = self.child.kill();
    }
}

fn clean(line: &str) -> String {
    line.replace("(lldb) ", "").trim_end().to_string()
}

fn parse_hex_after(s: &str, key: &str) -> Option<u64> {
    let i = s.find(key)? + key.len();
    let rest = s[i..].trim_start().strip_prefix("0x")?;
    let end = rest.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len());
    u64::from_str_radix(&rest[..end], 16).ok()
}

impl Dbg {
    pub fn start(path: &str, arch_flag: Option<&str>, args: &str, remote: &str, bps: &[u64], conditions: &HashMap<u64, String>) -> Result<Dbg, String> {
        // lldb needs a terminal: without one it buffers its output and stalls while the program runs
        let (mut master, mut slave) = (0i32, 0i32);
        if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) } != 0 {
            return Err("Couldn't open a terminal for lldb".into());
        }
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            libc::tcgetattr(slave, &mut t);
            t.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
            libc::tcsetattr(slave, libc::TCSANOW, &t);
        }
        let mut cmd = Command::new("lldb");
        cmd.arg("--no-lldbinit").env("TERM", "dumb");
        unsafe {
            cmd.stdin(Stdio::from_raw_fd(libc::dup(slave)));
            cmd.stdout(Stdio::from_raw_fd(libc::dup(slave)));
            cmd.stderr(Stdio::from_raw_fd(libc::dup(slave)));
            cmd.pre_exec(|| {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY as _, 0);
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(|e| format!("Couldn't start lldb ({e}). Install Xcode's command line tools: xcode-select --install"))?;
        unsafe { libc::close(slave) };
        let stdin = unsafe { File::from_raw_fd(master) };
        let reader = stdin.try_clone().map_err(|e| e.to_string())?;
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut reader = reader;
            let mut acc = String::new();
            let mut buf = [0u8; 4096];
            let strip = |t: &str| -> String {
                let mut out = String::new();
                let mut in_esc = false;
                for c in t.chars() {
                    if in_esc { if c.is_ascii_alphabetic() { in_esc = false } continue }
                    if c == '\x1b' { in_esc = true; continue }
                    if c != '\r' { out.push(c) }
                }
                out
            };
            loop {
                let n = match reader.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => n };
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                while let Some(pos) = acc.find('\n') {
                    let line: String = acc.drain(..=pos).collect();
                    let _ = tx.send(strip(&line));
                }
                // lldb shows "(lldb) " without a newline when it is ready for the next command
                let t = strip(&acc);
                if t.trim_end().ends_with("(lldb)") && t.ends_with(' ') {
                    let before = t.trim_end().trim_end_matches("(lldb)").to_string();
                    if !before.trim().is_empty() { let _ = tx.send(format!("{before}\n")); }
                    let _ = tx.send(format!("{DONE}\n"));
                    acc.clear();
                }
            }
        });
        let mut d = Dbg {
            child,
            stdin,
            rx,
            buf: vec![],
            queue: VecDeque::new(),
            inflight: None,
            ready: false,
            last_cmd: String::new(),
            state: RunState::Starting,
            slide: 0,
            pc: None,
            regs: vec![],
            stack: vec![],
            bt: vec![],
            watch_values: HashMap::new(),
            watch_exprs: vec![],
            console: vec![],
            bp_ids: HashMap::new(),
            bp_conditions: conditions.clone(),
            pending_bps: bps.to_vec(),
        };
        d.push(Kind::Plain, "settings set auto-confirm true");
        d.push(Kind::Plain, "settings set stop-line-count-before 0");
        let a = arch_flag.map(|a| format!("-a {a} ")).unwrap_or_default();
        d.push(Kind::Plain, &format!("target create {a}\"{path}\""));
        if remote.trim().is_empty() {
            d.push(Kind::Launch, &format!("process launch --stop-at-entry --stdin /dev/null -- {args}"));
        } else {
            d.push(Kind::Launch, &format!("gdb-remote {}", remote.trim()));
        }
        d.push(Kind::Slide, "target modules list -o -f");
        Ok(d)
    }

    fn push(&mut self, kind: Kind, cmd: &str) {
        self.queue.push_back(Req { kind, cmd: cmd.to_string() });
    }

    pub fn command(&mut self, cmd: &str) {
        self.push(Kind::Plain, cmd);
        self.console.push(format!("> {cmd}"));
    }

    pub fn resume(&mut self, cmd: &str) {
        if self.state != RunState::Stopped {
            return;
        }
        self.push(Kind::Resume, cmd);
    }

    pub fn queue_idle(&self) -> bool {
        self.queue.is_empty() && self.inflight.is_none()
    }

    pub fn interrupt(&mut self) {
        if self.state == RunState::Running {
            // lldb stops the program when it gets SIGINT
            let _ = self.stdin.write_all(&[3]); // ^C reaches lldb through the terminal and stops the program
        }
    }

    pub fn set_bp(&mut self, addr: u64, on: bool) {
        if on {
            if self.slide == 0 && self.state == RunState::Starting {
                self.pending_bps.push(addr);
            } else {
                self.push(Kind::Bp(addr), &format!("breakpoint set -a 0x{:x}", addr + self.slide));
            }
        } else {
            self.bp_conditions.remove(&addr);
            if let Some(id) = self.bp_ids.remove(&addr) {
                self.push(Kind::Plain, &format!("breakpoint delete {id}"));
            }
        }
        self.pending_bps.retain(|a| on || *a != addr);
    }

    pub fn set_condition(&mut self, addr: u64, condition: &str) {
        let condition = condition.trim();
        if condition.contains(['\n', '\r']) { return; }
        if condition.is_empty() {
            self.bp_conditions.remove(&addr);
        } else {
            self.bp_conditions.insert(addr, condition.to_string());
        }
        if let Some(id) = self.bp_ids.get(&addr).copied() {
            let escaped = condition.replace('\\', "\\\\").replace('"', "\\\"");
            let cmd = if condition.is_empty() {
                format!("breakpoint modify --condition '' {id}")
            } else {
                format!("breakpoint modify --condition \"{escaped}\" {id}")
            };
            self.push(Kind::Plain, &cmd);
        }
    }

    fn send_next(&mut self) {
        if self.inflight.is_some() || !self.ready {
            return;
        }
        let Some(r) = self.queue.pop_front() else { return };
        let ok = writeln!(self.stdin, "{}", r.cmd).is_ok() && self.stdin.flush().is_ok();
        if !ok {
            self.state = RunState::Exited;
            self.console.push("lldb stopped responding.".into());
            return;
        }
        if matches!(r.kind, Kind::Resume | Kind::Launch) {
            self.state = RunState::Running;
        }
        self.ready = false;
        self.last_cmd = r.cmd.clone();
        self.buf.clear();
        self.inflight = Some(r.kind);
    }

    fn after_stop(&mut self) {
        self.push(Kind::Pc, "register read pc");
        self.push(Kind::Regs, "register read");
        self.push(Kind::Stack, "memory read -s8 -fx -c24 $sp");
        self.push(Kind::Bt, "thread backtrace -c 16");
        for expression in self.watch_exprs.clone() {
            self.push(Kind::Watch(expression.clone()), &format!("expression -- {expression}"));
        }
    }

    pub fn set_watches(&mut self, expressions: Vec<String>) {
        let expressions: Vec<String> = expressions.into_iter().map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.contains(['\n', '\r']))
            .collect();
        if expressions == self.watch_exprs { return; }
        self.watch_exprs = expressions;
        self.watch_values.retain(|expr, _| self.watch_exprs.contains(expr));
        if self.state == RunState::Stopped {
            for expression in self.watch_exprs.clone() {
                self.push(Kind::Watch(expression.clone()), &format!("expression -- {expression}"));
            }
        }
    }

    /// Reads lldb's output. Returns the new program counter (static address) when the program stopped somewhere new.
    pub fn poll(&mut self) -> Option<u64> {
        let mut new_pc = None;
        while let Ok(line) = self.rx.try_recv() {
            let l = clean(&line);
            if l.trim() == DONE {
                self.ready = true;
                let lines = std::mem::take(&mut self.buf);
                if let Some(k) = self.inflight.take() {
                    new_pc = new_pc.or(self.finish(k, lines));
                }
            } else if l.trim().is_empty() || l.trim() == self.last_cmd {
                // blank lines and the echo of the command we just sent
            } else if self.inflight.is_some() {
                self.buf.push(l);
            } else {
                self.console.push(l);
            }
        }
        if let Ok(Some(_)) = self.child.try_wait() {
            self.state = RunState::Exited;
        }
        self.send_next();
        new_pc
    }

    fn finish(&mut self, kind: Kind, lines: Vec<String>) -> Option<u64> {
        let joined = lines.join("\n");
        match kind {
            Kind::Slide => {
                // "[  0] 0x0000000000000000 /path/to/program"
                if let Some(l) = lines.iter().find(|l| l.trim_start().starts_with("[  0]") || l.trim_start().starts_with("[0]")) {
                    self.slide = parse_hex_after(l, "]").unwrap_or(0);
                }
                let bps: Vec<u64> = std::mem::take(&mut self.pending_bps);
                for a in bps {
                    self.set_bp(a, true);
                }
                if self.state != RunState::Exited {
                    self.state = RunState::Stopped;
                }
                self.console.extend(lines);
                self.after_stop();
            }
            Kind::Launch | Kind::Resume => {
                self.console.extend(lines.iter().cloned());
                if joined.contains("exited with status") || (joined.contains("Process") && joined.contains("exited")) {
                    self.state = RunState::Exited;
                    self.pc = None;
                } else if joined.contains("error:") && !joined.contains("stop reason") {
                    self.state = RunState::Exited;
                } else {
                    self.state = RunState::Stopped;
                    if kind == Kind::Resume {
                        self.after_stop();
                    }
                }
            }
            Kind::Pc => {
                if let Some(pc) = lines.iter().find_map(|l| parse_hex_after(l, "= ")) {
                    self.pc = Some(pc.wrapping_sub(self.slide));
                    return self.pc;
                }
            }
            Kind::Regs => {
                self.regs = lines
                    .iter()
                    .filter_map(|l| {
                        let (n, v) = l.split_once('=')?;
                        let n = n.trim();
                        if n.is_empty() || n.contains(' ') { return None; }
                        Some((n.to_string(), v.split_whitespace().next()?.to_string()))
                    })
                    .collect();
            }
            Kind::Stack => self.stack = lines,
            Kind::Bt => self.bt = lines,
            Kind::Watch(expression) => {
                let value = lines.iter().filter(|line| !line.trim().is_empty()).cloned().collect::<Vec<_>>().join(" ");
                if self.watch_exprs.contains(&expression) {
                    self.watch_values.insert(expression, if value.is_empty() { "<no value>".into() } else { value });
                }
            }
            Kind::Bp(addr) => {
                // "Breakpoint 3: where = ..."
                if let Some(id) = joined.strip_prefix("Breakpoint ").and_then(|r| r.split(':').next()).and_then(|n| n.trim().parse::<u32>().ok()) {
                    self.bp_ids.insert(addr, id);
                    if let Some(condition) = self.bp_conditions.get(&addr).cloned() {
                        self.set_condition(addr, &condition);
                    }
                }
                self.console.extend(lines);
            }
            Kind::Plain => self.console.extend(lines),
        }
        if self.console.len() > 800 {
            let k = self.console.len() - 800;
            self.console.drain(..k);
        }
        None
    }
}

impl LensApp {
    pub fn dbg_sync_breakpoint(&mut self, addr: u64, on: bool) {
        if let Some(d) = &mut self.dbg {
            d.set_bp(addr, on);
        }
    }

    pub fn dbg_start(&mut self) {
        let Some(l) = self.loaded() else { return };
        let path = l.bin.path.clone();
        let arch = match l.bin.slice.as_str() {
            "x86_64" => Some("x86_64"),
            "arm64e" => Some("arm64e"),
            _ if l.bin.arch == crate::loader::Arch::X64 && cfg!(target_arch = "aarch64") => Some("x86_64"),
            _ => None,
        };
        let bps = l.ann.breakpoints.clone();
        let conditions = l.ann.bp_conditions.clone();
        let (args, remote) = (self.tools2.dbg.args.clone(), self.tools2.dbg.remote.clone());
        match Dbg::start(&path, arch, &args, &remote, &bps, &conditions) {
            Ok(d) => {
                self.dbg = Some(d);
                self.logm(format!("Debugging {path} with lldb"));
            }
            Err(e) => self.modal_message("Couldn't start the debugger", e),
        }
    }

    pub fn poll_debugger(&mut self, ctx: &egui::Context) {
        let follow = self.tools2.dbg.follow;
        let mut goto = None;
        let mut pc = None;
        if let Some(d) = &mut self.dbg {
            if let Some(a) = d.poll() {
                goto = Some(a);
            }
            pc = d.pc.filter(|_| d.state == RunState::Stopped);
            if !matches!(d.state, RunState::Exited) {
                ctx.request_repaint_after(std::time::Duration::from_millis(120));
            }
        }
        if let State::Ready(l) = &mut self.state {
            l.dbg_pc = pc;
        }
        let mapped = goto.map(|a| self.loaded().map(|l| l.bin.is_mapped(a)).unwrap_or(false)).unwrap_or(false);
        if let (Some(a), true, true) = (goto, follow, mapped) {
            if self.nav.view == crate::app::View::Overview {
                self.actions.push(Action::SetView(crate::app::View::Text));
            }
            self.actions.push(Action::Goto(a));
        }
    }

    pub fn debugger_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let ready = self.loaded().is_some();
        let cursor = self.nav.cursor;
        let mut start = false;
        let mut stop = false;
        let mut cmd: Option<String> = None;
        let mut resume: Option<&'static str> = None;
        let mut goto: Option<u64> = None;
        let mut bp: Option<u64> = None;
        let mut remove_watch: Option<usize> = None;
        let mut add_watch = false;
        let mut set_condition: Option<(u64, String)> = None;
        let bps = self.loaded().map(|l| l.ann.breakpoints.clone()).unwrap_or_default();
        let bp_conditions = self.loaded().map(|l| l.ann.bp_conditions.clone()).unwrap_or_default();
        let bin_map = self.loaded().map(|l| (l.bin.clone(), self.dbg.as_ref().map(|d| d.slide).unwrap_or(0)));
        egui::Window::new("Debugger").open(&mut open).default_size([760.0, 560.0]).show(ctx, |ui| {
            if !ready {
                ui.label(RichText::new("Open a program first.").color(p.muted));
                return;
            }
            let ui_state = &mut self.tools2.dbg;
            if ui_state.condition_addr != Some(cursor) {
                ui_state.condition_addr = Some(cursor);
                ui_state.condition = bp_conditions.get(&cursor).cloned().unwrap_or_default();
            }
            if bps.contains(&cursor) {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("Condition at {cursor:X}")).small().color(p.faint));
                    ui.add(TextEdit::singleline(&mut ui_state.condition).desired_width(260.0).font(FontId::monospace(13.0)).hint_text("e.g. $rax == 0"));
                    if ui.button("Apply").clicked() { set_condition = Some((cursor, ui_state.condition.clone())); }
                });
            }
            match &mut self.dbg {
                None => {
                    ui.label(RichText::new("Starting the debugger runs this program on your Mac. Only debug programs you trust.").color(p.muted));
                    ui.checkbox(&mut ui_state.confirm, "I understand, run it");
                    ui.horizontal(|ui| {
                        ui.label("Arguments");
                        ui.add(TextEdit::singleline(&mut ui_state.args).desired_width(260.0).font(FontId::monospace(13.0)));
                    });
                    ui.horizontal(|ui| {
                        ui.label("or connect to");
                        ui.add(TextEdit::singleline(&mut ui_state.remote).desired_width(220.0).hint_text("localhost:1234 (gdb server)").font(FontId::monospace(13.0)));
                    });
                    if ui.add_enabled(ui_state.confirm, egui::Button::new("Start").fill(p.accent_soft)).clicked() {
                        start = true;
                    }
                    ui.label(RichText::new("macOS only debugs programs that allow it: your own builds work; Apple's protected system programs don't.").small().color(p.faint));
                }
                Some(d) => {
                    ui.horizontal(|ui| {
                        let stopped = d.state == RunState::Stopped;
                        let st = match d.state { RunState::Starting => "starting", RunState::Stopped => "stopped", RunState::Running => "running", RunState::Exited => "exited" };
                        ui.label(RichText::new(st).strong().color(if stopped { p.accent } else { p.muted }));
                        if ui.add_enabled(stopped, egui::Button::new("Continue")).clicked() { resume = Some("process continue"); }
                        if ui.add_enabled(stopped, egui::Button::new("Step in")).clicked() { resume = Some("thread step-inst"); }
                        if ui.add_enabled(stopped, egui::Button::new("Step over")).clicked() { resume = Some("thread step-inst-over"); }
                        if ui.add_enabled(stopped, egui::Button::new("Step out")).clicked() { resume = Some("thread step-out"); }
                        if ui.add_enabled(d.state == RunState::Running, egui::Button::new("Pause")).clicked() { d.interrupt(); }
                        if ui.button("Stop").clicked() { stop = true; }
                        ui.checkbox(&mut ui_state.follow, "follow").on_hover_text("Move the listing to the current instruction");
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Breakpoint at cursor (F2)").clicked() { bp = Some(cursor); }
                        if let Some(pc) = d.pc { if ui.button(format!("Go to {pc:X}")).clicked() { goto = Some(pc); } }
                        ui.label(RichText::new(format!("{} breakpoints", bps.len())).small().color(p.muted));
                    });
                    ui.separator();
                    ui.columns(2, |cols| {
                        cols[0].label(RichText::new("REGISTERS").small().color(p.faint));
                        ScrollArea::vertical().id_salt("regs").max_height(170.0).show(&mut cols[0], |ui| {
                            egui::Grid::new("regsg").num_columns(2).spacing([12.0, 1.0]).show(ui, |ui| {
                                for (n, v) in &d.regs {
                                    ui.label(RichText::new(n).monospace().color(p.register));
                                    let target = u64::from_str_radix(v.trim_start_matches("0x"), 16).ok().map(|x| x.wrapping_sub(d.slide)).filter(|x| bin_map.as_ref().map(|(b, _)| b.is_mapped(*x)).unwrap_or(false));
                                    if ui.add(egui::Label::new(RichText::new(v).monospace().color(if target.is_some() { p.func_name } else { p.text })).sense(egui::Sense::click())).clicked() {
                                        goto = target;
                                    }
                                    ui.end_row();
                                }
                            });
                        });
                        cols[1].label(RichText::new("CALL STACK").small().color(p.faint));
                        ScrollArea::vertical().id_salt("bt").max_height(170.0).show(&mut cols[1], |ui| {
                            for l in &d.bt { ui.label(RichText::new(l).monospace().small()); }
                        });
                    });
                    ui.label(RichText::new("STACK").small().color(p.faint));
                    ScrollArea::vertical().id_salt("stk").max_height(90.0).show(ui, |ui| {
                        for l in &d.stack { ui.label(RichText::new(l).monospace().small()); }
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("WATCHES").small().color(p.faint));
                        ui.add(TextEdit::singleline(&mut ui_state.new_watch).desired_width(240.0).font(FontId::monospace(13.0)).hint_text("expression, e.g. $rax"));
                        if ui.button("Add watch").clicked() || (ui.input(|i| i.key_pressed(egui::Key::Enter)) && ui_state.new_watch.trim() != "") {
                            add_watch = true;
                        }
                    });
                    for (i, expression) in ui_state.watches.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(expression).monospace().color(p.keyword));
                            ui.label(RichText::new(d.watch_values.get(expression).map(String::as_str).unwrap_or("(waiting for stop)" )).monospace().small());
                            if ui.small_button("×").clicked() { remove_watch = Some(i); }
                        });
                    }
                    ui.separator();
                    ui.label(RichText::new("CONSOLE (any lldb command)").small().color(p.faint));
                    ScrollArea::vertical().id_salt("con").max_height(120.0).stick_to_bottom(true).show(ui, |ui| {
                        for l in &d.console { ui.label(RichText::new(l).monospace().small()); }
                    });
                    let r = ui.add(TextEdit::singleline(&mut ui_state.input).desired_width(f32::INFINITY).font(FontId::monospace(13.0)).hint_text("memory read 0x… · expr x0 · gdb-remote localhost:1234"));
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !ui_state.input.trim().is_empty() {
                        cmd = Some(std::mem::take(&mut ui_state.input));
                        r.request_focus();
                    }
                }
            }
        });
        if start {
            self.dbg_start();
        }
        if stop {
            self.dbg = None;
            if let State::Ready(l) = &mut self.state { l.dbg_pc = None; }
            self.logm("Debugger stopped.");
        }
        if let Some(d) = &mut self.dbg {
            if let Some(i) = remove_watch { if i < self.tools2.dbg.watches.len() { self.tools2.dbg.watches.remove(i); } }
            if add_watch {
                let expression = self.tools2.dbg.new_watch.trim().to_string();
                if !expression.is_empty() && !expression.contains(['\n', '\r']) && !self.tools2.dbg.watches.contains(&expression) {
                    self.tools2.dbg.watches.push(expression);
                }
                self.tools2.dbg.new_watch.clear();
            }
            d.set_watches(self.tools2.dbg.watches.clone());
            if let Some((addr, condition)) = &set_condition { d.set_condition(*addr, condition); }
            if let Some(c) = resume { d.resume(c); }
            if let Some(c) = cmd { d.command(&c); }
        }
        if let Some((addr, condition)) = set_condition {
            if let State::Ready(l) = &mut self.state {
                if condition.trim().is_empty() { l.ann.bp_conditions.remove(&addr); }
                else if !condition.contains(['\n', '\r']) { l.ann.bp_conditions.insert(addr, condition.trim().to_string()); }
                crate::store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
            }
        }
        if let Some(a) = bp { self.actions.push(Action::ToggleBreakpoint(a)); }
        if let Some(a) = goto { self.actions.push(Action::Goto(a)); }
        self.tools2.dbg.open = open;
        if !open {
            self.dbg = None;
        }
    }
}
