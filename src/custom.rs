//! User customisation: fonts, key bindings and external assistants (Claude Code, Codex, any command).

use eframe::egui::{self, FontData, FontFamily, Key, Modifiers};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

// ------------------------------------------------------------------ code size

static CODE_SIZE: AtomicU32 = AtomicU32::new(0x41500000); // 13.0

pub fn font_size() -> f32 {
    f32::from_bits(CODE_SIZE.load(Ordering::Relaxed))
}
pub fn set_font_size(s: f32) {
    CODE_SIZE.store(s.clamp(9.0, 28.0).to_bits(), Ordering::Relaxed);
}
/// Row height of the listing follows the code size.
pub fn row_h() -> f32 {
    (font_size() * 19.0 / 13.0).round()
}

// ------------------------------------------------------------------ fonts

/// (label, path, collection index)
const MONO: &[(&str, &str, u32)] = &[
    ("Menlo", "/System/Library/Fonts/Menlo.ttc", 0),
    ("SF Mono", "/System/Library/Fonts/SFNSMono.ttf", 0),
    ("Monaco", "/System/Library/Fonts/Monaco.ttf", 0),
    ("Courier New", "/System/Library/Fonts/Supplemental/Courier New.ttf", 0),
    ("JetBrains Mono", "~/Library/Fonts/JetBrainsMono-Regular.ttf", 0),
    ("Fira Code", "~/Library/Fonts/FiraCode-Regular.ttf", 0),
    ("Cascadia Code", "~/Library/Fonts/CascadiaCode.ttf", 0),
];
const UI: &[(&str, &str, u32)] = &[
    ("Helvetica Neue", "/System/Library/Fonts/HelveticaNeue.ttc", 0),
    ("SF Pro", "/System/Library/Fonts/SFNS.ttf", 0),
    ("Avenir", "/System/Library/Fonts/Avenir.ttc", 0),
    ("Arial", "/System/Library/Fonts/Supplemental/Arial.ttf", 0),
    ("Verdana", "/System/Library/Fonts/Supplemental/Verdana.ttf", 0),
    ("Georgia", "/System/Library/Fonts/Supplemental/Georgia.ttf", 0),
    ("Inter", "~/Library/Fonts/Inter-Regular.ttf", 0),
];

fn expand(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(r) => format!("{}/{}", std::env::var("HOME").unwrap_or_default(), r),
        None => p.to_string(),
    }
}

fn table(mono: bool) -> &'static [(&'static str, &'static str, u32)] {
    if mono { MONO } else { UI }
}

/// Fonts offered in Settings: only the ones that exist on this machine.
pub fn available(mono: bool) -> Vec<&'static str> {
    table(mono).iter().filter(|(_, p, _)| std::path::Path::new(&expand(p)).exists()).map(|(n, _, _)| *n).collect()
}

fn find(name: &str, mono: bool) -> Option<(String, u32)> {
    if let Some(path) = name.strip_prefix("file:") {
        return Some((path.to_string(), 0));
    }
    table(mono).iter().find(|(n, _, _)| *n == name).map(|(_, p, i)| (expand(p), *i))
}

fn load(name: &str, mono: bool) -> Option<FontData> {
    let (path, index) = find(name, mono)?;
    let bytes = std::fs::read(&path).ok()?;
    // egui panics later on a font it can't parse, so check it here
    ab_glyph::FontRef::try_from_slice_and_index(&bytes, index).ok()?;
    let mut d = FontData::from_owned(bytes);
    d.index = index;
    Some(d)
}

/// Checks a custom font file before it is accepted in Settings.
pub fn font_file_ok(path: &str) -> bool {
    std::fs::read(path).ok().map(|b| ab_glyph::FontRef::try_from_slice(&b).is_ok()).unwrap_or(false)
}

pub fn apply_fonts(ctx: &egui::Context, ui_font: &str, mono_font: &str) {
    let mut fd = egui::FontDefinitions::default();
    for (name, mono) in [(ui_font, false), (mono_font, true)] {
        if name.is_empty() || name == "Built-in" {
            continue;
        }
        if let Some(d) = load(name, mono) {
            let key = format!("lens-{}-{}", if mono { "mono" } else { "ui" }, name);
            fd.font_data.insert(key.clone(), Arc::new(d));
            let fam = if mono { FontFamily::Monospace } else { FontFamily::Proportional };
            fd.families.entry(fam).or_default().insert(0, key);
        }
    }
    ctx.set_fonts(fd);
}

// ------------------------------------------------------------------ key bindings

/// (id, label, default)
pub const BINDINGS: &[(&str, &str, &str)] = &[
    ("open", "Open a program", "Cmd+O"),
    ("search", "Search", "Cmd+F"),
    ("palette", "Command palette", "Cmd+P"),
    ("settings", "Settings", "Cmd+,"),
    ("assistant", "Ask the assistant", "Cmd+L"),
    ("jump", "Go to address or name", "G"),
    ("follow", "Follow the target", "Enter"),
    ("back", "Go back", "Escape"),
    ("forward", "Go forward", "Cmd+]"),
    ("graph", "Graph / listing", "Space"),
    ("pseudo", "Pseudocode", "F5"),
    ("hex", "Hex view", "H"),
    ("rename", "Rename", "N"),
    ("comment", "Add a note", ";"),
    ("xrefs", "Who uses this", "X"),
    ("make_func", "Make function", "P"),
    ("mark", "Bookmark", "M"),
    ("breakpoint", "Toggle breakpoint", "F2"),
    ("find", "Find text", "Alt+T"),
    ("find_next", "Find next", "F3"),
    ("side_funcs", "Sidebar: functions", "Shift+F3"),
    ("side_strings", "Sidebar: strings", "Shift+F12"),
    ("side_segs", "Sidebar: segments", "Shift+F7"),
];

pub fn spec(map: &HashMap<String, String>, id: &str) -> String {
    map.get(id).cloned().unwrap_or_else(|| BINDINGS.iter().find(|b| b.0 == id).map(|b| b.2.to_string()).unwrap_or_default())
}

pub fn parse(spec: &str) -> Option<(Modifiers, Key)> {
    let parts: Vec<&str> = spec.split('+').collect();
    // a trailing "+" key leaves an empty last part
    let (mods, key) = if spec.ends_with('+') && spec.len() > 1 {
        (&parts[..parts.len().saturating_sub(2)], "+")
    } else {
        (&parts[..parts.len() - 1], *parts.last()?)
    };
    let mut m = Modifiers::NONE;
    for p in mods {
        match p.trim().to_lowercase().as_str() {
            "cmd" | "command" => m |= Modifiers::COMMAND,
            "ctrl" | "control" => m |= Modifiers::CTRL,
            "alt" | "opt" | "option" => m |= Modifiers::ALT,
            "shift" => m |= Modifiers::SHIFT,
            _ => return None,
        }
    }
    Key::from_name(key.trim()).map(|k| (m, k))
}

pub fn hit(i: &mut egui::InputState, spec: &str) -> bool {
    match parse(spec) {
        Some((m, k)) => i.consume_key(m, k),
        None => false,
    }
}

pub fn describe(m: Modifiers, k: Key) -> String {
    let mut s = String::new();
    if m.command { s += "Cmd+"; } else if m.ctrl { s += "Ctrl+"; }
    if m.alt { s += "Alt+"; }
    if m.shift { s += "Shift+"; }
    s + k.name()
}

/// Which action already uses this binding?
pub fn conflict<'a>(map: &HashMap<String, String>, id: &str, spec_s: &str) -> Option<&'a str> {
    BINDINGS.iter().find(|b| b.0 != id && spec(map, b.0).eq_ignore_ascii_case(spec_s)).map(|b| b.1)
}

// ------------------------------------------------------------------ assistants

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Integration {
    pub name: String,
    /// Shell command. The question and the code are sent to it on standard input.
    /// {file}, {func} and {addr} are filled in.
    pub command: String,
    /// true: show what the command prints in the Assistant window. false: just start it (for opening other apps).
    #[serde(default = "yes")]
    pub capture: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
}
fn yes() -> bool {
    true
}

pub fn default_integrations() -> Vec<Integration> {
    vec![
        Integration { name: "Claude Code".into(), command: "claude -p".into(), capture: true, enabled: true },
        Integration { name: "Codex".into(), command: "codex exec".into(), capture: true, enabled: true },
        Integration { name: "Open in Cursor".into(), command: "open -a Cursor {file}".into(), capture: false, enabled: false },
    ]
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn path_env() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let extra = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"].iter().map(|s| s.to_string()).chain(
        [".local/bin", ".claude/local", ".npm-global/bin", ".cargo/bin", "bin"].iter().map(|s| format!("{home}/{s}")),
    );
    let cur = std::env::var("PATH").unwrap_or_default();
    extra.chain(std::iter::once(cur)).collect::<Vec<_>>().join(":")
}

fn command_for(tpl: &str, file: &str, func: &str, addr: &str) -> std::process::Command {
    let cmd = tpl.replace("{file}", &shell_quote(file)).replace("{func}", &shell_quote(func)).replace("{addr}", addr);
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".into());
    let mut c = std::process::Command::new(shell);
    c.args(["-l", "-c", &cmd]).env("PATH", path_env());
    c
}

/// Runs the integration on a background thread. The result is the text it printed.
pub fn run(it: &Integration, stdin_text: String, file: &str, func: &str, addr: &str) -> Receiver<Result<String, String>> {
    let (tx, rx) = channel();
    let mut c = command_for(&it.command, file, func, addr);
    let capture = it.capture;
    let name = it.name.clone();
    std::thread::spawn(move || {
        c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let child = c.spawn();
        let r = match child {
            Err(e) => Err(format!("Couldn't start {name}: {e}")),
            Ok(mut ch) => {
                if let Some(mut si) = ch.stdin.take() {
                    let _ = si.write_all(stdin_text.as_bytes());
                }
                if !capture {
                    // detach: apps like `open` return at once
                    match ch.wait() {
                        Ok(s) if s.success() => Ok(format!("{name} started.")),
                        Ok(s) => Err(format!("{name} exited with {s}")),
                        Err(e) => Err(e.to_string()),
                    }
                } else {
                    match ch.wait_with_output() {
                        Ok(o) => {
                            let out = String::from_utf8_lossy(&o.stdout).to_string();
                            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                            if o.status.success() && !out.trim().is_empty() {
                                Ok(out)
                            } else if o.status.success() {
                                Err(format!("{name} printed nothing. {err}"))
                            } else if err.contains("not found") || o.status.code() == Some(127) {
                                Err(format!("{name} isn't installed, or isn't on your PATH.\n\n{err}"))
                            } else {
                                Err(format!("{name} failed ({}).\n\n{err}", o.status))
                            }
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
            }
        };
        let _ = tx.send(r);
    });
    rx
}

/// Is the first word of the command available? Used by the "Test" button.
pub fn test(it: &Integration) -> String {
    let first = it.command.split_whitespace().next().unwrap_or("");
    if first.is_empty() {
        return "The command is empty.".into();
    }
    let mut c = command_for(&format!("command -v {}", shell_quote(first)), "", "", "");
    match c.output() {
        Ok(o) if o.status.success() => format!("Found: {}", String::from_utf8_lossy(&o.stdout).trim()),
        _ => format!("'{first}' was not found. Install it, or give the full path."),
    }
}
