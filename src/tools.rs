//! Floating tool windows: Search, Hex to Code translator and Settings.

use crate::app::{Action, LensApp, State, View};
use crate::loader::{self, Arch, RawSpec};
use crate::multiarch;
use eframe::egui::{self, vec2, Color32, FontId, RichText, ScrollArea, Sense, TextEdit};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SearchMode {
    Listing,
    Strings,
    Names,
    Bytes,
    Value,
}

impl SearchMode {
    fn label(self) -> &'static str {
        match self {
            SearchMode::Listing => "Code & notes",
            SearchMode::Strings => "Strings",
            SearchMode::Names => "Names",
            SearchMode::Bytes => "Bytes",
            SearchMode::Value => "Number",
        }
    }
    fn hint(self) -> &'static str {
        match self {
            SearchMode::Listing => "Text in instructions, labels and notes, e.g. call, xor eax, malloc",
            SearchMode::Strings => "Text inside the program's strings",
            SearchMode::Names => "Function, import and label names",
            SearchMode::Bytes => "Hex bytes, ?? matches any byte: 48 8B ?? 05",
            SearchMode::Value => "A number used by the code: 0x1F40, 8000, FFh",
        }
    }
}

pub struct SearchState {
    pub open: bool,
    pub focus: bool,
    pub mode: SearchMode,
    pub text: String,
    pub results: Vec<(u64, String)>,
    pub note: String,
}

pub struct FileSrc {
    pub name: String,
    pub path: String,
    pub segs: Vec<(u64, Vec<u8>)>,
}

pub struct HexState {
    pub open: bool,
    pub text: String,
    pub arch: Arch,
    pub big: bool,
    pub base: String,
    pub file: Option<FileSrc>,
    key: u64,
    rows: Vec<multiarch::Raw>,
    note: String,
}

pub struct Tools {
    pub search: SearchState,
    pub hex: HexState,
    pub settings_open: bool,
}

impl Default for Tools {
    fn default() -> Self {
        Tools {
            search: SearchState { open: false, focus: false, mode: SearchMode::Listing, text: String::new(), results: vec![], note: String::new() },
            hex: HexState { open: false, text: String::new(), arch: Arch::X64, big: false, base: "0".into(), file: None, key: 0, rows: vec![], note: String::new() },
            settings_open: false,
        }
    }
}

fn fnv(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for p in parts {
        for b in *p {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn parse_base(s: &str) -> u64 {
    crate::dialogs::parse_addr(s).unwrap_or(0)
}

fn parse_value(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    if let Some(h) = t.strip_suffix('h').or_else(|| t.strip_suffix('H')) {
        return u64::from_str_radix(h, 16).ok();
    }
    t.parse::<u64>().ok().or_else(|| u64::from_str_radix(t, 16).ok())
}

fn parse_pattern(s: &str) -> Option<Vec<Option<u8>>> {
    let mut out = vec![];
    for tk in s.split_whitespace() {
        if tk == "?" || tk == "??" {
            out.push(None);
        } else if tk.len() == 2 && tk.chars().all(|c| c.is_ascii_hexdigit()) {
            out.push(u8::from_str_radix(tk, 16).ok());
        } else {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}

impl LensApp {
    pub fn tool_windows(&mut self, ctx: &egui::Context) {
        if self.tools.search.open {
            self.search_window(ctx);
        }
        if self.tools.hex.open {
            self.hex_window(ctx);
        }
        if self.tools.settings_open {
            self.settings_window(ctx);
        }
        if self.ai.open {
            self.assistant_window(ctx);
        }
        if self.tools2.patch.open {
            self.patch_window(ctx);
        }
        if self.tools2.types.open {
            self.types_window(ctx);
        }
        if self.tools2.script.open {
            self.script_window(ctx);
        }
        if self.tools2.dbg.open {
            self.debugger_window(ctx);
        }
        if self.lists.open {
            self.lists_window(ctx);
        }
        if self.diff.open {
            self.diff_window(ctx);
        }
    }

    // ---------------------------------------------------------------- search
    fn run_search(&mut self) {
        let mode = self.tools.search.mode;
        let q = self.tools.search.text.trim().to_string();
        if q.is_empty() {
            return;
        }
        let State::Ready(l) = &mut self.state else { return };
        let mut res: Vec<(u64, String)> = vec![];
        let mut note = String::new();
        const CAP: usize = 3000;
        let start = Instant::now();
        let lq = q.to_lowercase();
        match mode {
            SearchMode::Strings => {
                for s in &l.an.strings {
                    if s.text.to_lowercase().contains(&lq) {
                        res.push((s.addr, crate::code::escape_str(&s.text, 120)));
                        if res.len() >= CAP { break; }
                    }
                }
            }
            SearchMode::Names => {
                let mut v: Vec<(&u64, &(String, crate::analysis::NameKind))> = l.names.iter().filter(|(_, (n, _))| n.to_lowercase().contains(&lq)).collect();
                v.sort_by_key(|(a, _)| **a);
                for (a, (n, _)) in v.into_iter().take(CAP) {
                    res.push((*a, n.clone()));
                }
            }
            SearchMode::Bytes => match parse_pattern(&q) {
                None => note = "Type bytes as two hex digits each, like 48 8B ?? 05.".into(),
                Some(pat) => {
                    'outer: for s in &l.bin.segments {
                        let d = &s.data;
                        if d.len() < pat.len() { continue; }
                        for i in 0..=d.len() - pat.len() {
                            if pat.iter().enumerate().all(|(k, b)| b.map(|b| d[i + k] == b).unwrap_or(true)) {
                                let a = s.start + i as u64;
                                let shown = crate::code::hex_bytes(&d[i..(i + pat.len().max(8)).min(d.len())]);
                                res.push((a, shown));
                                if res.len() >= CAP { break 'outer; }
                            }
                        }
                    }
                }
            },
            SearchMode::Listing | SearchMode::Value => {
                let needles: Vec<String> = if mode == SearchMode::Value {
                    match parse_value(&q) {
                        Some(v) => vec![format!("{v:x}h"), format!("0x{v:x}"), format!("{v}")],
                        None => { note = "That doesn't look like a number.".into(); vec![] }
                    }
                } else {
                    vec![lq.clone()]
                };
                if !needles.is_empty() {
                    let n = l.an.lines.len();
                    let mut scanned = 0;
                    for i in 0..n {
                        scanned = i;
                        if i % 2048 == 0 && start.elapsed() > Duration::from_millis(2500) {
                            note = format!("Stopped after {:.1}s — only part of the program was searched. Be more specific.", start.elapsed().as_secs_f32());
                            break;
                        }
                        let t = crate::app::line_text(l, i);
                        if t.is_empty() { continue; }
                        let tl = t.to_lowercase();
                        let hit = if mode == SearchMode::Value { needles.iter().take(2).any(|x| tl.contains(x.as_str())) || tl.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| w == needles[2]) } else { tl.contains(&needles[0]) };
                        if hit {
                            res.push((l.an.lines[i].addr, t.trim().to_string()));
                            if res.len() >= CAP { break; }
                        }
                    }
                    let _ = scanned;
                }
            }
        }
        if res.len() >= CAP {
            note = format!("Showing the first {CAP} matches.");
        } else if note.is_empty() {
            note = format!("{} match{}", res.len(), if res.len() == 1 { "" } else { "es" });
        }
        self.tools.search.results = res;
        self.tools.search.note = note;
    }

    fn search_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let mut run = false;
        let mut goto: Option<u64> = None;
        let ready = self.loaded().is_some();
        if ready && self.tools.search.focus && std::env::var("LENS_Q").is_ok() && self.tools.search.results.is_empty() {
            run = true;
        }
        egui::Window::new("Search").open(&mut open).default_size([640.0, 460.0]).min_width(420.0).show(ctx, |ui| {
            if !ready {
                ui.label(RichText::new("Open a program to search it.").color(p.muted));
                return;
            }
            ui.horizontal(|ui| {
                for m in [SearchMode::Listing, SearchMode::Strings, SearchMode::Names, SearchMode::Bytes, SearchMode::Value] {
                    if ui.selectable_label(self.tools.search.mode == m, m.label()).clicked() {
                        self.tools.search.mode = m;
                        self.tools.search.results.clear();
                        self.tools.search.note.clear();
                    }
                }
            });
            let s = &mut self.tools.search;
            ui.horizontal(|ui| {
                let r = ui.add(TextEdit::singleline(&mut s.text).desired_width(ui.available_width() - 70.0).hint_text(s.mode.hint()));
                if s.focus {
                    r.request_focus();
                    s.focus = false;
                }
                if (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) | ui.button("Search").clicked() {
                    run = true;
                }
            });
            ui.label(RichText::new(&s.note).small().color(p.muted));
            ui.add_space(4.0);
            let n = s.results.len();
            let row_h = 22.0;
            ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, row_h, n, |ui, range| {
                for i in range {
                    let (a, text) = &s.results[i];
                    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), row_h), Sense::click());
                    if resp.hovered() {
                        ui.painter().rect_filled(rect, 4.0, p.hover_row);
                    }
                    ui.painter().text(rect.left_center() + vec2(6.0, 0.0), egui::Align2::LEFT_CENTER, format!("{a:X}"), FontId::monospace(12.5), p.func_name);
                    ui.painter().text(rect.left_center() + vec2(110.0, 0.0), egui::Align2::LEFT_CENTER, text, FontId::monospace(12.5), p.text);
                    if resp.clicked() {
                        goto = Some(*a);
                    }
                }
            });
        });
        if run {
            self.run_search();
        }
        if let Some(a) = goto {
            if self.nav.view == View::Overview {
                self.actions.push(Action::SetView(View::Text));
            }
            self.actions.push(Action::Goto(a));
        }
        self.tools.search.open = open;
    }

    // ----------------------------------------------------------- hex → code
    fn hex_bytes_in(&self) -> (Vec<(u64, Vec<u8>)>, String) {
        let h = &self.tools.hex;
        if let Some(f) = &h.file {
            return (f.segs.clone(), f.name.clone());
        }
        let b = loader::parse_hex_text(&h.text);
        if b.is_empty() { (vec![], "pasted".into()) } else { (vec![(parse_base(&h.base), b)], "pasted bytes".into()) }
    }

    fn refresh_hex(&mut self) {
        let (segs, _) = self.hex_bytes_in();
        let h = &self.tools.hex;
        let key = fnv(&[h.text.as_bytes(), &[h.arch as u8, h.big as u8], h.base.as_bytes(), h.file.as_ref().map(|f| f.path.as_str()).unwrap_or("").as_bytes()]);
        if key == h.key && !h.rows.is_empty() || (segs.is_empty() && h.rows.is_empty()) {
            return;
        }
        let (arch, big) = (h.arch, h.big);
        let mut rows = vec![];
        let mut note = String::new();
        'segs: for (base, data) in &segs {
            let data = &data[..data.len().min(64 * 1024)];
            let mut off = 0usize;
            while off < data.len() {
                let v = multiarch::disasm(arch, big, &data[off..], base + off as u64, 0);
                let mut used = 0;
                for r in v {
                    used += r.len;
                    rows.push(r);
                    if rows.len() >= 4000 { note = "Showing the first 4000 instructions.".into(); break 'segs; }
                }
                off += used;
                if off < data.len() {
                    let w = arch.fixed_width().unwrap_or(1) as usize;
                    let end = (off + w).min(data.len());
                    rows.push(multiarch::Raw { addr: base + off as u64, len: end - off, bytes: data[off..end].to_vec(), mnemonic: ".byte".into(), ops: data[off..end].iter().map(|b| format!("0x{b:02x}")).collect::<Vec<_>>().join(", ") });
                    off = end;
                }
            }
        }
        let h = &mut self.tools.hex;
        h.key = key;
        h.rows = rows;
        h.note = note;
    }

    fn hex_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let mut open_prog = false;
        self.refresh_hex();
        egui::Window::new("Hex to Code").open(&mut open).default_size([700.0, 560.0]).min_width(480.0).show(ctx, |ui| {
            let h = &mut self.tools.hex;
            ui.label(RichText::new("Paste bytes (hex, a C array, \\x escapes, objdump columns) or load a .bin / .hex / .srec file to see the instructions.").color(p.muted));
            ui.add_space(4.0);
            if let Some((name, n, blocks)) = h.file.as_ref().map(|f| (f.name.clone(), f.segs.iter().map(|s| s.1.len()).sum::<usize>(), f.segs.len())) {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{name} · {n} bytes in {blocks} block{}", if blocks == 1 { "" } else { "s" })).strong());
                    if ui.button("Use pasted text instead").clicked() {
                        h.file = None;
                        h.key = 0;
                    }
                });
            } else {
                ui.add(TextEdit::multiline(&mut h.text).code_editor().desired_rows(5).desired_width(f32::INFINITY).hint_text("48 89 E5 48 83 EC 10 …"));
            }
            ui.horizontal_wrapped(|ui| {
                egui::ComboBox::from_id_salt("hexarch").selected_text(h.arch.name()).show_ui(ui, |ui| {
                    for a in Arch::all() {
                        ui.selectable_value(&mut h.arch, a, a.name());
                    }
                });
                if !h.arch.is_x86() && !matches!(h.arch, Arch::Arm64 | Arch::RiscV32 | Arch::RiscV64) {
                    ui.checkbox(&mut h.big, "Big-endian");
                } else {
                    h.big = false;
                }
                if h.file.is_none() {
                    ui.label("at address");
                    ui.add(TextEdit::singleline(&mut h.base).desired_width(100.0).font(FontId::monospace(13.0)));
                }
                if ui.button("Load file…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().set_title("Choose a .bin, .hex or .srec file").pick_file() {
                        if let Ok(bytes) = std::fs::read(&path) {
                            let name = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                            let text = String::from_utf8_lossy(&bytes[..bytes.len().min(4_000_000)]).to_string();
                            let segs = loader::parse_ihex(&text).or_else(|| loader::parse_srec(&text)).unwrap_or_else(|| vec![(parse_base(&h.base), bytes)]);
                            h.file = Some(FileSrc { name, path: path.to_string_lossy().to_string(), segs });
                            h.key = 0;
                        }
                    }
                }
            });
            ui.separator();
            let n = h.rows.len();
            if n == 0 {
                ui.label(RichText::new("Nothing to show yet.").color(p.faint));
            }
            let row_h = 21.0;
            let avail = (ui.available_height() - 44.0).max(120.0);
            ScrollArea::vertical().max_height(avail).auto_shrink([false, false]).show_rows(ui, row_h, n, |ui, range| {
                for i in range {
                    let r = &h.rows[i];
                    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), row_h), Sense::click());
                    if resp.hovered() {
                        ui.painter().rect_filled(rect, 4.0, p.hover_row);
                    }
                    let f = FontId::monospace(12.5);
                    let y = rect.left_center();
                    ui.painter().text(y + vec2(6.0, 0.0), egui::Align2::LEFT_CENTER, format!("{:08X}", r.addr), f.clone(), p.func_name);
                    let hb: String = r.bytes.iter().take(8).map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
                    ui.painter().text(y + vec2(92.0, 0.0), egui::Align2::LEFT_CENTER, hb, f.clone(), p.faint);
                    ui.painter().text(y + vec2(300.0, 0.0), egui::Align2::LEFT_CENTER, &r.mnemonic, f.clone(), p.mnemonic);
                    ui.painter().text(y + vec2(380.0, 0.0), egui::Align2::LEFT_CENTER, &r.ops, f, p.text);
                    if resp.clicked() {
                        ui.ctx().copy_text(multiarch::text(r));
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new(if h.note.is_empty() { format!("{n} instructions · click a row to copy it") } else { h.note.clone() }).small().color(p.muted));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(n > 0, egui::Button::new("Open as program").fill(p.accent_soft)).on_hover_text("Analyse it like a program: functions, graph, hex, notes").clicked() {
                        open_prog = true;
                    }
                    if ui.add_enabled(n > 0, egui::Button::new("Copy listing")).clicked() {
                        let t: String = h.rows.iter().map(|r| format!("{:08X}  {:<24} {}\n", r.addr, crate::code::hex_bytes(&r.bytes), multiarch::text(r))).collect();
                        ui.ctx().copy_text(t);
                    }
                });
            });
        });
        if open_prog {
            self.open_hex_as_program();
        }
        self.tools.hex.open = open;
    }

    fn open_hex_as_program(&mut self) {
        let (segs, name) = self.hex_bytes_in();
        if segs.is_empty() {
            return;
        }
        let h = &self.tools.hex;
        let (path, label, format) = match &h.file {
            Some(f) => (f.path.clone(), f.name.clone(), "Raw code (file)".to_string()),
            None => {
                let flat: Vec<u8> = segs.iter().flat_map(|s| s.1.clone()).collect();
                let dir = crate::store::config_dir().join("raw");
                let _ = std::fs::create_dir_all(&dir);
                let p = dir.join(format!("hex-{:016x}.bin", fnv(&[&flat])));
                let _ = std::fs::write(&p, &flat);
                (p.to_string_lossy().to_string(), format!("{name}.bin"), "Raw code (pasted)".to_string())
            }
        };
        let spec = RawSpec { path, name: label, arch: h.arch, big: h.big, entry: segs.first().map(|s| s.0), segs, format };
        self.actions.push(Action::OpenRaw(Box::new(spec)));
        self.tools.hex.open = false;
    }

    // -------------------------------------------------------------- settings
}
