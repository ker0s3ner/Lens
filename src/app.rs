//! The Lens window state, actions and keyboard shortcuts (from IDA's cfg/idagui.cfg).

use crate::analysis::{self, Analysis, FuncKind, LineKind, NameKind};
use crate::code::{CodeFormatter, NameTable};
use crate::detect::{self, Detection};
use crate::graph::{self, GraphView};
use crate::loader::{self, Arch, Binary};
use crate::store::{self, Annotations, Prefs};
use crate::theme::{self, Palette};
use eframe::egui::{self, Key};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Instant;

pub const ROW_H: f32 = 19.0;
pub const FONT_SIZE: f32 = 13.0;
pub const NAV_BUCKETS: usize = 2048;
/// IDA shows 2 cross-references next to an item (SHOW_XREFS = 2 in cfg/ida.cfg).
pub const SHOW_XREFS: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum View {
    Overview,
    Text,
    Graph,
    Pseudo,
    Calls,
    Map,
    Hex,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Functions,
    Strings,
    Imports,
    Exports,
    Segments,
    Names,
    Marks,
}

impl Side {
    pub fn all() -> [Side; 7] {
        [Side::Functions, Side::Strings, Side::Imports, Side::Exports, Side::Segments, Side::Names, Side::Marks]
    }
    pub fn title(self) -> &'static str {
        match self {
            Side::Functions => "Functions",
            Side::Strings => "Strings",
            Side::Imports => "Imports",
            Side::Exports => "Exports",
            Side::Segments => "Sections",
            Side::Names => "Names",
            Side::Marks => "Marks",
        }
    }
}

#[derive(Clone)]
pub enum Action {
    Goto(u64),
    Select(u64, usize),
    Open(String),
    OpenDialog,
    Close,
    Rename(u64),
    Comment(u64),
    Xrefs(u64),
    MakeFunction(u64),
    SetView(View),
    ToggleGraph,
    SetSide(Side),
    ToggleTheme,
    ToggleLog,
    ToggleInspector,
    Palette,
    Jump,
    Find,
    FindNext,
    Back,
    Forward,
    Follow,
    ExportC,
    Mark(u64),
    SetLang(crate::lang::Lang),
    ExtractAsar,
}

pub enum Modal {
    Jump { text: String, focus: bool },
    Rename { addr: u64, text: String, focus: bool },
    Comment { addr: u64, text: String, focus: bool },
    Xrefs { addr: u64 },
    Palette { text: String, sel: usize, focus: bool },
    Find { text: String, focus: bool },
    Message { title: String, text: String },
}

pub struct Loaded {
    pub bin: Arc<Binary>,
    pub an: Analysis,
    pub ann: Annotations,
    pub det: Detection,
    pub names: NameTable,
    pub fmt: CodeFormatter,
    pub nav: Vec<u8>,
    pub graphs: HashMap<u64, graph::Layout>,
    pub version: u64,
    pub digits: usize,
    pub side_cache: Option<(Side, String, u64, Vec<usize>)>,
    pub func_list: Vec<u64>,
    pub name_list: Vec<u64>,
    pub name_index: HashMap<String, u64>,
    pub pseudo: HashMap<u64, Arc<crate::decomp::Decompiled>>,
}

pub type LoadResult = Result<(Binary, Analysis, Annotations, Detection), String>;

pub enum State {
    Empty,
    Loading { path: String, rx: Receiver<LoadResult>, progress: Arc<AtomicU32>, started: Instant },
    Ready(Box<Loaded>),
}

pub struct NavState {
    pub cursor: u64,
    pub cursor_line: usize,
    pub scroll_to: Option<usize>,
    pub hex_scroll: bool,
    pub view: View,
    pub side: Side,
    pub filter: String,
    pub visible: (usize, usize),
    pub graph: GraphView,
}

pub struct Shot {
    pub path: String,
    pub done: Arc<AtomicBool>,
    pub requested: bool,
    pub ready_frame: Option<u64>,
}

pub struct LensApp {
    pub p: Palette,
    pub prefs: Prefs,
    pub state: State,
    pub nav: NavState,
    pub history: Vec<u64>,
    pub hist_pos: usize,
    pub modal: Option<Modal>,
    pub actions: Vec<Action>,
    pub log: Vec<String>,
    pub show_log: bool,
    pub find_text: String,
    pub frame: u64,
    pub shot: Option<Shot>,
    pub title: String,
    pub char_w: f32,
    pub vis: crate::visuals::VisState,
}

impl LensApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        file: Option<String>,
        screenshot: Option<String>,
        dark: Option<bool>,
        view: Option<String>,
    ) -> Self {
        let mut prefs = store::load_prefs();
        if screenshot.is_some() {
            prefs.dark = false;
            prefs.inspector = true;
        }
        if let Some(d) = dark {
            prefs.dark = d;
        }
        let p = if prefs.dark { Palette::dark() } else { Palette::light() };
        cc.egui_ctx.set_theme(if prefs.dark { egui::Theme::Dark } else { egui::Theme::Light });
        theme::apply(&cc.egui_ctx, &p);
        let mut app = LensApp {
            p,
            prefs,
            state: State::Empty,
            nav: NavState {
                cursor: 0,
                cursor_line: 0,
                scroll_to: None,
                hex_scroll: false,
                view: View::Overview,
                side: Side::Functions,
                filter: String::new(),
                visible: (0, 0),
                graph: GraphView::default(),
            },
            history: vec![],
            hist_pos: 0,
            modal: None,
            actions: vec![],
            log: vec!["Lens is ready. Open an x86 or x64 program to begin.".into()],
            show_log: false,
            find_text: String::new(),
            frame: 0,
            shot: screenshot.map(|path| Shot { path, done: Arc::new(AtomicBool::new(false)), requested: false, ready_frame: None }),
            title: String::new(),
            char_w: 7.8,
            vis: crate::visuals::VisState::new(),
        };
        match view.as_deref() {
            Some("graph") => app.nav.view = View::Graph,
            Some("hex") => app.nav.view = View::Hex,
            Some("pseudo") => app.nav.view = View::Pseudo,
            Some("calls") => app.nav.view = View::Calls,
            Some("map") => app.nav.view = View::Map,
            Some("overview") => app.nav.view = View::Overview,
            _ => {}
        }
        if let Some(f) = file {
            app.open(f);
        }
        app
    }

    pub fn logm(&mut self, s: impl Into<String>) {
        self.log.push(s.into());
        if self.log.len() > 500 {
            self.log.remove(0);
        }
    }

    pub fn open(&mut self, path: String) {
        let progress = Arc::new(AtomicU32::new(0));
        let (tx, rx) = channel();
        let pr = progress.clone();
        let min = self.prefs.min_string_len;
        let p2 = path.clone();
        std::thread::spawn(move || {
            let r = loader::load(&p2).map(|bin| {
                let ann = store::load_annotations(&bin.path, bin.file_size);
                let an = analysis::analyze(
                    &bin,
                    &analysis::Settings { min_string_len: min, extra_functions: ann.functions.clone() },
                    pr,
                );
                let det = detect::detect(&bin, &an);
                (bin, an, ann, det)
            });
            let _ = tx.send(r);
        });
        self.logm(format!("Opening {path} …"));
        self.state = State::Loading { path, rx, progress, started: Instant::now() };
        self.modal = None;
    }

    pub fn poll(&mut self) {
        let mut done = None;
        if let State::Loading { rx, started, path, .. } = &self.state {
            if let Ok(r) = rx.try_recv() {
                done = Some((r, started.elapsed().as_secs_f32(), path.clone()));
            }
        }
        let Some((r, secs, path)) = done else { return };
        match r {
            Ok((bin, an, ann, det)) => {
                let mut msgs = vec![format!("Loaded {} — {} · {}", bin.file_name, bin.format, bin.arch_name)];
                if bin.arch == Arch::Other {
                    msgs.push(format!(
                        "This program is built for {}. Like IDA Free, Lens reads x86 and x64 code, so only sections, strings, imports and exports are shown.",
                        bin.arch_name
                    ));
                }
                msgs.push(format!("Analysis finished in {secs:.2}s: {}", an.stats));
                msgs.push(format!(
                    "Detected: {} · {} · {} · calling convention {}",
                    det.kind,
                    det.compiler(),
                    det.language(),
                    det.conv.label()
                ));
                // notes last, so the newest message (shown in the status bar) explains what was opened
                msgs.extend(bin.notes.iter().cloned());
                let entry = bin.entry;
                let mut l = Loaded {
                    bin: Arc::new(bin),
                    an,
                    ann,
                    det,
                    names: Arc::new(HashMap::new()),
                    fmt: CodeFormatter::new(Arc::new(HashMap::new())),
                    nav: vec![],
                    graphs: HashMap::new(),
                    version: 0,
                    digits: 8,
                    side_cache: None,
                    func_list: vec![],
                    name_list: vec![],
                    name_index: HashMap::new(),
                    pseudo: HashMap::new(),
                };
                l.refresh();
                let start = pick_start(&l, entry);
                self.prefs.recent.retain(|r| r != &path);
                self.prefs.recent.insert(0, path);
                self.prefs.recent.truncate(8);
                if self.shot.is_none() {
                    store::save_prefs(&self.prefs);
                }
                self.state = State::Ready(Box::new(l));
                for m in msgs {
                    self.logm(m);
                }
                self.history.clear();
                self.hist_pos = 0;
                if let Some(s) = start {
                    self.goto(s, true);
                }
            }
            Err(e) => {
                self.logm(format!("Couldn't open {path}: {e}"));
                self.state = State::Empty;
                self.modal = Some(Modal::Message { title: "Couldn't open the file".into(), text: e });
            }
        }
    }

    pub fn loaded(&self) -> Option<&Loaded> {
        match &self.state {
            State::Ready(l) => Some(l),
            _ => None,
        }
    }

    pub fn goto(&mut self, addr: u64, push: bool) {
        let Some(l) = self.loaded() else { return };
        if !l.bin.is_mapped(addr) {
            self.logm(format!("Address {addr:X} isn't part of this program."));
            return;
        }
        let line = l.an.line_of(addr);
        let in_func = l.an.function_containing(addr).is_some();
        if push {
            self.history.truncate(if self.history.is_empty() { 0 } else { self.hist_pos + 1 });
            if self.history.last() != Some(&addr) {
                self.history.push(addr);
            }
            self.hist_pos = self.history.len() - 1;
        }
        self.nav.cursor = addr;
        self.nav.cursor_line = line;
        self.nav.scroll_to = Some(line);
        self.nav.hex_scroll = true;
        self.nav.graph.center_on = Some(addr);
        if matches!(self.nav.view, View::Graph | View::Pseudo | View::Calls) && !in_func {
            self.nav.view = View::Text;
        }
        self.vis.pseudo_scroll = None;
    }

    pub fn select(&mut self, addr: u64, line: usize) {
        let line = if line == usize::MAX { self.loaded().map(|l| l.an.line_of(addr)).unwrap_or(0) } else { line };
        // remember the spot so Esc comes back here after following something
        if let Some(h) = self.history.get_mut(self.hist_pos) {
            *h = addr;
        }
        self.nav.cursor = addr;
        self.nav.cursor_line = line;
        self.nav.hex_scroll = true;
    }

    pub fn apply_actions(&mut self, ctx: &egui::Context) {
        let acts = std::mem::take(&mut self.actions);
        for a in acts {
            match a {
                Action::Goto(x) => self.goto(x, true),
                Action::Select(x, line) => self.select(x, line),
                Action::Open(p) => self.open(p),
                Action::OpenDialog => {
                    if let Some(f) = rfd::FileDialog::new().set_title("Open a program").pick_file() {
                        self.open(f.to_string_lossy().to_string());
                    }
                }
                Action::Close => {
                    self.state = State::Empty;
                    self.logm("Closed the file.");
                }
                Action::Rename(x) => {
                    if let Some(l) = self.loaded() {
                        let cur = l.names.get(&x).map(|n| n.0.clone()).unwrap_or_default();
                        self.modal = Some(Modal::Rename { addr: x, text: cur, focus: true });
                    }
                }
                Action::Comment(x) => {
                    if let Some(l) = self.loaded() {
                        let cur = l.ann.comments.get(&x).cloned().unwrap_or_default();
                        self.modal = Some(Modal::Comment { addr: x, text: cur, focus: true });
                    }
                }
                Action::Xrefs(x) => self.modal = Some(Modal::Xrefs { addr: x }),
                Action::MakeFunction(x) => self.make_function(x),
                Action::ToggleGraph => {
                    let v = if self.nav.view == View::Graph { View::Text } else { View::Graph };
                    self.set_view(v);
                }
                Action::SetView(v) => self.set_view(v),
                Action::SetSide(s) => {
                    self.nav.side = s;
                    self.nav.filter.clear();
                }
                Action::ToggleTheme => {
                    self.prefs.dark = !self.prefs.dark;
                    self.p = if self.prefs.dark { Palette::dark() } else { Palette::light() };
                    ctx.set_theme(if self.prefs.dark { egui::Theme::Dark } else { egui::Theme::Light });
                    theme::apply(ctx, &self.p);
                    store::save_prefs(&self.prefs);
                }
                Action::ToggleLog => self.show_log = !self.show_log,
                Action::ToggleInspector => {
                    self.prefs.inspector = !self.prefs.inspector;
                    store::save_prefs(&self.prefs);
                }
                Action::Palette => self.modal = Some(Modal::Palette { text: String::new(), sel: 0, focus: true }),
                Action::Jump => self.modal = Some(Modal::Jump { text: String::new(), focus: true }),
                Action::Find => self.modal = Some(Modal::Find { text: self.find_text.clone(), focus: true }),
                Action::FindNext => self.find_next(),
                Action::Back => {
                    if self.hist_pos > 0 && !self.history.is_empty() {
                        self.hist_pos -= 1;
                        let a = self.history[self.hist_pos];
                        self.goto(a, false);
                    }
                }
                Action::Forward => {
                    if self.hist_pos + 1 < self.history.len() {
                        self.hist_pos += 1;
                        let a = self.history[self.hist_pos];
                        self.goto(a, false);
                    }
                }
                Action::ExportC => self.export_c(),
                Action::SetLang(lg) => {
                    self.vis.lang = Some(lg);
                    self.vis.lang_cache = None;
                }
                Action::ExtractAsar => self.extract_asar(),
                Action::Mark(x) => {
                    if let State::Ready(l) = &mut self.state {
                        if let Some(p) = l.ann.marks.iter().position(|m| *m == x) {
                            l.ann.marks.remove(p);
                        } else {
                            l.ann.marks.push(x);
                        }
                        store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
                        l.side_cache = None;
                    }
                }
                Action::Follow => {
                    if let Some(t) = self.loaded().and_then(|l| follow_target(l, self.nav.cursor, self.nav.cursor_line)) {
                        self.goto(t, true);
                    }
                }
            }
        }
    }

    fn set_view(&mut self, v: View) {
        if matches!(v, View::Graph | View::Pseudo | View::Calls) {
            let ok = self.loaded().map(|l| l.an.function_containing(self.nav.cursor).is_some()).unwrap_or(false);
            if !ok {
                self.logm("This view shows one function at a time — move the cursor into a function first.");
                return;
            }
            self.nav.graph.center_on = Some(self.nav.cursor);
        }
        if v == View::Pseudo {
            self.vis.pseudo_scroll = None;
        }
        if v == View::Text {
            self.nav.scroll_to = Some(self.nav.cursor_line);
        }
        if v == View::Hex {
            self.nav.hex_scroll = true;
        }
        self.nav.view = v;
    }

    fn extract_asar(&mut self) {
        let Some(info) = self.loaded().and_then(|l| l.det.asar.clone()) else { return };
        let Some(dir) = rfd::FileDialog::new().set_title("Choose a folder for the JavaScript source").pick_folder() else { return };
        let dest = dir.join("app-source");
        match crate::source::extract_asar(&info.path, &dest) {
            Ok(n) => self.logm(format!("Wrote {n} files of the original source to {}", dest.display())),
            Err(e) => self.logm(format!("Couldn't extract app.asar: {e}")),
        }
    }

    fn export_c(&mut self) {
        let Some(l) = self.loaded() else { return };
        let lg = self.vis.lang.unwrap_or(crate::lang::Lang::C);
        let default = format!("{}.{}", l.bin.file_name, lg.ext());
        let Some(path) = rfd::FileDialog::new().set_title("Save pseudocode").set_file_name(&default).save_file() else { return };
        let text = crate::visuals::export_c(l, lg);
        match std::fs::write(&path, text) {
            Ok(_) => self.logm(format!("Saved pseudocode for every function to {}", path.display())),
            Err(e) => self.logm(format!("Couldn't save the file: {e}")),
        }
    }

    fn make_function(&mut self, addr: u64) {
        let min = self.prefs.min_string_len;
        let State::Ready(l) = &mut self.state else { return };
        if l.an.functions.contains_key(&addr) {
            return;
        }
        if !l.bin.is_exec(addr) {
            self.logm(format!("{addr:X} isn't in a code section, so it can't start a function."));
            return;
        }
        l.ann.functions.push(addr);
        store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
        l.an = analysis::analyze(
            &l.bin,
            &analysis::Settings { min_string_len: min, extra_functions: l.ann.functions.clone() },
            Arc::new(AtomicU32::new(0)),
        );
        l.refresh();
        let msg = format!("Created a function at {addr:X}. {}", l.an.stats);
        self.logm(msg);
        self.goto(addr, false);
    }

    /// Searches the raw bytes of every section, starting after the cursor and wrapping round.
    fn find_bytes(&mut self, pat: &[Option<u8>]) {
        let cur = self.nav.cursor;
        let Some(l) = self.loaded() else { return };
        let mut segs: Vec<&crate::loader::Segment> = l.bin.segments.iter().collect();
        segs.sort_by_key(|s| s.start);
        let scan = |s: &crate::loader::Segment, from: usize| -> Option<u64> {
            let d = &s.data;
            if d.len() < pat.len() {
                return None;
            }
            (from..=d.len() - pat.len()).find(|i| pat.iter().enumerate().all(|(k, b)| b.map(|b| d[i + k] == b).unwrap_or(true))).map(|i| s.start + i as u64)
        };
        let mut hit = None;
        // rest of the section the cursor is in, then later sections, then wrap
        for pass in 0..2 {
            for s in &segs {
                let from = if pass == 0 && s.contains(cur) { (cur + 1 - s.start) as usize } else if pass == 0 && s.start < cur { continue } else { 0 };
                if pass == 1 && s.start > cur {
                    break;
                }
                if let Some(a) = scan(s, from) {
                    hit = Some(a);
                    break;
                }
            }
            if hit.is_some() {
                break;
            }
        }
        match hit {
            Some(a) => {
                self.logm(format!("Bytes found at {a:X}"));
                self.goto(a, true);
            }
            None => self.logm("Those bytes weren't found."),
        }
    }

    fn find_next(&mut self) {
        let needle = self.find_text.to_lowercase();
        if needle.is_empty() {
            return;
        }
        if let Some(pat) = parse_byte_pattern(&self.find_text) {
            self.find_bytes(&pat);
            return;
        }
        let start = self.nav.cursor_line + 1;
        let State::Ready(l) = &mut self.state else { return };
        let n = l.an.lines.len();
        let mut found = None;
        for k in 0..n.min(3_000_000) {
            let i = (start + k) % n;
            if line_text(l, i).to_lowercase().contains(&needle) {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => {
                let a = l.an.lines[i].addr;
                self.nav.cursor = a;
                self.nav.cursor_line = i;
                self.nav.scroll_to = Some(i);
                self.nav.hex_scroll = true;
                self.nav.graph.center_on = Some(a);
            }
            None => {
                let t = self.find_text.clone();
                self.logm(format!("“{t}” wasn't found."))
            }
        }
    }

    pub fn keys(&mut self, ctx: &egui::Context) {
        let typing = ctx.egui_wants_keyboard_input();
        let modal = self.modal.is_some();
        let ready = self.loaded().is_some();
        let cur = self.nav.cursor;
        let mut acts = vec![];
        let mut delta: i64 = 0;
        ctx.input_mut(|i| {
            use egui::Modifiers as M;
            if i.consume_key(M::COMMAND, Key::O) {
                acts.push(Action::OpenDialog);
            }
            if (i.consume_key(M::COMMAND, Key::P) || i.consume_key(M::COMMAND | M::SHIFT, Key::P)) && ready && !modal {
                acts.push(Action::Palette);
            }
            if modal || typing || !ready {
                return;
            }
            let none = M::NONE;
            if i.consume_key(none, Key::G) {
                acts.push(Action::Jump);
            }
            if i.consume_key(none, Key::N) {
                acts.push(Action::Rename(cur));
            }
            if i.consume_key(none, Key::Semicolon) || i.consume_key(M::SHIFT, Key::Semicolon) || i.consume_key(none, Key::Colon) {
                acts.push(Action::Comment(cur));
            }
            if i.consume_key(none, Key::X) || i.consume_key(M::CTRL, Key::X) {
                acts.push(Action::Xrefs(cur));
            }
            if i.consume_key(none, Key::P) {
                acts.push(Action::MakeFunction(cur));
            }
            if i.consume_key(none, Key::Escape) || i.consume_key(M::COMMAND, Key::OpenBracket) {
                acts.push(Action::Back);
            }
            if i.consume_key(M::COMMAND, Key::CloseBracket) || i.consume_key(M::CTRL, Key::Enter) {
                acts.push(Action::Forward);
            }
            if i.consume_key(none, Key::Enter) {
                acts.push(Action::Follow);
            }
            if i.consume_key(none, Key::Space) {
                acts.push(Action::ToggleGraph);
            }
            if i.consume_key(M::SHIFT, Key::F12) {
                acts.push(Action::SetSide(Side::Strings));
            }
            if i.consume_key(M::SHIFT, Key::F3) {
                acts.push(Action::SetSide(Side::Functions));
            }
            if i.consume_key(M::SHIFT, Key::F7) {
                acts.push(Action::SetSide(Side::Segments));
            }
            if i.consume_key(M::ALT, Key::T) || i.consume_key(M::COMMAND, Key::F) {
                acts.push(Action::Find);
            }
            if i.consume_key(M::CTRL, Key::T) || i.consume_key(none, Key::F3) {
                acts.push(Action::FindNext);
            }
            if i.consume_key(none, Key::F5) {
                acts.push(Action::SetView(View::Pseudo));
            }
            if i.consume_key(none, Key::M) {
                acts.push(Action::Mark(cur));
            }
            if i.consume_key(none, Key::H) {
                acts.push(Action::SetView(View::Hex));
            }
            if i.consume_key(none, Key::ArrowDown) {
                delta = 1;
            }
            if i.consume_key(none, Key::ArrowUp) {
                delta = -1;
            }
            if i.consume_key(none, Key::PageDown) {
                delta = 30;
            }
            if i.consume_key(none, Key::PageUp) {
                delta = -30;
            }
        });
        self.actions.extend(acts);
        if delta != 0 {
            self.move_cursor(delta);
        }
    }

    fn move_cursor(&mut self, delta: i64) {
        let Some(l) = self.loaded() else { return };
        if self.nav.view == View::Hex {
            let a = (self.nav.cursor as i64 + delta * 16).max(0) as u64;
            if l.bin.is_mapped(a) {
                let line = l.an.line_of(a);
                self.nav.cursor = a;
                self.nav.cursor_line = line;
                self.nav.hex_scroll = true;
            }
            return;
        }
        let n = l.an.lines.len() as i64;
        if n == 0 {
            return;
        }
        let mut i = (self.nav.cursor_line as i64 + delta).clamp(0, n - 1);
        while i > 0 && i < n - 1 && matches!(l.an.lines[i as usize].kind, LineKind::Blank | LineKind::FuncSep) {
            i += delta.signum();
        }
        let i = i.clamp(0, n - 1) as usize;
        let a = l.an.lines[i].addr;
        self.nav.cursor_line = i;
        self.nav.cursor = a;
        self.nav.hex_scroll = true;
        self.nav.graph.center_on = Some(a);
        let (v0, v1) = self.nav.visible;
        if i < v0 + 2 || i + 3 > v1 {
            // keep the cursor row on screen
            self.nav.scroll_to = Some(if i < v0 + 2 { i + 6 } else { i + 8 - v1.saturating_sub(v0).min(40) + 8 });
        }
    }
}

/// "48 8B ?? 05" (optionally after "hex:") → bytes to look for; `None` = a bytes pattern wasn't meant.
fn parse_byte_pattern(s: &str) -> Option<Vec<Option<u8>>> {
    let t = s.trim();
    let (t, forced) = match t.strip_prefix("hex:") {
        Some(r) => (r.trim(), true),
        None => (t, false),
    };
    let toks: Vec<&str> = t.split_whitespace().collect();
    if toks.is_empty() || (!forced && toks.len() < 2) {
        return None;
    }
    let mut out = vec![];
    for tk in toks {
        if tk == "?" || tk == "??" {
            out.push(None);
        } else if tk.len() == 2 && tk.chars().all(|c| c.is_ascii_hexdigit()) {
            out.push(u8::from_str_radix(tk, 16).ok());
        } else {
            return None;
        }
    }
    Some(out)
}

fn pick_start(l: &Loaded, entry: Option<u64>) -> Option<u64> {
    for n in ["main", "_main", "WinMain", "wmain", "DllMain"] {
        if let Some((a, _)) = l.names.iter().find(|(_, (x, k))| x == n && *k == NameKind::Function) {
            return Some(*a);
        }
    }
    entry
        .filter(|e| l.bin.is_mapped(*e))
        .or_else(|| l.an.functions.keys().next().copied())
        .or_else(|| l.bin.segments.first().map(|s| s.start))
}

impl Loaded {
    pub fn refresh(&mut self) {
        let m = build_names(&self.an, &self.ann, &self.det, &self.bin);
        self.names = Arc::new(m);
        self.fmt = CodeFormatter::new(self.names.clone());
        self.graphs.clear();
        self.version += 1;
        self.side_cache = None;
        self.func_list = self.an.functions.keys().copied().collect();
        let mut nl: Vec<u64> = self.names.keys().copied().collect();
        nl.sort();
        self.name_list = nl;
        self.name_index = self
            .names
            .iter()
            .filter(|(_, (_, k))| matches!(k, NameKind::Function | NameKind::Import))
            .map(|(a, (n, _))| (analysis::display_symbol(n), *a))
            .collect();
        self.pseudo.clear();
        self.digits = format!("{:X}", self.bin.max_addr()).len().max(4);
        self.nav = build_nav(self);
    }

    pub fn name(&self, a: u64) -> Option<&str> {
        self.names.get(&a).map(|x| x.0.as_str())
    }

    /// "main+1C" style location.
    pub fn loc(&self, a: u64) -> String {
        if let Some(f) = self.an.function_containing(a) {
            let n = self.name(f.start).unwrap_or("?");
            if a == f.start {
                return n.to_string();
            }
            return format!("{n}+{:X}", a - f.start);
        }
        if let Some(n) = self.name(a) {
            return n.to_string();
        }
        format!("{a:X}")
    }

    pub fn total_span(&self) -> u64 {
        self.bin.segments.iter().map(|s| s.size).sum::<u64>().max(1)
    }

    pub fn addr_to_off(&self, a: u64) -> Option<u64> {
        let mut acc = 0;
        for s in &self.bin.segments {
            if s.contains(a) {
                return Some(acc + (a - s.start));
            }
            acc += s.size;
        }
        None
    }

    pub fn off_to_addr(&self, mut o: u64) -> Option<u64> {
        for s in &self.bin.segments {
            if o < s.size {
                return Some(s.start + o);
            }
            o -= s.size;
        }
        self.bin.segments.last().map(|s| s.end().saturating_sub(1))
    }

    pub fn item_len(&self, line: usize) -> u64 {
        self.an.lines.get(line).map(|l| l.len.max(1) as u64).unwrap_or(1)
    }
}

/// Navigation band categories: 0 zero-fill, 1 unexplored, 2 data, 3 string, 4 import, 5 code.
fn build_nav(l: &Loaded) -> Vec<u8> {
    let mut nav = vec![0u8; NAV_BUCKETS];
    let total = l.total_span();
    let mut seg_off: Vec<(u64, u64, u64)> = vec![];
    let mut acc = 0;
    for s in &l.bin.segments {
        seg_off.push((s.start, s.end(), acc));
        acc += s.size;
    }
    let import_funcs: std::collections::HashSet<u64> =
        l.an.functions.values().filter(|f| f.kind == FuncKind::Import).map(|f| f.start).collect();
    let mut si = 0;
    for line in &l.an.lines {
        let cat = match line.kind {
            LineKind::Insn => {
                if import_funcs.contains(&line.addr) {
                    4
                } else {
                    5
                }
            }
            LineKind::Str => 3,
            LineKind::Ptr | LineKind::Data => 2,
            LineKind::Bytes => 1,
            _ => continue,
        };
        while si < seg_off.len() && line.addr >= seg_off[si].1 {
            si += 1;
        }
        if si >= seg_off.len() {
            break;
        }
        if line.addr < seg_off[si].0 {
            continue;
        }
        let o = seg_off[si].2 + (line.addr - seg_off[si].0);
        let b0 = (o as u128 * NAV_BUCKETS as u128 / total as u128) as usize;
        let b1 = ((o + line.len.max(1) as u64) as u128 * NAV_BUCKETS as u128 / total as u128) as usize;
        for b in b0.min(NAV_BUCKETS - 1)..=b1.min(NAV_BUCKETS - 1) {
            if nav[b] < cat {
                nav[b] = cat;
            }
        }
    }
    nav
}

/// All names shown in the listing: automatic ones, the person's own, and the guessed `main`.
pub fn build_names(an: &Analysis, ann: &Annotations, det: &Detection, bin: &Binary) -> HashMap<u64, (String, NameKind)> {
    let mut m: HashMap<u64, (String, NameKind)> = an.names.clone();
    if let Some((a, _)) = &det.main {
        let unnamed = m.get(a).map(|n| n.0.starts_with("sub_") || n.0 == "start" || n.0 == "_start").unwrap_or(true);
        if unnamed {
            m.insert(*a, ("main".to_string(), NameKind::Function));
        }
    }
    for (a, n) in &ann.names {
        let k = m.get(a).map(|x| x.1).unwrap_or(if an.functions.contains_key(a) {
            NameKind::Function
        } else if bin.is_exec(*a) {
            NameKind::Label
        } else {
            NameKind::Data
        });
        m.insert(*a, (n.clone(), k));
    }
    m
}

pub fn follow_target(l: &Loaded, addr: u64, line: usize) -> Option<u64> {
    let ln = l.an.lines.get(line)?;
    match ln.kind {
        LineKind::Insn => {
            let i = l.an.insns.get(&addr)?;
            [i.target, i.mem, i.imm].into_iter().find(|t| *t != 0 && l.bin.is_mapped(*t))
        }
        LineKind::Ptr => l.bin.read_ptr(addr).filter(|v| l.bin.is_mapped(*v)),
        _ => None,
    }
}

/// Plain text of a listing line (for find).
fn line_text(l: &mut Loaded, i: usize) -> String {
    let ln = l.an.lines[i];
    match ln.kind {
        LineKind::Insn => {
            let mut s = l
                .fmt
                .format(&l.bin, ln.addr)
                .map(|(_, t)| t.iter().map(|x| x.text.as_str()).collect::<String>())
                .unwrap_or_default();
            if let Some(c) = l.ann.comments.get(&ln.addr) {
                s.push_str(c);
            }
            s
        }
        LineKind::FuncStart | LineKind::Label | LineKind::Ptr | LineKind::Data => l.name(ln.addr).unwrap_or("").to_string(),
        LineKind::Str => l.an.string_at.get(&ln.addr).map(|s| l.an.strings[*s].text.clone()).unwrap_or_default(),
        _ => String::new(),
    }
}
