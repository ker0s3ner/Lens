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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Instant;

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

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DataDef {
    Cycle,
    Str,
    Pointer,
    Undefine,
}

#[derive(Clone)]
pub enum Action {
    Goto(u64),
    Select(u64, usize),
    Open(String),
    OpenDialog,
    SaveProject,
    AddProjectFile,
    Close,
    Rename(u64),
    Comment(u64),
    Xrefs(u64),
    MakeFunction(u64),
    DefineData(u64, DataDef),
    DefinePointerTable(u64),
    DefineArray(u64),
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
    CheckUpdate,
    InstallUpdate,
    ToggleAutoUpdate,
    CopyHash,
    Reveal,
    ExportNotes,
    Search,
    HexTool,
    Settings,
    Reanalyze,
    OpenRaw(Box<crate::loader::RawSpec>),
    Patches,
    Structs,
    LearnSigs,
    ApplySigs,
    ToggleBreakpoint(u64),
    Debugger,
    Script,
    RunPlugin(String),
    Assistant,
    AskAi(usize),
    ReleaseNotes,
    OpenUrl(String),
    Undo,
    Redo,
    Lists,
    Diff,
    Export(crate::ida::ExportKind),
    Import,
    Protos,
    RenameVar(u64, String),
}

pub enum Modal {
    Jump { text: String, focus: bool },
    Rename { addr: u64, text: String, focus: bool },
    Comment { addr: u64, text: String, focus: bool },
    Xrefs { addr: u64 },
    Palette { text: String, sel: usize, focus: bool },
    Find { text: String, focus: bool },
    Message { title: String, text: String },
    RenameVar { func: u64, old: String, text: String, focus: bool },
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
    pub dbg_pc: Option<u64>,
}

/// Runs analysis so that a bug in Lens becomes an error message instead of a frozen "Opening…" screen.
fn guard<F: FnOnce() -> LoadResult>(f: F) -> LoadResult {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(e) => {
            let msg = e.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| e.downcast_ref::<String>().cloned()).unwrap_or_default();
            Err(format!("Lens hit an internal error while analysing this file and stopped ({msg}). Please report it at github.com/ker0s3ner/Lens/issues with the file's name."))
        }
    }
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
    pub update: crate::updater::Status,
    pub update_manual: bool,
    /// The person dismissed the "update available" card (the toolbar button stays).
    pub update_hidden: bool,
    pub tools: crate::tools::Tools,
    pub tools2: TwoState,
    pub sui: crate::settings::SettingsUi,
    pub ai: crate::settings::AiState,
    pub menu: Option<crate::menubar::MenuBar>,
    pub undo: crate::ida::UndoStack,
    pub lists: crate::ida::ListState,
    pub diff: crate::ida::DiffState,
    pub protos: crate::ida::ProtoState,
    pub dbg: Option<crate::debugger::Dbg>,
    pub jobs: crate::tools2::Jobs,
    pub pending_goto: Option<u64>,
    pub last_raw: Option<crate::loader::RawSpec>,
    /// The open workspace manifest, when the current binary belongs to a project.
    pub project: Option<store::ProjectManifest>,
    pub project_path: Option<PathBuf>,
}

#[derive(Default)]
pub struct TwoState {
    pub patch: crate::tools2::PatchState,
    pub types: crate::tools2::TypesState,
    pub dbg: crate::debugger::DbgUi,
    pub script: crate::script::ScriptState,
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
            log: vec!["Lens is ready. Open a program to begin.".into()],
            show_log: false,
            find_text: String::new(),
            frame: 0,
            shot: screenshot.map(|path| Shot { path, done: Arc::new(AtomicBool::new(false)), requested: false, ready_frame: None }),
            title: String::new(),
            char_w: 7.8,
            vis: crate::visuals::VisState::new(),
            update: crate::updater::Status::Idle,
            update_manual: false,
            update_hidden: false,
            tools: crate::tools::Tools::default(),
            tools2: TwoState::default(),
            undo: Default::default(),
            lists: Default::default(),
            diff: Default::default(),
            protos: Default::default(),
            dbg: None,
            jobs: Default::default(),
            pending_goto: None,
            last_raw: None,
            project: None,
            project_path: None,
            sui: Default::default(),
            ai: Default::default(),
            menu: None,
        };
        crate::custom::set_font_size(app.prefs.code_size);
        crate::custom::apply_fonts(&cc.egui_ctx, &app.prefs.ui_font, &app.prefs.mono_font);
        cc.egui_ctx.set_zoom_factor(app.prefs.zoom.clamp(0.8, 1.6));
        if let Ok(t) = std::env::var("LENS_TOOL") {
            match t.as_str() {
                "hex" => {
                    app.tools.hex.open = true;
                    app.tools.hex.text = std::env::var("LENS_HEX").unwrap_or_default();
                    if let Ok(a) = std::env::var("LENS_ARCH") {
                        if let Some(x) = crate::loader::Arch::all().into_iter().find(|x| x.name().to_lowercase().starts_with(&a.to_lowercase())) { app.tools.hex.arch = x; }
                    }
                }
                "search" => { app.tools.search.open = true; app.tools.search.focus = true; app.tools.search.text = std::env::var("LENS_Q").unwrap_or_default(); }
                "settings" => { app.tools.settings_open = true; app.sui.tab = std::env::var("LENS_TAB").ok().and_then(|v| v.parse().ok()).unwrap_or(0); }
                "assistant" => app.ai.open = true,
                "protos" => { app.protos.open = true; app.protos.text = "int check_license(const char *key, int len);\nvoid fatal(const char *msg) noreturn;".into(); }
                "lists" => { app.lists.open = true; app.lists.tab = match std::env::var("LENS_TAB").as_deref() { Ok("imports") => crate::ida::ListTab::Imports, Ok("names") => crate::ida::ListTab::Names, Ok("arrays") => crate::ida::ListTab::Arrays, Ok("pointer_tables") => crate::ida::ListTab::PointerTables, Ok("vtables") => crate::ida::ListTab::Vtables, _ => crate::ida::ListTab::Functions }; }
                "patch" => app.tools2.patch.open = true,
                "structs" => { app.tools2.types.open = true; app.tools2.types.def = "struct Header {\n  uint32_t magic;\n  char name[16];\n  void *next;\n};".into(); }
                "script" => app.tools2.script.open = true,
                "debugger" => app.tools2.dbg.open = true,
                _ => {}
            }
        }
        if app.prefs.auto_update && app.shot.is_none() {
            app.update = crate::updater::Status::Checking(crate::updater::check_async());
        }
        if let Ok(d) = std::env::var("LENS_DEMO_UPDATE") {
            use crate::updater::{Progress, Release, Status};
            let rel = Release { version: "0.3.0".into(), notes: "## What's new\n- Faster analysis on large binaries\n- Switch-table recovery\n- New welcome screen".into(), url: String::new() };
            app.update_manual = true;
            app.update = match d.as_str() {
                "available" => Status::Available(rel),
                "uptodate" => Status::UpToDate(Instant::now()),
                "restart" => Status::Restarting(Instant::now()),
                _ => {
                    let (tx, rx) = std::sync::mpsc::channel();
                    std::mem::forget(tx);
                    let pr = std::sync::Arc::new(Progress::default());
                    pr.total.store(7_600_000, std::sync::atomic::Ordering::Relaxed);
                    pr.done.store(3_100_000, std::sync::atomic::Ordering::Relaxed);
                    Status::Downloading(rel, rx, pr)
                }
            };
        }
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

    pub fn modal_message(&mut self, title: &str, text: String) {
        self.modal = Some(Modal::Message { title: title.into(), text });
    }

    pub fn logm(&mut self, s: impl Into<String>) {
        self.log.push(s.into());
        if self.log.len() > 500 {
            self.log.remove(0);
        }
    }

    pub fn open(&mut self, path: String) {
        let mut binary_path = path.clone();
        if Path::new(&path).extension().and_then(|x| x.to_str()) == Some("lensproj") {
            match store::load_project(Path::new(&path)) {
                Ok(project) => {
                    let selected = project.active_file.as_deref().filter(|f| project.files.iter().any(|candidate| candidate == *f))
                        .or_else(|| project.files.first().map(String::as_str)).map(str::to_string);
                    let Some(selected) = selected else { self.modal = Some(Modal::Message { title: "Couldn't open project".into(), text: "The Lens project has no files.".into() }); return };
                    self.logm(format!("Opening project {} ({} files) …", project.name, project.files.len()));
                    self.project = Some(project);
                    self.project_path = Some(PathBuf::from(&path));
                    let selected_path = Path::new(&selected);
                    binary_path = if selected_path.is_absolute() {
                        selected
                    } else {
                        Path::new(&path).parent().unwrap_or_else(|| Path::new(".")).join(selected_path).to_string_lossy().to_string()
                    };
                }
                Err(e) => { self.modal = Some(Modal::Message { title: "Couldn't open project".into(), text: e }); return; }
            }
        } else {
            let in_project = self.project.as_ref().is_some_and(|project| project.files.iter().any(|file| {
                if file == &path { return true; }
                let Some(project_path) = self.project_path.as_ref() else { return false; };
                let candidate = Path::new(file);
                let resolved = if candidate.is_absolute() { candidate.to_path_buf() }
                    else { project_path.parent().unwrap_or_else(|| Path::new(".")).join(candidate) };
                resolved.to_string_lossy() == path
            }));
            if in_project {
                if let (Some(mut project), Some(project_path)) = (self.project.clone(), self.project_path.clone()) {
                    project.active_file = Some(path.clone());
                    let _ = store::save_project(&project_path, &project.name, &project.files, project.active_file.as_deref());
                    self.project = Some(project);
                }
            } else {
                self.project = None;
                self.project_path = None;
            }
        }
        self.last_raw = None;
        let progress = Arc::new(AtomicU32::new(0));
        let (tx, rx) = channel();
        let pr = progress.clone();
        let min = self.prefs.min_string_len;
        let p2 = binary_path.clone();
        std::thread::spawn(move || {
            let r = guard(move || loader::load(&p2).map(|mut bin| {
                let mut ann = store::load_annotations(&bin.path, bin.file_size);
                crate::patch::apply(&mut bin, &ann.patches);
                let an = analysis::analyze(
                    &bin,
                    &analysis::Settings { min_string_len: min, extra_functions: ann.functions.clone(), data_defs: ann.data_defs.clone() },
                    pr,
                );
                let det = detect::detect(&bin, &an);
                ann.sig_names = crate::sigs::apply(&bin, &an);
                (bin, an, ann, det)
            }));
            let _ = tx.send(r);
        });
        self.logm(format!("Opening {binary_path} …"));
        self.state = State::Loading { path: binary_path, rx, progress, started: Instant::now() };
        self.modal = None;
    }

    pub fn open_raw(&mut self, spec: crate::loader::RawSpec) {
        let progress = Arc::new(AtomicU32::new(0));
        let (tx, rx) = channel();
        let pr = progress.clone();
        let min = self.prefs.min_string_len;
        let label = spec.name.clone();
        std::thread::spawn(move || {
            let r = guard(move || {
            let mut bin = loader::raw_binary(&spec);
            let mut ann = store::load_annotations(&bin.path, bin.file_size);
            crate::patch::apply(&mut bin, &ann.patches);
            let an = analysis::analyze(&bin, &analysis::Settings { min_string_len: min, extra_functions: ann.functions.clone(), data_defs: ann.data_defs.clone() }, pr);
            let det = detect::detect(&bin, &an);
            ann.sig_names = crate::sigs::apply(&bin, &an);
            Ok((bin, an, ann, det))
            });
            let _ = tx.send(r);
        });
        self.logm(format!("Opening raw code {label} …"));
        self.state = State::Loading { path: label, rx, progress, started: Instant::now() };
        self.modal = None;
    }

    pub fn poll_update(&mut self, ctx: &egui::Context) {
        use crate::updater::Status;
        let st = std::mem::replace(&mut self.update, Status::Idle);
        self.update = match st {
            Status::Checking(rx) => match rx.try_recv() {
                Ok(Ok(Some(r))) => {
                    self.logm(format!("Lens {} is available (you have {}).", r.version, crate::updater::CURRENT));
                    Status::Available(r)
                }
                Ok(Ok(None)) => {
                    if self.update_manual { self.logm(format!("Lens {} is the latest version.", crate::updater::CURRENT)); }
                    Status::UpToDate(Instant::now())
                }
                Ok(Err(e)) => {
                    if self.update_manual { self.logm(format!("Update check failed: {e}")); }
                    Status::Failed(e, Instant::now())
                }
                Err(_) => { ctx.request_repaint_after(std::time::Duration::from_millis(300)); Status::Checking(rx) }
            },
            Status::Downloading(r, rx, prog) => match rx.try_recv() {
                Ok(Ok(())) => {
                    self.logm("Update ready — restarting Lens…");
                    Status::Restarting(Instant::now())
                }
                Ok(Err(e)) => {
                    self.logm(format!("Update failed: {e}"));
                    Status::Failed(e, Instant::now())
                }
                Err(_) => { ctx.request_repaint_after(std::time::Duration::from_millis(50)); Status::Downloading(r, rx, prog) }
            },
            Status::Restarting(t) => {
                if t.elapsed().as_millis() > 1300 {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ctx.request_repaint_after(std::time::Duration::from_millis(50));
                Status::Restarting(t)
            }
            Status::UpToDate(t) => {
                if t.elapsed().as_secs_f32() > 3.5 { Status::Idle } else { ctx.request_repaint_after(std::time::Duration::from_millis(100)); Status::UpToDate(t) }
            }
            Status::Failed(e, t) => {
                if t.elapsed().as_secs_f32() > 8.0 { Status::Idle } else { ctx.request_repaint_after(std::time::Duration::from_millis(200)); Status::Failed(e, t) }
            }
            other => other,
        };
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
                        "This program is built for {}. Lens can't decode that CPU yet, so only sections, strings, imports and exports are shown.",
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
                    dbg_pc: None,
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
                if let Some(s) = self.pending_goto.take().or(start) {
                    self.goto(s, true);
                }
                self.plugins_on_open();
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

    fn save_project(&mut self) {
        let Some(binary) = self.loaded().map(|l| l.bin.path.clone()) else {
            self.logm("Open a program before saving a project.");
            return;
        };
        let (name, files) = match &self.project {
            Some(project) => (project.name.clone(), project.files.clone()),
            None => (Path::new(&binary).file_stem().and_then(|s| s.to_str()).unwrap_or("Lens project").to_string(), vec![binary.clone()]),
        };
        let default = format!("{}.lensproj", name.replace(['/', '\\'], "_"));
        let Some(path) = rfd::FileDialog::new().set_title("Save Lens project").set_file_name(&default).save_file() else { return };
        match store::save_project(&path, &name, &files, Some(&binary)) {
            Ok(()) => {
                self.project = Some(store::ProjectManifest { schema_version: 1, name, files, active_file: Some(binary) });
                self.project_path = Some(path.clone());
                self.logm(format!("Saved project to {}", path.display()));
            }
            Err(e) => self.modal = Some(Modal::Message { title: "Couldn't save project".into(), text: e }),
        }
    }

    fn add_project_file(&mut self) {
        let (Some(project), Some(project_path)) = (self.project.clone(), self.project_path.clone()) else {
            self.logm("Save a project before adding files to it.");
            return;
        };
        let Some(file) = rfd::FileDialog::new().set_title("Add a binary to the Lens project").pick_file() else { return };
        let file = file.to_string_lossy().to_string();
        if project.files.iter().any(|f| f == &file) {
            self.logm("That file is already in the project.");
            return;
        }
        let mut files = project.files;
        files.push(file.clone());
        match store::save_project(&project_path, &project.name, &files, project.active_file.as_deref()) {
            Ok(()) => {
                self.project = Some(store::ProjectManifest { schema_version: 1, name: project.name, files, active_file: project.active_file });
                self.logm(format!("Added {file} to the project."));
            }
            Err(e) => self.modal = Some(Modal::Message { title: "Couldn't update project".into(), text: e }),
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
                Action::SaveProject => self.save_project(),
                Action::AddProjectFile => self.add_project_file(),
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
                Action::DefineData(x, d) => self.define_data(x, d),
                Action::DefinePointerTable(x) => self.define_pointer_table(x),
                Action::DefineArray(x) => self.define_array(x),
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
                Action::CheckUpdate => {
                    self.update_manual = true;
                    self.update_hidden = false;
                    self.update = crate::updater::Status::Checking(crate::updater::check_async());
                }
                Action::InstallUpdate => {
                    if let crate::updater::Status::Available(r) = &self.update {
                        let r = r.clone();
                        self.update_manual = true;
                        self.logm(format!("Downloading Lens {} …", r.version));
                        let (rx, prog) = crate::updater::install_async(r.clone());
                        self.update = crate::updater::Status::Downloading(r, rx, prog);
                    }
                }
                Action::Search => {
                    self.tools.search.open = true;
                    self.tools.search.focus = true;
                }
                Action::HexTool => self.tools.hex.open = true,
                Action::Settings => self.tools.settings_open = true,
                Action::Reanalyze => self.reanalyze(),
                Action::OpenRaw(spec) => {
                    self.last_raw = Some((*spec).clone());
                    self.open_raw(*spec)
                }
                Action::Debugger => self.tools2.dbg.open = true,
                Action::Script => self.tools2.script.open = true,
                Action::Assistant => { self.ai.open = true; self.ai.focus = true; }
                Action::ReleaseNotes => {
                    let notes = crate::updater::CURRENT_WHATS_NEW.iter().map(|s| format!("• {s}")).collect::<Vec<_>>().join("\n");
                    self.modal = Some(Modal::Message { title: crate::updater::current_release_title(), text: format!("What's new\n\n{notes}\n\nRelease cadence: x.y.z — major theme release, monthly minor feature release, and patch/QoL release.") });
                }
                Action::Undo => self.do_undo(false),
                Action::Redo => self.do_undo(true),
                Action::Lists => self.lists.open = true,
                Action::Diff => self.start_diff(),
                Action::Export(k) => self.export_db(k),
                Action::Import => self.import_db(),
                Action::RenameVar(f, old) => {
                    let cur = self.loaded().and_then(|l| l.ann.vars.get(&format!("{f:X}:{old}")).cloned()).unwrap_or_else(|| old.clone());
                    self.modal = Some(Modal::RenameVar { func: f, old, text: cur, focus: true });
                }
                Action::Protos => { self.protos.open = true; self.protos.text = self.loaded().map(|l| l.ann.protos.clone()).unwrap_or_default(); }
                Action::AskAi(i) => self.ask_ai(i),
                Action::OpenUrl(u) => { let _ = std::process::Command::new("open").arg(u).spawn(); }
                Action::RunPlugin(p) => self.run_plugin(&p),
                Action::Patches => self.tools2.patch.open = true,
                Action::Structs => self.tools2.types.open = true,
                Action::LearnSigs => self.learn_sigs(),
                Action::ApplySigs => self.apply_sigs_now(),
                Action::ToggleBreakpoint(a) => self.toggle_breakpoint(a),
                Action::CopyHash => {
                    if let Some(h) = self.loaded().map(|l| l.det.sha256.clone()) {
                        ctx.copy_text(h.clone());
                        self.logm(format!("Copied SHA-256 {h}"));
                    }
                }
                Action::Reveal => {
                    if let Some(p) = self.loaded().map(|l| l.bin.path.clone()) {
                        let _ = std::process::Command::new("open").arg("-R").arg(p).spawn();
                    }
                }
                Action::ExportNotes => {
                    let Some(l) = self.loaded() else { return };
                    let default = format!("{}.lens-notes.json", l.bin.file_name);
                    let json = serde_json::to_string_pretty(&l.ann).unwrap_or_default();
                    if let Some(path) = rfd::FileDialog::new().set_title("Save your names and notes").set_file_name(&default).save_file() {
                        match std::fs::write(&path, json) {
                            Ok(_) => self.logm(format!("Saved names and notes to {}", path.display())),
                            Err(e) => self.logm(format!("Couldn't save: {e}")),
                        }
                    }
                }
                Action::ToggleAutoUpdate => {
                    self.prefs.auto_update = !self.prefs.auto_update;
                    store::save_prefs(&self.prefs);
                }
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

    /// IDA's D / A / U: change what the bytes at `addr` are shown as, then redo the analysis.
    fn define_data(&mut self, addr: u64, d: DataDef) {
        let min = self.prefs.min_string_len;
        let State::Ready(l) = &mut self.state else { return };
        if l.an.insns.contains_key(&addr) || l.an.functions.contains_key(&addr) {
            self.logm(format!("{addr:X} is code. Data keys only work on data."));
            return;
        }
        if !l.bin.is_mapped(addr) {
            return;
        }
        let ptr = (l.bin.bitness() / 8) as u8;
        let cur = l.ann.data_defs.get(&addr).copied().or_else(|| l.an.data_size.get(&addr).copied());
        let (code, what) = match d {
            DataDef::Str => (analysis::DEF_STRING, "a string".to_string()),
            DataDef::Pointer => (ptr | 0x80, "a pointer".to_string()),
            DataDef::Undefine => (analysis::DEF_UNDEFINE, "undefined".to_string()),
            DataDef::Cycle => {
                let n = if l.an.string_at.contains_key(&addr) { 0 } else { cur.map(|c| c & 0x7f).unwrap_or(0) };
                let next = match n { 1 => 2, 2 => 4, 4 if ptr == 8 => 8, _ => 1 };
                let name = match next { 1 => "byte", 2 => "word", 4 => "dword", _ => "qword" };
                (next, name.to_string())
            }
        };
        l.ann.data_defs.insert(addr, code);
        store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
        l.an = analysis::analyze(
            &l.bin,
            &analysis::Settings { min_string_len: min, extra_functions: l.ann.functions.clone(), data_defs: l.ann.data_defs.clone() },
            Arc::new(AtomicU32::new(0)),
        );
        l.refresh();
        self.logm(format!("{addr:X} is now {what}."));
        self.goto(addr, false);
    }

    /// Promote an auto-discovered pointer run into persistent native pointer data.
    fn define_pointer_table(&mut self, addr: u64) {
        let min = self.prefs.min_string_len;
        let State::Ready(l) = &mut self.state else { return };
        let Some(entries) = l.an.pointer_tables.get(&addr).cloned() else {
            self.logm(format!("{addr:X} is not a discovered pointer table."));
            return;
        };
        if entries.is_empty() { return; }
        let width = (l.bin.bitness() / 8) as u64;
        let code = width as u8 | 0x80;
        for index in 0..entries.len() {
            let slot = addr.saturating_add(index as u64 * width);
            if l.bin.is_mapped(slot) && !l.an.insns.contains_key(&slot) {
                l.ann.data_defs.insert(slot, code);
            }
        }
        store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
        l.an = analysis::analyze(
            &l.bin,
            &analysis::Settings { min_string_len: min, extra_functions: l.ann.functions.clone(), data_defs: l.ann.data_defs.clone() },
            Arc::new(AtomicU32::new(0)),
        );
        l.refresh();
        self.logm(format!("Defined {} native pointers at {addr:X}.", entries.len()));
        self.goto(addr, false);
    }

    /// Persist a contiguous run of same-sized data elements as an array.
    fn define_array(&mut self, addr: u64) {
        let min = self.prefs.min_string_len;
        let State::Ready(l) = &mut self.state else { return };
        if l.an.insns.contains_key(&addr) || !l.bin.is_mapped(addr) { return; }
        let Some(&seed) = l.ann.data_defs.get(&addr).or_else(|| l.an.data_size.get(&addr)) else {
            self.logm(format!("{addr:X} has no inferred data element to extend."));
            return;
        };
        let width = (seed & 0x7f) as u64;
        if width == 0 || width > 8 { return; }
        let mut count = 0usize;
        let mut slot = addr;
        while count < 256 && l.bin.is_mapped(slot) && !l.an.insns.contains_key(&slot) {
            let same = l.ann.data_defs.get(&slot).copied().or_else(|| l.an.data_size.get(&slot).copied()).map(|v| v == seed).unwrap_or(false);
            if !same { break; }
            count += 1;
            slot = slot.saturating_add(width);
        }
        if count < 2 {
            self.logm(format!("No contiguous array found at {addr:X}."));
            return;
        }
        for index in 0..count {
            l.ann.data_defs.insert(addr + index as u64 * width, seed);
        }
        store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
        l.an = analysis::analyze(
            &l.bin,
            &analysis::Settings { min_string_len: min, extra_functions: l.ann.functions.clone(), data_defs: l.ann.data_defs.clone() },
            Arc::new(AtomicU32::new(0)),
        );
        l.refresh();
        self.logm(format!("Defined {count}-element array at {addr:X}."));
        self.goto(addr, false);
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
            &analysis::Settings { min_string_len: min, extra_functions: l.ann.functions.clone(), data_defs: l.ann.data_defs.clone() },
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
        // recording a new key binding in Settings
        if let Some(id) = self.sui.rebinding.clone() {
            let ev = ctx.input(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Key { key, pressed: true, modifiers, repeat: false, .. } => Some((*key, *modifiers)),
                    _ => None,
                })
            });
            if let Some((key, m)) = ev {
                let s = crate::custom::describe(m, key);
                if let Some(other) = crate::custom::conflict(&self.prefs.keys, &id, &s) {
                    self.sui.font_msg = format!("{s} is already used for \"{other}\".");
                } else {
                    self.prefs.keys.insert(id, s);
                    self.save_prefs();
                    self.sui.font_msg.clear();
                }
                self.sui.rebinding = None;
            }
            ctx.input_mut(|i| i.events.retain(|e| !matches!(e, egui::Event::Key { .. })));
            return;
        }
        let typing = ctx.egui_wants_keyboard_input();
        let modal = self.modal.is_some();
        let ready = self.loaded().is_some();
        let cur = self.nav.cursor;
        let mut acts = vec![];
        let mut delta: i64 = 0;
        let km = self.prefs.keys.clone();
        ctx.input_mut(|i| {
            use egui::Modifiers as M;
            let mut hit = |id: &str| crate::custom::hit(i, &crate::custom::spec(&km, id));
            if hit("breakpoint") && ready && !modal && !typing {
                acts.push(Action::ToggleBreakpoint(cur));
            }
            if hit("search") {
                acts.push(Action::Search);
            }
            if hit("settings") {
                acts.push(Action::Settings);
            }
            if hit("assistant") {
                acts.push(Action::Assistant);
            }
            if hit("open") {
                acts.push(Action::OpenDialog);
            }
            if (hit("palette") || i.consume_key(M::COMMAND | M::SHIFT, Key::P)) && ready && !modal {
                acts.push(Action::Palette);
            }
            if modal || typing || !ready {
                return;
            }
            if i.consume_key(M::COMMAND | M::SHIFT, Key::Z) { acts.push(Action::Redo); }
            if i.consume_key(M::COMMAND, Key::Z) { acts.push(Action::Undo); }
            let none = M::NONE;
            let mut hit = |id: &str| crate::custom::hit(i, &crate::custom::spec(&km, id));
            if hit("jump") { acts.push(Action::Jump); }
            if hit("rename") { acts.push(Action::Rename(cur)); }
            if hit("comment") { acts.push(Action::Comment(cur)); }
            if hit("xrefs") { acts.push(Action::Xrefs(cur)); }
            if hit("make_func") { acts.push(Action::MakeFunction(cur)); }
            if hit("data") { acts.push(Action::DefineData(cur, DataDef::Cycle)); }
            if hit("pointer") { acts.push(Action::DefineData(cur, DataDef::Pointer)); }
            if hit("table") { acts.push(Action::DefinePointerTable(cur)); }
            if hit("array") { acts.push(Action::DefineArray(cur)); }
            if hit("ascii") { acts.push(Action::DefineData(cur, DataDef::Str)); }
            if hit("undef") { acts.push(Action::DefineData(cur, DataDef::Undefine)); }
            if hit("back") { acts.push(Action::Back); }
            if hit("forward") { acts.push(Action::Forward); }
            if hit("follow") { acts.push(Action::Follow); }
            if hit("graph") { acts.push(Action::ToggleGraph); }
            if hit("side_strings") { acts.push(Action::SetSide(Side::Strings)); }
            if hit("side_funcs") { acts.push(Action::SetSide(Side::Functions)); }
            if hit("side_segs") { acts.push(Action::SetSide(Side::Segments)); }
            if hit("find") { acts.push(Action::Find); }
            if hit("find_next") { acts.push(Action::FindNext); }
            if hit("pseudo") { acts.push(Action::SetView(View::Pseudo)); }
            if hit("mark") { acts.push(Action::Mark(cur)); }
            if hit("hex") { acts.push(Action::SetView(View::Hex)); }
            // always available alongside the configurable ones
            if i.consume_key(M::SHIFT, Key::Semicolon) || i.consume_key(none, Key::Colon) { acts.push(Action::Comment(cur)); }
            if i.consume_key(M::COMMAND, Key::OpenBracket) { acts.push(Action::Back); }
            if i.consume_key(M::CTRL, Key::Enter) { acts.push(Action::Forward); }
            if i.consume_key(M::CTRL, Key::T) { acts.push(Action::FindNext); }
            if i.consume_key(none, Key::ArrowDown) { delta = 1; }
            if i.consume_key(none, Key::ArrowUp) { delta = -1; }
            if i.consume_key(none, Key::PageDown) { delta = 30; }
            if i.consume_key(none, Key::PageUp) { delta = -30; }
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
fn none_mod() -> egui::Modifiers {
    egui::Modifiers::NONE
}

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
        crate::protos::set_user(&format!("{}\n{}", self.bin.debug_protos, self.ann.protos));
        // Applied pointer members provide precise data-reference edges, including
        // packed or otherwise unaligned fields that the conservative segment scan may miss.
        let mut typed_edges = Vec::new();
        for (base, type_name) in &self.ann.applied {
            let Some(def) = self.ann.structs.iter().find(|d| d.name == *type_name) else { continue };
            if def.is_enum { continue; }
            for field in crate::types::flatten_fields(&self.ann.structs, def) {
                if !crate::types::is_pointer_type(&field.ty, &self.ann.structs) { continue; }
                let slot = base.saturating_add(field.off as u64);
                if let Some(target) = self.bin.read_ptr(slot).filter(|target| *target != 0 && self.bin.is_mapped(*target)) {
                    typed_edges.push((target, analysis::Xref { from: slot, kind: analysis::XrefKind::Data }));
                }
            }
        }
        for (target, edge) in typed_edges {
            let refs = self.an.xrefs_to.entry(target).or_default();
            if !refs.iter().any(|old| old.from == edge.from && old.kind == edge.kind) { refs.push(edge); }
            refs.sort_by_key(|xref| xref.from);
        }
        let m = build_names(&self.an, &self.ann, &self.det, &self.bin);
        self.names = Arc::new(m);
        self.fmt = CodeFormatter::new(self.names.clone());
        let frames: Vec<(u64, u64)> = self.an.functions.values().filter(|f| crate::code::has_frame_pointer(&self.bin, f.start)).map(|f| (f.start, f.end)).collect();
        self.fmt.set_frames(frames, self.ann.vars.clone());
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
    for (a, n, _) in &det.crypto {
        if !bin.is_exec(*a) && !m.contains_key(a) {
            m.insert(*a, (n.clone(), NameKind::Data));
        }
    }
    if let Some((a, _)) = &det.main {
        let unnamed = m.get(a).map(|n| n.0.starts_with("sub_") || n.0 == "start" || n.0 == "_start").unwrap_or(true);
        if unnamed {
            m.insert(*a, ("main".to_string(), NameKind::Function));
        }
    }
    for (a, n) in &ann.sig_names {
        let unnamed = m.get(a).map(|x| x.0.starts_with("sub_")).unwrap_or(true);
        if unnamed {
            m.insert(*a, (n.clone(), NameKind::Function));
        }
    }
    for (a, n) in crate::types::field_names(&ann.structs, &ann.applied) {
        m.insert(a, (n, NameKind::Data));
    }
    for (a, type_name) in &ann.applied {
        if let Some(def) = ann.structs.iter().find(|s| s.name == *type_name && s.is_enum) {
            if let Some(value) = crate::types::enum_value(bin, *a, def) {
                let member = value.split(" (").next().unwrap_or(&value);
                m.insert(*a, (format!("{type_name}::{member}"), NameKind::Data));
            }
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
pub fn line_text(l: &mut Loaded, i: usize) -> String {
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
