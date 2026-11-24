//! Things IDA has that Lens was missing: undo/redo, the Lists windows (Names, Imports, Exports,
//! Entry points, Bookmarks), binary diffing and database export (IDC, JSON, MAP, Ghidra script).

use crate::analysis::{self, display_symbol, NameKind};
use crate::app::{Action, Loaded, LensApp, State};
use crate::store::{self, Annotations};
use eframe::egui::{self, RichText, ScrollArea, TextEdit};
use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

// ------------------------------------------------------------------ undo / redo

#[derive(Default)]
pub struct UndoStack {
    key: String,
    shadow: Option<Annotations>,
    print: u64,
    undo: Vec<Annotations>,
    redo: Vec<Annotations>,
}

fn h<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

/// Order-independent fingerprint of everything the person edits (not patches).
fn fingerprint(a: &Annotations) -> u64 {
    let mut x = 0u64;
    for (k, v) in &a.names { x ^= h(&(1u8, k, v)); }
    for (k, v) in &a.comments { x ^= h(&(2u8, k, v)); }
    for f in &a.functions { x ^= h(&(3u8, f)); }
    for m in &a.marks { x ^= h(&(4u8, m)); }
    for b in &a.breakpoints { x ^= h(&(5u8, b)); }
    for (addr, condition) in &a.bp_conditions { x ^= h(&(10u8, addr, condition)); }
    for (k, v) in &a.applied { x ^= h(&(6u8, k, v)); }
    x ^= h(&(7u8, a.structs.len()));
    x ^= h(&(8u8, &a.protos));
    for (k, v) in &a.vars { x ^= h(&(9u8, k, v)); }
    x
}

impl UndoStack {
    pub fn can_undo(&self) -> bool { !self.undo.is_empty() }
    pub fn can_redo(&self) -> bool { !self.redo.is_empty() }
}

impl LensApp {
    /// Call once per frame: notices edits and remembers the state before them.
    pub fn track_undo(&mut self) {
        let State::Ready(l) = &self.state else {
            self.undo = UndoStack::default();
            return;
        };
        let key = format!("{}:{}", l.bin.path, l.bin.file_size);
        let fp = fingerprint(&l.ann);
        let u = &mut self.undo;
        if u.key != key || u.shadow.is_none() {
            *u = UndoStack { key, shadow: Some(l.ann.clone()), print: fp, ..Default::default() };
            return;
        }
        if fp != u.print {
            if let Some(prev) = u.shadow.take() {
                u.undo.push(prev);
                if u.undo.len() > 200 { u.undo.remove(0); }
            }
            u.redo.clear();
            u.shadow = Some(l.ann.clone());
            u.print = fp;
        }
    }

    pub fn do_undo(&mut self, redo: bool) {
        let from = if redo { self.undo.redo.pop() } else { self.undo.undo.pop() };
        let Some(target) = from else {
            self.logm(if redo { "Nothing to redo." } else { "Nothing to undo." });
            return;
        };
        let State::Ready(l) = &mut self.state else { return };
        let current = l.ann.clone();
        if redo { self.undo.undo.push(current); } else { self.undo.redo.push(current); }
        let funcs_changed = l.ann.functions != target.functions;
        l.ann.names = target.names.clone();
        l.ann.comments = target.comments.clone();
        l.ann.functions = target.functions.clone();
        l.ann.marks = target.marks.clone();
        l.ann.breakpoints = target.breakpoints.clone();
        l.ann.bp_conditions = target.bp_conditions.clone();
        l.ann.applied = target.applied.clone();
        l.ann.structs = target.structs.clone();
        l.ann.protos = target.protos.clone();
        l.ann.vars = target.vars.clone();
        store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
        l.refresh();
        self.undo.print = fingerprint(&l.ann);
        self.undo.shadow = Some(l.ann.clone());
        self.logm(if redo { "Redone." } else { "Undone." });
        if funcs_changed {
            self.reanalyze();
        }
    }
}

// ------------------------------------------------------------------ lists

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum ListTab {
    #[default]
    Functions,
    Names,
    Imports,
    Exports,
    Entries,
    Strings,
    Sections,
    Findings,
    Vtables,
    PointerTables,
    Arrays,
    Bookmarks,
}

impl ListTab {
    const ALL: [ListTab; 12] = [ListTab::Functions, ListTab::Names, ListTab::Imports, ListTab::Exports, ListTab::Entries, ListTab::Strings, ListTab::Sections, ListTab::Findings, ListTab::Vtables, ListTab::PointerTables, ListTab::Arrays, ListTab::Bookmarks];
    fn label(self) -> &'static str {
        match self {
            ListTab::Functions => "Functions",
            ListTab::Names => "Names",
            ListTab::Imports => "Imports",
            ListTab::Exports => "Exports",
            ListTab::Entries => "Entry points",
            ListTab::Strings => "Strings",
            ListTab::Sections => "Sections",
            ListTab::Findings => "Crypto",
            ListTab::Vtables => "Vtables",
            ListTab::PointerTables => "Pointer tables",
            ListTab::Arrays => "Arrays",
            ListTab::Bookmarks => "Bookmarks",
        }
    }
}

#[derive(Default)]
pub struct ListState {
    pub open: bool,
    pub tab: ListTab,
    pub filter: String,
    /// 0 = address, 1 = name, 2 = detail (size / library / note)
    pub sort: u8,
    pub desc: bool,
    cache: Option<((ListTab, String, u8, bool, u64), Vec<Row>)>,
}

#[derive(Clone)]
struct Row {
    addr: u64,
    name: String,
    detail: String,
    num: u64,
}

fn rows(l: &Loaded, tab: ListTab) -> Vec<Row> {
    let name_of = |a: u64| l.names.get(&a).map(|(n, _)| display_symbol(n)).unwrap_or_else(|| format!("{a:X}"));
    match tab {
        ListTab::Functions => l
            .an
            .functions
            .values()
            .map(|f| {
                let xr = l.an.xrefs_to.get(&f.start).map(|v| v.len()).unwrap_or(0);
                let thunk = f.thunk_target.map(|t| format!(" · thunk → {t:X}")).unwrap_or_default();
                Row { addr: f.start, name: name_of(f.start), detail: format!("{} B · {} blocks · {} callers{thunk}", f.size(), f.blocks.len(), xr), num: f.size() }
            })
            .collect(),
        ListTab::Names => l
            .names
            .iter()
            .map(|(a, (n, k))| Row {
                addr: *a,
                name: display_symbol(n),
                detail: match k { NameKind::Function => "function", NameKind::Import => "import", NameKind::Label => "label", NameKind::String => "string", NameKind::Data => "data" }.into(),
                num: 0,
            })
            .collect(),
        ListTab::Imports => l.bin.imports.iter().map(|i| Row { addr: i.slot, name: display_symbol(&i.name), detail: i.library.clone(), num: 0 }).collect(),
        ListTab::Exports => l.bin.exports.iter().map(|e| Row { addr: e.addr, name: display_symbol(&e.name), detail: String::new(), num: 0 }).collect(),
        ListTab::Entries => {
            let mut v: Vec<Row> = vec![];
            if let Some(e) = l.bin.entry {
                v.push(Row { addr: e, name: name_of(e), detail: "program entry".into(), num: 0 });
            }
            if let Some((a, _)) = &l.det.main {
                v.push(Row { addr: *a, name: name_of(*a), detail: "main".into(), num: 0 });
            }
            for e in &l.bin.exports {
                v.push(Row { addr: e.addr, name: display_symbol(&e.name), detail: "exported".into(), num: 0 });
            }
            v.sort_by_key(|r| r.addr);
            v.dedup_by_key(|r| r.addr);
            v
        }
        ListTab::Strings => l
            .an
            .strings
            .iter()
            .map(|s| {
                let xr = l.an.xrefs_to.get(&s.addr).map(|v| v.len()).unwrap_or(0);
                Row { addr: s.addr, name: crate::code::escape_str(&s.text, 90), detail: format!("{xr} uses"), num: xr as u64 }
            })
            .collect(),
        ListTab::Sections => l
            .bin
            .segments
            .iter()
            .map(|g| Row { addr: g.start, name: g.name.clone(), detail: format!("{} bytes · {}{}", g.size, if g.exec { "code " } else { "" }, if g.write { "writable" } else { "read-only" }), num: g.size })
            .collect(),
        ListTab::Findings => l
            .det
            .crypto
            .iter()
            .map(|(a, n, algo)| Row { addr: *a, name: n.clone(), detail: algo.clone(), num: 0 })
            .collect(),
        ListTab::Vtables => l
            .an
            .vtables
            .iter()
            .map(|(a, entries)| Row {
                addr: *a,
                name: l.an.vtable_names.get(a).cloned().unwrap_or_else(|| name_of(*a)),
                detail: format!("{} entries · {} code xrefs", entries.len(), entries.iter().map(|t| l.an.xrefs_to.get(t).map(|x| x.len()).unwrap_or(0)).sum::<usize>()),
                num: entries.len() as u64,
            })
            .collect(),
        ListTab::PointerTables => l
            .an
            .pointer_tables
            .iter()
            .map(|(a, entries)| Row {
                addr: *a,
                name: name_of(*a),
                detail: format!("{} entries", entries.len()),
                num: entries.len() as u64,
            })
            .collect(),
        ListTab::Arrays => {
            let mut defs: Vec<(u64, u8)> = l.ann.data_defs.iter().map(|(a, d)| (*a, *d)).filter(|(_, d)| *d != crate::analysis::DEF_STRING && *d != crate::analysis::DEF_UNDEFINE && (*d & 0x80) == 0 && (*d & 0x7f) > 0).collect();
            defs.sort_by_key(|(a, _)| *a);
            let mut out = Vec::new();
            let mut i = 0;
            while i < defs.len() {
                let (start, code) = defs[i];
                let width = (code & 0x7f) as u64;
                let mut n = 1usize;
                while i + n < defs.len() && defs[i + n].1 == code && defs[i + n].0 == start + n as u64 * width { n += 1; }
                if n >= 2 {
                    out.push(Row { addr: start, name: name_of(start), detail: format!("{n} elements · {}-byte", width), num: n as u64 });
                }
                i += n;
            }
            out
        }
        ListTab::Bookmarks => l
            .ann
            .marks
            .iter()
            .map(|a| Row { addr: *a, name: name_of(*a), detail: l.ann.comments.get(a).cloned().unwrap_or_default(), num: 0 })
            .collect(),
    }
}

impl LensApp {
    pub fn lists_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let mut goto: Option<u64> = None;
        let State::Ready(l) = &self.state else {
            self.lists.open = false;
            return;
        };
        let ls = &mut self.lists;
        let key = (ls.tab, ls.filter.clone(), ls.sort, ls.desc, l.version ^ (l.ann.marks.len() as u64) << 40);
        if ls.cache.as_ref().map(|c| c.0 != key).unwrap_or(true) {
            let q = ls.filter.to_lowercase();
            let mut r: Vec<Row> = rows(l, ls.tab).into_iter().filter(|r| q.is_empty() || r.name.to_lowercase().contains(&q) || r.detail.to_lowercase().contains(&q) || format!("{:x}", r.addr).contains(&q)).collect();
            match ls.sort {
                1 => r.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
                2 => if matches!(ls.tab, ListTab::Functions | ListTab::Strings | ListTab::Sections | ListTab::Vtables | ListTab::PointerTables | ListTab::Arrays) { r.sort_by_key(|x| x.num) } else { r.sort_by(|a, b| a.detail.cmp(&b.detail)) },
                _ => r.sort_by_key(|x| x.addr),
            }
            if ls.desc { r.reverse(); }
            ls.cache = Some((key, r));
        }
        let digits = l.digits;
        let detail_head = match ls.tab { ListTab::Functions | ListTab::Sections => "Size", ListTab::Strings => "Uses", ListTab::Imports => "Library", ListTab::Bookmarks => "Note", ListTab::Vtables | ListTab::PointerTables | ListTab::Arrays => "Entries", _ => "Kind" };
        egui::Window::new("Lists").open(&mut open).default_size([640.0, 520.0]).show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                for t in ListTab::ALL {
                    if ui.selectable_label(ls.tab == t, t.label()).clicked() {
                        ls.tab = t;
                        ls.sort = 0;
                        ls.desc = false;
                    }
                }
            });
            ui.add(TextEdit::singleline(&mut ls.filter).desired_width(f32::INFINITY).hint_text("Filter by name, address or note…"));
            let n = ls.cache.as_ref().map(|c| c.1.len()).unwrap_or(0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{n} shown")).small().color(p.faint));
                ui.add_space(12.0);
                for (i, name) in [(0u8, "Address"), (1, "Name"), (2, detail_head)] {
                    let arrow = if ls.sort == i { if ls.desc { " ↓" } else { " ↑" } } else { "" };
                    if ui.small_button(format!("{name}{arrow}")).clicked() {
                        if ls.sort == i { ls.desc = !ls.desc } else { ls.sort = i; ls.desc = false }
                    }
                }
            });
            ui.separator();
            let rows = ls.cache.as_ref().map(|c| &c.1[..]).unwrap_or(&[]);
            ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, 20.0, rows.len(), |ui, range| {
                for r in &rows[range] {
                    let resp = ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{:0w$X}", r.addr, w = digits)).monospace().color(p.func_name));
                        ui.label(RichText::new(&r.name).monospace());
                        ui.label(RichText::new(&r.detail).small().color(p.muted));
                    });
                    let resp = ui.interact(resp.response.rect, egui::Id::unique(("lrow", r.addr, &r.name)), egui::Sense::click());
                    if resp.clicked() { goto = Some(r.addr); }
                    if resp.hovered() { ui.painter().rect_filled(resp.rect, 2.0, p.accent.gamma_multiply(0.08)); }
                }
            });
        });
        if let Some(a) = goto { self.actions.push(Action::Goto(a)); }
        if !open { self.lists.open = false; }
    }
}

// ------------------------------------------------------------------ prototypes

#[derive(Default)]
pub struct ProtoState {
    pub open: bool,
    pub text: String,
    pub filter: String,
    pub msg: String,
}

impl LensApp {
    pub fn protos_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let mut apply = false;
        let mut msg = std::mem::take(&mut self.protos.msg);
        egui::Window::new("Function prototypes").open(&mut open).default_size([620.0, 560.0]).show(ctx, |ui| {
            if self.loaded().is_none() {
                ui.label(RichText::new("Open a program first.").color(p.muted));
                return;
            }
            ui.label(RichText::new("Tell Lens what a function takes and returns, in C. Calls get the right number of arguments, functions marked noreturn end the code path, and a function's own signature uses your types and parameter names.").color(p.muted));
            ui.add_space(4.0);
            ui.add(TextEdit::multiline(&mut self.protos.text).code_editor().desired_rows(8).desired_width(f32::INFINITY).hint_text("int check_license(const char *key, int len);\nvoid fatal(const char *msg) noreturn;\nint sub_401120(void *ctx, size_t n);"));
            ui.horizontal(|ui| {
                if ui.button("Apply").clicked() { apply = true; }
                ui.label(RichText::new(format!("{} built-in prototypes", crate::protos::builtin_count())).small().color(p.faint));
            });
            if !msg.is_empty() { ui.label(RichText::new(&msg).color(p.accent)); }
            ui.separator();
            ui.add(TextEdit::singleline(&mut self.protos.filter).desired_width(f32::INFINITY).hint_text("Search the built-in library (click one to copy it into the box above)…"));
            let q = self.protos.filter.to_lowercase();
            let names: Vec<String> = crate::protos::count_builtin_names().into_iter().filter(|n| q.is_empty() || n.to_lowercase().contains(&q)).collect();
            let mut pick: Option<String> = None;
            ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, 20.0, names.len(), |ui, range| {
                for n in &names[range] {
                    if let Some(pr) = crate::protos::find(n) {
                        if ui.add(egui::Label::new(RichText::new(pr.signature()).monospace().small()).sense(egui::Sense::click())).clicked() { pick = Some(format!("{};", pr.signature())); }
                    }
                }
            });
            if let Some(t) = pick {
                if !self.protos.text.is_empty() && !self.protos.text.ends_with('\n') { self.protos.text.push('\n'); }
                self.protos.text.push_str(&t);
                self.protos.text.push('\n');
            }
        });
        if apply {
            let (ps, errs) = crate::protos::parse(&self.protos.text);
            msg = if errs.is_empty() { format!("Applied {} prototypes.", ps.len()) } else { errs.join("\n") };
            let text = self.protos.text.clone();
            if let State::Ready(l) = &mut self.state {
                l.ann.protos = text;
                store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
                l.refresh();
            }
        }
        self.protos.msg = msg;
        if !open { self.protos.open = false; }
    }
}

// ------------------------------------------------------------------ binary diff

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    Same,
    Changed,
    Renamed,
    OnlyA,
    OnlyB,
}

impl DiffKind {
    fn label(self) -> &'static str {
        match self {
            DiffKind::Same => "identical",
            DiffKind::Changed => "changed",
            DiffKind::Renamed => "renamed",
            DiffKind::OnlyA => "only here",
            DiffKind::OnlyB => "only in other",
        }
    }
}

pub struct DiffRow {
    pub kind: DiffKind,
    pub name: String,
    pub a: Option<u64>,
    pub b: Option<u64>,
    pub size_a: u64,
    pub size_b: u64,
    pub note: String,
}

pub struct DiffOut {
    pub other: String,
    pub rows: Vec<DiffRow>,
}

#[derive(Default)]
pub struct DiffState {
    pub open: bool,
    pub filter: String,
    pub show: [bool; 5],
    pub busy: Option<(String, Arc<AtomicU32>, Receiver<Result<DiffOut, String>>)>,
    pub out: Option<DiffOut>,
    pub err: String,
}

struct Sig {
    name: String,
    addr: u64,
    size: u64,
    shape: u64,
    insns: usize,
}

fn signatures(bin: &crate::loader::Binary, an: &analysis::Analysis) -> Vec<Sig> {
    an.functions
        .values()
        .map(|f| {
            // hash instruction lengths + flow kinds: stable when only addresses move
            let mut hs = DefaultHasher::new();
            for b in &f.blocks {
                for a in &b.insns {
                    if let Some(i) = an.insns.get(a) {
                        i.len.hash(&mut hs);
                        format!("{:?}", i.flow).hash(&mut hs);
                    }
                }
            }
            let raw = bin.read(f.start, f.size() as usize);
            let _ = raw;
            let name = an.names.get(&f.start).map(|(n, _)| display_symbol(n)).unwrap_or_default();
            Sig { name, addr: f.start, size: f.size(), shape: hs.finish(), insns: f.insn_count }
        })
        .collect()
}

fn bytes_hash(bin: &crate::loader::Binary, f: &Sig) -> u64 {
    h(&bin.read(f.addr, f.size as usize).to_vec())
}

fn diff_binaries(a: &crate::loader::Binary, aa: &analysis::Analysis, b: &crate::loader::Binary, ab: &analysis::Analysis, names_a: &HashMap<u64, (String, NameKind)>) -> Vec<DiffRow> {
    let mut sa = signatures(a, aa);
    for s in &mut sa {
        if let Some((n, _)) = names_a.get(&s.addr) { s.name = display_symbol(n); }
    }
    let sb = signatures(b, ab);
    let named = |n: &str| !n.is_empty() && !n.starts_with("sub_") && !n.starts_with("loc_");
    let mut by_name: HashMap<&str, usize> = HashMap::new();
    for (i, s) in sb.iter().enumerate() {
        if named(&s.name) { by_name.insert(&s.name, i); }
    }
    let mut by_shape: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, s) in sb.iter().enumerate() {
        by_shape.entry(s.shape).or_default().push(i);
    }
    let mut used = vec![false; sb.len()];
    let mut out = vec![];
    let mut rest = vec![];
    for s in &sa {
        let m = if named(&s.name) { by_name.get(s.name.as_str()).copied().filter(|i| !used[*i]) } else { None };
        match m {
            Some(i) => {
                used[i] = true;
                let t = &sb[i];
                let same = bytes_hash(a, s) == bytes_hash(b, t);
                let (kind, note) = if same {
                    (DiffKind::Same, String::new())
                } else if s.shape == t.shape {
                    (DiffKind::Changed, "same shape, different bytes (constants or addresses)".into())
                } else {
                    (DiffKind::Changed, format!("{} → {} instructions", s.insns, t.insns))
                };
                out.push(DiffRow { kind, name: s.name.clone(), a: Some(s.addr), b: Some(t.addr), size_a: s.size, size_b: t.size, note });
            }
            None => rest.push(s),
        }
    }
    for s in rest {
        let m = by_shape.get(&s.shape).and_then(|v| v.iter().copied().find(|i| !used[*i] && sb[*i].size == s.size && s.insns > 3));
        match m {
            Some(i) => {
                used[i] = true;
                let t = &sb[i];
                let nm = if s.name.is_empty() { format!("sub_{:X}", s.addr) } else { s.name.clone() };
                out.push(DiffRow { kind: DiffKind::Renamed, name: nm, a: Some(s.addr), b: Some(t.addr), size_a: s.size, size_b: t.size, note: format!("now {}", if t.name.is_empty() { format!("sub_{:X}", t.addr) } else { t.name.clone() }) });
            }
            None => {
                let nm = if s.name.is_empty() { format!("sub_{:X}", s.addr) } else { s.name.clone() };
                out.push(DiffRow { kind: DiffKind::OnlyA, name: nm, a: Some(s.addr), b: None, size_a: s.size, size_b: 0, note: String::new() });
            }
        }
    }
    for (i, t) in sb.iter().enumerate() {
        if !used[i] {
            let nm = if t.name.is_empty() { format!("sub_{:X}", t.addr) } else { t.name.clone() };
            out.push(DiffRow { kind: DiffKind::OnlyB, name: nm, a: None, b: Some(t.addr), size_a: 0, size_b: t.size, note: String::new() });
        }
    }
    out.sort_by_key(|r| (r.kind == DiffKind::Same, r.a.or(r.b)));
    out
}

impl LensApp {
    pub fn start_diff(&mut self) {
        let Some(path) = rfd::FileDialog::new().set_title("Compare with another version of this program").pick_file() else { return };
        let State::Ready(l) = &self.state else { return };
        let (bin, names) = (l.bin.clone(), l.names.clone());
        let progress = Arc::new(AtomicU32::new(0));
        let pr = progress.clone();
        let (tx, rx) = channel();
        let p2 = path.to_string_lossy().to_string();
        let p3 = p2.clone();
        std::thread::spawn(move || {
            let aa = analysis::analyze(&bin, &analysis::Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
            let r = crate::loader::load(&p3).map(|other| {
                let ab = analysis::analyze(&other, &analysis::Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, pr);
                DiffOut { other: other.file_name.clone(), rows: diff_binaries(&bin, &aa, &other, &ab, &names) }
            });
            let _ = tx.send(r);
        });
        self.diff.busy = Some((p2, progress, rx));
        self.diff.open = true;
        self.diff.err.clear();
        self.diff.show = [false, true, true, true, true];
    }

    pub fn diff_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        if let Some((_, _, rx)) = &self.diff.busy {
            match rx.try_recv() {
                Ok(Ok(o)) => { self.diff.out = Some(o); self.diff.busy = None; }
                Ok(Err(e)) => { self.diff.err = e; self.diff.busy = None; }
                Err(_) => ctx.request_repaint_after(std::time::Duration::from_millis(200)),
            }
        }
        let mut open = true;
        let mut goto = None;
        let mut again = false;
        let d = &mut self.diff;
        egui::Window::new("Compare programs").open(&mut open).default_size([720.0, 520.0]).show(ctx, |ui| {
            if let Some((path, pr, _)) = &d.busy {
                ui.label(format!("Analysing {path} …"));
                ui.add(egui::ProgressBar::new((pr.load(Ordering::Relaxed) as f32 / 100.0).clamp(0.02, 1.0)).animate(true));
                return;
            }
            if !d.err.is_empty() { ui.label(RichText::new(&d.err).color(p.accent)); }
            let Some(o) = &d.out else {
                ui.label(RichText::new("Pick another version of this program to see which functions are new, gone, renamed or changed.").color(p.muted));
                if ui.button("Choose a file…").clicked() { again = true; }
                return;
            };
            let count = |k: DiffKind| o.rows.iter().filter(|r| r.kind == k).count();
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(format!("vs {}", o.other)).strong());
                if ui.button("Compare with another file…").clicked() { again = true; }
            });
            ui.horizontal_wrapped(|ui| {
                for (i, k) in [DiffKind::Same, DiffKind::Changed, DiffKind::Renamed, DiffKind::OnlyA, DiffKind::OnlyB].iter().enumerate() {
                    ui.checkbox(&mut d.show[i], format!("{} {}", count(*k), k.label()));
                }
            });
            ui.add(TextEdit::singleline(&mut d.filter).desired_width(f32::INFINITY).hint_text("Filter by name…"));
            ui.separator();
            let q = d.filter.to_lowercase();
            let list: Vec<&DiffRow> = o.rows.iter().filter(|r| {
                let i = match r.kind { DiffKind::Same => 0, DiffKind::Changed => 1, DiffKind::Renamed => 2, DiffKind::OnlyA => 3, DiffKind::OnlyB => 4 };
                d.show[i] && (q.is_empty() || r.name.to_lowercase().contains(&q))
            }).collect();
            ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, 20.0, list.len(), |ui, range| {
                for r in &list[range] {
                    let col = match r.kind { DiffKind::Same => p.muted, DiffKind::Changed => p.accent, DiffKind::Renamed => p.func_name, DiffKind::OnlyA => p.faint, DiffKind::OnlyB => p.faint };
                    let resp = ui.horizontal(|ui| {
                        ui.label(RichText::new(r.kind.label()).small().color(col));
                        ui.label(RichText::new(&r.name).monospace());
                        ui.label(RichText::new(format!("{} → {} B  {}", r.size_a, r.size_b, r.note)).small().color(p.muted));
                    });
                    let resp = ui.interact(resp.response.rect, egui::Id::unique(("drow", r.a, r.b, &r.name)), egui::Sense::click());
                    if resp.clicked() { goto = r.a; }
                }
            });
        });
        if let Some(a) = goto { self.actions.push(Action::Goto(a)); }
        if again { self.start_diff(); }
        if !open { self.diff.open = false; }
    }
}

// ------------------------------------------------------------------ export

#[derive(Clone, Copy)]
pub enum ExportKind {
    Idc,
    Json,
    Map,
    Ghidra,
    Asm,
    Dot,
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

pub fn export_text(l: &Loaded, kind: ExportKind) -> (String, &'static str) {
    let mut names: Vec<(&u64, &(String, NameKind))> = l.names.iter().collect();
    names.sort_by_key(|(a, _)| **a);
    let mut comments: Vec<(&u64, &String)> = l.ann.comments.iter().collect();
    comments.sort_by_key(|(a, _)| **a);
    match kind {
        ExportKind::Idc => {
            let mut s = String::from("// Generated by Lens. Run in IDA with File > Script file.\n#include <idc.idc>\nstatic main() {\n");
            for f in l.an.functions.keys() { s += &format!("  add_func(0x{f:X}, BADADDR);\n"); }
            for (a, (n, k)) in &names {
                if matches!(k, NameKind::Function | NameKind::Data | NameKind::Label) {
                    s += &format!("  set_name(0x{a:X}, \"{}\", SN_NOWARN);\n", esc(n));
                }
            }
            for (a, c) in &comments { s += &format!("  set_cmt(0x{a:X}, \"{}\", 0);\n", esc(c)); }
            s += "}\n";
            (s, "idc")
        }
        ExportKind::Ghidra => {
            let mut s = String::from("# Generated by Lens. Run in Ghidra's Script Manager (Python).\n# @category Lens\nfrom ghidra.program.model.symbol import SourceType\n\ndef addr(x):\n    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x)\n\n");
            for f in l.an.functions.keys() { s += &format!("try:\n    createFunction(addr(0x{f:X}), None)\nexcept Exception:\n    pass\n"); }
            for (a, (n, k)) in &names {
                if matches!(k, NameKind::Function | NameKind::Data | NameKind::Label) {
                    s += &format!("createLabel(addr(0x{a:X}), \"{}\", True, SourceType.USER_DEFINED)\n", esc(n));
                }
            }
            for (a, c) in &comments { s += &format!("setEOLComment(addr(0x{a:X}), \"{}\")\n", esc(c)); }
            (s, "py")
        }
        ExportKind::Asm => {
            let mut f = crate::code::CodeFormatter::new(l.names.clone());
            let mut s = format!("; Lens listing of {} ({}, {})\n", l.bin.file_name, l.bin.format, l.bin.arch_name);
            for func in l.an.functions.values() {
                let nm = l.names.get(&func.start).map(|n| display_symbol(&n.0)).unwrap_or_default();
                s += &format!("\n; ---------------------------------------------------------------\n; {nm}  ({:X}, {} bytes)\n", func.start, func.size());
                for b in &func.blocks {
                    for a in &b.insns {
                        let t = f.format(&l.bin, *a).map(|(_, t)| t.iter().map(|x| x.text.as_str()).collect::<String>()).unwrap_or_default();
                        let c = l.ann.comments.get(a).map(|c| format!("   ; {}", c.replace('\n', " "))).unwrap_or_default();
                        s += &format!("{a:016X}  {t}{c}\n");
                    }
                }
            }
            (s, "asm")
        }
        ExportKind::Dot => {
            let mut s = String::from("digraph calls {\n  rankdir=LR;\n  node [shape=box, fontname=Menlo, fontsize=10];\n");
            for func in l.an.functions.values().filter(|f| f.kind == analysis::FuncKind::Normal) {
                let nm = l.names.get(&func.start).map(|n| display_symbol(&n.0)).unwrap_or_default();
                s += &format!("  \"{:X}\" [label=\"{}\"];\n", func.start, esc(&nm));
                for c in &func.calls {
                    s += &format!("  \"{:X}\" -> \"{c:X}\";\n", func.start);
                }
            }
            s += "}\n";
            (s, "dot")
        }
        ExportKind::Map => {
            let mut s = format!("Lens map of {}\n{} · {}\n\nSections\n", l.bin.file_name, l.bin.format, l.bin.arch_name);
            for g in &l.bin.segments { s += &format!("  {:016X}  {:016X}  {}\n", g.start, g.end(), g.name); }
            s += "\nSymbols (by address)\n";
            for (a, (n, k)) in &names {
                s += &format!("  {a:016X}  {:<9} {n}\n", match k { NameKind::Function => "function", NameKind::Import => "import", NameKind::Label => "label", NameKind::String => "string", NameKind::Data => "data" });
            }
            (s, "map")
        }
        ExportKind::Json => {
            let v = serde_json::json!({
                "schema": 2,
                "schema_id": "lens.analysis.v1",
                "file": l.bin.file_name, "format": l.bin.format, "arch": l.bin.arch_name, "entry": l.bin.entry,
                "sha256": l.det.sha256,
                "segments": l.bin.segments.iter().map(|s| serde_json::json!({"name": s.name, "start": s.start, "end": s.end()})).collect::<Vec<_>>(),
                "functions": l.an.functions.values().map(|f| serde_json::json!({
                    "start": f.start, "end": f.end, "name": l.names.get(&f.start).map(|n| n.0.clone()),
                    "blocks": f.blocks.len(), "calls": f.calls, "noreturn": f.noreturn,
                    "thunk_target": f.thunk_target })).collect::<Vec<_>>(),
                "names": l.ann.names.iter().map(|(addr, name)| serde_json::json!({"addr": addr, "name": name})).collect::<Vec<_>>(),
                "imports": l.bin.imports.iter().map(|i| serde_json::json!({"slot": i.slot, "name": i.name, "library": i.library})).collect::<Vec<_>>(),
                "exports": l.bin.exports.iter().map(|e| serde_json::json!({"addr": e.addr, "name": e.name})).collect::<Vec<_>>(),
                "strings": l.an.strings.iter().map(|s| serde_json::json!({"addr": s.addr, "text": s.text})).collect::<Vec<_>>(),
                "vtables": l.an.vtables.iter().map(|(addr, entries)| serde_json::json!({"addr": addr, "name": l.an.vtable_names.get(addr), "entries": entries})).collect::<Vec<_>>(),
                "pointer_tables": l.an.pointer_tables.iter().map(|(addr, entries)| serde_json::json!({"addr": addr, "entries": entries})).collect::<Vec<_>>(),
                "xrefs": l.an.xrefs_to.iter().flat_map(|(target, refs)| refs.iter().map(move |x| serde_json::json!({
                    "from": x.from, "to": target, "kind": x.kind.label()
                }))).collect::<Vec<_>>(),
                "data_definitions": l.ann.data_defs.iter().map(|(addr, code)| serde_json::json!({"addr": addr, "code": code})).collect::<Vec<_>>(),
                "applied_types": l.ann.applied.iter().map(|(addr, ty)| serde_json::json!({"addr": addr, "type": ty})).collect::<Vec<_>>(),
                "types": l.ann.structs,
                "prototypes": l.ann.protos,
                "comments": l.ann.comments, "bookmarks": l.ann.marks,
            });
            (serde_json::to_string_pretty(&v).unwrap_or_default(), "json")
        }
    }
}

impl LensApp {
    pub fn export_db(&mut self, kind: ExportKind) {
        let Some(l) = self.loaded() else { return };
        let (text, ext) = export_text(l, kind);
        let default = format!("{}.{ext}", l.bin.file_name);
        if let Some(path) = rfd::FileDialog::new().set_title("Export").set_file_name(&default).save_file() {
            match std::fs::write(&path, text) {
                Ok(_) => self.logm(format!("Exported to {}", path.display())),
                Err(e) => self.logm(format!("Couldn't export: {e}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_changes_with_edits_not_order() {
        let mut a = Annotations::default();
        let f0 = fingerprint(&a);
        a.names.insert(0x10, "foo".into());
        a.names.insert(0x20, "bar".into());
        let f1 = fingerprint(&a);
        assert_ne!(f0, f1);
        let mut b = Annotations::default();
        b.names.insert(0x20, "bar".into());
        b.names.insert(0x10, "foo".into());
        assert_eq!(f1, fingerprint(&b));
        b.comments.insert(1, "x".into());
        assert_ne!(f1, fingerprint(&b));
    }

    #[test]
    fn reads_idc_and_ghidra_lines() {
        let t = "  set_name(0x401000, \"main\", SN_NOWARN);\n  set_cmt(0x401004, \"say \\\"hi\\\"\", 0);\n  add_func(0x402000, BADADDR);\ncreateLabel(addr(0x403000), \"foo\", True, SourceType.USER_DEFINED)\n";
        let (n, c, f) = parse_script(t);
        assert_eq!(n, vec![(0x401000, "main".to_string()), (0x403000, "foo".to_string())]);
        assert_eq!(c, vec![(0x401004, "say \"hi\"".to_string())]);
        assert_eq!(f, vec![0x402000]);
    }

    #[test]
    fn escapes_quotes_and_newlines_for_scripts() {
        assert_eq!(esc("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    fn restores_names_from_exported_json_collections() {
        let v = serde_json::json!({
            "functions": [{"start": 4096, "name": "main"}],
            "exports": [{"addr": 8192, "name": "exported"}],
            "imports": [{"slot": 12288, "name": "lib_call"}],
            "vtables": [{"addr": 16384, "name": "vtable_Base"}],
            "names": [{"addr": 20480, "name": "label"}]
        });
        assert_eq!(json_named_records(&v).len(), 5);
        assert!(json_named_records(&v).contains(&(12288, "lib_call".into())));
    }
}

// ------------------------------------------------------------------ import

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn quoted(s: &str) -> Option<String> {
    let a = s.find('"')? + 1;
    let mut out = String::new();
    let mut it = s[a..].chars();
    while let Some(c) = it.next() {
        match c {
            '"' => return Some(out),
            '\\' => match it.next() {
                Some('n') => out.push('\n'),
                Some(o) => out.push(o),
                None => break,
            },
            c => out.push(c),
        }
    }
    None
}

/// Reads names, comments and function starts from an IDC script (set_name / set_cmt / add_func and the older Make* forms)
/// or a Ghidra script written by Lens.
pub fn parse_script(text: &str) -> (Vec<(u64, String)>, Vec<(u64, String)>, Vec<u64>) {
    let (mut names, mut cmts, mut funcs) = (vec![], vec![], vec![]);
    for line in text.lines() {
        let t = line.trim();
        let call = |name: &str| t.split_once(&format!("{name}(")).map(|x| x.1.to_string());
        if let Some(a) = call("set_name").or_else(|| call("MakeName")).or_else(|| call("createLabel")) {
            if let (Some(ad), Some(n)) = (a.split(',').next().and_then(|x| parse_num(x.trim_start_matches("addr(").trim_end_matches(')'))), quoted(&a)) {
                names.push((ad, n));
            }
        } else if let Some(a) = call("set_cmt").or_else(|| call("MakeComm")).or_else(|| call("setEOLComment")) {
            if let (Some(ad), Some(n)) = (a.split(',').next().and_then(|x| parse_num(x.trim_start_matches("addr(").trim_end_matches(')'))), quoted(&a)) {
                cmts.push((ad, n));
            }
        } else if let Some(a) = call("add_func").or_else(|| call("MakeFunction")).or_else(|| call("createFunction")) {
            if let Some(ad) = a.split(',').next().and_then(|x| parse_num(x.trim_start_matches("addr(").trim_end_matches(')'))) {
                funcs.push(ad);
            }
        }
    }
    (names, cmts, funcs)
}

fn json_named_records(v: &serde_json::Value) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let fields = [("functions", "start"), ("exports", "addr"), ("imports", "slot"), ("vtables", "addr"), ("names", "addr")];
    for (collection, address_field) in fields {
        let Some(items) = v.get(collection).and_then(|x| x.as_array()) else { continue };
        for item in items {
            let Some(addr) = item.get(address_field).and_then(|x| x.as_u64()) else { continue };
            let Some(name) = item.get("name").and_then(|x| x.as_str()).filter(|x| !x.is_empty()) else { continue };
            out.push((addr, name.to_string()));
        }
    }
    out
}

impl LensApp {
    pub fn import_db(&mut self) {
        if self.loaded().is_none() { return; }
        let Some(path) = rfd::FileDialog::new().set_title("Import Lens database, names and notes (JSON, IDA .idc or Ghidra .py)").pick_file() else { return };
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => { self.logm(format!("Couldn't read the file: {e}")); return; }
        };
        let State::Ready(l) = &mut self.state else { return };
        let (mut n, mut c, mut f, mut d) = (0, 0, 0, 0);
        if text.trim_start().starts_with('{') {
            let exported = serde_json::from_str::<serde_json::Value>(&text).ok().map(|v| v.get("schema").is_some() || v.get("file").is_some() || v.get("data_definitions").is_some() || v.get("array_records").is_some()).unwrap_or(false);
            let parsed = if exported {
                Err(serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "Lens analysis export")))
            } else {
                serde_json::from_str::<Annotations>(&text)
            };
            match parsed {
                Ok(a) => {
                    for (k, v) in a.names { l.ann.names.insert(k, v); n += 1; }
                    for (k, v) in a.comments { l.ann.comments.insert(k, v); c += 1; }
                    for k in a.marks { if !l.ann.marks.contains(&k) { l.ann.marks.push(k); } }
                    for k in a.functions { if !l.ann.functions.contains(&k) { l.ann.functions.push(k); f += 1; } }
                }
                Err(e) => {
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                        self.logm(format!("That isn't a Lens notes file: {e}")); return;
                    };
                    let mut recognized = false;
                    if let Some(obj) = v.get("comments").and_then(|x| x.as_object()) {
                        for (addr, text) in obj {
                            if let (Some(a), Some(s)) = (parse_num(addr), text.as_str()) { l.ann.comments.insert(a, s.to_string()); c += 1; recognized = true; }
                        }
                    }
                    if let Some(arr) = v.get("bookmarks").and_then(|x| x.as_array()) {
                        for addr in arr.iter().filter_map(|x| x.as_u64()) { if !l.ann.marks.contains(&addr) { l.ann.marks.push(addr); } recognized = true; }
                    }
                    if let Some(arr) = v.get("data_definitions").and_then(|x| x.as_array()) {
                        for item in arr {
                            if let (Some(addr), Some(code)) = (item.get("addr").and_then(|x| x.as_u64()), item.get("code").and_then(|x| x.as_u64())) {
                                l.ann.data_defs.insert(addr, code as u8); d += 1; recognized = true;
                            }
                        }
                    }
                    if let Some(arr) = v.get("pointer_tables").and_then(|x| x.as_array()) {
                        let width = (l.bin.bitness() / 8) as u64;
                        let code = width as u8 | 0x80;
                        for item in arr {
                            let Some(addr) = item.get("addr").and_then(|x| x.as_u64()) else { continue };
                            let Some(entries) = item.get("entries").and_then(|x| x.as_array()) else { continue };
                            for index in 0..entries.len() {
                                let slot = addr.saturating_add(index as u64 * width);
                                if l.bin.is_mapped(slot) {
                                    l.ann.data_defs.insert(slot, code);
                                    d += 1;
                                }
                            }
                            recognized = true;
                        }
                    }
                    if let Some(arr) = v.get("array_records").and_then(|x| x.as_array()) {
                        for item in arr {
                            let (Some(addr), Some(width), Some(count)) = (
                                item.get("address").and_then(|x| x.as_u64()),
                                item.get("element_size").and_then(|x| x.as_u64()),
                                item.get("count").and_then(|x| x.as_u64()),
                            ) else { continue };
                            if !(1..=8).contains(&width) || !(2..=1_000_000).contains(&count) { continue; }
                            let code = width as u8;
                            let mut added = 0usize;
                            for index in 0..count {
                                let slot = addr.saturating_add(index.saturating_mul(width));
                                if l.bin.is_mapped(slot) && !l.an.insns.contains_key(&slot) {
                                    l.ann.data_defs.insert(slot, code);
                                    added += 1;
                                }
                            }
                            if added > 0 { d += added; recognized = true; }
                        }
                    }
                    if let Some(arr) = v.get("applied_types").and_then(|x| x.as_array()) {
                        for item in arr {
                            if let (Some(addr), Some(ty)) = (item.get("addr").and_then(|x| x.as_u64()), item.get("type").and_then(|x| x.as_str())) {
                                if let Some(existing) = l.ann.applied.iter_mut().find(|(a, _)| *a == addr) { existing.1 = ty.to_string(); }
                                else { l.ann.applied.push((addr, ty.to_string())); }
                                recognized = true;
                            }
                        }
                    }
                    if let Some(arr) = v.get("types") {
                        if let Ok(types) = serde_json::from_value::<Vec<crate::types::StructDef>>(arr.clone()) {
                            for def in types {
                                if let Some(existing) = l.ann.structs.iter_mut().find(|x| x.name == def.name) { *existing = def; }
                                else { l.ann.structs.push(def); }
                                recognized = true;
                            }
                        }
                    }
                    if let Some(protos) = v.get("prototypes").and_then(|x| x.as_str()) {
                        l.ann.protos = protos.to_string();
                        crate::protos::set_user(&l.ann.protos);
                        recognized = true;
                    }
                    for (addr, name) in json_named_records(&v) {
                        l.ann.names.insert(addr, name);
                        n += 1;
                        recognized = true;
                    }
                    if let Some(arr) = v.get("functions").and_then(|x| x.as_array()) {
                        for item in arr {
                            let Some(addr) = item.get("start").and_then(|a| a.as_u64()) else { continue };
                            if !l.ann.functions.contains(&addr) { l.ann.functions.push(addr); f += 1; }
                        }
                        recognized = true;
                    }
                    if !recognized { self.logm(format!("That isn't a Lens notes file: {e}")); return; }
                }
            }
        } else {
            let (names, cmts, funcs) = parse_script(&text);
            for (a, s) in names { l.ann.names.insert(a, s); n += 1; }
            for (a, s) in cmts { l.ann.comments.insert(a, s); c += 1; }
            for a in funcs { if !l.ann.functions.contains(&a) && !l.an.functions.contains_key(&a) { l.ann.functions.push(a); f += 1; } }
        }
        store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
        l.refresh();
        self.logm(format!("Imported {n} names, {c} notes, {d} data definitions and {f} new functions."));
        if f > 0 || d > 0 { self.reanalyze(); }
    }
}
