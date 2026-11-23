//! Scripting and plugins. Scripts are Rhai (a small Rust-like language). They read a snapshot of the
//! analysis and queue changes (rename, comment, patch, goto …) that Lens applies when the script ends.
//!
//! Plugins are `.rhai` files in the plugins folder; each shows up under Tools > Plugins and may define
//! `fn on_open() { … }`, which runs every time a program finishes loading.

use crate::analysis::FuncKind;
use crate::app::{Action, LensApp, State};
use crate::loader::Binary;
use eframe::egui::{self, FontId, RichText, ScrollArea, TextEdit};
use rhai::{Array, Blob, Dynamic, Engine, Map, Scope, INT};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

/// Increment when the public Rhai function surface or record shapes change incompatibly.
pub const API_VERSION: i64 = 1;

pub struct Snap {
    pub bin: Arc<Binary>,
    pub funcs: Vec<(u64, String, u64, usize)>,
    pub names: HashMap<u64, String>,
    pub comments: HashMap<u64, String>,
    pub bookmarks: Vec<u64>,
    pub data_defs: HashMap<u64, u8>,
    pub strings: Vec<(u64, String)>,
    pub xrefs: HashMap<u64, Vec<u64>>,
    pub xref_details: HashMap<u64, Vec<(u64, String)>>,
    pub out_xrefs: HashMap<u64, Vec<u64>>,
    pub out_xref_details: HashMap<u64, Vec<(u64, String)>>,
    pub pseudocode: HashMap<u64, String>,
    pub pointer_tables: Vec<(u64, Vec<u64>)>,
    pub vtables: Vec<(u64, Vec<u64>)>,
    pub vtable_names: HashMap<u64, String>,
    pub applied_types: HashMap<u64, String>,
    pub types: Vec<crate::types::StructDef>,
}

#[derive(Debug)]
pub enum Cmd {
    Rename(u64, String),
    Comment(u64, String),
    Mark(u64),
    Goto(u64),
    Log(String),
    Patch(u64, Vec<u8>),
    MakeFunction(u64),
    AddType(String),
    ApplyType(u64, String),
    DefinePointerTable(u64),
    DefineArray(u64),
}

pub struct Output {
    pub text: String,
    pub cmds: Vec<Cmd>,
    pub error: Option<String>,
}

pub fn plugins_dir() -> std::path::PathBuf {
    let d = crate::store::config_dir().join("plugins");
    let _ = std::fs::create_dir_all(&d);
    d
}

pub fn scripts_dir() -> std::path::PathBuf {
    let d = crate::store::config_dir().join("scripts");
    let _ = std::fs::create_dir_all(&d);
    d
}

pub fn list_plugins() -> Vec<(String, std::path::PathBuf)> {
    let mut v: Vec<(String, std::path::PathBuf)> = std::fs::read_dir(plugins_dir())
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "rhai").unwrap_or(false))
                .map(|p| (p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(), p))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn arr_u64(v: &[u64]) -> Array {
    v.iter().map(|x| Dynamic::from(*x as INT)).collect()
}

pub fn run(src: &str, snap: Snap, hook: Option<&str>) -> Output {
    let snap = Rc::new(snap);
    let cmds: Rc<RefCell<Vec<Cmd>>> = Rc::new(RefCell::new(vec![]));
    let out: Rc<RefCell<String>> = Rc::new(RefCell::new(String::new()));
    let mut e = Engine::new();
    e.set_max_operations(40_000_000);
    e.set_max_call_levels(48);
    e.set_max_string_size(4 << 20);
    e.set_max_array_size(2 << 20);
    e.set_max_map_size(1 << 20);
    {
        let o = out.clone();
        e.on_print(move |s| {
            let mut b = o.borrow_mut();
            b.push_str(s);
            b.push('\n');
        });
        let o = out.clone();
        e.on_debug(move |s, _, _| {
            let mut b = o.borrow_mut();
            b.push_str(s);
            b.push('\n');
        });
    }
    // ---- reading
    e.register_fn("script_api_version", || -> INT { API_VERSION as INT });
    let s = snap.clone();
    e.register_fn("functions", move || -> Array {
        s.funcs
            .iter()
            .map(|(a, n, size, blocks)| {
                let mut m = Map::new();
                m.insert("addr".into(), Dynamic::from(*a as INT));
                m.insert("name".into(), Dynamic::from(n.clone()));
                m.insert("size".into(), Dynamic::from(*size as INT));
                m.insert("blocks".into(), Dynamic::from(*blocks as INT));
                Dynamic::from_map(m)
            })
            .collect()
    });
    let s = snap.clone();
    e.register_fn("function_at", move |a: INT| -> Map {
        let addr = a as u64;
        s.funcs.iter().find(|(start, _, size, _)| addr >= *start && addr < start.saturating_add(*size as u64)).map(|(start, name, size, blocks)| {
            let mut m = Map::new();
            m.insert("addr".into(), Dynamic::from(*start as INT));
            m.insert("name".into(), Dynamic::from(name.clone()));
            m.insert("size".into(), Dynamic::from(*size as INT));
            m.insert("blocks".into(), Dynamic::from(*blocks as INT));
            m
        }).unwrap_or_default()
    });
    let s = snap.clone();
    e.register_fn("name_at", move |a: INT| -> String { s.names.get(&(a as u64)).cloned().unwrap_or_default() });
    let s = snap.clone();
    e.register_fn("find", move |n: &str| -> INT { s.names.iter().find(|(_, v)| v.as_str() == n).map(|(a, _)| *a as INT).unwrap_or(0) });
    let s = snap.clone();
    e.register_fn("search", move |query: &str| -> Array {
        let q = query.to_lowercase();
        let mut out = Vec::new();
        for (addr, name) in &s.names {
            if name.to_lowercase().contains(&q) {
                let mut m = Map::new();
                m.insert("addr".into(), Dynamic::from(*addr as INT));
                m.insert("kind".into(), Dynamic::from("name"));
                m.insert("text".into(), Dynamic::from(name.clone()));
                out.push(Dynamic::from_map(m));
            }
        }
        for (addr, text) in &s.strings {
            if text.to_lowercase().contains(&q) {
                let mut m = Map::new();
                m.insert("addr".into(), Dynamic::from(*addr as INT));
                m.insert("kind".into(), Dynamic::from("string"));
                m.insert("text".into(), Dynamic::from(text.clone()));
                out.push(Dynamic::from_map(m));
            }
        }
        for (addr, text) in &s.comments {
            if text.to_lowercase().contains(&q) {
                let mut m = Map::new();
                m.insert("addr".into(), Dynamic::from(*addr as INT));
                m.insert("kind".into(), Dynamic::from("comment"));
                m.insert("text".into(), Dynamic::from(text.clone()));
                out.push(Dynamic::from_map(m));
            }
        }
        for (addr, text) in &s.pseudocode {
            if text.to_lowercase().contains(&q) {
                let mut m = Map::new();
                m.insert("addr".into(), Dynamic::from(*addr as INT));
                m.insert("kind".into(), Dynamic::from("pseudocode"));
                m.insert("text".into(), Dynamic::from(text.clone()));
                out.push(Dynamic::from_map(m));
            }
        }
        out.sort_by_key(|v| v.clone_cast::<Map>().get("addr").and_then(|a| a.clone().try_cast::<INT>()).unwrap_or(0));
        out
    });
    let s = snap.clone();
    e.register_fn("comment_at", move |a: INT| -> String { s.comments.get(&(a as u64)).cloned().unwrap_or_default() });
    let s = snap.clone();
    e.register_fn("bookmarks", move || -> Array { arr_u64(&s.bookmarks) });
    let s = snap.clone();
    e.register_fn("data_at", move |a: INT| -> INT { s.data_defs.get(&(a as u64)).copied().unwrap_or(0) as INT });
    let s = snap.clone();
    e.register_fn("data_definitions", move || -> Array {
        let mut defs: Vec<_> = s.data_defs.iter().collect();
        defs.sort_by_key(|(a, _)| **a);
        defs.into_iter().map(|(a, code)| {
            let mut m = Map::new();
            m.insert("addr".into(), Dynamic::from(*a as INT));
            m.insert("code".into(), Dynamic::from(*code as INT));
            Dynamic::from_map(m)
        }).collect()
    });
    let s = snap.clone();
    e.register_fn("strings", move || -> Array {
        s.strings
            .iter()
            .map(|(a, t)| {
                let mut m = Map::new();
                m.insert("addr".into(), Dynamic::from(*a as INT));
                m.insert("text".into(), Dynamic::from(t.clone()));
                Dynamic::from_map(m)
            })
            .collect()
    });
    let s = snap.clone();
    e.register_fn("xrefs_to", move |a: INT| -> Array { arr_u64(s.xrefs.get(&(a as u64)).map(|v| v.as_slice()).unwrap_or(&[])) });
    let s = snap.clone();
    e.register_fn("xrefs_to_details", move |a: INT| -> Array {
        s.xref_details.get(&(a as u64)).map(|xs| xs.iter().map(|(from, kind)| {
            let mut m = Map::new();
            m.insert("from".into(), Dynamic::from(*from as INT));
            m.insert("kind".into(), Dynamic::from(kind.clone()));
            Dynamic::from_map(m)
        }).collect()).unwrap_or_default()
    });
    let s = snap.clone();
    e.register_fn("xrefs_from", move |a: INT| -> Array { arr_u64(s.out_xrefs.get(&(a as u64)).map(|v| v.as_slice()).unwrap_or(&[])) });
    let s = snap.clone();
    e.register_fn("xrefs_from_details", move |a: INT| -> Array {
        s.out_xref_details.get(&(a as u64)).map(|xs| xs.iter().map(|(to, kind)| {
            let mut m = Map::new();
            m.insert("to".into(), Dynamic::from(*to as INT));
            m.insert("kind".into(), Dynamic::from(kind.clone()));
            Dynamic::from_map(m)
        }).collect()).unwrap_or_default()
    });
    let s = snap.clone();
    e.register_fn("decompile", move |a: INT| -> String {
        s.pseudocode.get(&(a as u64)).cloned().unwrap_or_default()
    });
    let s = snap.clone();
    e.register_fn("pointer_tables", move || -> Array {
        s.pointer_tables.iter().map(|(a, entries)| {
            let mut m = Map::new();
            m.insert("addr".into(), Dynamic::from(*a as INT));
            m.insert("entries".into(), Dynamic::from(arr_u64(entries)));
            Dynamic::from_map(m)
        }).collect()
    });
    let s = snap.clone();
    e.register_fn("vtables", move || -> Array {
        s.vtables.iter().map(|(a, entries)| {
            let mut m = Map::new();
            m.insert("addr".into(), Dynamic::from(*a as INT));
            if let Some(name) = s.vtable_names.get(a) { m.insert("type".into(), Dynamic::from(name.clone())); }
            m.insert("entries".into(), Dynamic::from(arr_u64(entries)));
            Dynamic::from_map(m)
        }).collect()
    });
    let s = snap.clone();
    e.register_fn("type_at", move |a: INT| -> String { s.applied_types.get(&(a as u64)).cloned().unwrap_or_default() });
    let s = snap.clone();
    e.register_fn("types", move || -> Array {
        s.types.iter().map(|t| {
            let mut m = Map::new();
            m.insert("name".into(), Dynamic::from(t.name.clone()));
            m.insert("size".into(), Dynamic::from(t.size as INT));
            m.insert("union".into(), Dynamic::from(t.is_union));
            m.insert("enum".into(), Dynamic::from(t.is_enum));
            let fields: Array = t.fields.iter().map(|f| {
                let mut field = Map::new();
                field.insert("offset".into(), Dynamic::from(f.off as INT));
                field.insert("name".into(), Dynamic::from(f.name.clone()));
                field.insert("type".into(), Dynamic::from(f.ty.clone()));
                field.insert("size".into(), Dynamic::from(f.size as INT));
                field.insert("bit_offset".into(), Dynamic::from(f.bit_offset.unwrap_or(0) as INT));
                field.insert("bit_width".into(), Dynamic::from(f.bit_width.unwrap_or(0) as INT));
                Dynamic::from_map(field)
            }).collect();
            m.insert("fields".into(), Dynamic::from(fields));
            let values: Array = t.enum_values.iter().map(|v| {
                let mut value = Map::new();
                value.insert("name".into(), Dynamic::from(v.name.clone()));
                value.insert("value".into(), Dynamic::from(v.value as INT));
                Dynamic::from_map(value)
            }).collect();
            m.insert("values".into(), Dynamic::from(values));
            Dynamic::from_map(m)
        }).collect()
    });
    let s = snap.clone();
    e.register_fn("segments", move || -> Array {
        s.bin.segments.iter().map(|seg| {
            let mut m = Map::new();
            m.insert("name".into(), Dynamic::from(seg.name.clone()));
            m.insert("start".into(), Dynamic::from(seg.start as INT));
            m.insert("size".into(), Dynamic::from(seg.size as INT));
            m.insert("executable".into(), Dynamic::from(seg.exec));
            m.insert("writable".into(), Dynamic::from(seg.write));
            Dynamic::from_map(m)
        }).collect()
    });
    let s = snap.clone();
    e.register_fn("imports", move || -> Array {
        s.bin.imports.iter().map(|item| {
            let mut m = Map::new();
            m.insert("slot".into(), Dynamic::from(item.slot as INT));
            m.insert("name".into(), Dynamic::from(item.name.clone()));
            m.insert("library".into(), Dynamic::from(item.library.clone()));
            Dynamic::from_map(m)
        }).collect()
    });
    let s = snap.clone();
    e.register_fn("exports", move || -> Array {
        s.bin.exports.iter().map(|item| {
            let mut m = Map::new();
            m.insert("addr".into(), Dynamic::from(item.addr as INT));
            m.insert("name".into(), Dynamic::from(item.name.clone()));
            Dynamic::from_map(m)
        }).collect()
    });
    for (name, n) in [("read_u8", 1usize), ("read_u16", 2), ("read_u32", 4), ("read_u64", 8)] {
        let s = snap.clone();
        e.register_fn(name, move |a: INT| -> INT {
            let b = s.bin.read(a as u64, n);
            if b.len() < n {
                return -1;
            }
            let mut v: u64 = 0;
            if s.bin.big_endian { for x in b { v = (v << 8) | *x as u64 } } else { for x in b.iter().rev() { v = (v << 8) | *x as u64 } }
            v as INT
        });
    }
    let s = snap.clone();
    e.register_fn("read_bytes", move |a: INT, n: INT| -> Blob { s.bin.read(a as u64, n.clamp(0, 1 << 20) as usize).to_vec() });
    let s = snap.clone();
    e.register_fn("disasm", move |a: INT| -> String { crate::multiarch::one(&s.bin, a as u64).map(|r| crate::multiarch::text(&r)).unwrap_or_default() });
    let s = snap.clone();
    e.register_fn("is_code", move |a: INT| -> bool { s.bin.is_exec(a as u64) });
    let s = snap.clone();
    e.register_fn("entry", move || -> INT { s.bin.entry.unwrap_or(0) as INT });
    let s = snap.clone();
    e.register_fn("arch", move || -> String { s.bin.arch.name().to_string() });
    let s = snap.clone();
    e.register_fn("file_name", move || -> String { s.bin.file_name.clone() });
    e.register_fn("hex", |n: INT| -> String { format!("{:X}", n) });
    // ---- changing things (applied after the script finishes)
    let c = cmds.clone();
    e.register_fn("rename", move |a: INT, n: &str| c.borrow_mut().push(Cmd::Rename(a as u64, n.to_string())));
    let c = cmds.clone();
    e.register_fn("comment", move |a: INT, t: &str| c.borrow_mut().push(Cmd::Comment(a as u64, t.to_string())));
    let c = cmds.clone();
    e.register_fn("mark", move |a: INT| c.borrow_mut().push(Cmd::Mark(a as u64)));
    let c = cmds.clone();
    e.register_fn("goto", move |a: INT| c.borrow_mut().push(Cmd::Goto(a as u64)));
    let c = cmds.clone();
    e.register_fn("log", move |t: &str| c.borrow_mut().push(Cmd::Log(t.to_string())));
    let c = cmds.clone();
    e.register_fn("make_function", move |a: INT| c.borrow_mut().push(Cmd::MakeFunction(a as u64)));
    let c = cmds.clone();
    e.register_fn("add_type", move |decl: &str| c.borrow_mut().push(Cmd::AddType(decl.to_string())));
    let c = cmds.clone();
    e.register_fn("apply_type", move |a: INT, name: &str| c.borrow_mut().push(Cmd::ApplyType(a as u64, name.to_string())));
    let c = cmds.clone();
    e.register_fn("define_pointer_table", move |a: INT| c.borrow_mut().push(Cmd::DefinePointerTable(a as u64)));
    let c = cmds.clone();
    e.register_fn("define_array", move |a: INT| c.borrow_mut().push(Cmd::DefineArray(a as u64)));
    let c = cmds.clone();
    e.register_fn("patch", move |a: INT, b: Blob| c.borrow_mut().push(Cmd::Patch(a as u64, b)));
    let c = cmds.clone();
    e.register_fn("patch", move |a: INT, b: Array| {
        c.borrow_mut().push(Cmd::Patch(a as u64, b.iter().filter_map(|x| x.as_int().ok()).map(|x| x as u8).collect()))
    });

    let mut error = None;
    match e.compile(src) {
        Err(err) => error = Some(err.to_string()),
        Ok(ast) => {
            let mut scope = Scope::new();
            match hook {
                None => {
                    if let Err(err) = e.run_ast_with_scope(&mut scope, &ast) {
                        error = Some(err.to_string());
                    }
                }
                Some(h) => {
                    // run top-level code once so `const`s and helper fns exist, then call the hook
                    if let Err(err) = e.run_ast_with_scope(&mut scope, &ast) {
                        error = Some(err.to_string());
                    } else if ast.iter_functions().any(|f| f.name == h) {
                        if let Err(err) = e.call_fn::<Dynamic>(&mut scope, &ast, h, ()) {
                            error = Some(err.to_string());
                        }
                    }
                }
            }
        }
    }
    let text = out.borrow().clone();
    let cmds = std::mem::take(&mut *cmds.borrow_mut());
    Output { text, cmds, error }
}

#[derive(Default)]
pub struct ScriptState {
    pub open: bool,
    pub src: String,
    pub out: String,
    pub name: String,
}

pub const EXAMPLE: &str = r#"// Lens script (Rhai). Run with Cmd+Enter.
// Find functions that call exit-like imports and mark them.
let n = 0;
for f in functions() {
    if f.size > 2000 {
        print(`${hex(f.addr)}  ${f.name}  ${f.size} bytes`);
        n += 1;
    }
}
print(`${n} large functions`);
// rename(0x1000, "my_name");   comment(0x1000, "checks the licence");
// patch(0x1000, [0x90, 0x90]);   goto(entry());
"#;

impl LensApp {
    fn snapshot(&self) -> Option<Snap> {
        let l = self.loaded()?;
        let funcs = l
            .an
            .functions
            .values()
            .filter(|f| f.kind != FuncKind::Import)
            .map(|f| (f.start, l.name(f.start).unwrap_or("").to_string(), f.end.saturating_sub(f.start), f.blocks.len()))
            .collect();
        let xrefs: HashMap<u64, Vec<u64>> = l.an.xrefs_to.iter().map(|(a, v)| (*a, v.iter().map(|x| x.from).collect())).collect();
        let xref_details: HashMap<u64, Vec<(u64, String)>> = l.an.xrefs_to.iter().map(|(a, v)| (*a, v.iter().map(|x| (x.from, x.kind.label().to_string())).collect())).collect();
        let mut out_xrefs: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut out_xref_details: HashMap<u64, Vec<(u64, String)>> = HashMap::new();
        for (target, refs) in &l.an.xrefs_to {
            for x in refs { out_xref_details.entry(x.from).or_default().push((*target, x.kind.label().to_string())); }
        }
        for (target, sources) in &xrefs {
            for source in sources { out_xrefs.entry(*source).or_default().push(*target); }
        }
        let pseudocode = l.an.functions.values().filter(|f| f.kind != FuncKind::Import).map(|f| {
            let d = crate::decomp::decompile_with_types(&l.bin, &l.an, &l.names, f, l.det.conv, "", &l.ann.structs);
            (f.start, crate::decomp::render_text(&d))
        }).collect();
        Some(Snap {
            bin: l.bin.clone(),
            funcs,
            names: l.names.iter().map(|(a, (n, _))| (*a, n.clone())).collect(),
            comments: l.ann.comments.clone(),
            bookmarks: l.ann.marks.clone(),
            data_defs: l.ann.data_defs.clone(),
            strings: l.an.strings.iter().map(|s| (s.addr, s.text.clone())).collect(),
            xrefs,
            xref_details,
            out_xrefs,
            out_xref_details,
            pseudocode,
            pointer_tables: l.an.pointer_tables.iter().map(|(a, v)| (*a, v.clone())).collect(),
            vtables: l.an.vtables.iter().map(|(a, v)| (*a, v.clone())).collect(),
            vtable_names: l.an.vtable_names.clone(),
            applied_types: l.ann.applied.iter().cloned().collect(),
            types: l.ann.structs.clone(),
        })
    }

    pub fn run_script_text(&mut self, src: &str, hook: Option<&str>) -> String {
        let Some(snap) = self.snapshot() else { return "Open a program first.".into() };
        let r = run(src, snap, hook);
        let mut text = r.text;
        if let Some(e) = &r.error {
            text.push_str(&format!("\nerror: {e}\n"));
        }
        let mut patches = vec![];
        let mut changed = false;
        for c in r.cmds {
            match c {
                Cmd::Goto(a) => self.actions.push(Action::Goto(a)),
                Cmd::Log(t) => self.logm(t),
                Cmd::MakeFunction(a) => self.actions.push(Action::MakeFunction(a)),
                Cmd::Patch(a, b) => patches.push((a, b)),
                Cmd::Rename(a, n) => {
                    if let State::Ready(l) = &mut self.state {
                        l.ann.names.insert(a, n);
                        changed = true;
                    }
                }
                Cmd::Comment(a, t) => {
                    if let State::Ready(l) = &mut self.state {
                        l.ann.comments.insert(a, t);
                        changed = true;
                    }
                }
                Cmd::Mark(a) => {
                    if let State::Ready(l) = &mut self.state {
                        if !l.ann.marks.contains(&a) {
                            l.ann.marks.push(a);
                        }
                        changed = true;
                    }
                }
                Cmd::AddType(decl) => {
                    if let State::Ready(l) = &mut self.state {
                        match crate::types::parse_c(&decl, l.bin.bitness() / 8, &l.ann.structs) {
                            Ok(def) => {
                                l.ann.structs.retain(|old| old.name != def.name);
                                l.ann.structs.push(def);
                                changed = true;
                            }
                            Err(e) => text.push_str(&format!("\nadd_type failed: {e}")),
                        }
                    }
                }
                Cmd::ApplyType(addr, name) => {
                    if let State::Ready(l) = &mut self.state {
                        if l.bin.is_mapped(addr) && l.ann.structs.iter().any(|t| t.name == name) {
                            l.ann.applied.retain(|(old_addr, _)| *old_addr != addr);
                            l.ann.applied.push((addr, name));
                            changed = true;
                        } else {
                            text.push_str("\napply_type failed: address or type is not available");
                        }
                    }
                }
                Cmd::DefinePointerTable(a) => self.actions.push(Action::DefinePointerTable(a)),
                Cmd::DefineArray(a) => self.actions.push(Action::DefineArray(a)),
            }
        }
        if changed {
            if let State::Ready(l) = &mut self.state {
                crate::store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
                l.refresh();
            }
        }
        if !patches.is_empty() {
            if let State::Ready(l) = &mut self.state {
                for (a, b) in patches {
                    let old = l.bin.read(a, b.len()).to_vec();
                    if old.len() == b.len() && old != b {
                        l.ann.patches.push(crate::patch::Patch { addr: a, old, new: b });
                    }
                }
                crate::store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
            }
            self.reanalyze();
        }
        text
    }

    pub fn run_plugin(&mut self, name: &str) {
        let Some((_, path)) = list_plugins().into_iter().find(|(n, _)| n == name) else { return };
        match std::fs::read_to_string(&path) {
            Ok(src) => {
                let out = self.run_script_text(&src, None);
                if !out.trim().is_empty() {
                    self.logm(format!("[{name}] {}", out.trim().lines().last().unwrap_or("")));
                    self.tools2.script.out = out;
                    self.tools2.script.open = true;
                }
            }
            Err(e) => self.logm(format!("Couldn't read the plugin: {e}")),
        }
    }

    /// Runs `on_open` in every plugin that defines it.
    pub fn plugins_on_open(&mut self) {
        for (name, path) in list_plugins() {
            if let Ok(src) = std::fs::read_to_string(&path) {
                if !src.contains("fn on_open") {
                    continue;
                }
                let out = self.run_script_text(&src, Some("on_open"));
                if out.contains("error:") {
                    self.logm(format!("Plugin {name}: {}", out.trim()));
                }
            }
        }
    }

    pub fn script_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let mut run = false;
        egui::Window::new("Script").open(&mut open).default_size([640.0, 560.0]).show(ctx, |ui| {
            let s = &mut self.tools2.script;
            if s.src.is_empty() {
                s.src = EXAMPLE.to_string();
            }
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new("Run  (Cmd+Enter)").fill(p.accent_soft)).clicked() { run = true; }
                if ui.button("Open…").clicked() {
                    if let Some(f) = rfd::FileDialog::new().set_directory(scripts_dir()).add_filter("Rhai script", &["rhai"]).pick_file() {
                        if let Ok(t) = std::fs::read_to_string(&f) { s.src = t; s.name = f.file_stem().map(|x| x.to_string_lossy().to_string()).unwrap_or_default(); }
                    }
                }
                if ui.button("Save…").clicked() {
                    if let Some(f) = rfd::FileDialog::new().set_directory(scripts_dir()).set_file_name(if s.name.is_empty() { "script.rhai".to_string() } else { format!("{}.rhai", s.name) }).save_file() {
                        let _ = std::fs::write(&f, &s.src);
                    }
                }
                if ui.button("Install as plugin").on_hover_text("Saves it to the plugins folder so it appears under Tools > Plugins").clicked() {
                    let n = if s.name.is_empty() { "my_plugin".to_string() } else { s.name.clone() };
                    let f = plugins_dir().join(format!("{n}.rhai"));
                    s.out = match std::fs::write(&f, &s.src) { Ok(_) => format!("Saved {}", f.display()), Err(e) => e.to_string() };
                }
                if ui.button("Plugins folder").clicked() { let _ = std::process::Command::new("open").arg(plugins_dir()).spawn(); }
            });
            ScrollArea::vertical().id_salt("src").max_height(300.0).show(ui, |ui| {
                let r = ui.add(TextEdit::multiline(&mut s.src).code_editor().desired_rows(14).desired_width(f32::INFINITY).font(FontId::monospace(13.0)));
                if r.has_focus() && ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::Enter)) { run = true; }
            });
            ui.label(RichText::new("OUTPUT").small().color(p.faint));
            ScrollArea::vertical().id_salt("out").max_height(180.0).stick_to_bottom(true).show(ui, |ui| {
                ui.label(RichText::new(&s.out).monospace().small());
            });
            ui.label(RichText::new("API v1: script_api_version() functions() function_at(a) strings() types() type_at(a) segments() imports() exports() pointer_tables() vtables() name_at(a) find(name) search(query) comment_at(a) bookmarks() data_at(a) data_definitions() xrefs_to(a) xrefs_to_details(a) xrefs_from(a) xrefs_from_details(a) decompile(a) read_u8/16/32/64(a) read_bytes(a,n) disasm(a) entry() arch() · rename comment mark goto patch make_function add_type apply_type define_pointer_table define_array log").small().color(p.muted));
        });
        if run {
            let src = self.tools2.script.src.clone();
            let out = self.run_script_text(&src, None);
            self.tools2.script.out = out;
        }
        self.tools2.script.open = open;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{analyze, Settings};
    use crate::loader::{raw_binary, Arch, RawSpec};
    use std::sync::{atomic::AtomicU32, Arc};

    #[test]
    fn table_snapshot_apis_are_callable() {
        let bin = raw_binary(&RawSpec {
            path: "script-test".into(), name: "script-test".into(), arch: Arch::X64, big: false,
            segs: vec![(0x1000, vec![0xC3])], entry: Some(0x1000), format: "test".into(),
        });
        let an = analyze(&bin, &Settings { min_string_len: 4, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        let snap = Snap {
            bin: Arc::new(bin), funcs: vec![], names: [(0x1000, "needle_name".into())].into_iter().collect(), strings: vec![(0x2000, "needle string".into())],
            comments: [(0x3000, "needle note".into())].into_iter().collect(), bookmarks: vec![], data_defs: HashMap::new(), xrefs: HashMap::new(), xref_details: HashMap::new(), out_xrefs: HashMap::new(), out_xref_details: HashMap::new(), pseudocode: [(0x4000, "if (needle_condition) return;".into())].into_iter().collect(), pointer_tables: vec![], vtables: vec![], vtable_names: HashMap::new(),
            applied_types: HashMap::new(), types: vec![],
        };
        let out = run("print(script_api_version()); print(function_at(0x1000).len); print(comment_at(0x1000)); print(bookmarks().len); print(data_at(0x1000)); print(data_definitions().len); print(search(\"needle\").len); print(pointer_tables().len); print(vtables().len); print(decompile(0x1000)); define_pointer_table(0x2000); define_array(0x3000);", snap, None);
        assert!(out.error.is_none(), "script failed: {:?}", out.error);
        assert!(out.text.contains("1") && out.text.contains("4"), "unexpected output: {}", out.text);
        assert_eq!(out.cmds.len(), 2);
        let _ = an;
    }
}
