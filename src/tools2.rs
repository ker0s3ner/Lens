//! Windows for patching, structs and signature libraries.

use crate::app::{Action, LensApp, State};
use crate::loader::RawSpec;
use crate::patch::{self, Patch};
use crate::types;

use eframe::egui::{self, vec2, FontId, RichText, ScrollArea, Sense, TextEdit};
use std::sync::mpsc::Receiver;

#[derive(Default)]
pub struct PatchState {
    pub open: bool,
    pub text: String,
    pub for_addr: u64,
    pub any_len: bool,
    pub msg: String,
}

#[derive(Default)]
pub struct TypesState {
    pub open: bool,
    pub def: String,
    pub sel: usize,
    pub apply_addr: String,
    pub msg: String,
}

#[derive(Default)]
pub struct Jobs {
    pub sig: Option<Receiver<Result<String, String>>>,
}

fn parse_hex(s: &str) -> Vec<u8> {
    crate::loader::parse_hex_text(s)
}

impl LensApp {
    pub fn poll_jobs(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.jobs.sig else { return };
        match rx.try_recv() {
            Ok(r) => {
                self.jobs.sig = None;
                match r {
                    Ok(m) => {
                        self.logm(m);
                        self.actions.push(Action::ApplySigs);
                    }
                    Err(e) => self.logm(format!("Couldn't learn signatures: {e}")),
                }
            }
            Err(_) => ctx.request_repaint_after(std::time::Duration::from_millis(300)),
        }
    }

    pub fn learn_sigs(&mut self) {
        let Some(path) = rfd::FileDialog::new().set_title("Choose a program or library whose functions have names").pick_file() else { return };
        let path = path.to_string_lossy().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = (|| {
                let bin = crate::loader::load(&path)?;
                if bin.arch == crate::loader::Arch::Other {
                    return Err("That CPU isn't supported".to_string());
                }
                let an = crate::analysis::analyze(&bin, &crate::analysis::Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)));
                let sf = crate::sigs::learn(&bin, &an);
                if sf.entries.is_empty() {
                    return Err(format!("{} has no named functions with enough code to learn from", bin.file_name));
                }
                let n = sf.entries.len();
                let p = crate::sigs::save(&sf)?;
                Ok(format!("Learned {n} function signatures from {} → {}", bin.file_name, p.display()))
            })();
            let _ = tx.send(r);
        });
        self.jobs.sig = Some(rx);
        self.logm("Learning signatures… (this runs in the background)");
    }

    pub fn apply_sigs_now(&mut self) {
        let State::Ready(l) = &mut self.state else { return };
        l.ann.sig_names = crate::sigs::apply(&l.bin, &l.an);
        let n = l.ann.sig_names.len();
        l.refresh();
        self.logm(if n > 0 { format!("Recognised {n} library functions from signature files.") } else { "No functions matched the signature files in Settings > Signatures.".to_string() });
    }

    pub fn reanalyze(&mut self) {
        self.pending_goto = Some(self.nav.cursor);
        if let Some(spec) = self.last_raw.clone() {
            self.open_raw(spec);
        } else if let Some(p) = self.loaded().map(|l| l.bin.path.clone()) {
            self.open(p);
        }
    }

    pub fn add_patch(&mut self, addr: u64, new: Vec<u8>) {
        let State::Ready(l) = &mut self.state else { return };
        let old = l.bin.read(addr, new.len()).to_vec();
        if old.len() != new.len() {
            self.logm("That patch runs past the end of the section.");
            return;
        }
        if old == new {
            return;
        }
        l.ann.patches.push(Patch { addr, old, new });
        crate::store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
        self.logm(format!("Patched {addr:X}. Re-analysing…"));
        self.reanalyze();
    }

    pub fn revert_patch(&mut self, i: usize) {
        let State::Ready(l) = &mut self.state else { return };
        if i < l.ann.patches.len() {
            let p = l.ann.patches.remove(i);
            crate::store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
            self.logm(format!("Reverted the patch at {:X}. Re-analysing…", p.addr));
            self.reanalyze();
        }
    }

    pub fn toggle_breakpoint(&mut self, addr: u64) {
        let State::Ready(l) = &mut self.state else { return };
        let on = if let Some(p) = l.ann.breakpoints.iter().position(|b| *b == addr) {
            l.ann.breakpoints.remove(p);
            l.ann.bp_conditions.remove(&addr);
            false
        } else {
            l.ann.breakpoints.push(addr);
            true
        };
        crate::store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
        self.logm(format!("Breakpoint {} at {addr:X}", if on { "set" } else { "cleared" }));
        self.dbg_sync_breakpoint(addr, on);
    }

    // ------------------------------------------------------------------ patch window
    pub fn patch_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let addr = self.nav.cursor;
        let info = self.loaded().map(|l| {
            let len = l.an.insns.get(&addr).map(|i| i.len as usize).unwrap_or(1);
            let bytes = l.bin.read(addr, len).to_vec();
            let text = l.fmt.clone_names_text(&l.bin, addr);
            (len, bytes, text, l.bin.arch, l.bin.big_endian, l.ann.patches.clone(), l.bin.format.starts_with("Mach-O"))
        });
        if self.tools2.patch.for_addr != addr {
            self.tools2.patch.for_addr = addr;
            if let Some((_, b, ..)) = &info {
                self.tools2.patch.text = crate::code::hex_bytes(b);
            }
        }
        let mut do_apply: Option<Vec<u8>> = None;
        let mut revert: Option<usize> = None;
        let mut save = false;
        let mut msg = std::mem::take(&mut self.tools2.patch.msg);
        egui::Window::new("Patch bytes").open(&mut open).default_width(520.0).show(ctx, |ui| {
            let Some((len, bytes, text, arch, big, patches, macho)) = &info else {
                ui.label(RichText::new("Open a program to patch it.").color(p.muted));
                return;
            };
            ui.label(RichText::new("Edits are kept as a list and applied on top of the original file. Nothing on disk changes until you save a patched copy.").color(p.muted));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{addr:X}")).monospace().color(p.func_name));
                ui.label(RichText::new(text).monospace());
            });
            ui.label(RichText::new(format!("current bytes: {}", crate::code::hex_bytes(bytes))).monospace().small().color(p.faint));
            ui.add_space(4.0);
            ui.add(TextEdit::singleline(&mut self.tools2.patch.text).desired_width(f32::INFINITY).font(FontId::monospace(13.0)).hint_text("new bytes, e.g. 90 90"));
            ui.checkbox(&mut self.tools2.patch.any_len, "Allow a different length than the instruction (overwrites what follows)");
            ui.horizontal_wrapped(|ui| {
                if ui.button("Apply bytes").clicked() {
                    let nb = parse_hex(&self.tools2.patch.text);
                    if nb.is_empty() { msg = "Type the new bytes first.".into(); }
                    else if nb.len() != *len && !self.tools2.patch.any_len { msg = format!("That's {} bytes but the instruction is {len}. Tick the box to allow it.", nb.len()); }
                    else { do_apply = Some(nb); }
                }
                if ui.button("NOP it").on_hover_text("Replace the instruction with no-operations").clicked() {
                    match patch::nop_bytes(*arch, *big, *len) { Some(n) => do_apply = Some(n), None => msg = "Can't fill an instruction of this size with NOPs on this CPU.".into() }
                }
                if ui.button("Invert branch").on_hover_text("je ⇄ jne, cbz ⇄ cbnz, beq ⇄ bne …").clicked() {
                    match patch::invert_branch(*arch, *big, bytes) { Some(n) => do_apply = Some(n), None => msg = "This isn't a conditional branch Lens knows how to invert.".into() }
                }
                if ui.button("Always jump").on_hover_text("Make a conditional branch unconditional").clicked() {
                    match patch::force_jump(*arch, *big, bytes) { Some(n) => do_apply = Some(n), None => msg = "Can't make this branch unconditional.".into() }
                }
            });
            if !msg.is_empty() {
                ui.label(RichText::new(&msg).color(p.accent));
            }
            ui.separator();
            ui.label(RichText::new(format!("PATCHES · {}", patches.len())).small().color(p.faint));
            ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                for (i, pt) in patches.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{:X}", pt.addr)).monospace().color(p.func_name));
                        ui.label(RichText::new(format!("{}  →  {}", crate::code::hex_bytes(&pt.old), crate::code::hex_bytes(&pt.new))).monospace().small());
                        if ui.small_button("Revert").clicked() { revert = Some(i); }
                    });
                }
                if patches.is_empty() {
                    ui.label(RichText::new("No patches yet.").color(p.faint));
                }
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(!patches.is_empty(), egui::Button::new("Save patched copy…").fill(p.accent_soft)).clicked() { save = true; }
                if *macho { ui.label(RichText::new("re-signed ad hoc so macOS will run it").small().color(p.muted)); }
            });
        });
        self.tools2.patch.msg = msg;
        if let Some(n) = do_apply {
            self.add_patch(addr, n);
        }
        if let Some(i) = revert {
            self.revert_patch(i);
        }
        if save {
            self.save_patched_copy();
        }
        self.tools2.patch.open = open;
    }

    fn save_patched_copy(&mut self) {
        let Some(l) = self.loaded() else { return };
        let default = format!("{}.patched", l.bin.file_name);
        let Some(dest) = rfd::FileDialog::new().set_title("Save the patched program").set_file_name(&default).save_file() else { return };
        let macho = l.bin.format.starts_with("Mach-O");
        match patch::save_patched(&l.bin, &l.ann.patches, &dest) {
            Ok(n) => {
                let mut m = format!("Saved {} with {n} patched bytes.", dest.display());
                if macho {
                    let _ = std::process::Command::new("codesign").args(["--remove-signature"]).arg(&dest).output();
                    match std::process::Command::new("codesign").args(["--force", "--sign", "-"]).arg(&dest).output() {
                        Ok(o) if o.status.success() => m.push_str(" Re-signed ad hoc."),
                        _ => m.push_str(" It couldn't be re-signed; run `codesign --force --sign - <file>` before opening it."),
                    }
                }
                self.logm(m);
            }
            Err(e) => self.logm(e),
        }
    }

    // ----------------------------------------------------------------- structs window
    pub fn types_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let cursor = self.nav.cursor;
        let data = self.loaded().map(|l| (l.ann.structs.clone(), l.ann.applied.clone(), l.bin.arch.bits() / 8, l.bin.debug_structs.clone(), l.an.xrefs_to.clone()));
        let mut add_def: Option<types::StructDef> = None;
        let mut import_debug = false;
        let mut remove: Option<usize> = None;
        let mut apply: Option<(u64, String)> = None;
        let mut unapply: Option<usize> = None;
        let mut pointer_goto: Option<u64> = None;
        let mut field_goto: Option<u64> = None;
        let mut field_xrefs: Option<u64> = None;
        let mut msg = std::mem::take(&mut self.tools2.types.msg);
        egui::Window::new("Types").open(&mut open).default_size([560.0, 560.0]).show(ctx, |ui| {
            let Some((structs, applied, ptr, debug_structs, xrefs_to)) = &data else {
                ui.label(RichText::new("Open a program to define structs, unions and enums.").color(p.muted));
                return;
            };
            ui.label(RichText::new("Paste a C struct, union or enum. Apply it to data to see field names or resolve an enum value.").color(p.muted));
            if !debug_structs.is_empty() && ui.button(format!("Import {} DWARF layouts", debug_structs.len())).on_hover_text("Copies compiler-recovered struct, union and enum offsets into this file's type database").clicked() {
                import_debug = true;
            }
            ui.add(TextEdit::multiline(&mut self.tools2.types.def).code_editor().desired_rows(5).desired_width(f32::INFINITY).hint_text("struct Header {\n  uint32_t magic;\n  char name[16];\n  void *next;\n};\n\nunion Value { uint32_t integer; float real; };\n\nenum State { IDLE, BUSY = 4, DONE };\n\ntypedef uint32_t HeaderSize;"));
            ui.horizontal(|ui| {
                if ui.button("Add type").clicked() {
                    match types::parse_c(&self.tools2.types.def, *ptr, structs) {
                        Ok(s) => { add_def = Some(s); self.tools2.types.def.clear(); msg.clear(); }
                        Err(e) => msg = e,
                    }
                }
                if !msg.is_empty() { ui.label(RichText::new(&msg).color(p.accent)); }
            });
            ui.separator();
            ui.label(RichText::new(format!("TYPES · {}", structs.len())).small().color(p.faint));
            for (i, s) in structs.iter().enumerate() {
                ui.horizontal(|ui| {
                    let kind = if s.is_enum { "enum" } else if s.is_union { "union" } else { "struct" };
                    if ui.selectable_label(self.tools2.types.sel == i, format!("{} {}  ({} bytes)", kind, s.name, s.size)).clicked() { self.tools2.types.sel = i; }
                    if ui.small_button("Remove").clicked() { remove = Some(i); }
                });
            }
            if let Some(s) = structs.get(self.tools2.types.sel) {
                if s.is_enum {
                    egui::Grid::new("enum_values").num_columns(2).spacing([14.0, 2.0]).show(ui, |ui| {
                        for v in &s.enum_values {
                            ui.label(RichText::new(&v.name).monospace());
                            ui.label(RichText::new(v.value.to_string()).monospace().color(p.keyword));
                            ui.end_row();
                        }
                    });
                }
                egui::Grid::new("fields").num_columns(4).spacing([14.0, 2.0]).show(ui, |ui| {
                    for f in types::flatten_fields(structs, s) {
                        ui.label(RichText::new(format!("+{:X}", f.off)).monospace().color(p.func_name));
                        let field_type = f.bit_width.map(|w| format!("{} :{}", f.ty, w)).unwrap_or_else(|| f.ty.clone());
                        ui.label(RichText::new(field_type).monospace().color(p.keyword));
                        ui.label(RichText::new(&f.name).monospace());
                        ui.end_row();
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Apply at");
                    if self.tools2.types.apply_addr.is_empty() { self.tools2.types.apply_addr = format!("{cursor:X}"); }
                    ui.add(TextEdit::singleline(&mut self.tools2.types.apply_addr).desired_width(120.0).font(FontId::monospace(13.0)));
                    if ui.small_button("cursor").clicked() { self.tools2.types.apply_addr = format!("{cursor:X}"); }
                    if ui.button("Apply").clicked() {
                        match crate::dialogs::parse_addr(&self.tools2.types.apply_addr) { Some(a) => apply = Some((a, s.name.clone())), None => msg = "Type an address in hex.".into() }
                    }
                });
            }
            ui.separator();
            ui.label(RichText::new(format!("APPLIED · {}", applied.len())).small().color(p.faint));
            ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                for (i, (a, n)) in applied.iter().enumerate() {
                    let Some(s) = structs.iter().find(|s| &s.name == n) else { continue };
                    egui::CollapsingHeader::new(RichText::new(format!("{n} at {a:X}")).monospace()).id_salt(("ap", i)).show(ui, |ui| {
                        if ui.small_button("Remove from this address").clicked() { unapply = Some(i); }
                        let l = self.loaded();
                        if s.is_enum {
                            ui.label(RichText::new(l.and_then(|l| types::enum_value(&l.bin, *a, s)).unwrap_or_else(|| "?".into())).monospace().color(p.keyword));
                        }
                        egui::Grid::new(("vals", i)).num_columns(3).spacing([14.0, 2.0]).show(ui, |ui| {
                            for f in types::flatten_fields(structs, s) {
                                let field_addr = a.saturating_add(f.off as u64);
                                if ui.small_button(RichText::new(&f.name).monospace()).on_hover_text(format!("Select field at {field_addr:X}")).clicked() {
                                    field_goto = Some(field_addr);
                                }
                                if let Some(refs) = xrefs_to.get(&field_addr).filter(|refs| !refs.is_empty()) {
                                    if ui.small_button(RichText::new(format!("×{}", refs.len())).color(p.xref)).on_hover_text("Show incoming xrefs").clicked() {
                                        field_xrefs = Some(field_addr);
                                    }
                                } else {
                                    ui.label("");
                                }
                                let field_type = f.bit_width.map(|w| format!("{} :{}", f.ty, w)).unwrap_or_else(|| f.ty.clone());
                                ui.label(RichText::new(field_type).monospace().color(p.keyword));
                                let enum_name = f.ty.split('[').next().unwrap_or(&f.ty).trim().trim_start_matches("enum ");
                                let value = l.and_then(|l| {
                                    let en = structs.iter().find(|d| d.is_enum && d.name == enum_name);
                                    en.and_then(|d| types::enum_value(&l.bin, field_addr, d)).or_else(|| Some(types::value(&l.bin, *a, &f)))
                                }).unwrap_or_default();
                                let pointer_target = if types::is_pointer_type(&f.ty, structs) {
                                    l.and_then(|loaded| loaded.bin.read_ptr(field_addr))
                                        .filter(|target| *target != 0 && l.map(|loaded| loaded.bin.is_mapped(*target)).unwrap_or(false))
                                } else { None };
                                if let Some(target) = pointer_target {
                                    if ui.small_button(RichText::new(value).monospace().color(p.accent)).on_hover_text(format!("Follow pointer to {target:X}")).clicked() {
                                        pointer_goto = Some(target);
                                    }
                                } else {
                                    ui.label(RichText::new(value).monospace());
                                }
                                ui.end_row();
                            }
                        });
                    });
                }
            });
        });
        if let Some(target) = pointer_goto { self.actions.push(Action::Goto(target)); }
        if let Some(target) = field_goto { self.actions.push(Action::Goto(target)); }
        if let Some(target) = field_xrefs { self.actions.push(Action::Xrefs(target)); }
        let mut changed = false;
        if let State::Ready(l) = &mut self.state {
            if import_debug {
                let mut imported = 0usize;
                let mut skipped = 0usize;
                for def in &l.bin.debug_structs {
                    if l.ann.structs.iter().any(|existing| existing.name == def.name) { skipped += 1; }
                    else { l.ann.structs.push(def.clone()); imported += 1; }
                }
                msg = format!("Imported {imported} DWARF layouts; skipped {skipped} existing names.");
                changed |= imported > 0;
            }
            if let Some(s) = add_def {
                l.ann.structs.retain(|x| x.name != s.name);
                l.ann.structs.push(s);
                changed = true;
            }
            if let Some(i) = remove {
                let name = l.ann.structs.remove(i).name;
                l.ann.applied.retain(|(_, n)| *n != name);
                changed = true;
            }
            if let Some(a) = apply {
                if !l.ann.applied.contains(&a) { l.ann.applied.push(a); }
                changed = true;
            }
            if let Some(i) = unapply {
                l.ann.applied.remove(i);
                changed = true;
            }
            if changed {
                crate::store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
                l.refresh();
            }
        }
        self.tools2.types.msg = msg;
        self.tools2.types.open = open;
        let _ = (vec2(0.0, 0.0), Sense::hover());
    }
}

pub fn remember_raw(app: &mut LensApp, spec: &RawSpec) {
    app.last_raw = Some(spec.clone());
}
