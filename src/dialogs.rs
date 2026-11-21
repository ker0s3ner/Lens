//! Dialogs (go to, rename, note, cross-references, find, command list) and the --screenshot option.

use crate::analysis::{NameKind, XrefKind};
use crate::app::{Action, LensApp, Modal, Side, State, View};
use crate::code;
use crate::store;
use eframe::egui::{self, vec2, Align2, Color32, CornerRadius, FontId, Key, Margin, RichText, ScrollArea, Sense, Stroke, TextEdit};
use std::sync::atomic::Ordering;

pub fn parse_addr(s: &str) -> Option<u64> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X").trim_end_matches(['h', 'H']);
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(t, 16).ok()
}

impl LensApp {
    pub fn modals(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let Some(mut m) = self.modal.take() else { return };
        let mut keep = true;
        let mut acts: Vec<Action> = vec![];
        let mut find_text: Option<String> = None;
        let view = self.nav.view;
        let cur = self.nav.cursor;
        let modal = egui::Modal::new(egui::Id::new("lens_modal")).frame(
            egui::Frame::new()
                .fill(p.panel)
                .stroke(Stroke::new(1.0, p.border))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(Margin::same(18)),
        );
        let mut l = match &mut self.state {
            State::Ready(l) => Some(l),
            _ => None,
        };
        let title = |ui: &mut egui::Ui, t: &str, sub: &str| {
            ui.label(RichText::new(t).size(17.0).strong());
            if !sub.is_empty() {
                ui.label(RichText::new(sub).color(p.muted));
            }
            ui.add_space(6.0);
        };
        let resp = modal.show(ctx, |ui| {
            ui.set_width(520.0);
            match &mut m {
                Modal::Message { title: t, text } => {
                    title(ui, t, "");
                    ui.label(text.as_str());
                    ui.add_space(10.0);
                    if ui.button("OK").clicked() {
                        keep = false;
                    }
                }
                Modal::Jump { text, focus } => {
                    let Some(l) = l.as_deref() else {
                        keep = false;
                        return;
                    };
                    title(ui, "Go to", "Type an address (like 401000) or part of a name.");
                    let r = ui.add(TextEdit::singleline(text).desired_width(f32::INFINITY).hint_text("Address or name"));
                    if *focus {
                        r.request_focus();
                        *focus = false;
                    }
                    let q = text.trim().to_string();
                    let mut hits: Vec<(u64, String, NameKind)> = vec![];
                    if !q.is_empty() {
                        let ql = q.to_lowercase();
                        for (a, (n, k)) in l.names.iter() {
                            if *k != NameKind::Label && n.to_lowercase().contains(&ql) {
                                hits.push((*a, n.clone(), *k));
                            }
                        }
                        hits.sort_by_key(|h| (!h.1.to_lowercase().starts_with(&ql), h.1.len(), h.0));
                        hits.truncate(12);
                    }
                    let addr = parse_addr(&q).filter(|a| l.bin.is_mapped(*a));
                    if let Some(a) = addr {
                        ui.label(RichText::new(format!("Enter → address {a:X}  ({})", l.loc(a))).color(p.accent));
                    }
                    for (a, n, k) in &hits {
                        let b = egui::Button::new(RichText::new(n).monospace().color(code::name_color(*k, &p))).frame(false);
                        if ui.add(b).clicked() {
                            acts.push(Action::Goto(*a));
                            keep = false;
                        }
                    }
                    if !q.is_empty() && addr.is_none() && hits.is_empty() {
                        ui.label(RichText::new("No address or name matches.").color(p.faint));
                    }
                    if ui.input(|i| i.key_pressed(Key::Enter)) {
                        if let Some(a) = addr {
                            acts.push(Action::Goto(a));
                            keep = false;
                        } else if let Some(h) = hits.iter().find(|h| h.1.eq_ignore_ascii_case(&q)).or(hits.first()) {
                            acts.push(Action::Goto(h.0));
                            keep = false;
                        }
                    }
                }
                Modal::Rename { addr, text, focus } => {
                    let a = *addr;
                    title(ui, "Rename", &format!("Give {a:X} a name that says what it does. Leave it empty to go back to the automatic name."));
                    let r = ui.add(TextEdit::singleline(text).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                    if *focus {
                        r.request_focus();
                        *focus = false;
                    }
                    let enter = ui.input(|i| i.key_pressed(Key::Enter));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() || enter {
                            if let Some(l) = l.as_deref_mut() {
                                let t: String = text.trim().chars().map(|c| if c.is_whitespace() { '_' } else { c }).collect();
                                let auto = l.an.names.get(&a).map(|x| x.0.clone());
                                if t.is_empty() || Some(&t) == auto.as_ref() {
                                    l.ann.names.remove(&a);
                                } else {
                                    l.ann.names.insert(a, t);
                                }
                                store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
                                l.refresh();
                            }
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                        }
                    });
                }
                Modal::Comment { addr, text, focus } => {
                    let a = *addr;
                    title(ui, "Note", &format!("A note for {a:X}, shown beside the code."));
                    let r = ui.add(TextEdit::singleline(text).desired_width(f32::INFINITY));
                    if *focus {
                        r.request_focus();
                        *focus = false;
                    }
                    let enter = ui.input(|i| i.key_pressed(Key::Enter));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() || enter {
                            if let Some(l) = l.as_deref_mut() {
                                if text.trim().is_empty() {
                                    l.ann.comments.remove(&a);
                                } else {
                                    l.ann.comments.insert(a, text.trim().to_string());
                                }
                                store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
                                l.graphs.clear();
                            }
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                        }
                    });
                }
                Modal::Xrefs { addr } => {
                    let Some(l) = l.as_deref() else {
                        keep = false;
                        return;
                    };
                    let a = *addr;
                    let xs = l.an.xrefs_to.get(&a).cloned().unwrap_or_default();
                    title(ui, &format!("Who uses {}", l.loc(a)), &format!("{} place(s) refer to {a:X}. Click one to go there.", xs.len()));
                    if xs.is_empty() {
                        ui.label(RichText::new("Nothing in the program refers to this address directly.").color(p.faint));
                    }
                    ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                        for x in &xs {
                            ui.horizontal(|ui| {
                                let (tag, col) = match x.kind {
                                    XrefKind::Call => ("call", p.edge_taken),
                                    XrefKind::Jump => ("jump", p.edge_always),
                                    XrefKind::Read => ("read", p.data_name),
                                    XrefKind::Write => ("write", p.edge_not),
                                    _ => ("address", p.muted),
                                };
                                ui.label(RichText::new(format!("{tag:<7}")).monospace().color(col));
                                let b = egui::Button::new(RichText::new(format!("{:X}   {}", x.from, l.loc(x.from))).monospace()).frame(false);
                                if ui.add(b).clicked() {
                                    acts.push(Action::Goto(x.from));
                                    keep = false;
                                }
                            });
                        }
                    });
                    ui.add_space(6.0);
                    if ui.button("Close").clicked() {
                        keep = false;
                    }
                }
                Modal::Find { text, focus } => {
                    title(ui, "Find text", "Searches the listing from the cursor down. Type bytes like 48 8B ?? 05 to search the raw bytes instead. F3 finds the next one.");
                    let r = ui.add(TextEdit::singleline(text).desired_width(f32::INFINITY));
                    if *focus {
                        r.request_focus();
                        *focus = false;
                    }
                    if ui.input(|i| i.key_pressed(Key::Enter)) || ui.button("Find").clicked() {
                        find_text = Some(text.clone());
                        acts.push(Action::FindNext);
                        keep = false;
                    }
                }
                Modal::Palette { text, sel, focus } => {
                    let r = ui.add(TextEdit::singleline(text).desired_width(f32::INFINITY).hint_text("Type a command or a function name…"));
                    if *focus {
                        r.request_focus();
                        *focus = false;
                    }
                    let q = text.to_lowercase();
                    let cmds: Vec<(&str, &str, Action)> = vec![
                        ("Open a program", "Cmd+O", Action::OpenDialog),
                        ("Search…", "Cmd+F", Action::Search),
                        ("Patch bytes…", "", Action::Patches),
                        ("Structs…", "", Action::Structs),
                        ("Undo", "Cmd+Z", Action::Undo),
                        ("Redo", "Cmd+Shift+Z", Action::Redo),
                        ("Lists: names, imports, exports, entry points, bookmarks…", "", Action::Lists),
                        ("Compare with another program…", "", Action::Diff),
                        ("Export IDA script (.idc)…", "", Action::Export(crate::ida::ExportKind::Idc)),
                        ("Export Ghidra script (.py)…", "", Action::Export(crate::ida::ExportKind::Ghidra)),
                        ("Export database as JSON…", "", Action::Export(crate::ida::ExportKind::Json)),
                        ("Export map file…", "", Action::Export(crate::ida::ExportKind::Map)),
                        ("Debugger…", "", Action::Debugger),
                        ("Toggle breakpoint at cursor", "F2", Action::ToggleBreakpoint(cur)),
                        ("Script…", "", Action::Script),
                        ("Learn signatures from a file…", "", Action::LearnSigs),
                        ("Recognise library functions", "", Action::ApplySigs),
                        ("Hex to Code translator…", "", Action::HexTool),
                        ("Settings…", "Cmd+,", Action::Settings),
                        ("Copy file SHA-256", "", Action::CopyHash),
                        ("Show file in Finder", "", Action::Reveal),
                        ("Export my names and notes…", "", Action::ExportNotes),
                        ("Check for updates", "", Action::CheckUpdate),
                        ("Install available update", "", Action::InstallUpdate),
                        ("Toggle automatic update checks", "", Action::ToggleAutoUpdate),
                        ("Go to address or name", "G", Action::Jump),
                        ("Switch graph / code view", "Space", Action::SetView(if view == View::Graph { View::Text } else { View::Graph })),
                        ("Show overview (what was detected)", "", Action::SetView(View::Overview)),
                        ("Show pseudocode (decompile)", "F5", Action::SetView(View::Pseudo)),
                        ("Show call graph", "", Action::SetView(View::Calls)),
                        ("Show function map", "", Action::SetView(View::Map)),
                        ("Export pseudocode of every function…", "", Action::ExportC),
                        ("Show pseudocode as Python", "", Action::SetLang(crate::lang::Lang::Python)),
                        ("Show pseudocode as Rust", "", Action::SetLang(crate::lang::Lang::Rust)),
                        ("Show pseudocode as Go", "", Action::SetLang(crate::lang::Lang::Go)),
                        ("Show pseudocode as JavaScript", "", Action::SetLang(crate::lang::Lang::JavaScript)),
                        ("Show pseudocode as C", "", Action::SetLang(crate::lang::Lang::C)),
                        ("Bookmark this spot", "M", Action::Mark(cur)),
                        ("Show names", "", Action::SetSide(Side::Names)),
                        ("Show bookmarks", "", Action::SetSide(Side::Marks)),
                        ("Show hex view", "H", Action::SetView(View::Hex)),
                        ("Rename at cursor", "N", Action::Rename(cur)),
                        ("Add a note at cursor", ";", Action::Comment(cur)),
                        ("Who uses this (cross-references)", "X", Action::Xrefs(cur)),
                        ("Make a function here", "P", Action::MakeFunction(cur)),
                        ("Find text", "Alt+T", Action::Find),
                        ("Find next", "Ctrl+T", Action::FindNext),
                        ("Show functions", "Shift+F3", Action::SetSide(Side::Functions)),
                        ("Show strings", "Shift+F12", Action::SetSide(Side::Strings)),
                        ("Show imports", "", Action::SetSide(Side::Imports)),
                        ("Show exports", "", Action::SetSide(Side::Exports)),
                        ("Show sections", "Shift+F7", Action::SetSide(Side::Segments)),
                        ("Go back", "Esc", Action::Back),
                        ("Go forward", "", Action::Forward),
                        ("Switch light / dark", "", Action::ToggleTheme),
                        ("Show or hide messages", "", Action::ToggleLog),
                        ("Show or hide the outline", "", Action::ToggleInspector),
                        ("Close file", "", Action::Close),
                    ];
                    let mut items: Vec<(String, String, Action, Color32)> = cmds
                        .into_iter()
                        .filter(|c| q.is_empty() || c.0.to_lowercase().contains(&q))
                        .map(|c| (c.0.to_string(), c.1.to_string(), c.2, p.text))
                        .collect();
                    if let (Some(l), false) = (l.as_deref(), q.is_empty()) {
                        let mut fs: Vec<(u64, String)> = l
                            .an
                            .functions
                            .keys()
                            .filter_map(|a| l.names.get(a).map(|n| (*a, n.0.clone())))
                            .filter(|(_, n)| n.to_lowercase().contains(&q))
                            .collect();
                        fs.sort_by_key(|(a, n)| (!n.to_lowercase().starts_with(&q), n.len(), *a));
                        for (a, n) in fs.into_iter().take(30) {
                            items.push((n, format!("{a:X}"), Action::Goto(a), p.func_name));
                        }
                    }
                    let (down, up, enter) =
                        ui.input(|i| (i.key_pressed(Key::ArrowDown), i.key_pressed(Key::ArrowUp), i.key_pressed(Key::Enter)));
                    if down {
                        *sel = (*sel + 1).min(items.len().saturating_sub(1));
                    }
                    if up {
                        *sel = sel.saturating_sub(1);
                    }
                    if *sel >= items.len() {
                        *sel = 0;
                    }
                    ui.add_space(6.0);
                    ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
                        for (i, (label, hint, act, col)) in items.iter().enumerate() {
                            let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 28.0), Sense::click());
                            if i == *sel || resp.hovered() {
                                ui.painter().rect_filled(rect, 6.0, if i == *sel { p.accent_soft } else { p.hover_row });
                            }
                            ui.painter().text(rect.left_center() + vec2(10.0, 0.0), Align2::LEFT_CENTER, label, FontId::proportional(14.0), *col);
                            ui.painter().text(rect.right_center() - vec2(10.0, 0.0), Align2::RIGHT_CENTER, hint, FontId::monospace(12.0), p.muted);
                            if resp.clicked() || (enter && i == *sel) {
                                acts.push(act.clone());
                                keep = false;
                            }
                            if i == *sel && (down || up) {
                                resp.scroll_to_me(None);
                            }
                        }
                        if items.is_empty() {
                            ui.label(RichText::new("No matches.").color(p.faint));
                        }
                    });
                }
            }
        });
        if resp.should_close() {
            keep = false;
        }
        if keep {
            self.modal = Some(m);
        }
        if let Some(t) = find_text {
            self.find_text = t;
        }
        self.actions.extend(acts);
    }

    pub fn screenshot_tick(&mut self, ctx: &egui::Context) {
        let ready = !matches!(self.state, State::Loading { .. });
        let frame = self.frame;
        let Some(s) = &mut self.shot else { return };
        ctx.request_repaint();
        if s.done.load(Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if ready && s.ready_frame.is_none() {
            s.ready_frame = Some(frame);
        }
        let due = match s.ready_frame {
            Some(r) => frame >= 120.max(r + 30),
            None => frame > 3000,
        };
        if due && !s.requested {
            s.requested = true;
            let path = s.path.clone();
            let done = s.done.clone();
            let ctx2 = ctx.clone();
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::ScreenshotCallback::new(move |img| {
                let [w, h] = img.size;
                let mut buf = Vec::with_capacity(w * h * 4);
                for c in &img.pixels {
                    buf.extend_from_slice(&c.to_srgba_unmultiplied());
                }
                if let Some(parent) = std::path::Path::new(&path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = image::save_buffer(&path, &buf, w as u32, h as u32, image::ColorType::Rgba8) {
                    eprintln!("Couldn't save the screenshot: {e}");
                }
                done.store(true, Ordering::Relaxed);
                ctx2.request_repaint();
            })));
        }
    }
}
