//! Panels around the code: top bar, navigation band, sidebar lists, function outline,
//! status bar, messages and the welcome screen. Also the eframe::App entry.

use crate::analysis::{self, Flow, FuncKind, NameKind};
use crate::app::{Action, LensApp, Side, State, View, FONT_SIZE};
use crate::code;
use crate::theme::Palette;
use crate::views::short_lib;
use eframe::egui::{
    self, pos2, vec2, Align, Color32, CornerRadius, FontId, Layout, Margin, Rect, RichText, ScrollArea, Sense, Stroke, TextEdit,
};
use std::sync::atomic::Ordering;

impl LensApp {
    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let State::Ready(l) = &mut self.state else { return };
        let nav = &mut self.nav;
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = vec2(4.0, 4.0);
            for s in Side::all() {
                if ui.add(egui::Button::selectable(nav.side == s, s.title())).clicked() {
                    nav.side = s;
                    nav.filter.clear();
                }
            }
        });
        ui.add_space(6.0);
        let hint = format!("Filter {}…", nav.side.title().to_lowercase());
        ui.add(TextEdit::singleline(&mut nav.filter).hint_text(hint).desired_width(f32::INFINITY));
        ui.add_space(4.0);
        let key = (nav.side, nav.filter.clone(), l.version);
        let rebuild = match &l.side_cache {
            Some((s, f, v, _)) => (*s, f.clone(), *v) != key,
            None => true,
        };
        if rebuild {
            let q = nav.filter.to_lowercase();
            let m = |s: &str| q.is_empty() || s.to_lowercase().contains(&q);
            let idx: Vec<usize> = match nav.side {
                Side::Functions => (0..l.func_list.len())
                    .filter(|i| {
                        let a = l.func_list[*i];
                        m(l.name(a).unwrap_or("")) || m(&format!("{a:x}"))
                    })
                    .collect(),
                Side::Strings => (0..l.an.strings.len()).filter(|i| m(&l.an.strings[*i].text)).collect(),
                Side::Imports => (0..l.bin.imports.len())
                    .filter(|i| m(&l.bin.imports[*i].name) || m(&l.bin.imports[*i].library))
                    .collect(),
                Side::Exports => (0..l.bin.exports.len()).filter(|i| m(&l.bin.exports[*i].name)).collect(),
                Side::Segments => (0..l.bin.segments.len()).filter(|i| m(&l.bin.segments[*i].name)).collect(),
                Side::Names => (0..l.name_list.len())
                    .filter(|i| {
                        let a = l.name_list[*i];
                        m(l.name(a).unwrap_or("")) || m(&format!("{a:x}"))
                    })
                    .collect(),
                Side::Marks => (0..l.ann.marks.len())
                    .filter(|i| {
                        let a = l.ann.marks[*i];
                        m(l.name(a).unwrap_or("")) || m(&format!("{a:x}")) || m(l.ann.comments.get(&a).map(|s| s.as_str()).unwrap_or(""))
                    })
                    .collect(),
            };
            l.side_cache = Some((key.0, key.1, key.2, idx));
        }
        let idx = l.side_cache.as_ref().map(|c| c.3.clone()).unwrap_or_default();
        let total = match nav.side {
            Side::Functions => l.func_list.len(),
            Side::Strings => l.an.strings.len(),
            Side::Imports => l.bin.imports.len(),
            Side::Exports => l.bin.exports.len(),
            Side::Segments => l.bin.segments.len(),
            Side::Names => l.name_list.len(),
            Side::Marks => l.ann.marks.len(),
        };
        let count = if idx.len() == total { format!("{total} items") } else { format!("{} of {total}", idx.len()) };
        ui.label(RichText::new(count).small().color(p.muted));
        ui.add_space(2.0);
        let cur_func = l.an.function_containing(nav.cursor).map(|f| f.start);
        let font = FontId::monospace(12.5);
        let small = FontId::proportional(11.5);
        ui.spacing_mut().item_spacing.y = 0.0;
        let mut go = None;
        let row_h = 24.0;
        ScrollArea::vertical().auto_shrink(false).id_salt(("side", nav.side as u8)).show_rows(ui, row_h, idx.len(), |ui, range| {
            for r in range {
                let i = idx[r];
                let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), row_h), Sense::click());
                let painter = ui.painter_at(rect);
                let (addr, main, mcol, side) = match nav.side {
                    Side::Functions => {
                        let a = l.func_list[i];
                        let f = &l.an.functions[&a];
                        let col = if f.kind == FuncKind::Import { p.import_name } else { p.func_name };
                        (a, l.name(a).unwrap_or("?").to_string(), col, format!("{a:X}"))
                    }
                    Side::Strings => {
                        let s = &l.an.strings[i];
                        (s.addr, format!("\"{}\"", code::escape_str(&s.text, 80)), p.string, format!("{:X}", s.addr))
                    }
                    Side::Imports => {
                        let im = &l.bin.imports[i];
                        (im.slot, im.name.clone(), p.import_name, short_lib(&im.library))
                    }
                    Side::Exports => {
                        let e = &l.bin.exports[i];
                        (e.addr, analysis::display_symbol(&e.name), p.func_name, format!("{:X}", e.addr))
                    }
                    Side::Names => {
                        let a = l.name_list[i];
                        let (n, k) = l.names.get(&a).cloned().unwrap_or((String::new(), NameKind::Data));
                        (a, analysis::display_symbol(&n), code::name_color(k, &p), format!("{a:X}"))
                    }
                    Side::Marks => {
                        let a = l.ann.marks[i];
                        let label = l.ann.comments.get(&a).cloned().unwrap_or_else(|| l.loc(a));
                        (a, label, p.func_name, format!("{a:X}"))
                    }
                    Side::Segments => {
                        let s = &l.bin.segments[i];
                        let fl = format!("r{}{}  {}", if s.write { "w" } else { "-" }, if s.exec { "x" } else { "-" }, human(s.size));
                        (s.start, s.name.clone(), p.segment, fl)
                    }
                };
                let active = match nav.side {
                    Side::Functions => cur_func == Some(addr),
                    _ => nav.cursor == addr,
                };
                if active {
                    painter.rect_filled(rect.shrink2(vec2(2.0, 1.0)), 5.0, p.accent_soft);
                } else if resp.hovered() {
                    painter.rect_filled(rect.shrink2(vec2(2.0, 1.0)), 5.0, p.hover_row);
                }
                let sg = painter.layout_no_wrap(side, small.clone(), p.muted);
                let sx = rect.right() - sg.size().x - 10.0;
                painter.galley(pos2(sx, rect.center().y - sg.size().y / 2.0), sg, p.muted);
                let clip = Rect::from_min_max(rect.min, pos2(sx - 8.0, rect.max.y));
                let mg = painter.layout_no_wrap(main.clone(), font.clone(), mcol);
                painter.with_clip_rect(clip).galley(pos2(rect.left() + 8.0, rect.center().y - mg.size().y / 2.0), mg, mcol);
                if resp.on_hover_text(&main).clicked() {
                    go = Some(addr);
                }
            }
        });
        if let Some(a) = go {
            // an import opens on the little stub that calls it, when there is one
            let target = if nav.side == Side::Imports {
                l.an.functions
                    .values()
                    .find(|f| f.kind == FuncKind::Import && l.an.insns.get(&f.start).map(|i| i.mem) == Some(a))
                    .map(|f| f.start)
                    .unwrap_or(a)
            } else {
                a
            };
            self.actions.push(Action::Goto(target));
        }
    }

    fn inspector(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let State::Ready(l) = &self.state else { return };
        let cur = self.nav.cursor;
        let mut acts = vec![];
        ScrollArea::vertical().auto_shrink(false).id_salt("inspector").show(ui, |ui| {
            ui.add_space(12.0);
            let section = |ui: &mut egui::Ui, t: &str| {
                ui.add_space(12.0);
                ui.label(RichText::new(t.to_uppercase()).small().strong().color(p.muted));
                ui.add_space(2.0);
            };
            let link = |ui: &mut egui::Ui, text: String, col: Color32, a: u64, acts: &mut Vec<Action>| {
                let r = ui.add(egui::Label::new(RichText::new(text).monospace().color(col)).sense(Sense::click()).truncate());
                if r.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                if r.clicked() {
                    acts.push(Action::Goto(a));
                }
            };
            if let Some(f) = l.an.function_containing(cur) {
                let name = l.name(f.start).unwrap_or("?").to_string();
                ui.label(RichText::new("FUNCTION OUTLINE").small().strong().color(p.muted));
                ui.add(egui::Label::new(RichText::new(&name).size(17.0).strong().color(p.func_name)).truncate());
                ui.horizontal(|ui| {
                    if ui.small_button("Rename").on_hover_text("N").clicked() {
                        acts.push(Action::Rename(f.start));
                    }
                    if ui.small_button("Graph").on_hover_text("Space").clicked() {
                        acts.push(Action::SetView(View::Graph));
                    }
                    if ui.small_button("Callers").on_hover_text("X").clicked() {
                        acts.push(Action::Xrefs(f.start));
                    }
                });
                if let Some((_, raw)) = l.bin.symbols.iter().find(|s| s.0 == f.start) {
                    if analysis::demangle(raw).is_some() {
                        ui.label(RichText::new(raw).small().monospace().color(p.faint));
                    }
                }
                section(ui, "Facts");
                egui::Grid::new("facts").num_columns(2).spacing(vec2(12.0, 4.0)).show(ui, |ui| {
                    let row = |ui: &mut egui::Ui, k: &str, v: String| {
                        ui.label(RichText::new(k).color(p.muted));
                        ui.label(RichText::new(v).monospace());
                        ui.end_row();
                    };
                    row(ui, "Starts at", format!("{:X}", f.start));
                    row(ui, "Size", format!("{} bytes", f.size()));
                    row(ui, "Blocks", format!("{}", f.blocks.len()));
                    row(ui, "Instructions", format!("{}", f.insn_count));
                    let loops = f.blocks.iter().filter(|b| b.succs.iter().any(|(t, _)| *t <= b.start)).count();
                    if loops > 0 {
                        row(ui, "Loops back", format!("{loops}×"));
                    }
                    if f.kind == FuncKind::Import {
                        row(ui, "Kind", "import stub".into());
                    }
                    if f.noreturn {
                        row(ui, "Returns", "never".into());
                    }
                });
                let callers = l.an.xrefs_to.get(&f.start).cloned().unwrap_or_default();
                section(ui, &format!("Called from · {}", callers.len()));
                if callers.is_empty() {
                    ui.label(RichText::new("Nothing calls this directly.").color(p.faint));
                }
                for x in callers.iter().take(40) {
                    link(ui, format!("{}  · {}", l.loc(x.from), x.kind.label()), p.func_name, x.from, &mut acts);
                }
                let mut callees: Vec<u64> = vec![];
                let mut strs: Vec<u64> = vec![];
                let mut data: Vec<u64> = vec![];
                for b in &f.blocks {
                    for a in &b.insns {
                        let i = &l.an.insns[a];
                        if i.flow == Flow::Call && i.target != 0 {
                            callees.push(i.target);
                        }
                        if i.flow == Flow::IndirectCall && l.an.import_slot.contains_key(&i.mem) {
                            callees.push(i.mem);
                        }
                        for t in [i.mem, i.imm] {
                            if t == 0 {
                                continue;
                            }
                            if l.an.string_at.contains_key(&t) {
                                strs.push(t);
                            } else if !l.bin.is_exec(t) && i.flow != Flow::IndirectCall {
                                data.push(t);
                            }
                        }
                    }
                }
                for v in [&mut callees, &mut strs, &mut data] {
                    v.sort();
                    v.dedup();
                }
                section(ui, &format!("Calls · {}", callees.len()));
                if callees.is_empty() {
                    ui.label(RichText::new("Calls no other functions.").color(p.faint));
                }
                for c in callees.iter().take(60) {
                    let (n, k) = l.names.get(c).cloned().unwrap_or((format!("{c:X}"), NameKind::Function));
                    link(ui, n, code::name_color(k, &p), *c, &mut acts);
                }
                if !strs.is_empty() {
                    section(ui, &format!("Text it uses · {}", strs.len()));
                    for s in strs.iter().take(40) {
                        let t = &l.an.strings[l.an.string_at[s]].text;
                        link(ui, format!("\"{}\"", code::escape_str(t, 48)), p.string, *s, &mut acts);
                    }
                }
                if !data.is_empty() {
                    section(ui, &format!("Data it touches · {}", data.len()));
                    for d in data.iter().take(30) {
                        let n = l.name(*d).map(|s| s.to_string()).unwrap_or(format!("{d:X}"));
                        link(ui, n, p.data_name, *d, &mut acts);
                    }
                }
            } else {
                ui.label(RichText::new("NOT IN A FUNCTION").small().strong().color(p.muted));
                ui.label(RichText::new(l.name(cur).unwrap_or("Data or unexplored bytes")).size(15.0).strong());
            }
            section(ui, "At the cursor");
            egui::Grid::new("cur").num_columns(2).spacing(vec2(12.0, 4.0)).show(ui, |ui| {
                ui.label(RichText::new("Address").color(p.muted));
                ui.label(RichText::new(format!("{cur:X}")).monospace());
                ui.end_row();
                if let Some(s) = l.bin.segment_of(cur) {
                    ui.label(RichText::new("Section").color(p.muted));
                    ui.label(RichText::new(&s.name).monospace().color(p.segment));
                    ui.end_row();
                    if let Some(fo) = s.file_offset {
                        ui.label(RichText::new("File offset").color(p.muted));
                        ui.label(RichText::new(format!("{:X}", fo + (cur - s.start))).monospace());
                        ui.end_row();
                    }
                }
                let b = l.bin.read(cur, l.item_len(self.nav.cursor_line).min(12) as usize);
                if !b.is_empty() {
                    ui.label(RichText::new("Bytes").color(p.muted));
                    ui.label(RichText::new(code::hex_bytes(b)).monospace().color(p.bytes));
                    ui.end_row();
                }
            });
            let xs = l.an.xrefs_to.get(&cur).cloned().unwrap_or_default();
            if !xs.is_empty() {
                section(ui, &format!("Used by · {}", xs.len()));
                for x in xs.iter().take(30) {
                    link(ui, format!("{}  · {}", l.loc(x.from), x.kind.label()), p.xref, x.from, &mut acts);
                }
            }
            section(ui, "Your note");
            match l.ann.comments.get(&cur) {
                Some(c) => ui.label(RichText::new(c).color(p.comment)),
                None => ui.label(RichText::new("No note here yet.").color(p.faint)),
            };
            if ui.small_button("Write a note   ;").clicked() {
                acts.push(Action::Comment(cur));
            }
            ui.add_space(20.0);
        });
        self.actions.extend(acts);
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            logo(ui, &p, 22.0);
            ui.label(RichText::new("Lens").size(16.0).strong());
            ui.add_space(8.0);
            let info = self.loaded().map(|l| (l.bin.file_name.clone(), l.bin.format.clone(), l.bin.arch_name.clone()));
            if let Some((name, fmt, arch)) = info {
                chip(ui, &p, &name, p.text, p.panel_alt);
                chip(ui, &p, &fmt, p.muted, p.panel);
                chip(ui, &p, &arch, p.muted, p.panel);
                ui.add_space(10.0);
                let back = self.hist_pos > 0;
                let fwd = self.hist_pos + 1 < self.history.len();
                if ui.add_enabled(back, egui::Button::new("‹  Back")).on_hover_text("Back (Esc)").clicked() {
                    self.actions.push(Action::Back);
                }
                if ui.add_enabled(fwd, egui::Button::new("Forward  ›")).on_hover_text("Forward").clicked() {
                    self.actions.push(Action::Forward);
                }
                let search = egui::Button::new(RichText::new("Go to address or name…     G").color(p.muted))
                    .min_size(vec2(280.0, 26.0))
                    .fill(p.panel_alt);
                if ui.add(search).on_hover_text("G").clicked() {
                    self.actions.push(Action::Jump);
                }
            } else if let State::Loading { path, .. } = &self.state {
                ui.label(RichText::new(format!("Opening {}", short_path(path))).color(p.muted));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(4.0);
                if ui.button(if p.dark { "Light" } else { "Dark" }).on_hover_text("Switch light / dark").clicked() {
                    self.actions.push(Action::ToggleTheme);
                }
                if self.loaded().is_some() {
                    if ui.selectable_label(self.prefs.inspector, "Outline").on_hover_text("Show the function outline").clicked() {
                        self.actions.push(Action::ToggleInspector);
                    }
                    if ui.button("Commands").on_hover_text("Cmd+P / Ctrl+P").clicked() {
                        self.actions.push(Action::Palette);
                    }
                }
                if ui.button("Open…").on_hover_text("Cmd+O / Ctrl+O").clicked() {
                    self.actions.push(Action::OpenDialog);
                }
            });
        });
    }

    fn nav_band(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let State::Ready(l) = &self.state else { return };
        let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 14.0), Sense::click_and_drag());
        let painter = ui.painter_at(rect);
        let r = rect.shrink2(vec2(12.0, 2.0));
        painter.rect_filled(r, 4.0, p.nav_zero);
        let bw = r.width() / l.nav.len().max(1) as f32;
        let mut i = 0;
        while i < l.nav.len() {
            let c = l.nav[i];
            let mut j = i;
            while j < l.nav.len() && l.nav[j] == c {
                j += 1;
            }
            let col = match c {
                5 => p.nav_code,
                4 => p.nav_import,
                3 => p.nav_string,
                2 => p.nav_data,
                1 => p.nav_unexplored,
                _ => p.nav_zero,
            };
            if c != 0 {
                painter.rect_filled(
                    Rect::from_min_max(pos2(r.left() + i as f32 * bw, r.top()), pos2(r.left() + j as f32 * bw, r.bottom())),
                    0.0,
                    col,
                );
            }
            i = j;
        }
        if let Some(o) = l.addr_to_off(self.nav.cursor) {
            let x = r.left() + (o as f64 / l.total_span() as f64) as f32 * r.width();
            painter.line_segment([pos2(x, rect.top()), pos2(x, rect.bottom())], Stroke::new(3.0, p.nav_cursor));
        }
        if let Some(h) = resp.hover_pos() {
            let frac = ((h.x - r.left()) / r.width()).clamp(0.0, 1.0) as f64;
            let a = l.off_to_addr((frac * l.total_span() as f64) as u64).unwrap_or(0);
            let tip = format!("{a:X}  {}", l.loc(a));
            let clicked = resp.clicked() || resp.dragged();
            resp.on_hover_text_at_pointer(tip);
            if clicked {
                self.actions.push(Action::Goto(a));
            }
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            match &self.state {
                State::Ready(l) => {
                    { let (r, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover()); ui.painter().circle_filled(r.center(), 4.0, p.edge_taken); }
                    ui.label(RichText::new("Ready").color(p.muted).small());
                    ui.separator();
                    ui.label(RichText::new(format!("{:X}", self.nav.cursor)).monospace().small());
                    ui.label(RichText::new(l.loc(self.nav.cursor)).monospace().small().color(p.func_name));
                    ui.separator();
                    ui.label(RichText::new(&l.an.stats).small().color(p.muted));
                    ui.separator();
                    legend(ui, &p);
                }
                State::Loading { progress, started, .. } => {
                    ui.add(egui::Spinner::new().size(12.0));
                    ui.label(
                        RichText::new(format!(
                            "Analysing… {} functions found ({:.0}s)",
                            progress.load(Ordering::Relaxed),
                            started.elapsed().as_secs_f32()
                        ))
                        .small()
                        .color(p.muted),
                    );
                }
                State::Empty => {
                    ui.label(RichText::new("No file open").small().color(p.muted));
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(6.0);
                let t = if self.show_log { "Hide messages" } else { "Messages" };
                if ui.add(egui::Button::new(RichText::new(t).small()).frame(false)).clicked() {
                    self.actions.push(Action::ToggleLog);
                }
                if let Some(last) = self.log.last() {
                    ui.add(egui::Label::new(RichText::new(last).small().color(p.faint)).truncate());
                }
            });
        });
    }

    fn welcome(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        if let State::Loading { path, progress, .. } = &self.state {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() * 0.35);
                ui.add(egui::Spinner::new().size(28.0));
                ui.add_space(10.0);
                ui.label(RichText::new(format!("Reading {}", short_path(path))).size(16.0));
                ui.label(RichText::new(format!("{} functions found so far", progress.load(Ordering::Relaxed))).color(p.muted));
            });
            return;
        }
        let avail = ui.available_size();
        let card_w = 560.0f32.min(avail.x - 40.0);
        ui.add_space((avail.y * 0.08).max(16.0));
        ui.vertical_centered(|ui| {
            logo(ui, &p, 64.0);
            ui.add_space(8.0);
            ui.label(RichText::new("Lens").size(30.0).strong());
            ui.label(RichText::new("Drop in an .exe or an .app — Lens works out the rest.").size(15.0).color(p.muted));
            ui.add_space(22.0);
            let b = egui::Button::new(RichText::new("Open a program…").size(15.0).color(Color32::WHITE))
                .fill(p.accent)
                .min_size(vec2(220.0, 40.0))
                .corner_radius(CornerRadius::same(8));
            if ui.add(b).clicked() {
                self.actions.push(Action::OpenDialog);
            }
            ui.add_space(6.0);
            ui.label(RichText::new("or drop a file anywhere in this window").color(p.faint));
            ui.add_space(24.0);
            egui::Frame::new()
                .fill(p.panel)
                .stroke(Stroke::new(1.0, p.border))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(Margin::same(18))
                .show(ui, |ui| {
                    ui.set_width(card_w);
                    ui.with_layout(Layout::top_down(Align::Min), |ui| {
                        ui.label(RichText::new("RECENT").small().strong().color(p.muted));
                        ui.add_space(4.0);
                        if self.prefs.recent.is_empty() {
                            ui.label(RichText::new("Nothing opened yet.").color(p.faint));
                        }
                        for r in self.prefs.recent.clone() {
                            let name = std::path::Path::new(&r).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or(r.clone());
                            ui.horizontal(|ui| {
                                if ui.add(egui::Button::new(RichText::new(name).strong()).frame(false)).clicked() {
                                    self.actions.push(Action::Open(r.clone()));
                                }
                                ui.label(RichText::new(short_path(&r)).small().color(p.faint));
                            });
                        }
                        if let Some(sample) = sample_path() {
                            ui.add_space(6.0);
                            if ui.link(format!("Try a sample: {sample}")).clicked() {
                                self.actions.push(Action::Open(sample.to_string()));
                            }
                        }
                        ui.add_space(14.0);
                        ui.label(RichText::new("WORKS WITH").small().strong().color(p.muted));
                        ui.label("Windows .exe / .dll  ·  Linux ELF  ·  macOS .app and Mach-O (incl. universal)  ·  x86 and x64 code\nFinds the compiler, language, packer and calling convention by itself.");
                        ui.add_space(14.0);
                        ui.label(RichText::new("HANDY KEYS").small().strong().color(p.muted));
                        egui::Grid::new("keys").num_columns(4).spacing(vec2(14.0, 6.0)).show(ui, |ui| {
                            let keys = [
                                ("G", "Go to address"),
                                ("Space", "Graph / code"),
                                ("F5", "Pseudocode"),
                                ("M", "Bookmark"),
                                ("N", "Rename"),
                                ("X", "Who uses this"),
                                (";", "Add a note"),
                                ("Esc", "Go back"),
                                ("Enter", "Follow"),
                                ("Cmd/Ctrl P", "All commands"),
                            ];
                            for (i, (k, d)) in keys.iter().enumerate() {
                                kbd(ui, &p, k);
                                ui.label(RichText::new(*d).color(p.muted));
                                if i % 2 == 1 {
                                    ui.end_row();
                                }
                            }
                        });
                    });
                });
        });
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        ui.horizontal(|ui| {
            ui.label(RichText::new("MESSAGES").small().strong().color(p.muted));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("Clear").clicked() {
                    self.log.clear();
                }
            });
        });
        ScrollArea::vertical().auto_shrink(false).stick_to_bottom(true).show(ui, |ui| {
            for m in &self.log {
                ui.label(RichText::new(m).monospace().size(12.0));
            }
        });
    }
}

impl eframe::App for LensApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.frame += 1;
        self.char_w = ctx.fonts_mut(|f| f.glyph_width(&FontId::monospace(FONT_SIZE), '0'));
        self.poll();
        if matches!(self.state, State::Loading { .. }) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        let dropped: Vec<String> = ctx.input(|i| {
            i.raw.dropped_files.iter().map(|f| f.path().to_string_lossy().to_string()).filter(|s| !s.is_empty()).collect()
        });
        if let Some(f) = dropped.into_iter().next() {
            self.actions.push(Action::Open(f));
        }
        let title = match &self.state {
            State::Ready(l) => format!("{} — Lens", l.bin.file_name),
            _ => "Lens".into(),
        };
        if title != self.title {
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.clone()));
            self.title = title;
        }
        self.keys(&ctx);
        let p = self.p;
        let bar = |fill: Color32| egui::Frame::new().fill(fill).inner_margin(Margin::symmetric(10, 6));
        egui::Panel::top("top").frame(bar(p.panel)).show(ui, |ui| self.top_bar(ui));
        if self.loaded().is_some() {
            egui::Panel::top("band")
                .frame(egui::Frame::new().fill(p.panel).inner_margin(Margin::symmetric(0, 3)))
                .show(ui, |ui| self.nav_band(ui));
        }
        egui::Panel::bottom("status").frame(bar(p.panel)).show(ui, |ui| self.status_bar(ui));
        if self.show_log {
            egui::Panel::bottom("log").resizable(true).default_size(140.0).frame(bar(p.panel_alt)).show(ui, |ui| self.log_panel(ui));
        }
        if self.loaded().is_some() {
            egui::Panel::left("side")
                .resizable(true)
                .default_size(290.0)
                .size_range(200.0..=520.0)
                .frame(egui::Frame::new().fill(p.panel).inner_margin(Margin { left: 10, right: 8, top: 0, bottom: 6 }))
                .show(ui, |ui| self.sidebar(ui));
            if self.prefs.inspector {
                egui::Panel::right("inspector")
                    .resizable(true)
                    .default_size(300.0)
                    .size_range(220.0..=520.0)
                    .frame(egui::Frame::new().fill(p.panel).inner_margin(Margin { left: 14, right: 10, top: 0, bottom: 6 }))
                    .show(ui, |ui| self.inspector(ui));
            }
            egui::CentralPanel::default()
                .frame(egui::Frame::new().fill(p.panel).inner_margin(Margin::ZERO))
                .show(ui, |ui| self.center(ui));
        } else {
            egui::CentralPanel::default().frame(egui::Frame::new().fill(p.bg)).show(ui, |ui| self.welcome(ui));
        }
        self.modals(&ctx);
        self.apply_actions(&ctx);
        self.screenshot_tick(&ctx);
    }
}

pub fn short_path(s: &str) -> String {
    if let Ok(h) = std::env::var("HOME") {
        if let Some(r) = s.strip_prefix(&h) {
            return format!("~{r}");
        }
    }
    s.to_string()
}

fn human(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{:.1} MB", n as f64 / 1048576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn sample_path() -> Option<&'static str> {
    let c: &[&str] = if cfg!(target_os = "windows") { &["C:\\Windows\\System32\\notepad.exe"] } else { &["/bin/ls", "/usr/bin/ls"] };
    c.iter().copied().find(|p| std::path::Path::new(p).exists())
}

fn chip(ui: &mut egui::Ui, p: &Palette, text: &str, fg: Color32, bg: Color32) {
    egui::Frame::new()
        .fill(bg)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(9, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(fg).size(12.5));
        });
}

fn kbd(ui: &mut egui::Ui, p: &Palette, k: &str) {
    egui::Frame::new()
        .fill(p.panel_alt)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(6, 1))
        .show(ui, |ui| {
            ui.label(RichText::new(k).monospace().size(12.0));
        });
}

fn legend(ui: &mut egui::Ui, p: &Palette) {
    for (c, t) in [(p.nav_code, "code"), (p.nav_import, "imports"), (p.nav_string, "text"), (p.nav_data, "data"), (p.nav_unexplored, "unexplored")] {
        let (r, _) = ui.allocate_exact_size(vec2(9.0, 9.0), Sense::hover());
        ui.painter().rect_filled(r, 2.0, c);
        ui.label(RichText::new(t).small().color(p.muted));
    }
}

pub fn logo(ui: &mut egui::Ui, p: &Palette, size: f32) {
    let (r, _) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    let painter = ui.painter();
    let c = r.center() - vec2(size * 0.08, size * 0.08);
    let rad = size * 0.32;
    painter.circle(c, rad, p.accent_soft, Stroke::new(size * 0.09, p.accent));
    let h0 = c + vec2(rad * 0.72, rad * 0.72);
    painter.line_segment([h0, r.right_bottom() - vec2(size * 0.08, size * 0.08)], Stroke::new(size * 0.12, p.accent));
    for (k, w) in [(-0.35f32, 0.9f32), (0.0, 0.6), (0.35, 0.75)] {
        let y = c.y + rad * k;
        painter.line_segment([pos2(c.x - rad * 0.5, y), pos2(c.x - rad * 0.5 + rad * w, y)], Stroke::new(size * 0.05, p.accent));
    }
}
