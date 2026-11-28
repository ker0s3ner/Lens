//! The centre area: code listing, flow graph and hex view.

use crate::analysis::{FuncKind, LineKind, NameKind};
use crate::app::{follow_target, Action, LensApp, Loaded, State, View, SHOW_XREFS};
use crate::code::{self, Tok};
use crate::graph::{self, GraphAction};
use eframe::egui::{self, pos2, vec2, Color32, FontId, Margin, Pos2, Rect, RichText, ScrollArea, Sense, Stroke};

pub struct Painted {
    pub rect: Rect,
    pub target: Option<u64>,
    pub color: Color32,
}

pub fn paint_text(painter: &egui::Painter, pos: Pos2, text: &str, font: &FontId, color: Color32) -> Rect {
    let g = painter.layout_no_wrap(text.to_string(), font.clone(), color);
    let r = Rect::from_min_size(pos, g.size());
    painter.galley(pos, g, color);
    r
}

fn paint_parts(painter: &egui::Painter, mut pos: Pos2, parts: &[(String, Color32, Option<u64>)], font: &FontId) -> (f32, Vec<Painted>) {
    let mut out = vec![];
    for (t, c, tgt) in parts {
        let r = paint_text(painter, pos, t, font, *c);
        out.push(Painted { rect: r, target: *tgt, color: *c });
        pos.x = r.right();
    }
    (pos.x, out)
}

pub fn xref_comment(l: &Loaded, addr: u64) -> Option<String> {
    let mut comments = Vec::new();
    if let Some(xs) = l.an.xrefs_to.get(&addr).filter(|xs| !xs.is_empty()) {
        let code = xs.iter().all(|x| x.kind.is_code());
        let mut s = String::from(if code { "CODE XREF: " } else { "DATA XREF: " });
        let parts: Vec<String> = xs
            .iter()
            .take(SHOW_XREFS)
            .map(|x| format!("{}{}{}", l.loc(x.from), if x.from < addr { "↑" } else { "↓" }, x.kind.mark()))
            .collect();
        s.push_str(&parts.join(", "));
        if xs.len() > SHOW_XREFS {
            s.push_str(&format!("  (+{} more, press X)", xs.len() - SHOW_XREFS));
        }
        comments.push(s);
    }
    for (base, name) in &l.ann.applied {
        if *base != addr { continue; }
        let Some(def) = l.ann.structs.iter().find(|s| s.name == *name && s.is_enum) else { continue };
        if let Some(value) = crate::types::enum_value(&l.bin, addr, def) {
            let member = value.split(" (").next().unwrap_or(&value);
            comments.push(format!("ENUM: {name}::{member}"));
        }
    }
    if comments.is_empty() { None } else { Some(comments.join(" · ")) }
}

fn auto_comment(l: &Loaded, addr: u64) -> Option<String> {
    let i = l.an.insns.get(&addr)?;
    for t in [i.mem, i.imm] {
        if t == 0 {
            continue;
        }
        if let Some(si) = l.an.string_at.get(&t) {
            return Some(format!("\"{}\"", code::escape_str(&l.an.strings[*si].text, 60)));
        }
        if let Some(v) = l.bin.read_ptr(t) {
            if let Some(si) = l.an.string_at.get(&v) {
                return Some(format!("\"{}\"", code::escape_str(&l.an.strings[*si].text, 60)));
            }
        }
    }
    None
}

pub fn short_lib(s: &str) -> String {
    s.rsplit('/').next().unwrap_or(s).to_string()
}

pub fn row_menu(ui: &mut egui::Ui, addr: u64, acts: &mut Vec<Action>) {
    let items: [(&str, Action); 11] = [
        ("Rename…            N", Action::Rename(addr)),
        ("Add a note…        ;", Action::Comment(addr)),
        ("Who uses this      X", Action::Xrefs(addr)),
        ("Make a function    P", Action::MakeFunction(addr)),
        ("Define data        D", Action::DefineData(addr, crate::app::DataDef::Cycle)),
        ("Define pointer     O", Action::DefineData(addr, crate::app::DataDef::Pointer)),
        ("Define pointer table T", Action::DefinePointerTable(addr)),
        ("Define inferred array Y", Action::DefineArray(addr)),
        ("Define string      A", Action::DefineData(addr, crate::app::DataDef::Str)),
        ("Undefine           U", Action::DefineData(addr, crate::app::DataDef::Undefine)),
        ("Show in hex        H", Action::SetView(View::Hex)),
    ];
    for (t, a) in items {
        if ui.button(t).clicked() {
            acts.push(Action::Select(addr, usize::MAX));
            acts.push(a);
            ui.close();
        }
    }
    if ui.button("Copy address").clicked() {
        ui.ctx().copy_text(format!("{addr:X}"));
        ui.close();
    }
}

impl LensApp {
    pub fn center(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let (has_func, crumbs) = match self.loaded() {
            Some(l) => {
                let f = l.an.function_containing(self.nav.cursor).map(|f| l.name(f.start).unwrap_or("?").to_string());
                let seg = l.bin.segment_of(self.nav.cursor).map(|s| s.name.clone()).unwrap_or_default();
                (f.is_some(), Some((seg, f)))
            }
            None => (false, None),
        };
        egui::Frame::NONE.inner_margin(Margin { left: 12, right: 12, top: 8, bottom: 6 }).show(ui, |ui| {
            ui.horizontal(|ui| {
                for (v, label, tip) in [
                    (View::Overview, "Overview", "What Lens detected about this program"),
                    (View::Text, "Code", "Disassembly listing"),
                    (View::Graph, "Graph", "Flow graph of the current function (Space)"),
                    (View::Pseudo, "Pseudocode", "C-like version of the current function (F5)"),
                    (View::Calls, "Call graph", "Who calls this function and what it calls"),
                    (View::Map, "Map", "Every function as a treemap"),
                    (View::Hex, "Hex", "Raw bytes (H)"),
                ] {
                    let on = self.nav.view == v;
                    let enabled = !matches!(v, View::Graph | View::Pseudo | View::Calls) || has_func;
                    if ui.add_enabled(enabled, egui::Button::selectable(on, label)).on_hover_text(tip).clicked() {
                        self.actions.push(Action::SetView(v));
                    }
                }
                ui.add_space(12.0);
                if let Some((seg, f)) = crumbs {
                    ui.label(RichText::new(seg).color(p.segment).monospace());
                    if let Some(f) = f {
                        ui.label(RichText::new("›").color(p.faint));
                        ui.label(RichText::new(f).color(p.func_name).monospace().strong());
                    }
                }
            });
        });
        ui.add(egui::Separator::default().spacing(0.0));
        match self.nav.view {
            View::Overview => self.overview(ui),
            View::Pseudo => self.pseudo_view(ui),
            View::Calls => self.calls_view(ui),
            View::Map => self.map_view(ui),
            View::Text => self.listing(ui),
            View::Graph => self.graph_view(ui),
            View::Hex => self.hex_view(ui),
        }
    }

    fn listing(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let cw = self.char_w;
        let State::Ready(l) = &mut self.state else { return };
        let nav = &mut self.nav;
        let acts = &mut self.actions;
        let font = FontId::monospace(crate::custom::font_size());
        ui.spacing_mut().item_spacing.y = 0.0;
        let n = l.an.lines.len();
        let mut sa = ScrollArea::both().auto_shrink(false).id_salt("listing");
        if let Some(li) = nav.scroll_to.take() {
            sa = sa.vertical_scroll_offset((li as f32 - 8.0).max(0.0) * crate::custom::row_h());
        }
        let x_addr = 14.0;
        let x_code = x_addr + (l.digits as f32 + 3.0) * cw;
        let x_cmt = x_code + 58.0 * cw;
        sa.show_rows(ui, crate::custom::row_h(), n, |ui, range| {
            nav.visible = (range.start, range.end);
            for i in range {
                let ln = l.an.lines[i];
                let w = ui.available_width().max(x_cmt + 360.0);
                let (rect, resp) = ui.allocate_exact_size(vec2(w, crate::custom::row_h()), Sense::click());
                let painter = ui.painter_at(rect);
                if i == nav.cursor_line {
                    painter.rect_filled(rect, 0.0, p.selection);
                } else if resp.hovered() {
                    painter.rect_filled(rect, 0.0, p.hover_row);
                }
                let y = rect.top() + 2.0;
                let cx = rect.left() + x_code;
                if matches!(ln.kind, LineKind::Insn) {
                    if l.dbg_pc == Some(ln.addr) {
                        painter.rect_filled(rect, 0.0, p.accent_soft);
                        painter.text(pos2(rect.left() + 1.0, rect.center().y), egui::Align2::LEFT_CENTER, ">", FontId::monospace(12.0), p.accent);
                    }
                    if l.ann.breakpoints.contains(&ln.addr) {
                        painter.circle_filled(pos2(rect.left() + 8.0, rect.center().y), 4.5, Color32::from_rgb(214, 62, 62));
                    }
                }
                if !matches!(ln.kind, LineKind::Blank | LineKind::FuncSep) {
                    paint_text(&painter, pos2(rect.left() + x_addr, y), &format!("{:0w$X}", ln.addr, w = l.digits), &font, p.address);
                }
                let mut parts: Vec<(String, Color32, Option<u64>)> = vec![];
                let mut comment: Option<(String, Color32)> = None;
                let mut indent = 0.0;
                match ln.kind {
                    LineKind::Segment => {
                        if let Some(s) = l.bin.segment_of(ln.addr) {
                            painter.rect_filled(
                                Rect::from_min_max(pos2(cx - 6.0, rect.top() + 2.0), pos2(rect.right() - 8.0, rect.bottom() - 2.0)),
                                4.0,
                                p.panel_alt,
                            );
                            let kind = if s.exec { "code" } else if s.write { "data" } else { "read-only data" };
                            parts.push((format!("section {}", s.name), p.segment, None));
                            parts.push((format!("   {kind} · {:X}–{:X} · {} bytes", s.start, s.end(), s.size), p.muted, None));
                        }
                    }
                    LineKind::FuncSep => {
                        let my = rect.center().y;
                        painter.line_segment([pos2(cx, my), pos2(rect.right() - 20.0, my)], Stroke::new(1.0, p.border));
                    }
                    LineKind::FuncStart => {
                        let name = l.name(ln.addr).unwrap_or("?").to_string();
                        let f = l.an.functions.get(&ln.addr);
                        let kind = if f.map(|f| f.kind == FuncKind::Import).unwrap_or(false) { NameKind::Import } else { NameKind::Function };
                        parts.push((name, code::name_color(kind, &p), None));
                        if let Some(f) = f {
                            let mut info = if f.kind == FuncKind::Import {
                                "   import stub".to_string()
                            } else {
                                format!("   proc · {} instructions", f.insn_count)
                            };
                            if f.noreturn {
                                info.push_str(" · never returns");
                            }
                            parts.push((info, p.faint, None));
                        }
                        comment = l
                            .ann
                            .comments
                            .get(&ln.addr)
                            .map(|c| (c.clone(), p.comment))
                            .or_else(|| xref_comment(l, ln.addr).map(|c| (c, p.xref)));
                    }
                    LineKind::Label => {
                        let name = l.name(ln.addr).unwrap_or("?").to_string();
                        parts.push((format!("{name}:"), p.label_name, None));
                        comment = xref_comment(l, ln.addr).map(|c| (c, p.xref));
                    }
                    LineKind::Insn => {
                        indent = 3.0 * cw;
                        if let Some((_, toks)) = l.fmt.format(&l.bin, ln.addr) {
                            // Operands start in one column: pad the mnemonic (with any prefix) to 8
                            // characters and drop the formatter's own padding after it.
                            let last_m = toks.iter().rposition(|t| t.kind == Tok::Mnemonic);
                            let mut used = 0;
                            for (k, t) in toks.into_iter().enumerate() {
                                let c = t.color(&p);
                                let mut text = t.text;
                                if let Some(m) = last_m {
                                    if k <= m {
                                        used += text.chars().count();
                                        if k == m {
                                            while used < 8 {
                                                text.push(' ');
                                                used += 1;
                                            }
                                            text.push(' ');
                                        }
                                    } else if k == m + 1 && text.trim().is_empty() {
                                        continue;
                                    }
                                }
                                parts.push((text, c, t.target));
                            }
                        } else {
                            parts.push(("(invalid instruction)".into(), p.edge_not, None));
                        }
                        comment = l
                            .ann
                            .comments
                            .get(&ln.addr)
                            .map(|c| (c.clone(), p.comment))
                            .or_else(|| auto_comment(l, ln.addr).map(|c| (c, p.auto_comment)));
                    }
                    LineKind::FuncEnd => {
                        let f = l.an.function_containing(ln.addr.saturating_sub(1));
                        let name = f.and_then(|f| l.name(f.start)).unwrap_or("function").to_string();
                        parts.push((format!("; end of {name}"), p.faint, None));
                    }
                    LineKind::Str => {
                        if let Some(si) = l.an.string_at.get(&ln.addr) {
                            let s = &l.an.strings[*si];
                            let name = l.name(ln.addr).unwrap_or("").to_string();
                            parts.push((format!("{name:<20} "), p.data_name, None));
                            parts.push(("text  ".into(), p.keyword, None));
                            parts.push((format!("\"{}\"", code::escape_str(&s.text, 120)), p.string, None));
                            if s.wide {
                                parts.push(("  UTF-16".into(), p.faint, None));
                            }
                        }
                        comment = xref_comment(l, ln.addr).map(|c| (c, p.xref));
                    }
                    LineKind::Ptr => {
                        let name = l.name(ln.addr).unwrap_or("").to_string();
                        let kind = l.names.get(&ln.addr).map(|n| n.1).unwrap_or(NameKind::Data);
                        parts.push((format!("{name:<20} "), code::name_color(kind, &p), None));
                        parts.push((if ln.len == 4 { "dd  ".into() } else { "dq  ".into() }, p.keyword, None));
                        if let Some(ix) = l.an.import_slot.get(&ln.addr) {
                            let im = &l.bin.imports[*ix];
                            parts.push(("→ ".into(), p.keyword, None));
                            parts.push((im.name.clone(), p.import_name, None));
                            if !im.library.is_empty() {
                                comment = Some((format!("from {}", short_lib(&im.library)), p.auto_comment));
                            }
                        } else if let Some(v) = l.bin.read_ptr(ln.addr) {
                            parts.push(("offset ".into(), p.keyword, None));
                            match l.names.get(&v) {
                                Some((n, k)) => parts.push((n.clone(), code::name_color(*k, &p), Some(v))),
                                None => parts.push((format!("{v:X}h"), p.number, None)),
                            }
                        }
                        if comment.is_none() {
                            comment = xref_comment(l, ln.addr).map(|c| (c, p.xref));
                        }
                    }
                    LineKind::Data => {
                        let name = l.name(ln.addr).unwrap_or("").to_string();
                        let b = l.bin.read(ln.addr, ln.len as usize);
                        let (dir, val) = match b.len() {
                            1 => ("db", format!("{:X}h", b[0])),
                            2 => ("dw", format!("{:X}h", u16::from_le_bytes([b[0], b[1]]))),
                            4 => ("dd", format!("{:X}h", u32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
                            8 => ("dq", format!("{:X}h", u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))),
                            _ => ("db", code::hex_bytes(b)),
                        };
                        parts.push((format!("{name:<20} "), p.data_name, None));
                        parts.push((format!("{dir}  "), p.keyword, None));
                        parts.push((val, p.number, None));
                        comment = xref_comment(l, ln.addr).map(|c| (c, p.xref));
                    }
                    LineKind::Bytes => {
                        let b = l.bin.read(ln.addr, ln.len as usize);
                        let ascii: String = b.iter().map(|c| if (0x20..0x7f).contains(c) { *c as char } else { '·' }).collect();
                        parts.push((format!("{:<21}", ""), p.faint, None));
                        parts.push(("db  ".into(), p.keyword, None));
                        parts.push((format!("{:<48}", code::hex_bytes(b)), p.bytes, None));
                        parts.push((ascii, p.faint, None));
                    }
                    LineKind::Zeros => {
                        parts.push((format!("{:<21}", ""), p.faint, None));
                        parts.push(("db  ".into(), p.keyword, None));
                        parts.push((format!("{} dup(0)", ln.len), p.bytes, None));
                        parts.push(("   empty space".into(), p.faint, None));
                    }
                    LineKind::Blank => {}
                }
                let (end_x, painted) = paint_parts(&painter, pos2(cx + indent, y), &parts, &font);
                if let Some((c, col)) = comment {
                    let x = (rect.left() + x_cmt).max(end_x + 2.0 * cw);
                    paint_text(&painter, pos2(x, y), &format!("; {c}"), &font, col);
                }
                let hover = resp.hover_pos();
                let mut follow = None;
                for pt in &painted {
                    if let (Some(t), Some(h)) = (pt.target, hover) {
                        if pt.rect.contains(h) {
                            painter.line_segment([pt.rect.left_bottom(), pt.rect.right_bottom()], Stroke::new(1.0, pt.color));
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                            if resp.double_clicked() {
                                follow = Some(t);
                            }
                        }
                    }
                }
                if resp.clicked() || resp.secondary_clicked() {
                    acts.push(Action::Select(ln.addr, i));
                }
                if let Some(t) = follow {
                    acts.push(Action::Goto(t));
                } else if resp.double_clicked() {
                    if matches!(ln.kind, LineKind::FuncStart | LineKind::Label) {
                        acts.push(Action::Xrefs(ln.addr));
                    } else if let Some(t) = follow_target(l, ln.addr, i) {
                        acts.push(Action::Goto(t));
                    }
                }
                resp.context_menu(|ui| row_menu(ui, ln.addr, acts));
            }
        });
    }

    fn hex_view(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let cw = self.char_w;
        let State::Ready(l) = &mut self.state else { return };
        let nav = &mut self.nav;
        let Some(seg) = l.bin.segment_of(nav.cursor).or(l.bin.segments.first()) else { return };
        let font = FontId::monospace(crate::custom::font_size());
        let base = seg.start & !15;
        let rows = (seg.end() - base).div_ceil(16) as usize;
        let cur_len = l.item_len(nav.cursor_line);
        let (c0, c1) = (nav.cursor, nav.cursor.saturating_add(cur_len));
        egui::Frame::NONE.inner_margin(Margin::symmetric(14, 6)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("Section {}", seg.name)).strong());
                ui.label(RichText::new(format!("{:X}–{:X}", seg.start, seg.end())).color(p.muted).monospace());
                if seg.file_offset.is_none() {
                    ui.label(RichText::new("zero-filled when the program runs").color(p.faint));
                }
            });
        });
        ui.spacing_mut().item_spacing.y = 0.0;
        let mut sa = ScrollArea::vertical().auto_shrink(false).id_salt(("hex", seg.start));
        if nav.hex_scroll {
            nav.hex_scroll = false;
            let r = (nav.cursor.saturating_sub(base) / 16) as f32;
            sa = sa.vertical_scroll_offset((r - 8.0).max(0.0) * crate::custom::row_h());
        }
        let mut click = None;
        sa.show_rows(ui, crate::custom::row_h(), rows, |ui, range| {
            for r in range {
                let a = base + r as u64 * 16;
                let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), crate::custom::row_h()), Sense::click());
                let painter = ui.painter_at(rect);
                if resp.hovered() {
                    painter.rect_filled(rect, 0.0, p.hover_row);
                }
                let y = rect.top() + 2.0;
                paint_text(&painter, pos2(rect.left() + 14.0, y), &format!("{:0w$X}", a, w = l.digits), &font, p.address);
                let hx = rect.left() + 14.0 + (l.digits as f32 + 3.0) * cw;
                let ax = hx + 50.0 * cw;
                for k in 0..16u64 {
                    let ba = a + k;
                    let x = hx + (k as f32 * 3.0 + if k >= 8 { 1.0 } else { 0.0 }) * cw;
                    let inside = seg.contains(ba);
                    let br = Rect::from_min_size(pos2(x - 2.0, rect.top() + 1.0), vec2(cw * 2.0 + 4.0, crate::custom::row_h() - 2.0));
                    let ar = Rect::from_min_size(pos2(ax + k as f32 * cw, rect.top() + 1.0), vec2(cw, crate::custom::row_h() - 2.0));
                    if ba >= c0 && ba < c1 {
                        painter.rect_filled(br, 3.0, p.selection);
                        painter.rect_filled(ar, 2.0, p.selection);
                    }
                    if !inside {
                        continue;
                    }
                    let off = (ba - seg.start) as usize;
                    let (t, ch) = match seg.data.get(off) {
                        Some(b) => (format!("{b:02X}"), if (0x20..0x7f).contains(b) { *b as char } else { '·' }),
                        None => ("??".to_string(), '?'),
                    };
                    let col = if t == "00" {
                        p.faint
                    } else if l.an.insns.contains_key(&ba) || seg.exec {
                        p.mnemonic
                    } else {
                        p.bytes
                    };
                    paint_text(&painter, pos2(x, y), &t, &font, col);
                    paint_text(&painter, pos2(ar.left(), y), &ch.to_string(), &font, if ch == '·' { p.faint } else { p.text });
                    if resp.clicked() {
                        if let Some(h) = resp.interact_pointer_pos() {
                            if br.contains(h) || ar.contains(h) {
                                click = Some(ba);
                            }
                        }
                    }
                }
            }
        });
        if let Some(a) = click {
            let line = l.an.line_of(a);
            self.actions.push(Action::Select(a, line));
        }
    }

    fn graph_view(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let cursor = self.nav.cursor;
        let State::Ready(l) = &mut self.state else { return };
        let Some(fs) = l.an.function_containing(cursor).map(|f| f.start) else {
            ui.centered_and_justified(|ui| ui.label(RichText::new("Move the cursor into a function to see its graph.").color(p.muted)));
            return;
        };
        if !l.graphs.contains_key(&fs) {
            let f = l.an.functions[&fs].clone();
            let lay = graph::build(&l.bin, &l.an, &f, &mut l.fmt);
            l.graphs.insert(fs, lay);
            self.nav.graph.center_on = Some(cursor);
        }
        let lay = &l.graphs[&fs];
        if let Some(a) = graph::show(ui, lay, &mut self.nav.graph, &p, cursor, &l.ann.comments) {
            match a {
                GraphAction::Select(x) | GraphAction::Context(x) => {
                    let line = l.an.line_of(x);
                    self.actions.push(Action::Select(x, line));
                }
                GraphAction::Follow(x) => self.actions.push(Action::Goto(x)),
                GraphAction::Xrefs(x) => self.actions.push(Action::Xrefs(x)),
            }
        }
    }
}
