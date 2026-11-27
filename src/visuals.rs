//! The extra views: Overview (what Lens detected), Pseudocode, Call graph and Map (treemap).

use crate::analysis::{display_symbol, FuncKind, NameKind};
use crate::app::{Action, LensApp, Loaded, State, View};
use crate::decomp::{self, DLine, Decompiled};
use crate::lang::{self, Lang};
use crate::detect::Detection;
use crate::loader::Binary;
use crate::theme::Palette;
use eframe::egui::{
    self, pos2, vec2, Align2, Color32, CornerRadius, FontId, Margin, Pos2, Rect, RichText, ScrollArea, Sense, Shape, Stroke, StrokeKind, Vec2,
};
use std::collections::{HashMap, HashSet};

const CALL_GRAPH_MAX_NODES: usize = 120;
const CALL_GRAPH_MAX_NEIGHBORS: usize = 24;
const CALL_GRAPH_MAX_INSTRUCTIONS_PER_FUNCTION: usize = 8192;
const CALL_GRAPH_MAX_EDGES: usize = 2048;
const CALL_GRAPH_MAX_CALLER_XREFS: usize = CALL_GRAPH_MAX_NEIGHBORS * 8;
use std::path::Path;
use std::sync::Arc;

#[derive(Default)]
pub struct VisState {
    pub cg_pan: Vec2,
    pub cg_zoom: f32,
    pub cg_depth: usize,
    pub cg_for: u64,
    pub cg_cache: Option<(u64, usize, u64, Vec<CNode>, Vec<(usize, usize)>)>,
    pub map_mode: u8,
    pub map_pan: Vec2,
    pub map_zoom: f32,
    pub pseudo_scroll: Option<usize>,
    pub pseudo_for: u64,
    pub lang: Option<Lang>,
    pub lang_cache: Option<(u64, u8, Arc<Vec<DLine>>)>,
}

impl VisState {
    pub fn new() -> Self {
        VisState { cg_zoom: 1.0, map_zoom: 1.0, cg_depth: 1, lang: Some(Lang::C), ..Default::default() }
    }
}

fn human(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{:.1} MB", n as f64 / 1048576.0)
    } else if n >= 1 << 10 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn card(ui: &mut egui::Ui, p: &Palette, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(p.panel)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title.to_uppercase()).small().strong().color(p.muted));
            ui.add_space(6.0);
            add(ui);
        });
    ui.add_space(10.0);
}

fn kv(ui: &mut egui::Ui, p: &Palette, k: &str, v: &str) {
    ui.horizontal_top(|ui| {
        ui.add_sized([118.0, 18.0], egui::Label::new(RichText::new(k).color(p.muted)));
        ui.add(egui::Label::new(RichText::new(v)).wrap());
    });
}

fn pill(ui: &mut egui::Ui, text: &str, fg: Color32, bg: Color32) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(text.to_string(), FontId::proportional(12.5), fg);
    let (rect, resp) = ui.allocate_exact_size(galley.size() + vec2(16.0, 8.0), Sense::hover());
    ui.painter().rect_filled(rect, 11.0, bg);
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, fg);
    resp
}

fn bar(ui: &mut egui::Ui, p: &Palette, frac: f32, col: Color32, w: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(w, 8.0), Sense::hover());
    ui.painter().rect_filled(rect, 4.0, p.panel_alt);
    let mut r = rect;
    r.set_width(rect.width() * frac.clamp(0.0, 1.0));
    ui.painter().rect_filled(r, 4.0, col);
}

/// Colour that grows warmer with a 0–1 value (used by charts).
fn heat(p: &Palette, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let (a, b) = (p.nav_code, p.nav_unexplored);
    let (c, d) = (b, p.edge_not);
    let lerp = |x: Color32, y: Color32, k: f32| {
        Color32::from_rgb(
            (x.r() as f32 + (y.r() as f32 - x.r() as f32) * k) as u8,
            (x.g() as f32 + (y.g() as f32 - x.g() as f32) * k) as u8,
            (x.b() as f32 + (y.b() as f32 - x.b() as f32) * k) as u8,
        )
    };
    if t < 0.5 {
        lerp(a, c, t * 2.0)
    } else {
        lerp(c, d, (t - 0.5) * 2.0)
    }
}

// ------------------------------------------------------------------ overview charts

fn section_map(ui: &mut egui::Ui, p: &Palette, bin: &Binary, acts: &mut Vec<Action>) {
    let total: u64 = bin.segments.iter().map(|s| s.size.max(1)).sum::<u64>().max(1);
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(vec2(w, 46.0), Sense::hover());
    let painter = ui.painter_at(rect);
    let mut x = rect.left();
    let min_w = 6.0;
    let scale = (w - min_w * bin.segments.len() as f32).max(10.0) / total as f32;
    for (i, s) in bin.segments.iter().enumerate() {
        let sw = min_w + s.size as f32 * scale;
        let r = Rect::from_min_size(pos2(x, rect.top()), vec2((sw - 2.0).max(2.0), rect.height()));
        let col = if s.exec {
            p.nav_code
        } else if s.write {
            p.nav_unexplored
        } else {
            p.nav_string
        };
        painter.rect_filled(r, 4.0, col);
        if r.width() > 46.0 {
            let name = s.name.rsplit(',').next().unwrap_or(&s.name);
            painter.with_clip_rect(r).text(r.left_top() + vec2(5.0, 4.0), Align2::LEFT_TOP, name, FontId::monospace(11.0), Color32::WHITE);
            painter.with_clip_rect(r).text(r.left_bottom() + vec2(5.0, -4.0), Align2::LEFT_BOTTOM, human(s.size), FontId::proportional(10.5), Color32::WHITE);
        }
        let id = ui.scope_id().with(("seg", i));
        let resp = ui.interact(r, id, Sense::click());
        if resp.hovered() {
            painter.rect_stroke(r, 4.0, Stroke::new(2.0, p.text), StrokeKind::Inside);
        }
        if resp
            .on_hover_text(format!("{}\n{:X}–{:X}  ({})\n{}", s.name, s.start, s.end(), human(s.size), if s.exec { "code" } else if s.write { "writable data" } else { "read-only data" }))
            .clicked()
        {
            acts.push(Action::Goto(s.start));
        }
        x += sw;
    }
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        for (c, t) in [(p.nav_code, "code"), (p.nav_unexplored, "writable data"), (p.nav_string, "read-only data")] {
            let (r, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
            ui.painter().rect_filled(r, 2.0, c);
            ui.label(RichText::new(t).small().color(p.muted));
        }
    });
}

fn entropy_chart(ui: &mut egui::Ui, p: &Palette, det: &Detection) {
    let w = ui.available_width();
    let h = 90.0;
    let (rect, resp) = ui.allocate_exact_size(vec2(w, h), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 6.0, p.panel_alt);
    let n = det.entropy.len().max(1);
    let bw = rect.width() / n as f32;
    for (i, e) in det.entropy.iter().enumerate() {
        let t = (e / 8.0).clamp(0.0, 1.0);
        let col = if *e > 7.2 { p.edge_not } else if *e > 6.0 { p.nav_unexplored } else { p.nav_code };
        let r = Rect::from_min_max(pos2(rect.left() + i as f32 * bw, rect.bottom() - t * (h - 4.0) - 2.0), pos2(rect.left() + (i as f32 + 1.0) * bw + 0.5, rect.bottom() - 2.0));
        painter.rect_filled(r, 0.0, col);
    }
    let y72 = rect.bottom() - 0.9 * (h - 4.0) - 2.0;
    let mut x = rect.left();
    while x < rect.right() {
        painter.line_segment([pos2(x, y72), pos2((x + 4.0).min(rect.right()), y72)], Stroke::new(1.0, p.faint));
        x += 8.0;
    }
    painter.text(pos2(rect.right() - 4.0, y72 - 2.0), Align2::RIGHT_BOTTOM, "7.2 = likely packed", FontId::proportional(10.0), p.muted);
    if let Some(m) = resp.hover_pos() {
        let i = (((m.x - rect.left()) / bw) as usize).min(n - 1);
        if let Some(e) = det.entropy.get(i) {
            resp.on_hover_text(format!("{:.0}% into the file · entropy {:.2} of 8", i as f32 / n as f32 * 100.0, e));
        }
    }
}

fn import_bars(ui: &mut egui::Ui, p: &Palette, bin: &Binary) {
    let mut by: HashMap<String, usize> = HashMap::new();
    for im in &bin.imports {
        let k = crate::views::short_lib(&im.library);
        *by.entry(if k.is_empty() { "(unknown)".into() } else { k }).or_default() += 1;
    }
    let mut v: Vec<(String, usize)> = by.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let max = v.first().map(|x| x.1).unwrap_or(1).max(1) as f32;
    if v.is_empty() {
        ui.label(RichText::new("No imported functions.").color(p.faint));
    }
    let w = ui.available_width();
    for (name, n) in v.iter().take(10) {
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(vec2(150.0, 16.0), Sense::hover());
            ui.painter().with_clip_rect(r).text(r.left_center(), Align2::LEFT_CENTER, name, FontId::proportional(12.5), p.text);
            bar(ui, p, *n as f32 / max, p.nav_import, (w - 215.0).max(40.0));
            ui.label(RichText::new(n.to_string()).small().color(p.muted));
        });
    }
    if v.len() > 10 {
        ui.label(RichText::new(format!("+ {} more libraries", v.len() - 10)).small().color(p.faint));
    }
}

fn function_size_chart(ui: &mut egui::Ui, p: &Palette, l: &Loaded, acts: &mut Vec<Action>) {
    let mut fs: Vec<(u64, u64)> = l.an.functions.values().filter(|f| f.kind == FuncKind::Normal).map(|f| (f.start, f.size())).collect();
    fs.sort_by(|a, b| b.1.cmp(&a.1));
    let max = fs.first().map(|x| x.1).unwrap_or(1).max(1) as f32;
    let w = ui.available_width();
    for (a, sz) in fs.iter().take(8) {
        let name = l.name(*a).map(display_symbol).unwrap_or_default();
        ui.horizontal(|ui| {
            let (r, resp) = ui.allocate_exact_size(vec2(190.0, 16.0), Sense::click());
            ui.painter().with_clip_rect(r).text(r.left_center(), Align2::LEFT_CENTER, &name, FontId::monospace(12.0), p.func_name);
            if resp.on_hover_text(format!("{name} at {a:X}")).clicked() {
                acts.push(Action::Goto(*a));
            }
            bar(ui, p, *sz as f32 / max, p.nav_code, (w - 255.0).max(40.0));
            ui.label(RichText::new(human(*sz)).small().color(p.muted));
        });
    }
}

impl LensApp {
    // ------------------------------------------------------------------ overview
    pub fn overview(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let project = self.project.clone();
        let project_path = self.project_path.clone();
        let State::Ready(l) = &self.state else { return };
        let det = &l.det;
        let bin = &l.bin;
        let mut acts: Vec<Action> = vec![];
        let has_main = det.main.is_some();
        ScrollArea::vertical().auto_shrink(false).id_salt("overview").show(ui, |ui| {
            egui::Frame::NONE.inner_margin(Margin { left: 20, right: 20, top: 14, bottom: 20 }).show(ui, |ui| {
                // headline
                ui.label(RichText::new(&bin.file_name).size(22.0).strong());
                let comp = det.compiler();
                ui.label(
                    RichText::new(format!("{}  ·  {}  ·  {}-bit {}  ·  {}  ·  {}", det.kind, det.os, det.bits, det.arch, comp, det.language()))
                        .color(p.muted),
                );
                for c in &det.container {
                    ui.label(RichText::new(c).small().color(p.faint));
                }
                ui.add_space(10.0);
                if let Some(note) = &det.unsupported_note {
                    egui::Frame::new()
                        .fill(p.selection)
                        .corner_radius(CornerRadius::same(8))
                        .inner_margin(Margin::same(12))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(note).color(p.text));
                        });
                    ui.add_space(10.0);
                }
                ui.horizontal(|ui| {
                    let go = egui::Button::new(RichText::new("Open pseudocode of main").color(Color32::WHITE).strong()).fill(p.accent).min_size(vec2(200.0, 32.0));
                    if ui.add_enabled(has_main, go).on_hover_text("F5").clicked() {
                        if let Some((a, _)) = &det.main {
                            acts.push(Action::Goto(*a));
                            acts.push(Action::SetView(View::Pseudo));
                        }
                    }
                    if ui.add_sized([150.0, 32.0], egui::Button::new("Disassembly")).clicked() {
                        if let Some((a, _)) = &det.main {
                            acts.push(Action::Goto(*a));
                        }
                        acts.push(Action::SetView(View::Text));
                    }
                    if ui.add_sized([150.0, 32.0], egui::Button::new("Function map")).clicked() {
                        acts.push(Action::SetView(View::Map));
                    }
                });
                if let Some(project) = &project {
                    ui.add_space(10.0);
                    card(ui, &p, &format!("Project · {}", project.name), |ui| {
                        ui.label(RichText::new(format!("{} files", project.files.len())).small().color(p.muted));
                        for file in &project.files {
                            let active = project.active_file.as_deref() == Some(file.as_str()) || project.active_file.as_ref().is_some_and(|active| {
                                let Some(project_path) = &project_path else { return false; };
                                let candidate = Path::new(file);
                                let resolved = if candidate.is_absolute() { candidate.to_path_buf() }
                                    else { project_path.parent().unwrap_or_else(|| Path::new(".")).join(candidate) };
                                resolved.to_string_lossy() == active.as_str()
                            });
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(if active { "●" } else { "○" }).color(if active { p.accent } else { p.faint }));
                                ui.add(egui::Label::new(RichText::new(file).monospace()).truncate());
                                if ui.small_button("Open").clicked() {
                                    let selected = if Path::new(file).is_absolute() {
                                        file.clone()
                                    } else if let Some(project_path) = &project_path {
                                        project_path.parent().unwrap_or_else(|| Path::new(".")).join(file).to_string_lossy().to_string()
                                    } else {
                                        file.clone()
                                    };
                                    acts.push(Action::Open(selected));
                                }
                            });
                        }
                    });
                }
                ui.add_space(14.0);
                let wide = ui.available_width() > 800.0;
                let left_w = if wide { (ui.available_width() * 0.46).floor() } else { ui.available_width() };
                let mut body = |ui: &mut egui::Ui| {
                    ui.vertical(|ui| {
                        ui.set_width(left_w);
                        card(ui, &p, "What Lens decided", |ui| {
                            for (i, s) in det.plan.iter().enumerate() {
                                ui.horizontal_top(|ui| {
                                    ui.label(RichText::new(format!("{}", i + 1)).color(p.accent).strong());
                                    ui.add(egui::Label::new(RichText::new(s)).wrap());
                                });
                                ui.add_space(2.0);
                            }
                        });
                        card(ui, &p, "Toolchain", |ui| {
                            let rows: Vec<(&str, &Vec<crate::detect::Guess>)> = vec![("Compiler", &det.compilers), ("Language", &det.languages)];
                            for (label, list) in rows {
                                ui.label(RichText::new(label).small().color(p.faint));
                                for g in list.iter().take(4) {
                                    ui.horizontal(|ui| {
                                        let col = if g.score > 0.7 { p.edge_taken } else if g.score > 0.4 { p.nav_unexplored } else { p.faint };
                                        bar(ui, &p, g.score, col, 70.0);
                                        ui.label(RichText::new(format!("{:.0}%", g.score * 100.0)).small().color(p.muted));
                                        ui.add(egui::Label::new(RichText::new(&g.name).strong()).truncate()).on_hover_text(g.why.join("\n"));
                                    });
                                }
                                ui.add_space(4.0);
                            }
                            ui.label(RichText::new("Packer / protector").small().color(p.faint));
                            if det.packers.is_empty() {
                                ui.label(RichText::new("None found").color(p.edge_taken));
                            }
                            for g in &det.packers {
                                ui.label(RichText::new(format!("{} ({:.0}%)", g.name, g.score * 100.0)).color(p.edge_not)).on_hover_text(g.why.join("\n"));
                            }
                            ui.add_space(6.0);
                            kv(ui, &p, "Calling convention", det.conv.label());
                            kv(ui, &p, "Symbols", if det.stripped { "stripped (names are guessed)" } else { "present" });
                            kv(ui, &p, "Debug info", if det.has_debug_info { "present" } else { "none" });
                        });
                        if !det.app_info.is_empty() {
                            card(ui, &p, "App bundle", |ui| {
                                for (k, v) in &det.app_info {
                                    kv(ui, &p, k, v);
                                }
                            });
                        }
                        card(ui, &p, "Source code", |ui| {
                            let top = det.language();
                            let native = !(top.starts_with(".NET") || top.starts_with("JavaScript") || top.starts_with("Python"));
                            for g in det.languages.iter().take(3) {
                                ui.label(RichText::new(format!("{} ({:.0}%)", g.name, g.score * 100.0)).strong());
                            }
                            ui.add_space(4.0);
                            if let Some(a) = &det.asar {
                                ui.add(egui::Label::new(RichText::new(format!(
                                    "The original JavaScript is inside app.asar: {} files, {} of them scripts. It can be written out exactly as the authors wrote it.",
                                    a.files, a.js_files
                                ))).wrap());
                                if ui.button("Extract the JavaScript source…").clicked() {
                                    acts.push(Action::ExtractAsar);
                                }
                            } else if top.starts_with(".NET") {
                                ui.add(egui::Label::new(RichText::new("Managed code keeps its structure, so real C# can be recovered. Lens doesn't read .NET intermediate language; open this file in ILSpy or dnSpy.")).wrap());
                            } else if top.starts_with("Python") {
                                ui.add(egui::Label::new(RichText::new("Python programs keep their bytecode. Unpack it with pyinstxtractor, then decompile the .pyc files.")).wrap());
                            }
                            if native && det.unsupported_note.is_none() {
                                ui.add(egui::Label::new(RichText::new(format!(
                                    "This is compiled machine code. The {} source is not stored in it and can't be recovered. Lens instead writes what each function does, in the language you pick:",
                                    if top.contains("Rust") || top.contains("Go") || top.contains("Swift") || top.contains("C++") { top.to_string() } else { "original".to_string() }
                                ))).wrap());
                                ui.horizontal_wrapped(|ui| {
                                    for lgx in Lang::all() {
                                        if ui.button(format!("As {}", lgx.label())).clicked() {
                                            acts.push(Action::SetLang(lgx));
                                            if let Some((a, _)) = &det.main {
                                                acts.push(Action::Goto(*a));
                                            }
                                            acts.push(Action::SetView(View::Pseudo));
                                        }
                                    }
                                });
                                ui.label(RichText::new(if det.stripped { "No symbols: function names are guessed." } else { "Symbols present: original function names are kept." }).small().color(p.faint));
                            }
                        });
                        card(ui, &p, "Protections", |ui| {
                            ui.horizontal_wrapped(|ui| {
                                for (n, on) in &det.protections {
                                    let (fg, bg) = if *on { (p.edge_taken, p.accent_soft) } else { (p.muted, p.panel_alt) };
                                    pill(ui, &format!("{}  {n}", if *on { "ON" } else { "off" }), fg, bg);
                                }
                            });
                        });
                        if !det.capabilities.is_empty() {
                            card(ui, &p, "What it can do (from its imports)", |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    for c in &det.capabilities {
                                        let t = format!("{} · {}", c.name, c.apis.len());
                                        let risky = matches!(c.name, "Memory tricks" | "Anti-debugging" | "Keyboard & screen capture");
                                        pill(ui, &t, if risky { p.edge_not } else { p.text }, p.panel_alt).on_hover_text(c.apis.join("\n"));
                                    }
                                });
                            });
                        }
                    });
                    ui.add_space(12.0);
                    {
                        ui.vertical(|ui| {
                            card(ui, &p, "File", |ui| {
                                kv(ui, &p, "Size", &human(bin.file_size));
                                kv(ui, &p, "Format", &bin.format);
                                kv(ui, &p, "Entry point", &bin.entry.map(|e| format!("{e:X}")).unwrap_or("none".into()));
                                if let Some((a, how)) = &det.main {
                                    kv(ui, &p, "main", &format!("{a:X}  ({how})"));
                                }
                                if let Some(t) = det.timestamp {
                                    kv(ui, &p, "Built (stamp)", &format_unix(t));
                                }
                                kv(ui, &p, "Entropy", &format!("{:.2} of 8", det.overall_entropy));
                                kv(ui, &p, "SHA-256", &det.sha256);
                                kv(ui, &p, "Found", &l.an.stats);
                            });
                            card(ui, &p, "Where things are (sections)", |ui| section_map(ui, &p, bin, &mut acts));
                            card(ui, &p, "Randomness across the file", |ui| entropy_chart(ui, &p, det));
                            card(ui, &p, "Imports by library", |ui| import_bars(ui, &p, bin));
                            card(ui, &p, "Biggest functions", |ui| function_size_chart(ui, &p, l, &mut acts));
                        });
                    }
                };
                if wide {
                    ui.horizontal_top(|ui| body(ui));
                } else {
                    ui.vertical(|ui| body(ui));
                }
            });
        });
        self.actions.extend(acts);
    }

    // ------------------------------------------------------------------ pseudocode
    pub fn pseudo_for(&mut self) -> Option<(u64, Arc<Decompiled>)> {
        let cursor = self.nav.cursor;
        let State::Ready(l) = &mut self.state else { return None };
        let fs = l.an.function_containing(cursor).map(|f| f.start)?;
        if let Some(d) = l.pseudo.get(&fs) {
            return Some((fs, d.clone()));
        }
        let f = l.an.functions.get(&fs)?.clone();
        let note = format!("{}  ·  {}", l.det.compiler(), l.det.conv.label());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decomp::decompile_with_types(&l.bin, &l.an, &l.names, &f, l.det.conv, &note, &l.ann.structs)));
        let mut dec = r.unwrap_or_else(|_| Decompiled {
            lines: vec![DLine { text: "// The decompiler failed on this function. The listing and graph still work.".into(), addr: f.start, indent: 0 }],
        });
        let prefix = format!("{fs:X}:");
        for (k, v) in &l.ann.vars {
            if let Some(old) = k.strip_prefix(&prefix) {
                for line in dec.lines.iter_mut() {
                    line.text = crate::protos::replace_word(&line.text, old, v);
                }
            }
        }
        let d = Arc::new(dec);
        l.pseudo.insert(fs, d.clone());
        Some((fs, d))
    }

    pub fn pseudo_view(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let cw = self.char_w;
        let unsupported = self.loaded().map(|l| l.bin.arch == crate::loader::Arch::Other).unwrap_or(true);
        if unsupported {
            ui.centered_and_justified(|ui| ui.label(RichText::new("Pseudocode needs a CPU Lens can decode.").color(p.muted)));
            return;
        }
        let Some((fs, d)) = self.pseudo_for() else {
            ui.centered_and_justified(|ui| ui.label(RichText::new("Move the cursor into a function to see its pseudocode.").color(p.muted)));
            return;
        };
        if self.vis.pseudo_for != fs {
            self.vis.pseudo_for = fs;
            self.vis.pseudo_scroll = None;
        }
        let cursor = self.nav.cursor;
        let lg = self.vis.lang.unwrap_or(Lang::C);
        let lines: Arc<Vec<DLine>> = match &self.vis.lang_cache {
            Some((f, li, ls)) if *f == fs && *li == lg.index() => ls.clone(),
            _ => {
                let ls = Arc::new(lang::render(&d, lg));
                self.vis.lang_cache = Some((fs, lg.index(), ls.clone()));
                ls
            }
        };
        // line that matches the cursor best
        let cur_line = lines
            .iter()
            .enumerate()
            .filter(|(_, ln)| ln.addr <= cursor && ln.indent > 0)
            .max_by_key(|(_, ln)| ln.addr)
            .map(|(i, _)| i);
        let mut acts: Vec<Action> = vec![];
        let State::Ready(l) = &self.state else { return };
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(RichText::new("Show as").color(p.muted));
            for lgx in Lang::all() {
                if ui.add(egui::Button::selectable(lg == lgx, lgx.label())).clicked() {
                    acts.push(Action::SetLang(lgx));
                }
            }
            ui.add_space(8.0);
            if ui.button("Copy").on_hover_text("Copy this function").clicked() {
                ui.ctx().copy_text(lang::render_text(&lines));
            }
            if ui.button(format!("Export all as .{}…", lg.ext())).on_hover_text("Write every function to one file").clicked() {
                acts.push(Action::ExportC);
            }
        });
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(RichText::new(format!("{}  Double-click a variable to rename it.", lang::caveat(lg))).small().color(p.faint));
        });
        ui.add(egui::Separator::default().spacing(2.0));
        let font = FontId::monospace(13.5);
        let row_h = 19.0;
        let mut sa = ScrollArea::both().auto_shrink(false).id_salt("pseudo");
        if self.vis.pseudo_scroll.is_none() {
            if let Some(c) = cur_line {
                sa = sa.vertical_scroll_offset((c as f32 - 6.0).max(0.0) * row_h);
            }
            self.vis.pseudo_scroll = Some(0);
        }
        let n = lines.len();
        let name_index = &l.name_index;
        let mut select: Option<u64> = None;
        let mut goto: Option<u64> = None;
        let mut rename_var: Option<String> = None;
        ui.spacing_mut().item_spacing.y = 0.0;
        sa.show_rows(ui, row_h, n, |ui, range| {
            for i in range {
                let ln = &lines[i];
                let w = ui.available_width().max(1400.0);
                let (rect, resp) = ui.allocate_exact_size(vec2(w, row_h), Sense::click());
                let painter = ui.painter_at(rect);
                if Some(i) == cur_line {
                    painter.rect_filled(rect, 0.0, p.selection);
                } else if resp.hovered() {
                    painter.rect_filled(rect, 0.0, p.hover_row);
                }
                let x0 = rect.left() + 16.0 + ln.indent as f32 * 4.0 * cw;
                if ln.indent > 0 && ln.addr != 0 {
                    painter.text(pos2(rect.left() + 6.0, rect.center().y), Align2::LEFT_CENTER, "", font.clone(), p.faint);
                }
                let mut hit_name: Option<(Rect, u64)> = None;
                let mut hit_var: Option<String> = None;
                let mut xref_hit = false;
                for (tx, kind, text) in tokenize(&ln.text) {
                    let col = match kind {
                        Tok2::Keyword => p.keyword,
                        Tok2::Type => p.register,
                        Tok2::Number => p.number,
                        Tok2::Str => p.string,
                        Tok2::Comment => p.auto_comment,
                        Tok2::Label => p.label_name,
                        Tok2::Ident => p.text,
                        Tok2::Punct => p.punct,
                    };
                    let pos = pos2(x0 + tx as f32 * cw, rect.center().y);
                    let (col, target) = if kind == Tok2::Ident {
                        match name_index.get(&text) {
                            Some(a) => (p.func_name, Some(*a)),
                            None if text.starts_with("sub_") => (p.func_name, parse_hex_suffix(&text)),
                            None => (col, None),
                        }
                    } else {
                        (col, None)
                    };
                    let r = painter.text(pos, Align2::LEFT_CENTER, &text, font.clone(), col);
                    if kind == Tok2::Ident && target.is_none() {
                        if let Some(h) = resp.hover_pos() {
                            if r.contains(h) { hit_var = Some(text.clone()); }
                        }
                    }
                    if let Some(a) = target {
                        if let Some(h) = resp.hover_pos() {
                            if r.contains(h) {
                                hit_name = Some((r, a));
                            }
                        }
                    }
                }
                if let Some(v) = hit_var {
                    if resp.double_clicked() { rename_var = Some(v); }
                }
                if ln.indent > 0 && ln.addr != 0 {
                    if let Some(refs) = l.an.xrefs_to.get(&ln.addr).filter(|refs| !refs.is_empty()) {
                        let label = format!("×{}", refs.len());
                        let marker = painter.text(pos2(rect.left() + 2.0, rect.center().y), Align2::LEFT_CENTER, label, FontId::monospace(11.5), p.xref);
                        if resp.hover_pos().map(|h| marker.contains(h)).unwrap_or(false) {
                            xref_hit = true;
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                    }
                }
                if let Some((r, a)) = hit_name {
                    painter.line_segment([r.left_bottom(), r.right_bottom()], Stroke::new(1.0, p.func_name));
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    if resp.clicked() {
                        goto = Some(a);
                    }
                } else if xref_hit && resp.clicked() {
                    acts.push(Action::Xrefs(ln.addr));
                } else if resp.clicked() && ln.addr != 0 {
                    select = Some(ln.addr);
                }
                if ln.indent > 0 && ln.addr != 0 && resp.hovered() {
                    painter.text(pos2(rect.right() - 12.0, rect.center().y), Align2::RIGHT_CENTER, format!("{:X}", ln.addr), FontId::monospace(11.5), p.address);
                }
            }
        });
        if let Some(v) = rename_var {
            acts.push(Action::RenameVar(fs, v));
        } else if let Some(a) = goto {
            acts.push(Action::Goto(a));
        } else if let Some(a) = select {
            let line = l.an.line_of(a);
            acts.push(Action::Select(a, line));
        }
        self.actions.extend(acts);
    }

    // ------------------------------------------------------------------ call graph
    pub fn calls_view(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let cursor = self.nav.cursor;
        let State::Ready(l) = &self.state else { return };
        let Some(fs) = l.an.function_containing(cursor).map(|f| f.start) else {
            ui.centered_and_justified(|ui| ui.label(RichText::new("Move the cursor into a function to see who calls it and what it calls.").color(p.muted)));
            return;
        };
        let vis = &mut self.vis;
        if vis.cg_for != fs {
            vis.cg_for = fs;
            vis.cg_pan = Vec2::ZERO;
            vis.cg_zoom = 1.0;
            vis.cg_cache = None;
        }
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(RichText::new("How far to look").color(p.muted));
            for d in 1..=3usize {
                if ui.add(egui::Button::selectable(vis.cg_depth == d, d.to_string())).clicked() {
                    vis.cg_depth = d;
                    vis.cg_pan = Vec2::ZERO;
                    vis.cg_zoom = 1.0;
                    vis.cg_cache = None;
                }
            }
            ui.add_space(10.0);
            ui.label(RichText::new("callers (left)  ->  this function  ->  callees (right)").small().color(p.faint));
        });
        if vis.cg_cache.as_ref().map(|(cached_for, cached_depth, cached_version, _, _)| (*cached_for, *cached_depth, *cached_version)) != Some((fs, vis.cg_depth, l.version)) {
            let (nodes, edges) = build_callgraph(l, fs, vis.cg_depth);
            vis.cg_cache = Some((fs, vis.cg_depth, l.version, nodes, edges));
        }
        let Some((_, _, _, nodes, edges)) = vis.cg_cache.as_ref() else {
            ui.centered_and_justified(|ui| ui.label(RichText::new("Call graph is still preparing…").color(p.muted)));
            return;
        };
        if nodes.len() >= CALL_GRAPH_MAX_NODES {
            ui.label(RichText::new("large graph truncated for responsiveness").small().color(p.nav_unexplored));
        }
        if edges.len() >= CALL_GRAPH_MAX_EDGES {
            ui.label(RichText::new("edge limit reached; some relationships are hidden").small().color(p.nav_unexplored));
        }
        let (resp, painter) = ui.allocate_painter(ui.available_size(), Sense::click_and_drag());
        let area = resp.rect;
        painter.rect_filled(area, 0.0, p.panel_alt);
        if resp.dragged() {
            vis.cg_pan += resp.drag_delta();
            vis.cg_pan.x = vis.cg_pan.x.clamp(-20000.0, 20000.0);
            vis.cg_pan.y = vis.cg_pan.y.clamp(-20000.0, 20000.0);
        }
        if resp.hovered() {
            let (scroll, zoom_d, cmd) = ui.input(|i| (i.smooth_scroll_delta, i.zoom_delta(), i.modifiers.command));
            if (zoom_d - 1.0).abs() > 1e-4 || (cmd && scroll.y != 0.0) {
                let f = if (zoom_d - 1.0).abs() > 1e-4 { zoom_d } else { (scroll.y * 0.003).exp() };
                let old = vis.cg_zoom;
                vis.cg_zoom = (vis.cg_zoom * f).clamp(0.25, 2.5);
                if !vis.cg_zoom.is_finite() { vis.cg_zoom = 1.0; }
                if let Some(mp) = resp.hover_pos() {
                    let rel = mp - (area.center() + vis.cg_pan);
                    vis.cg_pan += rel - rel * (vis.cg_zoom / old);
                }
            } else {
                vis.cg_pan += scroll.clamp(vec2(-1200.0, -1200.0), vec2(1200.0, 1200.0));
            }
        }
        if !vis.cg_pan.x.is_finite() || !vis.cg_pan.y.is_finite() { vis.cg_pan = Vec2::ZERO; }
        let z = vis.cg_zoom;
        let origin = area.center() + vis.cg_pan;
        let (nw, nh) = (214.0f32, 40.0f32);
        let rect_of = |n: &CNode| Rect::from_min_size(origin + vec2(n.layer as f32 * 280.0 - nw / 2.0, n.y - nh / 2.0) * z, vec2(nw, nh) * z);
        let hover = resp.hover_pos();
        let hovered = nodes.iter().position(|n| hover.map(|h| rect_of(n).contains(h)).unwrap_or(false));
        // edges
        for (a, b) in edges {
            if *a >= nodes.len() || *b >= nodes.len() { continue; }
            let (ra, rb) = (rect_of(&nodes[*a]), rect_of(&nodes[*b]));
            let (s, e) = (pos2(ra.right(), ra.center().y), pos2(rb.left(), rb.center().y));
            let hot = hovered == Some(*a) || hovered == Some(*b);
            let col = if hot { p.accent } else { p.faint.gamma_multiply(0.7) };
            let dx = ((e.x - s.x).abs() * 0.5).max(40.0 * z);
            let (c1, c2) = (s + vec2(dx, 0.0), e - vec2(dx, 0.0));
            let pts: Vec<Pos2> = (0..=12)
                .map(|i| {
                    let t = i as f32 / 12.0;
                    let u = 1.0 - t;
                    pos2(
                        u * u * u * s.x + 3.0 * u * u * t * c1.x + 3.0 * u * t * t * c2.x + t * t * t * e.x,
                        u * u * u * s.y + 3.0 * u * u * t * c1.y + 3.0 * u * t * t * c2.y + t * t * t * e.y,
                    )
                })
                .collect();
            painter.add(Shape::line(pts, Stroke::new(if hot { 2.0 } else { 1.2 }, col)));
            let tangent = e - c2;
            let dir = if tangent.length_sq() > f32::EPSILON { tangent.normalized() } else { vec2(1.0, 0.0) };
            let sz = 7.0 * z.max(0.6);
            let nrm = vec2(-dir.y, dir.x);
            painter.add(Shape::convex_polygon(vec![e, e - dir * sz + nrm * sz * 0.5, e - dir * sz - nrm * sz * 0.5], col, Stroke::NONE));
        }
        // nodes
        let mut goto = None;
        for (i, n) in nodes.iter().enumerate() {
            let r = rect_of(n);
            if !r.intersects(area) {
                continue;
            }
            let is_import = n.import;
            let border = if n.layer == 0 { p.accent } else if is_import { p.import_name } else { p.block_border };
            painter.rect(r, 8.0 * z, if n.layer == 0 { p.accent_soft } else { p.block_bg }, Stroke::new(if n.layer == 0 || hovered == Some(i) { 2.0 } else { 1.0 }, border), StrokeKind::Inside);
            let fcol = if is_import { p.import_name } else { p.func_name };
            let name = trunc(&n.name, 27);
            painter.text(r.left_top() + vec2(9.0, 6.0) * z, Align2::LEFT_TOP, name, FontId::monospace(12.5 * z), fcol);
            painter.text(r.left_bottom() + vec2(9.0, -5.0) * z, Align2::LEFT_BOTTOM, &n.sub, FontId::proportional(10.5 * z), p.muted);
            if n.noreturn {
                painter.text(r.right_top() + vec2(-8.0, 6.0) * z, Align2::RIGHT_TOP, "no return", FontId::proportional(9.5 * z), p.edge_not);
            }
        }
        if let Some(i) = hovered {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            let n = &nodes[i];
            if resp.clicked() {
                goto = Some(n.addr);
            }
            resp.on_hover_text(format!("{}  ({:X})\nClick to centre the graph here.", n.name, n.addr));
        }
        painter.text(area.left_bottom() + vec2(12.0, -10.0), Align2::LEFT_BOTTOM, "Drag to move · Ctrl/Cmd + scroll to zoom · click a box to centre it", FontId::proportional(11.5), p.faint);
        if let Some(a) = goto {
            if l.an.functions.contains_key(&a) {
                self.actions.push(Action::Goto(a));
            }
        }
    }

    // ------------------------------------------------------------------ map (treemap)
    pub fn map_view(&mut self, ui: &mut egui::Ui) {
        let p = self.p;
        let State::Ready(l) = &self.state else { return };
        let mut zoom_btn = 1.0f32;
        let mode_ref = &mut self.vis.map_mode;
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            let mode = mode_ref;
            ui.label(RichText::new("Every function, sized by its code. Colour shows").color(p.muted));
            for (m, t) in [(0u8, "how often it's called"), (1, "how branchy it is"), (2, "named vs guessed")] {
                if ui.add(egui::Button::selectable(*mode == m, t)).clicked() {
                    *mode = m;
                }
            }
            ui.add_space(16.0);
            if ui.button("−").on_hover_text("Zoom out").clicked() { zoom_btn = 0.7; }
            if ui.button("+").on_hover_text("Zoom in").clicked() { zoom_btn = 1.4; }
            if ui.button("Fit").on_hover_text("Show everything").clicked() { zoom_btn = 0.0; }
        });
        let (resp, painter) = ui.allocate_painter(ui.available_size(), Sense::click_and_drag());
        let area = resp.rect.shrink(8.0);
        let full = resp.rect;
        painter.rect_filled(full, 0.0, p.panel_alt);
        let painter = painter.with_clip_rect(full);
        // pan and zoom: drag or scroll to move, Cmd/Ctrl + scroll or pinch to zoom
        let vis = &mut self.vis;
        if resp.dragged() {
            vis.map_pan += resp.drag_delta();
        }
        if resp.hovered() {
            // scrolling zooms toward the pointer; holding Shift scrolls sideways instead
            let (scroll, zoom_d, shift) = ui.input(|i| (i.smooth_scroll_delta, i.zoom_delta(), i.modifiers.shift));
            let f = if (zoom_d - 1.0).abs() > 1e-4 { zoom_d } else if !shift && scroll.y != 0.0 { (scroll.y * 0.004).exp() } else { 1.0 };
            if f != 1.0 {
                let old = vis.map_zoom;
                vis.map_zoom = (vis.map_zoom * f).clamp(1.0, 60.0);
                if let Some(mp) = resp.hover_pos() {
                    let rel = mp - (area.center() + vis.map_pan);
                    vis.map_pan += rel - rel * (vis.map_zoom / old);
                }
            } else if shift {
                vis.map_pan += vec2(scroll.x + scroll.y, 0.0);
            } else {
                vis.map_pan += vec2(scroll.x, 0.0);
            }
        }
        if zoom_btn == 0.0 {
            vis.map_zoom = 1.0;
            vis.map_pan = Vec2::ZERO;
        } else if zoom_btn != 1.0 {
            vis.map_zoom = (vis.map_zoom * zoom_btn).clamp(1.0, 60.0);
        }
        if vis.map_zoom <= 1.0 {
            vis.map_pan = Vec2::ZERO;
        }
        if vis.map_zoom <= 1.0 {
            vis.map_pan = Vec2::ZERO;
        } else {
            let lim = vec2(area.width(), area.height()) * 0.5 * vis.map_zoom;
            vis.map_pan = vec2(vis.map_pan.x.clamp(-lim.x, lim.x), vis.map_pan.y.clamp(-lim.y, lim.y));
        }
        let (mz, mpan) = (vis.map_zoom, vis.map_pan);
        let ctr = area.center();
        let tf = |r: Rect| Rect::from_min_max(ctr + mpan + (r.min - ctr) * mz, ctr + mpan + (r.max - ctr) * mz);
        let mode = &self.vis.map_mode;
        let mut items: Vec<(u64, f64)> = l
            .an
            .functions
            .values()
            .filter(|f| f.kind == FuncKind::Normal && f.size() > 0)
            .map(|f| (f.start, f.size() as f64))
            .collect();
        if items.is_empty() {
            painter.text(area.center(), Align2::CENTER_CENTER, "No functions to show.", FontId::proportional(15.0), p.muted);
            return;
        }
        items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap().then(a.0.cmp(&b.0)));
        items.truncate(8000);
        let total: f64 = items.iter().map(|i| i.1).sum();
        let scale = (area.width() * area.height()) as f64 / total;
        let norm: Vec<(usize, f64)> = items.iter().enumerate().map(|(i, it)| (i, it.1 * scale)).collect();
        let rects = squarify(&norm, area);
        let max_callers = l.an.xrefs_to.values().map(|v| v.len()).max().unwrap_or(1).max(1) as f32;
        let hover = resp.hover_pos();
        let mut hit: Option<usize> = None;
        for (i, r) in &rects {
            let r = &tf(*r);
            if !r.intersects(full) {
                continue;
            }
            let (addr, _) = items[*i];
            let f = &l.an.functions[&addr];
            let col = match *mode {
                0 => {
                    let c = l.an.xrefs_to.get(&addr).map(|v| v.len()).unwrap_or(0) as f32;
                    heat(&p, (c + 1.0).ln() / (max_callers + 1.0).ln())
                }
                1 => heat(&p, (f.blocks.len() as f32 / 40.0).min(1.0)),
                _ => {
                    if f.has_symbol {
                        p.nav_code
                    } else {
                        p.nav_unexplored
                    }
                }
            };
            let rr = r.shrink(0.6);
            painter.rect_filled(rr, 2.0, col.gamma_multiply(0.85));
            if hover.map(|h| rr.contains(h)).unwrap_or(false) {
                hit = Some(*i);
            }
            if rr.width() > 54.0 && rr.height() > 16.0 {
                let name = l.name(addr).map(display_symbol).unwrap_or_default();
                painter.with_clip_rect(rr).text(rr.left_top() + vec2(4.0, 2.0), Align2::LEFT_TOP, trunc(&name, ((rr.width() / 6.8) as usize).max(4)), FontId::monospace(11.0), Color32::WHITE);
            }
        }
        if let Some(i) = hit {
            let (addr, sz) = items[i];
            let f = &l.an.functions[&addr];
            if let Some((_, r)) = rects.iter().find(|(k, _)| *k == i) {
                painter.rect_stroke(tf(*r).shrink(0.6), 2.0, Stroke::new(2.5, p.text), StrokeKind::Inside);
            }
            let callers = l.an.xrefs_to.get(&addr).map(|v| v.len()).unwrap_or(0);
            let tip = format!(
                "{}\n{:X} · {} bytes · {} blocks · {} instructions\ncalled from {} place(s)\nClick: open · double-click: pseudocode · scroll to zoom · drag to move",
                l.name(addr).map(display_symbol).unwrap_or_default(),
                addr,
                sz as u64,
                f.blocks.len(),
                f.insn_count,
                callers
            );
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            let clicked = resp.clicked();
            let dbl = resp.double_clicked();
            resp.on_hover_text(tip);
            if dbl {
                self.actions.push(Action::Goto(addr));
                self.actions.push(Action::SetView(View::Pseudo));
            } else if clicked {
                self.actions.push(Action::Goto(addr));
            }
        }
    }
}

// ------------------------------------------------------------------ helpers

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>())
    }
}

fn format_unix(t: u64) -> String {
    // civil-from-days, enough for a build stamp
    let days = (t / 86400) as i64;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

fn parse_hex_suffix(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("sub_"), 16).ok()
}

#[derive(PartialEq, Clone, Copy)]
enum Tok2 {
    Keyword,
    Type,
    Number,
    Str,
    Comment,
    Label,
    Ident,
    Punct,
}

/// (column, kind, text) pieces of one pseudocode line.
fn tokenize(s: &str) -> Vec<(usize, Tok2, String)> {
    let cs: Vec<char> = s.chars().collect();
    let mut out = vec![];
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        let start = i;
        if c == ' ' {
            i += 1;
            continue;
        }
        if c == '#' || (c == '/' && cs.get(i + 1) == Some(&'/')) {
            out.push((start, Tok2::Comment, cs[i..].iter().collect()));
            break;
        }
        if c == '"' {
            i += 1;
            while i < cs.len() && cs[i] != '"' {
                if cs[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(cs.len());
            out.push((start, Tok2::Str, cs[start..i].iter().collect()));
            continue;
        }
        if c.is_ascii_digit() {
            while i < cs.len() && (cs[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            out.push((start, Tok2::Number, cs[start..i].iter().collect()));
            continue;
        }
        if c.is_alphabetic() || c == '_' || c == '$' || c == '?' || c == '@' {
            while i < cs.len() && (cs[i].is_alphanumeric() || matches!(cs[i], '_' | '$' | '?' | '@' | '.')
                || (cs[i] == ':' && cs.get(i + 1) == Some(&':') && cs.get(i + 2).map(|c| c.is_alphanumeric() || *c == '_' || *c == '~').unwrap_or(false))
                || (cs[i] == ':' && i > 0 && cs[i - 1] == ':'))
            {
                i += 1;
            }
            let w: String = cs[start..i].iter().collect();
            let kind = if matches!(w.as_str(), "if" | "else" | "while" | "do" | "return" | "goto" | "break" | "continue" | "switch" | "case" | "def" | "fn" | "let" | "mut" | "func" | "var" | "function" | "loop" | "for" | "pass" | "and" | "or" | "not" | "True" | "False" | "true" | "false" | "unsafe" | "as") {
                Tok2::Keyword
            } else if matches!(w.as_str(), "void" | "int8_t" | "int16_t" | "int32_t" | "int64_t" | "uint8_t" | "uint16_t" | "uint32_t" | "uint64_t" | "float" | "double" | "__m128" | "i8" | "i16" | "i32" | "i64" | "u8" | "u16" | "u32" | "u64" | "f32" | "f64" | "int8" | "int16" | "int32" | "int64" | "uint8" | "uint16" | "uint32" | "uint64" | "float32" | "float64") {
                Tok2::Type
            } else if w.starts_with("L_") && cs.get(i) == Some(&':') {
                i += 1;
                out.push((start, Tok2::Label, cs[start..i].iter().collect()));
                continue;
            } else if w.starts_with("L_") {
                Tok2::Label
            } else {
                Tok2::Ident
            };
            out.push((start, kind, w));
            continue;
        }
        i += 1;
        out.push((start, Tok2::Punct, c.to_string()));
    }
    out
}

pub struct CNode {
    pub addr: u64,
    pub layer: i32,
    pub y: f32,
    pub name: String,
    pub sub: String,
    pub import: bool,
    pub noreturn: bool,
}

fn callees_of(l: &Loaded, f: u64) -> Vec<u64> {
    let Some(func) = l.an.functions.get(&f) else { return vec![] };
    if func.kind == FuncKind::Import {
        return vec![];
    }
    // Analysis already canonicalizes direct calls, indirect import-slot calls,
    // and conservative tail-call edges in Function::calls. Reusing that index
    // avoids rescanning thousands of instructions every time the graph opens.
    let mut v: Vec<u64> = func.calls.iter().copied()
        .filter(|target| l.an.functions.contains_key(target))
        .collect();
    // Indirect switch cases have no single instruction target. Walk only this
    // function's instructions and consult the analyzer's indexed switch map;
    // this bounded scan preserves case edges without redoing call discovery.
    for a in func.blocks.iter().flat_map(|b| b.insns.iter().copied()).take(CALL_GRAPH_MAX_INSTRUCTIONS_PER_FUNCTION) {
        if let Some(targets) = l.an.switches.get(&a) {
            v.extend(targets.iter().copied().filter(|target| l.an.functions.contains_key(target)));
        }
    }
    v.sort_unstable();
    v.dedup();
    v
}

fn callers_of(l: &Loaded, f: u64) -> Vec<u64> {
    let mut refs: Vec<_> = l
        .an
        .xrefs_to
        .get(&f)
        .map(|xs| xs.iter().filter(|x| matches!(x.kind, crate::analysis::XrefKind::Call | crate::analysis::XrefKind::Jump)).collect())
        .unwrap_or_default();
    refs.sort_by_key(|x| x.from);
    refs.truncate(CALL_GRAPH_MAX_CALLER_XREFS);
    let mut v: Vec<u64> = refs.into_iter().filter_map(|x| l.an.function_containing(x.from).map(|f| f.start)).filter(|caller| *caller != f).collect();
    v.sort_unstable();
    v.dedup();
    v.truncate(CALL_GRAPH_MAX_NEIGHBORS * 4);
    v
}

pub fn build_callgraph(l: &Loaded, center: u64, depth: usize) -> (Vec<CNode>, Vec<(usize, usize)>) {
    if !l.an.functions.contains_key(&center) {
        return (Vec::new(), Vec::new());
    }
    // Keep the first render bounded even if a future caller supplies an
    // untrusted depth (the UI currently exposes only 1..=3).
    let depth = depth.min(3);
    let mut callees_cache: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut callers_cache: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut cached_callees = |addr: u64| -> Vec<u64> {
        callees_cache.entry(addr).or_insert_with(|| callees_of(l, addr)).clone()
    };
    let mut cached_callers = |addr: u64| -> Vec<u64> {
        callers_cache.entry(addr).or_insert_with(|| callers_of(l, addr)).clone()
    };
    let mk = |addr: u64, layer: i32| -> CNode {
        let f = l.an.functions.get(&addr);
        let name = l.name(addr).map(display_symbol).unwrap_or_else(|| format!("{addr:X}"));
        let import = f.map(|f| f.kind == FuncKind::Import).unwrap_or(true);
        let mut sub = match f {
            Some(f) if f.kind == FuncKind::Normal => format!("{:X} · {} bytes · {} blocks", addr, f.size(), f.blocks.len()),
            Some(_) => "imported function".to_string(),
            None => "imported function".to_string(),
        };
        if let Some(target) = f.and_then(|f| f.thunk_target) {
            let target_name = l.name(target).map(display_symbol).unwrap_or_else(|| format!("{:X}", target));
            sub.push_str(&format!(" · thunk → {target_name}"));
        }
        CNode { addr, layer, y: 0.0, name, sub, import, noreturn: f.map(|f| f.noreturn).unwrap_or(false) }
    };
    let mut nodes = vec![mk(center, 0)];
    let mut idx: HashMap<u64, usize> = HashMap::new();
    idx.insert(center, 0);
    for dir in [1i32, -1] {
        let mut frontier = vec![center];
        for d in 1..=depth as i32 {
            let mut next = vec![];
            for a in &frontier {
                let list = if dir > 0 { cached_callees(*a) } else { cached_callers(*a) };
                for c in list.into_iter().take(CALL_GRAPH_MAX_NEIGHBORS) {
                    if !idx.contains_key(&c) && nodes.len() < CALL_GRAPH_MAX_NODES {
                        idx.insert(c, nodes.len());
                        nodes.push(mk(c, dir * d));
                        next.push(c);
                    }
                }
            }
            frontier = next;
        }
    }
    // edges among the nodes shown
    let mut edges: Vec<(usize, usize)> = vec![];
    let mut seen_edges: HashSet<(usize, usize)> = HashSet::new();
    let addrs: Vec<u64> = nodes.iter().map(|n| n.addr).collect();
    for (i, a) in addrs.iter().enumerate() {
        for c in cached_callees(*a) {
            if let Some(&j) = idx.get(&c) {
                if i != j {
                    if seen_edges.insert((i, j)) && edges.len() < CALL_GRAPH_MAX_EDGES {
                        edges.push((i, j));
                    }
                }
            }
        }
    }
    edges.sort();
    edges.dedup();
    // vertical order: closest layer first by name, then by the average height of neighbours
    let max_layer = depth as i32;
    for layer in 1..=max_layer {
        for dir in [1i32, -1] {
            let lay = dir * layer;
            let mut members: Vec<usize> = (0..nodes.len()).filter(|i| nodes[*i].layer == lay).collect();
            let key = |i: usize, nodes: &Vec<CNode>| -> f32 {
                let ys: Vec<f32> = edges
                    .iter()
                    .filter_map(|(a, b)| if *a == i && nodes[*b].layer == lay - dir && layer > 1 { Some(nodes[*b].y) } else if *b == i && nodes[*a].layer == lay - dir && layer > 1 { Some(nodes[*a].y) } else { None })
                    .collect();
                if ys.is_empty() {
                    0.0
                } else {
                    ys.iter().sum::<f32>() / ys.len() as f32
                }
            };
            if layer == 1 {
                members.sort_by(|a, b| nodes[*a].name.cmp(&nodes[*b].name));
            } else {
                members.sort_by(|a, b| key(*a, &nodes).total_cmp(&key(*b, &nodes)).then(nodes[*a].name.cmp(&nodes[*b].name)));
            }
            let n = members.len() as f32;
            for (k, m) in members.iter().enumerate() {
                nodes[*m].y = (k as f32 - (n - 1.0) / 2.0) * 58.0;
            }
        }
    }
    (nodes, edges)
}

fn squarify(items: &[(usize, f64)], rect: Rect) -> Vec<(usize, Rect)> {
    let mut out = vec![];
    let mut rest = items;
    let mut r = rect;
    let worst = |row: &[(usize, f64)], side: f64| -> f64 {
        let s: f64 = row.iter().map(|x| x.1).sum();
        let mx = row.iter().map(|x| x.1).fold(0.0, f64::max);
        let mn = row.iter().map(|x| x.1).fold(f64::MAX, f64::min);
        ((side * side * mx) / (s * s)).max((s * s) / (side * side * mn))
    };
    while !rest.is_empty() {
        let side = (r.width().min(r.height()) as f64).max(1.0);
        let mut n = 1;
        while n < rest.len() && worst(&rest[..n + 1], side) <= worst(&rest[..n], side) {
            n += 1;
        }
        let row = &rest[..n];
        let s: f64 = row.iter().map(|x| x.1).sum();
        if r.width() >= r.height() {
            let w = (s / r.height() as f64) as f32;
            let mut y = r.top();
            for (id, a) in row {
                let h = (*a / w as f64) as f32;
                out.push((*id, Rect::from_min_size(pos2(r.left(), y), vec2(w, h))));
                y += h;
            }
            r = Rect::from_min_max(pos2(r.left() + w, r.top()), r.max);
        } else {
            let h = (s / r.width() as f64) as f32;
            let mut x = r.left();
            for (id, a) in row {
                let w = (*a / h as f64) as f32;
                out.push((*id, Rect::from_min_size(pos2(x, r.top()), vec2(w, h))));
                x += w;
            }
            r = Rect::from_min_max(pos2(r.left(), r.top() + h), r.max);
        }
        rest = &rest[n..];
        if r.width() < 1.0 || r.height() < 1.0 {
            break;
        }
    }
    let _ = HashSet::<u8>::new();
    out
}

pub fn export_c(l: &Loaded, lg: Lang) -> String {
    let det = &l.det;
    let mut s = String::new();
    let c = lg.comment();
    s.push_str(&format!(
        "{c} Pseudocode ({}) exported by Lens from {}\n{c} {} · {} · {}-bit {}\n{c} toolchain guess: {} · calling convention: {}\n{c} {}\n\n",
        lg.label(), l.bin.file_name, det.kind, det.os, det.bits, det.arch, det.compiler(), det.conv.label(), lang::caveat(lg)
    ));
    for f in l.an.functions.values() {
        if f.kind == FuncKind::Import {
            continue;
        }
        let d = decomp::decompile_with_types(&l.bin, &l.an, &l.names, f, det.conv, "", &l.ann.structs);
        s.push_str(&format!("{c} {:X}\n", f.start));
        s.push_str(&lang::render_text(&lang::render(&d, lg)));
        s.push('\n');
    }
    s
}

#[allow(dead_code)]
fn unused(_: NameKind) {}
