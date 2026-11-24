//! Function flow graph: basic blocks laid out in layers with coloured edges
//! (green = branch taken, red = not taken, blue = always), plus a small overview map.

use crate::analysis::{Analysis, EdgeKind, Function};
use crate::code::{CodeFormatter, Tok, Token};
use crate::loader::Binary;
use crate::theme::Palette;
use eframe::egui::{self, pos2, vec2, Align2, Color32, FontId, Pos2, Rect, Sense, Shape, Stroke, StrokeKind, Vec2};
use std::collections::HashMap;

pub struct GRow {
    pub addr: u64,
    pub toks: Vec<Token>,
    pub label: bool,
    pub chars: usize,
    pub xrefs: usize,
}

pub struct GNode {
    pub start: u64,
    pub rows: Vec<GRow>,
    pub rect: Rect,
}

pub struct GEdge {
    pub kind: EdgeKind,
    pub points: Vec<Pos2>,
}

pub struct Layout {
    pub nodes: Vec<GNode>,
    pub edges: Vec<GEdge>,
    pub bounds: Rect,
}

pub const ROW_H: f32 = 17.0;
pub const CHAR_W: f32 = 7.8;
const PAD: f32 = 10.0;
const HGAP: f32 = 36.0;
const VGAP: f32 = 56.0;

pub fn build(bin: &Binary, an: &Analysis, f: &Function, fmt: &mut CodeFormatter) -> Layout {
    let n = f.blocks.len();
    let idx: HashMap<u64, usize> = f.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
    let succ: Vec<Vec<(usize, EdgeKind)>> = f
        .blocks
        .iter()
        .map(|b| b.succs.iter().filter_map(|(t, k)| idx.get(t).map(|i| (*i, *k))).collect())
        .collect();
    // Rows of text.
    let mut nodes: Vec<GNode> = f
        .blocks
        .iter()
        .map(|b| {
            let mut rows = vec![];
            if let Some((name, _)) = fmt.names().get(&b.start) {
                let name = name.clone();
                if b.start != f.start || true {
                    let t = Token { text: format!("{name}:"), kind: Tok::Name(fmt.names()[&b.start].1), target: None };
                    rows.push(GRow { addr: b.start, chars: t.text.chars().count(), toks: vec![t], label: true, xrefs: an.xrefs_to.get(&b.start).map(Vec::len).unwrap_or(0) });
                }
            }
            for a in &b.insns {
                if let Some((_, toks)) = fmt.format(bin, *a) {
                    let chars = toks.iter().map(|t| t.text.chars().count()).sum();
                rows.push(GRow { addr: *a, toks, label: false, chars, xrefs: an.xrefs_to.get(a).map(Vec::len).unwrap_or(0) });
                }
            }
            let w = rows.iter().map(|r| r.chars).max().unwrap_or(10).clamp(12, 90) as f32 * CHAR_W + PAD * 2.0;
            let h = rows.len().max(1) as f32 * ROW_H + PAD * 1.4;
            GNode { start: b.start, rows, rect: Rect::from_min_size(Pos2::ZERO, vec2(w, h)) }
        })
        .collect();
    let _ = an;
    if n == 0 {
        return Layout { nodes, edges: vec![], bounds: Rect::from_min_size(Pos2::ZERO, vec2(100.0, 100.0)) };
    }

    // DFS order and back edges.
    let mut order = vec![];
    let mut state = vec![0u8; n]; // 0 new, 1 on stack, 2 done
    let mut back = std::collections::HashSet::new();
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    state[0] = 1;
    order.push(0);
    while let Some((v, i)) = stack.pop() {
        if i < succ[v].len() {
            stack.push((v, i + 1));
            let w = succ[v][i].0;
            if state[w] == 0 {
                state[w] = 1;
                order.push(w);
                stack.push((w, 0));
            } else if state[w] == 1 {
                back.insert((v, w));
            }
        } else {
            state[v] = 2;
        }
    }
    for v in 0..n {
        if state[v] == 0 {
            order.push(v);
        }
    }
    // Longest-path layers over forward edges (in DFS order which is a topological order of the DAG
    // after removing back edges, approximately; iterate to a fixed point).
    let mut layer = vec![0usize; n];
    for _ in 0..n.min(200) {
        let mut changed = false;
        for &v in &order {
            for &(w, _) in &succ[v] {
                if back.contains(&(v, w)) || w == v {
                    continue;
                }
                if layer[w] < layer[v] + 1 {
                    layer[w] = layer[v] + 1;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let nl = layer.iter().max().copied().unwrap_or(0) + 1;
    let mut layers: Vec<Vec<usize>> = vec![vec![]; nl];
    for &v in &order {
        layers[layer[v]].push(v);
    }
    let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
    for v in 0..n {
        for &(w, _) in &succ[v] {
            if !back.contains(&(v, w)) && w != v {
                preds[w].push(v);
            }
        }
    }
    // Barycenter ordering.
    let mut pos = vec![0f32; n];
    for l in &layers {
        for (i, v) in l.iter().enumerate() {
            pos[*v] = i as f32;
        }
    }
    for _ in 0..4 {
        for li in 1..nl {
            let mut l = layers[li].clone();
            l.sort_by(|a, b| {
                let ba = bary(&preds[*a], &pos, pos[*a]);
                let bb = bary(&preds[*b], &pos, pos[*b]);
                ba.partial_cmp(&bb).unwrap_or(std::cmp::Ordering::Equal)
            });
            for (i, v) in l.iter().enumerate() {
                pos[*v] = i as f32;
            }
            layers[li] = l;
        }
    }
    // Coordinates.
    let mut y = 0.0;
    let mut cx = vec![0f32; n];
    for li in 0..nl {
        let h = layers[li].iter().map(|v| nodes[*v].rect.height()).fold(0.0, f32::max);
        let mut right = f32::MIN;
        let total_w: f32 = layers[li].iter().map(|v| nodes[*v].rect.width() + HGAP).sum::<f32>() - HGAP;
        let mut seq = -total_w / 2.0;
        for &v in &layers[li] {
            let w = nodes[v].rect.width();
            let desired = if preds[v].is_empty() {
                seq + w / 2.0
            } else {
                preds[v].iter().map(|p| cx[*p]).sum::<f32>() / preds[v].len() as f32
            };
            let mut left = desired - w / 2.0;
            if right != f32::MIN && left < right + HGAP {
                left = right + HGAP;
            }
            cx[v] = left + w / 2.0;
            right = left + w;
            seq += w + HGAP;
            nodes[v].rect = Rect::from_min_size(pos2(left, y), vec2(w, nodes[v].rect.height()));
        }
        y += h + VGAP;
    }
    // Edges.
    let mut edges = vec![];
    let max_x = nodes.iter().map(|n| n.rect.right()).fold(f32::MIN, f32::max);
    let mut back_lane = 0.0;
    let mut in_count = vec![0usize; n];
    let mut in_used = vec![0usize; n];
    for v in 0..n {
        for &(w, _) in &succ[v] {
            in_count[w] += 1;
        }
    }
    for v in 0..n {
        let k = succ[v].len();
        for (si, &(w, kind)) in succ[v].iter().enumerate() {
            let a = nodes[v].rect;
            let b = nodes[w].rect;
            let sx = a.left() + a.width() * (si as f32 + 1.0) / (k as f32 + 1.0);
            in_used[w] += 1;
            let ex = b.left() + b.width() * in_used[w] as f32 / (in_count[w] as f32 + 1.0);
            let pts = if back.contains(&(v, w)) || w == v || b.top() <= a.top() {
                back_lane += 12.0;
                let lane = max_x + 24.0 + back_lane;
                vec![
                    pos2(sx, a.bottom()),
                    pos2(sx, a.bottom() + 14.0),
                    pos2(lane, a.bottom() + 14.0),
                    pos2(lane, b.top() - 16.0),
                    pos2(ex, b.top() - 16.0),
                    pos2(ex, b.top()),
                ]
            } else {
                let mid = b.top() - 18.0 - (si as f32) * 6.0;
                vec![pos2(sx, a.bottom()), pos2(sx, mid), pos2(ex, mid), pos2(ex, b.top())]
            };
            edges.push(GEdge { kind, points: pts });
        }
    }
    let mut bounds = nodes[0].rect;
    for nd in &nodes {
        bounds = bounds.union(nd.rect);
    }
    for e in &edges {
        for p in &e.points {
            bounds.extend_with(*p);
        }
    }
    Layout { nodes, edges, bounds: bounds.expand(40.0) }
}

fn bary(preds: &[usize], pos: &[f32], own: f32) -> f32 {
    if preds.is_empty() {
        own
    } else {
        preds.iter().map(|p| pos[*p]).sum::<f32>() / preds.len() as f32
    }
}

pub struct GraphView {
    pub pan: Vec2,
    pub zoom: f32,
    pub center_on: Option<u64>,
}

impl Default for GraphView {
    fn default() -> Self {
        Self { pan: Vec2::ZERO, zoom: 1.0, center_on: None }
    }
}

pub enum GraphAction {
    Select(u64),
    Follow(u64),
    Context(u64),
    Xrefs(u64),
}

pub fn show(
    ui: &mut egui::Ui,
    lay: &Layout,
    view: &mut GraphView,
    p: &Palette,
    cursor: u64,
    comments: &HashMap<u64, String>,
) -> Option<GraphAction> {
    let (resp, painter) = ui.allocate_painter(ui.available_size(), Sense::click_and_drag());
    let area = resp.rect;
    painter.rect_filled(area, 0.0, p.panel_alt);
    // dotted grid backdrop
    let mut action = None;

    if let Some(target) = view.center_on.take() {
        if let Some(nd) = lay.nodes.iter().find(|n| n.rows.iter().any(|r| r.addr == target && !r.label) || n.start == target) {
            let row_y = nd.rows.iter().position(|r| r.addr == target).unwrap_or(0) as f32 * ROW_H;
            let focus = pos2(nd.rect.center().x, nd.rect.top() + row_y);
            // place focus at 1/3 from the top of the view
            view.pan = vec2(-focus.x * view.zoom, -(focus.y * view.zoom) + area.height() * 0.18 - area.height() / 2.0);
            if nd.start == lay.nodes[0].start && lay.bounds.width() * view.zoom < area.width() {
                view.pan.x = -lay.bounds.center().x * view.zoom;
            }
        }
    }

    if resp.dragged() {
        view.pan += resp.drag_delta();
    }
    if resp.hovered() {
        let (scroll, zoom_d, cmd) = ui.input(|i| (i.smooth_scroll_delta, i.zoom_delta(), i.modifiers.command));
        if (zoom_d - 1.0).abs() > 1e-4 || (cmd && scroll.y != 0.0) {
            let factor = if (zoom_d - 1.0).abs() > 1e-4 { zoom_d } else { (scroll.y * 0.003).exp() };
            let old = view.zoom;
            view.zoom = (view.zoom * factor).clamp(0.15, 2.5);
            if let Some(mp) = resp.hover_pos() {
                let c = area.center() + view.pan;
                let rel = mp - c;
                view.pan += rel - rel * (view.zoom / old);
            }
        } else {
            view.pan += scroll;
        }
    }

    let z = view.zoom;
    let origin = area.center() + view.pan;
    let to_screen = |q: Pos2| origin + q.to_vec2() * z;
    let clip = painter.clip_rect();
    let font = FontId::monospace(12.0 * z);
    let show_text = z >= 0.4;

    // edges
    for e in &lay.edges {
        let col = match e.kind {
            EdgeKind::Taken => p.edge_taken,
            EdgeKind::NotTaken => p.edge_not,
            EdgeKind::Always => p.edge_always,
        };
        let pts: Vec<Pos2> = e.points.iter().map(|q| to_screen(*q)).collect();
        painter.add(Shape::line(pts.clone(), Stroke::new(1.4 * z.max(0.6), col)));
        if let (Some(end), Some(prev)) = (pts.last(), pts.get(pts.len().wrapping_sub(2))) {
            let dir = (*end - *prev).normalized();
            let s = 7.0 * z.max(0.5);
            let n = vec2(-dir.y, dir.x);
            painter.add(Shape::convex_polygon(
                vec![*end, *end - dir * s + n * s * 0.5, *end - dir * s - n * s * 0.5],
                col,
                Stroke::NONE,
            ));
        }
    }
    // nodes
    let hover = resp.hover_pos();
    let (clicked, dbl, secondary) = (resp.clicked(), resp.double_clicked(), resp.secondary_clicked());
    let interact = resp.interact_pointer_pos().or(hover);
    for nd in &lay.nodes {
        let r = Rect::from_min_max(to_screen(nd.rect.min), to_screen(nd.rect.max));
        if !r.intersects(clip) {
            continue;
        }
        let has_cursor = nd.rows.iter().any(|row| row.addr == cursor);
        painter.rect(
            r,
            6.0 * z,
            p.block_bg,
            Stroke::new(if has_cursor { 1.6 } else { 1.0 }, if has_cursor { p.accent } else { p.block_border }),
            StrokeKind::Inside,
        );
        if !show_text {
            for (i, _) in nd.rows.iter().enumerate().step_by(2) {
                let y = r.top() + (PAD * 0.7 + i as f32 * ROW_H + ROW_H * 0.5) * z;
                painter.line_segment(
                    [pos2(r.left() + PAD * z, y), pos2(r.right() - PAD * z * 3.0, y)],
                    Stroke::new(1.0, p.faint),
                );
            }
            continue;
        }
        for (i, row) in nd.rows.iter().enumerate() {
            let top = r.top() + (PAD * 0.7 + i as f32 * ROW_H) * z;
            let row_rect = Rect::from_min_size(pos2(r.left() + 2.0, top), vec2(r.width() - 4.0, ROW_H * z));
            if !row_rect.intersects(clip) {
                continue;
            }
            if row.addr == cursor && !row.label {
                painter.rect_filled(row_rect, 3.0, p.selection);
            }
            let mut x = r.left() + PAD * z;
            if !row.label {
                x += CHAR_W * z;
            }
            for t in &row.toks {
                let g = painter.layout_no_wrap(t.text.clone(), font.clone(), t.color(p));
                let tr = Rect::from_min_size(pos2(x, top + 1.0), g.size());
                let is_link = t.target.is_some();
                if is_link && interact.map(|h| tr.contains(h)).unwrap_or(false) {
                    painter.line_segment([tr.left_bottom(), tr.right_bottom()], Stroke::new(1.0, t.color(p)));
                    if dbl {
                        action = Some(GraphAction::Follow(t.target.unwrap()));
                    }
                }
                painter.galley(tr.min, g, t.color(p));
                x = tr.right();
            }
            if let Some(c) = comments.get(&row.addr) {
                let g = painter.layout_no_wrap(format!("  ; {c}"), font.clone(), p.comment);
                painter.galley(pos2(x, top + 1.0), g, p.comment);
            }
            if row.xrefs > 0 && !row.label {
                let g = painter.layout_no_wrap(format!("  ×{}", row.xrefs), font.clone(), p.xref);
                let marker = Rect::from_min_size(pos2(r.right() - g.size().x - PAD * z, top + 1.0), g.size());
                if interact.map(|h| marker.contains(h)).unwrap_or(false) {
                    painter.galley(marker.min, g, p.xref);
                    if clicked { action = Some(GraphAction::Xrefs(row.addr)); }
                } else {
                    painter.galley(marker.min, g, p.xref);
                }
            }
            if let Some(h) = interact {
                if row_rect.contains(h) {
                    if clicked && action.is_none() {
                        action = Some(GraphAction::Select(row.addr));
                    }
                    if secondary {
                        action = Some(GraphAction::Context(row.addr));
                    }
                }
            }
        }
    }

    // overview map (IDA's "Graph overview")
    let ov_w = 170.0;
    let ov_h = 120.0;
    let ov = Rect::from_min_size(area.right_bottom() - vec2(ov_w + 12.0, ov_h + 12.0), vec2(ov_w, ov_h));
    if area.width() > 420.0 && area.height() > 260.0 {
        painter.rect(ov, 8.0, p.panel, Stroke::new(1.0, p.border), StrokeKind::Inside);
        let b = lay.bounds;
        let s = ((ov_w - 16.0) / b.width()).min((ov_h - 16.0) / b.height());
        let off = ov.center() - b.center().to_vec2() * s;
        let m = |q: Pos2| off + q.to_vec2() * s;
        for nd in &lay.nodes {
            painter.rect_filled(Rect::from_min_max(m(nd.rect.min), m(nd.rect.max)), 1.0, p.faint);
        }
        // viewport rect
        let inv = |sp: Pos2| ((sp - origin) / z).to_pos2();
        let vr = Rect::from_min_max(m(inv(area.min)), m(inv(area.max))).intersect(ov);
        painter.rect_stroke(vr, 2.0, Stroke::new(1.2, p.accent), StrokeKind::Inside);
        if let Some(h) = interact {
            if ov.contains(h) && (resp.clicked() || resp.dragged()) {
                let gp = ((h - off) / s).to_pos2();
                view.pan = -gp.to_vec2() * z;
                action = None;
            }
        }
        painter.text(ov.left_top() + vec2(8.0, 4.0), Align2::LEFT_TOP, "Overview", FontId::proportional(10.0), p.muted);
    }
    // zoom hint
    painter.text(
        area.left_bottom() + vec2(12.0, -10.0),
        Align2::LEFT_BOTTOM,
        format!("{:.0}%  ·  drag to move  ·  Cmd/Ctrl + scroll to zoom  ·  Space for text view", z * 100.0),
        FontId::proportional(11.0),
        p.faint,
    );
    let _ = Color32::TRANSPARENT;
    action
}
