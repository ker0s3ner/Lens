//! Colours. Code colours follow IDA's own palette (themes/default/theme.css, light and
//! os-dark-theme sections) with softer, more readable tones.

use eframe::egui::{self, Color32, CornerRadius, Stroke, Visuals};

#[derive(Clone, Copy)]
pub struct Palette {
    pub dark: bool,
    pub bg: Color32,
    pub panel: Color32,
    pub panel_alt: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub faint: Color32,
    pub accent: Color32,
    pub accent_soft: Color32,
    pub selection: Color32,
    pub hover_row: Color32,
    // code
    pub address: Color32,
    pub mnemonic: Color32,
    pub register: Color32,
    pub number: Color32,
    pub keyword: Color32,
    pub punct: Color32,
    pub func_name: Color32,
    pub label_name: Color32,
    pub data_name: Color32,
    pub import_name: Color32,
    pub string: Color32,
    pub comment: Color32,
    pub auto_comment: Color32,
    pub xref: Color32,
    pub segment: Color32,
    pub bytes: Color32,
    // graph edges (IDA: green = taken, red = not taken, blue = unconditional)
    pub edge_taken: Color32,
    pub edge_not: Color32,
    pub edge_always: Color32,
    pub block_bg: Color32,
    pub block_border: Color32,
    // navigation band
    pub nav_code: Color32,
    pub nav_import: Color32,
    pub nav_data: Color32,
    pub nav_string: Color32,
    pub nav_unexplored: Color32,
    pub nav_zero: Color32,
    pub nav_cursor: Color32,
}

fn hex(s: &str) -> Color32 {
    let v = u32::from_str_radix(s.trim_start_matches('#'), 16).unwrap_or(0);
    Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

impl Palette {
    pub fn light() -> Self {
        Palette {
            dark: false,
            bg: hex("#F4F5F7"),
            panel: hex("#FFFFFF"),
            panel_alt: hex("#F8F9FB"),
            border: hex("#E2E5EA"),
            text: hex("#1E2330"),
            muted: hex("#6B7383"),
            faint: hex("#A3A9B5"),
            accent: hex("#3563E9"),
            accent_soft: hex("#E8EEFD"),
            selection: hex("#FFF1C9"),
            hover_row: hex("#F3F5F9"),
            address: hex("#9AA1AD"),
            mnemonic: hex("#1A2766"),
            register: hex("#2D5F8B"),
            number: hex("#13855A"),
            keyword: hex("#6E7684"),
            punct: hex("#465068"),
            func_name: hex("#2F5BEA"),
            label_name: hex("#2F5BEA"),
            data_name: hex("#3B54C4"),
            import_name: hex("#C0268C"),
            string: hex("#13855A"),
            comment: hex("#2F5BEA"),
            auto_comment: hex("#8C93A0"),
            xref: hex("#13855A"),
            segment: hex("#8A7A16"),
            bytes: hex("#5B6475"),
            edge_taken: hex("#1E9E5A"),
            edge_not: hex("#D64545"),
            edge_always: hex("#3563E9"),
            block_bg: hex("#FFFFFF"),
            block_border: hex("#C9CED8"),
            nav_code: hex("#4C7BF0"),
            nav_import: hex("#E05BB5"),
            nav_data: hex("#A0A7B4"),
            nav_string: hex("#5BB98B"),
            nav_unexplored: hex("#C9B55C"),
            nav_zero: hex("#E7E9EE"),
            nav_cursor: hex("#F5A623"),
        }
    }

    pub fn dark() -> Self {
        Palette {
            dark: true,
            bg: hex("#17181B"),
            panel: hex("#1F2024"),
            panel_alt: hex("#24262B"),
            border: hex("#33363D"),
            text: hex("#DADCE1"),
            muted: hex("#8B909A"),
            faint: hex("#5B6069"),
            accent: hex("#6E95FF"),
            accent_soft: hex("#263252"),
            selection: hex("#4A3F1E"),
            hover_row: hex("#26282E"),
            address: hex("#6A707B"),
            mnemonic: hex("#EDEDED"),
            register: hex("#7DB8B8"),
            number: hex("#E08A6A"),
            keyword: hex("#9DA1A8"),
            punct: hex("#B9BCC2"),
            func_name: hex("#F2C94C"),
            label_name: hex("#F2C94C"),
            data_name: hex("#E6E6B8"),
            import_name: hex("#F07CE8"),
            string: hex("#8FD460"),
            comment: hex("#F3B6E4"),
            auto_comment: hex("#727780"),
            xref: hex("#F0B08A"),
            segment: hex("#E8E58A"),
            bytes: hex("#9AA0AA"),
            edge_taken: hex("#4CC27E"),
            edge_not: hex("#EF6B6B"),
            edge_always: hex("#6E95FF"),
            block_bg: hex("#232529"),
            block_border: hex("#3D414A"),
            nav_code: hex("#5C86F5"),
            nav_import: hex("#E76FC6"),
            nav_data: hex("#7F8590"),
            nav_string: hex("#5BB98B"),
            nav_unexplored: hex("#A8943F"),
            nav_zero: hex("#2C2E33"),
            nav_cursor: hex("#F5A623"),
        }
    }
}

pub fn apply(ctx: &egui::Context, p: &Palette) {
    let mut v = if p.dark { Visuals::dark() } else { Visuals::light() };
    v.panel_fill = p.panel;
    v.window_fill = p.panel;
    v.extreme_bg_color = p.panel_alt;
    v.faint_bg_color = p.panel_alt;
    v.override_text_color = Some(p.text);
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(10);
    v.menu_corner_radius = CornerRadius::same(8);
    v.selection.bg_fill = p.accent_soft;
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.hyperlink_color = p.accent;
    let r = CornerRadius::same(6);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.corner_radius = r;
    v.widgets.open.corner_radius = r;
    v.widgets.inactive.weak_bg_fill = p.panel_alt;
    v.widgets.inactive.bg_fill = p.panel_alt;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, p.border);
    v.widgets.hovered.weak_bg_fill = p.hover_row;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.faint);
    v.widgets.active.weak_bg_fill = p.accent_soft;
    v.popup_shadow.spread = 0;
    ctx.set_visuals(v);
    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(10.0, 5.0);
        s.spacing.interact_size.y = 26.0;
    });
}
