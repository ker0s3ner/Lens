//! Settings window (tabs) and the Assistant window.

use crate::app::{Action, LensApp};
use crate::custom;
use eframe::egui::{self, vec2, Color32, CornerRadius, Margin, RichText, ScrollArea, Stroke, TextEdit};
use std::sync::mpsc::Receiver;

#[derive(Default)]
pub struct AiState {
    pub open: bool,
    pub sel: usize,
    pub running: Option<Receiver<Result<String, String>>>,
    pub output: String,
    pub error: bool,
    pub title: String,
    pub started: Option<std::time::Instant>,
}

#[derive(Default)]
pub struct SettingsUi {
    pub tab: usize,
    pub rebinding: Option<String>,
    pub font_path: String,
    pub font_msg: String,
    pub test_msg: Vec<(usize, String)>,
}

impl LensApp {
    pub fn save_prefs(&self) {
        crate::store::save_prefs(&self.prefs);
    }

    pub fn settings_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let mut acts: Vec<Action> = vec![];
        let mut refonts = false;
        let mut dirty = false;
        let mut zoom = self.prefs.zoom;
        egui::Window::new("Settings").open(&mut open).default_width(560.0).default_height(520.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                for (i, t) in ["General", "Fonts", "Keys", "Assistants", "Updates"].iter().enumerate() {
                    if ui.selectable_label(self.sui.tab == i, RichText::new(*t).strong()).clicked() {
                        self.sui.tab = i;
                    }
                }
            });
            ui.separator();
            let head = |ui: &mut egui::Ui, t: &str| {
                ui.add_space(8.0);
                ui.label(RichText::new(t).strong().color(p.muted));
                ui.add_space(2.0);
            };
            ScrollArea::vertical().auto_shrink(false).show(ui, |ui| match self.sui.tab {
                0 => {
                    head(ui, "Appearance");
                    ui.horizontal(|ui| {
                        ui.label("Theme");
                        if ui.selectable_label(!self.prefs.dark, "Light").clicked() && self.prefs.dark { acts.push(Action::ToggleTheme); }
                        if ui.selectable_label(self.prefs.dark, "Dark").clicked() && !self.prefs.dark { acts.push(Action::ToggleTheme); }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Interface size");
                        ui.add(egui::Slider::new(&mut zoom, 0.8..=1.6).custom_formatter(|v, _| format!("{:.0}%", v * 100.0)));
                        if ui.small_button("Reset").clicked() { zoom = 1.0; }
                    });
                    let mut insp = self.prefs.inspector;
                    if ui.checkbox(&mut insp, "Show the function outline panel").changed() { acts.push(Action::ToggleInspector); }
                    head(ui, "Analysis");
                    let mut ms = self.prefs.min_string_len;
                    ui.horizontal(|ui| {
                        ui.label("Shortest string to list");
                        ui.add(egui::Slider::new(&mut ms, 3..=16).suffix(" chars"));
                    });
                    if ms != self.prefs.min_string_len { self.prefs.min_string_len = ms; dirty = true; }
                    ui.label(RichText::new("Applies the next time a program is opened.").small().color(p.muted));
                    if self.loaded().is_some() && ui.button("Re-analyse the open program").clicked() { acts.push(Action::Reanalyze); }
                    head(ui, "Files");
                    ui.horizontal(|ui| {
                        if ui.button("Clear recent files").clicked() { self.prefs.recent.clear(); dirty = true; }
                        if ui.button("Open settings folder").clicked() { let _ = std::process::Command::new("open").arg(crate::store::config_dir()).spawn(); }
                    });
                }
                1 => {
                    head(ui, "Code size");
                    let mut cs = self.prefs.code_size;
                    ui.horizontal(|ui| {
                        ui.add(egui::Slider::new(&mut cs, 9.0..=24.0).step_by(1.0).suffix(" pt"));
                        if ui.small_button("Reset").clicked() { cs = 13.0; }
                    });
                    if (cs - self.prefs.code_size).abs() > 0.01 { self.prefs.code_size = cs; custom::set_font_size(cs); dirty = true; }
                    for (mono, title) in [(true, "Code font (listing, hex, pseudocode)"), (false, "Interface font")] {
                        head(ui, title);
                        let cur = if mono { self.prefs.mono_font.clone() } else { self.prefs.ui_font.clone() };
                        let shown = cur.strip_prefix("file:").map(|p| format!("File: {}", p.rsplit('/').next().unwrap_or(p))).unwrap_or(cur.clone());
                        let mut pick: Option<String> = None;
                        egui::ComboBox::from_id_salt(if mono { "monofont" } else { "uifont" }).selected_text(shown).width(260.0).show_ui(ui, |ui| {
                            if ui.selectable_label(cur == "Built-in", "Built-in").clicked() { pick = Some("Built-in".into()); }
                            for n in custom::available(mono) {
                                if ui.selectable_label(cur == n, n).clicked() { pick = Some(n.to_string()); }
                            }
                        });
                        if let Some(n) = pick {
                            if mono { self.prefs.mono_font = n; } else { self.prefs.ui_font = n; }
                            refonts = true;
                            dirty = true;
                        }
                    }
                    head(ui, "Use any font file (.ttf or .otf)");
                    ui.horizontal(|ui| {
                        ui.add(TextEdit::singleline(&mut self.sui.font_path).hint_text("/path/to/Font.ttf").desired_width(300.0));
                        for (mono, label) in [(true, "Use for code"), (false, "Use for interface")] {
                            if ui.button(label).clicked() {
                                let path = self.sui.font_path.trim().to_string();
                                if custom::font_file_ok(&path) {
                                    if mono { self.prefs.mono_font = format!("file:{path}"); } else { self.prefs.ui_font = format!("file:{path}"); }
                                    self.sui.font_msg = "Font applied.".into();
                                    refonts = true;
                                    dirty = true;
                                } else {
                                    self.sui.font_msg = "That isn't a font file Lens can read.".into();
                                }
                            }
                        }
                    });
                    if !self.sui.font_msg.is_empty() { ui.label(RichText::new(&self.sui.font_msg).small().color(p.muted)); }
                    ui.add_space(6.0);
                    ui.label(RichText::new("The code font should be monospaced, or columns will not line up.").small().color(p.muted));
                }
                2 => {
                    ui.label(RichText::new("Click Change, then press the keys you want. Cmd is the Command key on a Mac.").color(p.muted));
                    ui.add_space(6.0);
                    egui::Grid::new("binds").num_columns(3).spacing([16.0, 6.0]).show(ui, |ui| {
                        for (id, label, def) in custom::BINDINGS {
                            ui.label(*label);
                            let cur = custom::spec(&self.prefs.keys, id);
                            let recording = self.sui.rebinding.as_deref() == Some(*id);
                            if recording {
                                ui.label(RichText::new("Press keys...").color(p.accent));
                            } else {
                                let changed = cur != *def;
                                ui.label(RichText::new(&cur).monospace().color(if changed { p.accent } else { p.text }));
                            }
                            ui.horizontal(|ui| {
                                if recording {
                                    if ui.button("Cancel").clicked() { self.sui.rebinding = None; }
                                } else {
                                    if ui.button("Change").clicked() { self.sui.rebinding = Some(id.to_string()); }
                                    if cur != *def && ui.small_button("Reset").clicked() { self.prefs.keys.remove(*id); dirty = true; }
                                }
                            });
                            ui.end_row();
                        }
                    });
                    ui.add_space(8.0);
                    if ui.button("Reset all keys").clicked() { self.prefs.keys.clear(); dirty = true; }
                }
                3 => {
                    ui.label(RichText::new("Send the function you are looking at to Claude Code, Codex or any command-line tool. The question and the code go to the command on standard input; what it prints appears in the Assistant window (Cmd+L).").color(p.muted));
                    ui.add_space(6.0);
                    let mut remove: Option<usize> = None;
                    for (i, it) in self.prefs.integrations.iter_mut().enumerate() {
                        egui::Frame::new().fill(p.panel_alt).stroke(Stroke::new(1.0, p.border)).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(12)).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                if ui.checkbox(&mut it.enabled, "").changed() { dirty = true; }
                                if ui.add(TextEdit::singleline(&mut it.name).desired_width(170.0)).changed() { dirty = true; }
                                if ui.button("Test").clicked() {
                                    let m = custom::test(it);
                                    self.sui.test_msg.retain(|(k, _)| *k != i);
                                    self.sui.test_msg.push((i, m));
                                }
                                if ui.button("Remove").clicked() { remove = Some(i); }
                            });
                            ui.add_space(2.0);
                            if ui.add(TextEdit::singleline(&mut it.command).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY).hint_text("command")).changed() { dirty = true; }
                            if ui.checkbox(&mut it.capture, "Show its answer in Lens (untick for apps that just open)").changed() { dirty = true; }
                            if let Some((_, m)) = self.sui.test_msg.iter().find(|(k, _)| *k == i) {
                                ui.label(RichText::new(m).small().color(p.muted));
                            }
                        });
                        ui.add_space(6.0);
                    }
                    if let Some(i) = remove { self.prefs.integrations.remove(i); self.sui.test_msg.clear(); dirty = true; }
                    ui.horizontal(|ui| {
                        if ui.button("Add command").clicked() {
                            self.prefs.integrations.push(custom::Integration { name: "My tool".into(), command: "cat".into(), capture: true, enabled: true });
                            dirty = true;
                        }
                        if ui.button("Restore defaults").clicked() { self.prefs.integrations = custom::default_integrations(); self.sui.test_msg.clear(); dirty = true; }
                    });
                    ui.add_space(6.0);
                    ui.label(RichText::new("{file} is the program's path, {func} the function name and {addr} its address. Example: open -a Cursor {file}").small().color(p.muted));
                }
                _ => {
                    head(ui, "Updates");
                    let mut auto = self.prefs.auto_update;
                    if ui.checkbox(&mut auto, "Check for new versions when Lens starts").changed() { acts.push(Action::ToggleAutoUpdate); }
                    ui.horizontal(|ui| {
                        ui.label(format!("Lens {}", crate::updater::CURRENT));
                        match &self.update {
                            crate::updater::Status::Available(r) => {
                                ui.label(RichText::new(format!("{} is available", r.version)).color(p.accent));
                                if ui.button("Install and restart").clicked() { acts.push(Action::InstallUpdate); }
                            }
                            crate::updater::Status::Checking(_) => { ui.add(egui::Spinner::new().size(12.0)); }
                            crate::updater::Status::UpToDate(_) => { ui.label(RichText::new("Up to date").color(p.muted)); }
                            crate::updater::Status::Failed(e, _) => { ui.label(RichText::new(e.as_str()).color(p.muted)); }
                            _ => {}
                        }
                        if ui.button("Check now").clicked() { acts.push(Action::CheckUpdate); }
                    });
                }
            });
        });
        if (zoom - self.prefs.zoom).abs() > 0.001 {
            self.prefs.zoom = zoom;
            ctx.set_zoom_factor(zoom);
            dirty = true;
        }
        if refonts {
            custom::apply_fonts(ctx, &self.prefs.ui_font, &self.prefs.mono_font);
        }
        if dirty {
            self.save_prefs();
            self.menu_refresh();
        }
        if !open { self.sui.rebinding = None; }
        self.tools.settings_open = open;
        self.actions.extend(acts);
    }

    /// Text sent to an assistant: where we are, the question and the current function as pseudocode.
    pub fn ai_context(&mut self, question: &str) -> Option<(String, String, String)> {
        let (fs, d) = self.pseudo_for()?;
        let l = self.loaded()?;
        let name = l.names.get(&fs).map(|n| n.0.clone()).unwrap_or_else(|| format!("sub_{fs:X}"));
        let code = crate::lang::render_text(&crate::lang::render(&d, crate::lang::Lang::C));
        let mut code: String = code.chars().take(60_000).collect();
        if code.len() >= 60_000 { code.push_str("\n/* truncated */"); }
        let text = format!(
            "{question}\n\nProgram: {} ({}, {}). Function {name} at 0x{fs:X}. This is pseudocode produced by a decompiler, so names and types are guesses.\n\n{code}\n",
            l.bin.file_name, l.bin.arch.name(), l.det.kind
        );
        Some((text, name, format!("{fs:X}")))
    }

    pub fn ask_ai(&mut self, idx: usize) {
        let Some(it) = self.prefs.integrations.get(idx).cloned() else { return };
        let q = self.prefs.ask_text.clone();
        let Some((text, func, addr)) = self.ai_context(&q) else {
            self.ai.output = "Open a program and put the cursor inside a function first.".into();
            self.ai.error = true;
            self.ai.open = true;
            return;
        };
        let file = self.loaded().map(|l| l.bin.path.clone()).unwrap_or_default();
        self.ai.sel = idx;
        self.ai.title = format!("{} on {func}", it.name);
        self.ai.output.clear();
        self.ai.error = false;
        self.ai.started = Some(std::time::Instant::now());
        self.ai.running = Some(custom::run(&it, text, &file, &func, &addr));
        self.ai.open = true;
        self.logm(format!("Asked {} about {func}.", it.name));
    }

    pub fn poll_ai(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.ai.running {
            match rx.try_recv() {
                Ok(r) => {
                    self.ai.error = r.is_err();
                    self.ai.output = r.unwrap_or_else(|e| e);
                    self.ai.running = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => ctx.request_repaint_after(std::time::Duration::from_millis(150)),
                Err(_) => self.ai.running = None,
            }
        }
    }

    pub fn assistant_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let mut ask: Option<usize> = None;
        egui::Window::new("Assistant").open(&mut open).default_width(640.0).default_height(520.0).show(ctx, |ui| {
            let enabled: Vec<usize> = self.prefs.integrations.iter().enumerate().filter(|(_, i)| i.enabled).map(|(i, _)| i).collect();
            if enabled.is_empty() {
                ui.label("No assistants are switched on. Open Settings > Assistants to add Claude Code, Codex or your own command.");
                if ui.button("Open settings").clicked() { self.tools.settings_open = true; self.sui.tab = 3; }
                return;
            }
            ui.horizontal(|ui| {
                ui.label("Ask");
                let cur = self.prefs.integrations.get(self.ai.sel).map(|i| i.name.clone()).unwrap_or_default();
                egui::ComboBox::from_id_salt("aisel").selected_text(cur).show_ui(ui, |ui| {
                    for i in &enabled {
                        if ui.selectable_label(self.ai.sel == *i, self.prefs.integrations[*i].name.as_str()).clicked() { self.ai.sel = *i; }
                    }
                });
                ui.label(RichText::new("about the function under the cursor").color(p.muted));
            });
            ui.add_space(4.0);
            let r = ui.add(TextEdit::multiline(&mut self.prefs.ask_text).desired_rows(2).desired_width(f32::INFINITY).hint_text("What do you want to know?"));
            if r.lost_focus() { self.save_prefs(); }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let busy = self.ai.running.is_some();
                let b = egui::Button::new(RichText::new(if busy { "Waiting..." } else { "Send" }).strong().color(Color32::WHITE)).fill(p.accent).min_size(vec2(90.0, 28.0));
                if ui.add_enabled(!busy, b).clicked() { ask = Some(self.ai.sel); }
                if busy {
                    ui.add(egui::Spinner::new().size(14.0));
                    if let Some(t) = self.ai.started { ui.label(RichText::new(format!("{:.0}s", t.elapsed().as_secs_f32())).color(p.muted)); }
                }
                if !self.ai.output.is_empty() && ui.button("Copy answer").clicked() { ui.ctx().copy_text(self.ai.output.clone()); }
            });
            ui.separator();
            if !self.ai.title.is_empty() { ui.label(RichText::new(&self.ai.title).small().color(p.faint)); }
            ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                if self.ai.output.is_empty() && self.ai.running.is_none() {
                    ui.label(RichText::new("The answer appears here. Claude Code and Codex must be installed and signed in on this Mac.").color(p.faint));
                } else {
                    let col = if self.ai.error { p.edge_not } else { p.text };
                    ui.add(egui::Label::new(RichText::new(&self.ai.output).color(col)).selectable(true));
                }
            });
        });
        self.ai.open = open;
        if let Some(i) = ask { self.ask_ai(i); }
    }
}
