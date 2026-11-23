//! The native macOS menu bar (File, View, Navigate, Analysis, Assistant, Window, Help).

use crate::app::{Action, LensApp, Side, View};

#[cfg(target_os = "macos")]
mod imp {
    use muda::accelerator::Accelerator;
    use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};

    pub struct MenuBar {
        _menu: Menu,
        ai_sub: Submenu,
        ai_items: Vec<MenuItem>,
        plug_sub: Submenu,
        plug_items: Vec<MenuItem>,
    }

    fn item(id: &str, text: &str) -> MenuItem {
        MenuItem::with_id(id, text, true, None::<Accelerator>)
    }

    fn add(sub: &Submenu, rows: &[(&str, &str)]) {
        for (id, text) in rows {
            if id.is_empty() {
                let _ = sub.append(&PredefinedMenuItem::separator());
            } else {
                let _ = sub.append(&item(id, text));
            }
        }
    }

    impl MenuBar {
        pub fn new() -> Self {
            let menu = Menu::new();
            let app = Submenu::new("Lens", true);
            let _ = app.append(&PredefinedMenuItem::about(Some("About Lens"), None));
            let _ = app.append(&PredefinedMenuItem::separator());
            add(&app, &[("settings", "Settings..."), ("update", "Check for Updates..."), ("", "")]);
            let _ = app.append(&PredefinedMenuItem::services(None));
            let _ = app.append(&PredefinedMenuItem::separator());
            let _ = app.append(&PredefinedMenuItem::hide(None));
            let _ = app.append(&PredefinedMenuItem::hide_others(None));
            let _ = app.append(&PredefinedMenuItem::show_all(None));
            let _ = app.append(&PredefinedMenuItem::separator());
            let _ = app.append(&PredefinedMenuItem::quit(None));
            let _ = menu.append(&app);

            let file = Submenu::new("File", true);
            add(&file, &[
                ("open", "Open..."), ("hex_tool", "Hex to Code..."), ("", ""),
                ("export_notes", "Export Names and Notes..."), ("export_c", "Export Pseudocode..."),
                ("import", "Import Names and Notes..."), ("export_idc", "Export IDA Script (.idc)..."), ("export_ghidra", "Export Ghidra Script (.py)..."), ("export_json", "Export Database (JSON)..."), ("export_map", "Export Map File..."), ("export_asm", "Export Listing (.asm)..."), ("export_dot", "Export Call Graph (.dot)..."), ("", ""),
                ("reveal", "Show in Finder"), ("hash", "Copy SHA-256"), ("close", "Close Program"),
            ]);
            let _ = menu.append(&file);

            let edit = Submenu::new("Edit", true);
            add(&edit, &[("undo", "Undo"), ("redo", "Redo")]);
            let _ = menu.append(&edit);

            let view = Submenu::new("View", true);
            add(&view, &[
                ("graph", "Graph / Listing"), ("pseudo", "Pseudocode"), ("hex", "Hex"), ("calls", "Call Graph"), ("map", "Function Map"), ("overview", "Overview"), ("", ""),
                ("inspector", "Show / Hide Outline"), ("log", "Show / Hide Messages"), ("theme", "Switch Light / Dark"),
            ]);
            let _ = view.append(&PredefinedMenuItem::separator());
            let _ = view.append(&PredefinedMenuItem::fullscreen(None));
            let _ = menu.append(&view);

            let nav = Submenu::new("Navigate", true);
            add(&nav, &[
                ("jump", "Go to Address or Name..."), ("back", "Back"), ("forward", "Forward"), ("", ""),
                ("search", "Search..."), ("palette", "Command Palette..."), ("", ""),
                ("rename", "Rename"), ("comment", "Add Note"), ("mark", "Bookmark"), ("xrefs", "Who Uses This"), ("make_func", "Make Function"),
                ("data", "Define Data (D)"), ("ascii", "Define String (A)"), ("undef", "Undefine (U)"),
                ("", ""), ("side_funcs", "Show Functions"), ("side_strings", "Show Strings"), ("side_imports", "Show Imports"), ("side_segs", "Show Sections"),
            ]);
            let _ = menu.append(&nav);

            let tools = Submenu::new("Analysis", true);
            add(&tools, &[
                ("lists", "Lists (Names, Imports, Exports)..."), ("protos", "Function Prototypes..."), ("diff", "Compare With Another Program..."), ("", ""), ("patches", "Patch Bytes..."), ("structs", "Structs..."), ("debugger", "Debugger..."), ("breakpoint", "Toggle Breakpoint"), ("", ""),
                ("script", "Script..."),
            ]);
            let plug_sub = Submenu::new("Plugins", true);
            let _ = tools.append(&plug_sub);
            add(&tools, &[("", ""), ("learn_sigs", "Learn Signatures From a File..."), ("apply_sigs", "Recognise Library Functions"), ("reanalyze", "Re-analyse Program")]);
            let _ = menu.append(&tools);

            let ai = Submenu::new("Assistant", true);
            let _ = menu.append(&ai);

            let win = Submenu::new("Window", true);
            let _ = win.append(&PredefinedMenuItem::minimize(None));
            let _ = win.append(&PredefinedMenuItem::maximize(None));
            let _ = menu.append(&win);
            win.set_as_windows_menu_for_nsapp();

            let help = Submenu::new("Help", true);
            add(&help, &[("docs", "Lens Documentation"), ("releases", "Release Notes"), ("roadmap", "Roadmap"), ("issues", "Report a Problem")]);
            let _ = menu.append(&help);
            help.set_as_help_menu_for_nsapp();

            menu.init_for_nsapp();
            MenuBar { _menu: menu, ai_sub: ai, ai_items: vec![], plug_sub, plug_items: vec![] }
        }

        /// Rebuilds the assistant and plugin lists.
        pub fn refresh(&mut self, assistants: &[(usize, String)], plugins: &[String]) {
            for i in self.ai_items.drain(..) { let _ = self.ai_sub.remove(&i); }
            let top = item("assistant", "Ask Assistant...");
            let _ = self.ai_sub.append(&top);
            self.ai_items.push(top);
            for (i, n) in assistants {
                let m = item(&format!("ai:{i}"), &format!("Ask {n} About This Function"));
                let _ = self.ai_sub.append(&m);
                self.ai_items.push(m);
            }
            let st = item("ai_settings", "Assistant Settings...");
            let _ = self.ai_sub.append(&st);
            self.ai_items.push(st);
            for i in self.plug_items.drain(..) { let _ = self.plug_sub.remove(&i); }
            if plugins.is_empty() {
                let m = MenuItem::with_id("none", "No plugins installed", false, None::<Accelerator>);
                let _ = self.plug_sub.append(&m);
                self.plug_items.push(m);
            }
            for n in plugins {
                let m = item(&format!("plugin:{n}"), n);
                let _ = self.plug_sub.append(&m);
                self.plug_items.push(m);
            }
        }

        pub fn poll(&self) -> Vec<String> {
            let mut v = vec![];
            while let Ok(e) = MenuEvent::receiver().try_recv() {
                v.push(e.id().0.clone());
            }
            v
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub struct MenuBar;
    impl MenuBar {
        pub fn new() -> Self { MenuBar }
        pub fn refresh(&mut self, _: &[(usize, String)], _: &[String]) {}
        pub fn poll(&self) -> Vec<String> { vec![] }
    }
}

pub use imp::MenuBar;

impl LensApp {
    pub fn menu_refresh(&mut self) {
        let plugs: Vec<String> = crate::script::list_plugins().into_iter().map(|(n, _)| n).collect();
        let enabled: Vec<(usize, String)> = self.prefs.integrations.iter().enumerate().filter(|(_, i)| i.enabled).map(|(i, it)| (i, it.name.clone())).collect();
        if let Some(m) = &mut self.menu {
            m.refresh(&enabled, &plugs);
        }
    }

    pub fn poll_menu(&mut self) {
        let ids = match &self.menu { Some(m) => m.poll(), None => return };
        let cur = self.nav.cursor;
        for id in ids {
            let a = match id.as_str() {
                "settings" | "ai_settings" => {
                    if id == "ai_settings" { self.sui.tab = 3; }
                    Action::Settings
                }
                "update" => Action::CheckUpdate,
                "open" => Action::OpenDialog,
                "hex_tool" => Action::HexTool,
                "export_notes" => Action::ExportNotes,
                "export_c" => Action::ExportC,
                "reveal" => Action::Reveal,
                "hash" => Action::CopyHash,
                "close" => Action::Close,
                "graph" => Action::ToggleGraph,
                "pseudo" => Action::SetView(View::Pseudo),
                "hex" => Action::SetView(View::Hex),
                "calls" => Action::SetView(View::Calls),
                "map" => Action::SetView(View::Map),
                "overview" => Action::SetView(View::Overview),
                "inspector" => Action::ToggleInspector,
                "log" => Action::ToggleLog,
                "theme" => Action::ToggleTheme,
                "jump" => Action::Jump,
                "back" => Action::Back,
                "forward" => Action::Forward,
                "search" => Action::Search,
                "palette" => Action::Palette,
                "rename" => Action::Rename(cur),
                "comment" => Action::Comment(cur),
                "mark" => Action::Mark(cur),
                "xrefs" => Action::Xrefs(cur),
                "make_func" => Action::MakeFunction(cur),
                "data" => Action::DefineData(cur, crate::app::DataDef::Cycle),
                "ascii" => Action::DefineData(cur, crate::app::DataDef::Str),
                "undef" => Action::DefineData(cur, crate::app::DataDef::Undefine),
                "side_funcs" => Action::SetSide(Side::Functions),
                "side_strings" => Action::SetSide(Side::Strings),
                "side_imports" => Action::SetSide(Side::Imports),
                "side_segs" => Action::SetSide(Side::Segments),
                "import" => Action::Import,
                "undo" => Action::Undo,
                "redo" => Action::Redo,
                "lists" => Action::Lists,
                "protos" => Action::Protos,
                "diff" => Action::Diff,
                "export_idc" => Action::Export(crate::ida::ExportKind::Idc),
                "export_ghidra" => Action::Export(crate::ida::ExportKind::Ghidra),
                "export_json" => Action::Export(crate::ida::ExportKind::Json),
                "export_asm" => Action::Export(crate::ida::ExportKind::Asm),
                "export_dot" => Action::Export(crate::ida::ExportKind::Dot),
                "export_map" => Action::Export(crate::ida::ExportKind::Map),
                "patches" => Action::Patches,
                "structs" => Action::Structs,
                "debugger" => Action::Debugger,
                "breakpoint" => Action::ToggleBreakpoint(cur),
                "script" => Action::Script,
                "learn_sigs" => Action::LearnSigs,
                "apply_sigs" => Action::ApplySigs,
                "reanalyze" => Action::Reanalyze,
                "assistant" => Action::Assistant,
                "docs" => Action::OpenUrl("https://ker0s3ner.github.io/Lens/docs.html".into()),
                "releases" => Action::OpenUrl("https://github.com/ker0s3ner/Lens/releases".into()),
                "roadmap" => Action::OpenUrl("https://github.com/ker0s3ner/Lens/blob/main/ROADMAP.md".into()),
                "issues" => Action::OpenUrl("https://github.com/ker0s3ner/Lens/issues".into()),
                s if s.starts_with("ai:") => match s[3..].parse::<usize>() {
                    Ok(i) => Action::AskAi(i),
                    Err(_) => continue,
                },
                s if s.starts_with("plugin:") => Action::RunPlugin(s[7..].to_string()),
                _ => continue,
            };
            self.actions.push(a);
        }
    }
}
