mod analysis;
mod app;
mod code;
mod dialogs;
mod graph;
mod loader;
mod panels;
mod store;
mod theme;
mod views;

use eframe::egui;

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut screenshot: Option<String> = None;
    let mut file: Option<String> = None;
    let mut dark: Option<bool> = None;
    let mut view: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--screenshot" => {
                screenshot = args.get(i + 1).cloned();
                i += 1;
            }
            "--dark" => dark = Some(true),
            "--light" => dark = Some(false),
            "--view" => {
                view = args.get(i + 1).cloned();
                i += 1;
            }
            a if !a.starts_with("--") => file = Some(a.to_string()),
            _ => {}
        }
        i += 1;
    }

    let mut vp = egui::ViewportBuilder::default()
        .with_title("Lens")
        .with_inner_size([1440.0, 900.0])
        .with_min_inner_size([900.0, 560.0]);
    if screenshot.is_some() {
        vp = vp.with_active(false);
        #[cfg(target_os = "windows")]
        {
            vp = vp.with_window_level(egui::WindowLevel::AlwaysOnBottom);
        }
    }
    let mut options = eframe::NativeOptions { viewport: vp, ..Default::default() };
    #[cfg(target_os = "macos")]
    if screenshot.is_some() {
        options.event_loop_builder = Some(Box::new(|b| {
            use winit::platform::macos::EventLoopBuilderExtMacOS;
            b.with_activate_ignoring_other_apps(false);
        }));
    }
    eframe::run_native(
        "Lens",
        options,
        Box::new(move |cc| Ok(Box::new(app::LensApp::new(cc, file, screenshot, dark, view)))),
    )
}
