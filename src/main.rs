mod analysis;
mod app;
mod code;
mod detect;
mod decomp;
mod dialogs;
mod graph;
mod lang;
mod loader;
mod panels;
mod source;
mod store;
mod theme;
mod views;
mod visuals;

use eframe::egui;

fn cli(args: &[String]) -> bool {
    let Some(file) = args.iter().find(|a| !a.starts_with("--") && std::path::Path::new(a.as_str()).exists()).cloned() else { return false };
    let report = args.iter().any(|a| a == "--report");
    let dec = args.iter().position(|a| a == "--decompile").and_then(|i| args.get(i + 1)).cloned();
    if !report && dec.is_none() {
        return false;
    }
    let bin = match loader::load(&file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return true;
        }
    };
    let an = analysis::analyze(&bin, &analysis::Settings { min_string_len: 5, extra_functions: vec![] }, std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)));
    let det = detect::detect(&bin, &an);
    if report {
        println!("{} | {} | {} | {}-bit", det.kind, det.os, det.arch, det.bits);
        for c in &det.container { println!("container: {c}"); }
        for (k, v) in &det.app_info { println!("  {k}: {v}"); }
        for g in &det.compilers { println!("compiler: {} ({:.0}%) {:?}", g.name, g.score * 100.0, g.why); }
        for g in &det.languages { println!("language: {} ({:.0}%)", g.name, g.score * 100.0); }
        for g in &det.packers { println!("packer: {} ({:.0}%)", g.name, g.score * 100.0); }
        for (n, on) in &det.protections { println!("protection: {n} = {on}"); }
        println!("conv: {} | stripped {} | debug {} | entropy {:.2} | sha256 {}", det.conv.label(), det.stripped, det.has_debug_info, det.overall_entropy, det.sha256);
        if let Some(a) = &det.asar { println!("asar: {} files, {} js, {} bytes at {}", a.files, a.js_files, a.bytes, a.path.display()); if let Some(i) = args.iter().position(|x| x == "--extract") { if let Some(d) = args.get(i + 1) { println!("extracted {:?}", source::extract_asar(&a.path, std::path::Path::new(d))); } } }
        println!("main: {:?}", det.main.as_ref().map(|(a, h)| format!("{a:X} via {h}")));
        for c in &det.capabilities { println!("cap {}: {}", c.name, c.apis.join(", ")); }
        for p in &det.plan { println!("plan: {p}"); }
        println!("{}", an.stats);
    }
    if let Some(target) = dec {
        let ann = store::Annotations::default();
        let names = app::build_names(&an, &ann, &det, &bin);
        let addrs: Vec<u64> = if target == "all" {
            an.functions.keys().copied().collect()
        } else if target == "main" {
            det.main.iter().map(|m| m.0).collect()
        } else if let Some(a) = dialogs::parse_addr(&target) {
            vec![a]
        } else {
            names.iter().filter(|(_, (n, _))| *n == target).map(|(a, _)| *a).collect()
        };
        for a in addrs {
            if let Some(f) = an.functions.get(&a) {
                if f.kind == analysis::FuncKind::Import { continue; }
                if std::env::var("LENS_TRACE2").is_ok() { eprintln!("start {a:X}"); }
                let t0 = std::time::Instant::now();
                let d = decomp::decompile(&bin, &an, &names, f, det.conv, "");
                if std::env::var("LENS_TRACE").is_ok() && t0.elapsed().as_millis() > 100 { eprintln!("{a:X} {} blocks {} insns {}ms", f.blocks.len(), f.insn_count, t0.elapsed().as_millis()); }
                let lg = match args.iter().position(|x| x == "--lang").and_then(|i| args.get(i + 1)).map(|s| s.as_str()) { Some("python") => lang::Lang::Python, Some("rust") => lang::Lang::Rust, Some("go") => lang::Lang::Go, Some("js") => lang::Lang::JavaScript, _ => lang::Lang::C };
                println!("{}", lang::render_text(&lang::render(&d, lg)));
            }
        }
    }
    true
}

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if cli(&args) {
        return Ok(());
    }
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
