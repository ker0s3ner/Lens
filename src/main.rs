#![recursion_limit = "512"]

mod analysis;
mod app;
mod code;
mod consts;
mod custom;
mod findcrypt;
mod hints;
mod ida;
mod protos;
mod detect;
mod dwarf;
mod debugger;
mod decomp;
mod dialogs;
mod graph;
mod lang;
mod loader;
mod menubar;
mod multiarch;
mod panels;
mod patch;
mod pdb;
mod script;
mod settings;
mod sigs;
mod source;
mod store;
mod theme;
mod tools;
mod tools2;
mod types;
mod updater;
mod views;
mod visuals;

use eframe::egui;

fn cli(args: &[String]) -> bool {
    if let Some(a) = args.iter().position(|a| a == "--arch").and_then(|i| args.get(i + 1)) {
        let want = a.to_lowercase().replace(['-', ' '], "");
        let want = match want.as_str() { "ppc" | "ppc32" => "powerpc".to_string(), "ppc64" => "powerpc64".to_string(), "arm" => "arm(32".to_string(), "x64" | "amd64" => "x8664".to_string(), "i386" | "i686" => "x86".to_string(), w => w.to_string() };
        let arch = loader::Arch::all().into_iter().find(|x| x.name().to_lowercase().replace([' ', '-'], "").starts_with(&want));
        let base = args.iter().position(|a| a == "--base").and_then(|i| args.get(i + 1)).and_then(|b| dialogs::parse_addr(b)).unwrap_or(0);
        if let Some(x) = arch {
            *loader::RAW_PREF.lock().unwrap() = Some((x, args.iter().any(|a| a == "--big"), base));
        }
    }
    if let Some(entry) = args.iter().position(|a| a == "--entry").and_then(|i| args.get(i + 1)).and_then(|e| dialogs::parse_addr(e)) {
        *loader::RAW_ENTRY_PREF.lock().unwrap() = Some(entry);
    }
    if let Some(sl) = args.iter().position(|a| a == "--slice").and_then(|i| args.get(i + 1)) {
        *loader::SLICE_PREF.lock().unwrap() = Some(sl.clone());
    }
    let Some(file) = args.iter().find(|a| !a.starts_with("--") && std::path::Path::new(a.as_str()).exists()).cloned() else { return false };
    let report = args.iter().any(|a| a == "--report");
    let json_report = args.iter().any(|a| a == "--json");
    let arg_of = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    if let Some(sf) = arg_of("--learn-sigs") {
        let bin = match loader::load(&sf) { Ok(b) => b, Err(e) => { eprintln!("{e}"); return true } };
        let an = analysis::analyze(&bin, &analysis::Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)));
        let sig = sigs::learn(&bin, &an);
        println!("learned {} signatures -> {:?}", sig.entries.len(), sigs::save(&sig));
        return true;
    }
    let script = arg_of("--run-script");
    let sig_apply = args.iter().any(|a| a == "--sigs");
    let patch = arg_of("--patch");
    let report = report || json_report || args.iter().any(|a| a == "--dbg-test") || script.is_some() || sig_apply || patch.is_some();
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
    let an = analysis::analyze(&bin, &analysis::Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)));
    let det = detect::detect(&bin, &an);
    if sig_apply {
        let m = sigs::apply(&bin, &an);
        println!("signatures matched {} functions", m.len());
        for (a, n) in m.iter().take(8) { println!("  {a:X} {n}"); }
    }
    if let Some(p) = &patch {
        // ADDR:HEX  e.g. 1000:9090
        if let Some((a, h)) = p.split_once(':') {
            let addr = dialogs::parse_addr(a).unwrap_or(0);
            let new = loader::parse_hex_text(h);
            let old = bin.read(addr, new.len()).to_vec();
            let pt = patch::Patch { addr, old, new };
            if let Some(out) = arg_of("--save") {
                println!("{:?}", patch::save_patched(&bin, &[pt], std::path::Path::new(&out)));
            }
        }
    }
    if args.iter().any(|a| a == "--dbg-test") {
        let main_addr = det.main.as_ref().map(|m| m.0).unwrap_or(0);
        let mut d = match debugger::Dbg::start(&bin.path, None, "", "", "", false, &[main_addr], &std::collections::HashMap::new()) { Ok(d) => d, Err(e) => { println!("{e}"); return true } };
        let t0 = std::time::Instant::now();
        let mut step = 0;
        while t0.elapsed().as_secs() < 25 {
            let pc = d.poll();
            if let Some(pc) = pc { println!("pc {pc:X} (slide {:X}) regs={} bt={} state={:?}", d.slide, d.regs.len(), d.bt.len(), d.state); }
            if d.state == debugger::RunState::Stopped && d.regs.len() > 0 && d.queue_idle() {
                step += 1;
                match step { 1 => { println!("main is {main_addr:X}; continuing"); d.resume("process continue") } 2 => d.resume("thread step-inst"), 3 => d.resume("process continue"), _ => break }
            }
            if d.state == debugger::RunState::Exited { println!("exited"); break; }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let skip = d.console.len().saturating_sub(45); for l in d.console.iter().skip(skip) { println!("| {l}"); } println!("regs: {:?}", d.regs.iter().take(6).collect::<Vec<_>>()); println!("bt: {:?}", d.bt); println!("stack: {:?}", d.stack.iter().take(2).collect::<Vec<_>>());
        return true;
    }
    if let Some(sp) = &script {
        let src = std::fs::read_to_string(sp).unwrap_or_default();
        let ann = store::load_annotations(&bin.path, bin.file_size);
        let names = app::build_names(&an, &ann, &det, &bin);
        let xrefs: std::collections::HashMap<u64, Vec<u64>> = an.xrefs_to.iter().map(|(a, v)| (*a, v.iter().map(|x| x.from).collect())).collect();
        let mut out_xrefs: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
        let mut out_xref_details: std::collections::HashMap<u64, Vec<(u64, String)>> = std::collections::HashMap::new();
        for (target, refs) in &an.xrefs_to { for x in refs { out_xref_details.entry(x.from).or_default().push((*target, x.kind.label().to_string())); } }
        for (target, sources) in &xrefs { for source in sources { out_xrefs.entry(*source).or_default().push(*target); } }
        let pseudocode = an.functions.values().filter(|f| f.kind != analysis::FuncKind::Import).map(|f| {
            let d = decomp::decompile_with_types(&bin, &an, &names, f, det.conv, "", &ann.structs);
            (f.start, decomp::render_text(&d))
        }).collect();
        let snap = script::Snap {
            bin: std::sync::Arc::new(bin.clone()),
            funcs: an.functions.values().filter(|f| f.kind != analysis::FuncKind::Import).map(|f| (f.start, names.get(&f.start).map(|n| n.0.clone()).unwrap_or_default(), f.end - f.start, f.blocks.len())).collect(),
            names: names.iter().map(|(a, (n, _))| (*a, n.clone())).collect(),
            comments: ann.comments.clone(),
            bookmarks: ann.marks.clone(),
            data_defs: ann.data_defs.clone(),
            strings: an.strings.iter().map(|s| (s.addr, s.text.clone())).collect(),
            xrefs,
            xref_details: an.xrefs_to.iter().map(|(a, v)| (*a, v.iter().map(|x| (x.from, x.kind.label().to_string())).collect())).collect(),
            out_xref_details,
            out_xrefs,
            pseudocode,
            pointer_tables: an.pointer_tables.iter().map(|(a, v)| (*a, v.clone())).collect(),
            vtables: an.vtables.iter().map(|(a, v)| (*a, v.clone())).collect(),
            vtable_names: an.vtable_names.clone(),
            applied_types: ann.applied.iter().cloned().collect(),
            types: ann.structs.clone(),
        };
        let r = script::run(&src, snap, None);
        print!("{}", r.text);
        if let Some(e) = r.error { println!("error: {e}"); }
        for c in r.cmds { println!("cmd: {c:?}"); }
    }
    if json_report {
        let value = serde_json::json!({
            "schema": "lens.analysis.v1",
            "file": bin.file_name,
            "format": det.kind,
            "os": det.os,
            "architecture": det.arch,
            "bits": det.bits,
            "slice": bin.slice,
            "file_base": bin.file_base,
            "stripped": det.stripped,
            "debug_info": det.has_debug_info,
            "sha256": det.sha256,
            "entry_point": det.main.as_ref().map(|(a, _)| *a).or(bin.entry),
            "functions": an.functions.len(),
            "instructions": an.insns.len(),
            "basic_blocks": an.functions.values().map(|f| f.blocks.len()).sum::<usize>(),
            "noreturn_functions": an.functions.values().filter(|f| f.noreturn).count(),
            "forwarding_thunks": an.functions.values().filter(|f| f.thunk_target.is_some()).count(),
            "switch_tables": an.switches.len(),
            "function_records": an.functions.values().map(|f| serde_json::json!({
                "start": f.start,
                "end": f.end,
                "name": bin.symbols.iter().find(|(address, _)| *address == f.start).map(|(_, name)| name),
                "kind": format!("{:?}", f.kind),
                "segment": bin.segment_of(f.start).map(|segment| segment.name.clone()),
                "has_symbol": f.has_symbol,
                "blocks": f.blocks.len(),
                "instructions": f.insn_count,
                "calls": f.calls,
                "references": an.xrefs_to.get(&f.start).map(|refs| refs.iter().map(|xref| xref.from).collect::<Vec<_>>()).unwrap_or_default(),
                "noreturn": f.noreturn,
                "thunk_target": f.thunk_target,
            })).collect::<Vec<_>>(),
            "pseudocode_records": an.functions.values().filter(|f| f.kind != analysis::FuncKind::Import).map(|function| {
                let code = decomp::decompile_with_types(&bin, &an, &an.names, function, det.conv, "", &[]);
                serde_json::json!({
                    "address": function.start,
                    "name": bin.symbols.iter().find(|(address, _)| *address == function.start).map(|(_, name)| name),
                    "kind": format!("{:?}", function.kind),
                    "segment": bin.segment_of(function.start).map(|segment| segment.name.clone()),
                    "lines": code.lines.len(),
                    "text": decomp::render_text(&code),
                })
            }).collect::<Vec<_>>(),
            "instruction_records": an.insns.iter().map(|(address, insn)| serde_json::json!({
                "address": address,
                "length": insn.len,
                "flow": match insn.flow {
                    analysis::Flow::Normal => "normal",
                    analysis::Flow::Call => "call",
                    analysis::Flow::IndirectCall => "indirect_call",
                    analysis::Flow::Jump => "jump",
                    analysis::Flow::IndirectJump => "indirect_jump",
                    analysis::Flow::CondJump => "conditional_jump",
                    analysis::Flow::Ret => "return",
                    analysis::Flow::Stop => "stop",
                },
                "target": insn.target,
                "memory": insn.mem,
                "memory_size": insn.mem_size,
                "immediate": insn.imm,
                "lea": insn.is_lea,
                "write": insn.is_write,
            })).collect::<Vec<_>>(),
            "listing_records": an.lines.iter().map(|line| serde_json::json!({
                "address": line.addr,
                "length": line.len,
                "kind": match line.kind {
                    analysis::LineKind::Segment => "segment",
                    analysis::LineKind::Blank => "blank",
                    analysis::LineKind::FuncSep => "function_separator",
                    analysis::LineKind::FuncStart => "function_start",
                    analysis::LineKind::Label => "label",
                    analysis::LineKind::Insn => "instruction",
                    analysis::LineKind::FuncEnd => "function_end",
                    analysis::LineKind::Str => "string",
                    analysis::LineKind::Ptr => "pointer",
                    analysis::LineKind::Data => "data",
                    analysis::LineKind::Bytes => "bytes",
                    analysis::LineKind::Zeros => "zeros",
                },
            })).collect::<Vec<_>>(),
            "block_records": an.functions.values().flat_map(|function| function.blocks.iter().map(move |block| serde_json::json!({
                "function": function.start,
                "start": block.start,
                "end": block.end,
                "instructions": block.insns,
                "successors": block.succs.iter().map(|(target, kind)| serde_json::json!({
                    "target": target,
                    "kind": match kind {
                        analysis::EdgeKind::Taken => "taken",
                        analysis::EdgeKind::NotTaken => "not_taken",
                        analysis::EdgeKind::Always => "always",
                    },
                })).collect::<Vec<_>>(),
            }))).collect::<Vec<_>>(),
            "call_records": an.functions.values().flat_map(|function| function.calls.iter().map(move |target| serde_json::json!({
                "from": function.start,
                "to": target,
            }))).collect::<Vec<_>>(),
            "entry_records": bin.entry.into_iter().chain(det.main.iter().map(|(address, _)| *address)).collect::<Vec<_>>(),
            "name_records": bin.symbols.iter().map(|(address, name)| serde_json::json!({
                "address": address,
                "name": name,
                "kind": "function",
            })).chain(bin.data_symbols.iter().map(|(address, name)| serde_json::json!({
                "address": address,
                "name": name,
                "kind": "data",
            }))).chain(bin.exports.iter().map(|export| serde_json::json!({
                "address": export.addr,
                "name": export.name,
                "kind": "export",
            }))).collect::<Vec<_>>(),
            "debug_type_records": bin.debug_structs,
            "debug_prototype_records": bin.debug_protos.lines().filter(|line| !line.trim().is_empty()).map(|prototype| serde_json::json!({
                "text": prototype,
            })).collect::<Vec<_>>(),
            "switch_records": an.switches.iter().map(|(jump, targets)| serde_json::json!({
                "jump": jump,
                "targets": targets,
                "references": an.xrefs_to.get(jump).map(|refs| refs.iter().map(|xref| xref.from).collect::<Vec<_>>()).unwrap_or_default(),
            })).collect::<Vec<_>>(),
            "xref_records": an.xrefs_to.iter().flat_map(|(target, refs)| refs.iter().map(move |xref| serde_json::json!({
                "from": xref.from,
                "to": target,
                "kind": xref.kind.label(),
            }))).collect::<Vec<_>>(),
            "string_records": an.strings.iter().map(|s| serde_json::json!({
                "address": s.addr,
                "length": s.len,
                "wide": s.wide,
                "text": s.text,
                "references": an.xrefs_to.get(&s.addr).map(|refs| refs.iter().map(|xref| xref.from).collect::<Vec<_>>()).unwrap_or_default(),
            })).collect::<Vec<_>>(),
            "segment_records": bin.segments.iter().map(|s| serde_json::json!({
                "name": s.name,
                "start": s.start,
                "end": s.end(),
                "size": s.size,
                "file_bytes": s.data.len(),
                "executable": s.exec,
                "writable": s.write,
                "file_offset": s.file_offset,
            })).collect::<Vec<_>>(),
            "import_records": bin.imports.iter().map(|i| serde_json::json!({
                "slot": i.slot,
                "name": i.name,
                "library": i.library,
                "references": an.xrefs_to.get(&i.slot).map(|refs| refs.iter().map(|xref| xref.from).collect::<Vec<_>>()).unwrap_or_default(),
            })).collect::<Vec<_>>(),
            "export_records": bin.exports.iter().map(|e| serde_json::json!({
                "address": e.addr,
                "name": e.name,
            })).collect::<Vec<_>>(),
            "library_records": bin.libraries.iter().map(|library| serde_json::json!({
                "name": library,
            })).collect::<Vec<_>>(),
            "data_records": an.data_size.iter().map(|(address, code)| serde_json::json!({
                "address": address,
                "code": code,
                "kind": if *code == analysis::DEF_STRING { "string" } else if (*code & 0x80) != 0 { "pointer" } else { "scalar" },
                "size": if *code == analysis::DEF_STRING { serde_json::Value::Null } else { serde_json::json!(code & 0x7f) },
                "references": an.xrefs_to.get(address).map(|refs| refs.iter().map(|xref| xref.from).collect::<Vec<_>>()).unwrap_or_default(),
            })).collect::<Vec<_>>(),
            "pointer_table_records": an.pointer_tables.iter().map(|(address, targets)| serde_json::json!({
                "address": address,
                "targets": targets,
                "references": an.xrefs_to.get(address).map(|refs| refs.iter().map(|xref| xref.from).collect::<Vec<_>>()).unwrap_or_default(),
            })).collect::<Vec<_>>(),
            "vtable_records": an.vtables.iter().map(|(address, targets)| serde_json::json!({
                "address": address,
                "name": an.vtable_names.get(address),
                "targets": targets,
                "references": an.xrefs_to.get(address).map(|refs| refs.iter().map(|xref| xref.from).collect::<Vec<_>>()).unwrap_or_default(),
            })).collect::<Vec<_>>(),
            "symbol_records": bin.symbols.iter().map(|(address, name)| serde_json::json!({
                "address": address,
                "name": name,
                "kind": "function",
            })).chain(bin.data_symbols.iter().map(|(address, name)| serde_json::json!({
                "address": address,
                "name": name,
                "kind": "data",
            }))).collect::<Vec<_>>(),
            "strings": an.strings.len(),
            "imports": bin.imports.len(),
            "exports": bin.exports.len(),
            "call_edges": an.functions.values().map(|f| f.calls.len()).sum::<usize>(),
            "xrefs": an.xrefs_to.values().map(Vec::len).sum::<usize>(),
            "notes": bin.notes,
        });
        println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
    }
    if report && !json_report && script.is_none() && !sig_apply && patch.is_none() || args.iter().any(|a| a == "--report") && !json_report {
        println!("{} | {} | {} | {}-bit", det.kind, det.os, det.arch, det.bits);
        if !bin.slice.is_empty() || bin.file_base != 0 { println!("image: slice={} file_base=0x{:X}", bin.slice, bin.file_base); }
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
            "--slice" => {
                *loader::SLICE_PREF.lock().unwrap() = args.get(i + 1).cloned();
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
        .with_inner_size([1440.0, std::env::var("LENS_H").ok().and_then(|v| v.parse().ok()).unwrap_or(900.0)])
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
