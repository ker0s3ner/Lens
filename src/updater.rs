//! In-app updates: checks GitHub Releases, downloads the new Lens.app and swaps it in, then relaunches.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Instant;

/// Live progress of a download, shared with the UI thread.
#[derive(Default)]
pub struct Progress {
    pub done: AtomicU64,
    pub total: AtomicU64,
    /// 0 = downloading, 1 = unpacking and verifying
    pub phase: AtomicU64,
}

impl Progress {
    /// 0.0 to 1.0 while downloading (None if the size is unknown).
    pub fn fraction(&self) -> Option<f32> {
        let t = self.total.load(Ordering::Relaxed);
        (t > 0).then(|| (self.done.load(Ordering::Relaxed) as f32 / t as f32).clamp(0.0, 1.0))
    }
}

const REPO: &str = "ker0s3ner/Lens";
const ASSET: &str = "Lens-macos-arm64.zip";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
pub const CODENAME: &str = "Fourier";
pub const CURRENT_WHATS_NEW: &[&str] = &[
    "PDB class layouts containing unsupported base-class records are now skipped instead of partially imported.",
    "Direct-member-only C++ class and interface layouts remain available through the Types database.",
    "PDB C++ class and interface records now import supported explicit data members through the Types database.",
    "Unsupported C++ inheritance, methods, and virtual-layout records remain conservative skips.",
    "PDB struct and union layouts now retain named enum members with their CodeView underlying widths.",
    "Enum-typed fields are no longer dropped during conservative PDB layout recovery.",
    "PDB CodeView modifier records now preserve const and volatile qualifiers in recovered types.",
    "Qualified scalar fields continue to receive correct storage sizing during layout import.",
    "PDB fixed-array members now import supported element counts and storage sizes from CodeView dimensions.",
    "Unknown array element layouts remain skipped instead of being assigned guessed sizes.",
    "PDB LF_BITFIELD members now retain CodeView bit positions and widths in imported layouts.",
    "Supported PDB bitfields no longer collapse into ordinary scalar fields during type recovery.",
    "PDB struct and union recovery now retains supported CodeView callback members as pointer-sized fields.",
    "Procedure-type members are routed through Lens callback declarations instead of being discarded.",
    "Split CodeView field lists are now reconstructed across continuation records.",
    "Large PDB structs, unions, and enums no longer lose members at field-list boundaries.",
    "PE/PDB union records now import supported overlapping members through the Types database.",
    "Union layouts reuse CodeView member offsets and declared sizes without guessing unsupported fields.",
    "PE/PDB struct records now import supported scalar and pointer members with their CodeView offsets.",
    "Incomplete or unsupported PDB layouts are skipped instead of producing partial types.",
    "PE/PDB enum records now import named CodeView members into the Types database.",
    "Recovered PDB enum values are available to pseudocode constant propagation.",
    "PDB no-return name matching in pseudocode is now exact and regression-tested.",
    "Decompiler tests cover the boundary between CodeView metadata and terminating callees.",
    "PDB-marked never-returning procedures now also terminate pseudocode call lifting.",
    "Decompiler control flow now agrees with PE analysis for CodeView no-return metadata.",
    "CodeView never-returning procedure flags now terminate PE control-flow analysis conservatively.",
    "PDB no-return metadata is preserved alongside imported symbols and prototypes.",
    "CodeView LF_BITFIELD records now retain their underlying scalar type in recovered PDB prototypes.",
    "Bitfield width and layout remain conservative until full PDB field-layout import is implemented.",
    "PDB primitive and pointer-indirected type decoding now has direct regression coverage.",
    "The deterministic suite now covers 57 cases across analysis, interchange, DWARF, and PDB paths.",
    "PDB prototype recovery now decodes inline CodeView primitive type indices for concrete parameter and return types.",
    "Primitive PDB signatures no longer fall back to `void` merely because their types are encoded below the TPI stream.",
    "PDB prototypes are now retained even when their symbol names were already known from PE exports.",
    "Debug type recovery is no longer coupled to whether PDB names add new function entries.",
    "PE/PDB procedure records now contribute conservative primitive/pointer prototypes to decompilation.",
    "Unsupported PDB type records remain skipped instead of generating guessed signatures.",
    "PDB ingestion now has a malformed-input regression guard before type-stream expansion.",
    "The deterministic test suite now covers 56 cases, including PE debug-symbol safety.",
    "PE analysis now imports procedure/public symbols from PDB module streams in addition to global symbols.",
    "Static and compiler-generated module procedures are available to function discovery when PDB data is present.",
    "PDB discovery now honors a valid embedded CodeView path before local executable-directory fallbacks.",
    "Malformed individual PDB symbol records no longer discard the rest of the symbol import.",
    "PE analysis now imports global procedure/public symbols from an adjacent CodeView PDB when available.",
    "PDB-backed function names are mapped through the executable image base before analysis begins.",
    "DWARF variadic callback signatures now retain their `...` parameter marker.",
    "Imported callback types preserve fixed parameters and variadic ABI shape together.",
    "Named DWARF callback parameters are retained in imported function-pointer signatures when available.",
    "Type recovery now preserves both callback shapes and analyst-useful parameter names.",
    "DWARF callback types now retain return and formal-parameter types in imported function-pointer fields.",
    "Typed callbacks no longer collapse to opaque `void *` declarations in the Types tool.",
    "Supported DWARF bitfields now import with their native storage offsets and widths.",
    "The Types tool can preserve compiler-emitted bitfield layouts instead of skipping those structs.",
    "Go runtime panic symbol matching now covers versioned panic and throw families without exact-name tables.",
    "No-return regression coverage includes bounds, slice, and goroutine-exit helpers.",
    "Go runtime.panic* and runtime.goexit symbol families are recognized as no-return functions.",
    "Version-specific compiler panic helpers now terminate analysis consistently.",
    "Go runtime panic/throw and additional Rust bounds-panic symbols are recognized as no-return functions.",
    "Call graphs and decompilation now terminate more accurately across Go and Rust binaries.",
    "ARM32 register-relative switch recovery now has a raw-binary regression fixture.",
    "The analyzer test suite now covers 55 deterministic cases across architecture and interchange paths.",
    "ARM32 table-base switch idioms now recover bounded targets from `add pc, #imm` plus indexed loads.",
    "Compiler-generated indirect branches through register-relative tables become real graph edges.",
    "AArch64 direct 32/64-bit pointer switch tables now recover bounded targets alongside offset tables.",
    "Common compiler-generated br-through-table cases become real graph edges and pseudocode cases.",
    "Lens JSON import now restores exported pointer-table entries as persistent native pointer definitions.",
    "Interchange preserves analyst-promoted pointer data across files and sessions.",
    "RISC-V, MIPS and PowerPC jump-table recognizers now participate in live indirect-branch analysis.",
    "Switch cases on these architectures can now become real graph edges and pseudocode cases.",
    "AArch64 SM4 round and key-schedule instructions now remain visible as named pseudocode intrinsics.",
    "Modern block-cipher operand groups are preserved alongside existing AES and SHA coverage.",
    "AArch64 SHA-3/SM3-style Boolean and rotate-combine instructions now remain visible as named pseudocode intrinsics.",
    "Modern cryptographic mix operations preserve their operand groups.",
    "AArch64 SHA-512 round and schedule instructions now remain visible as named pseudocode intrinsics.",
    "SHA-512 cryptographic operand groups are preserved alongside existing SHA-1/SHA-256 coverage.",
    "AVX-512 ternary-logic instructions now remain visible as named pseudocode intrinsics.",
    "Three-input Boolean operand groups are preserved for crypto and bit-manipulation code.",
    "x86/x64 VNNI and 4-way fused multiply-add dot-product families now remain visible as named pseudocode intrinsics.",
    "ML-oriented packed dot-product operand groups are preserved in decompiler output.",
    "AArch64 NEON pairwise-long and absolute-difference accumulation families now remain visible as named pseudocode intrinsics.",
    "Image/audio reduction kernels preserve their widening accumulation operands.",
    "AArch64 NEON numeric min/max and horizontal reduction families now remain visible as named pseudocode intrinsics.",
    "Vector aggregation operations preserve their operands instead of falling through to opaque generic handling.",
    "AArch64 NEON saturating rounded multiply-accumulate/subtract families now remain visible as named pseudocode intrinsics.",
    "Modern fixed-point codec and DSP operations preserve their operand groups.",
    "AArch64 NEON fixed-point saturating, rounded, and high-half multiply families now remain visible as named pseudocode intrinsics.",
    "Codec and DSP-oriented widening multiply-accumulate operations preserve their operand groups.",
    "README decompiler capability documentation now includes the latest AArch64 NEON reciprocal, complex, dot-product, and mask semantics.",
    "User-facing architecture coverage is synchronized with the shipped implementation.",
    "AArch64 NEON dot-product and widening multiply-accumulate families now remain visible as named pseudocode intrinsics.",
    "Common ML, image, and DSP vector accumulation operations no longer fall through to opaque generic handling.",
    "AArch64 NEON bit-select and mask-combine families now remain visible as named pseudocode intrinsics.",
    "Branchless vector mask operations no longer fall through to opaque generic handling.",
    "AArch64 NEON complex add and multiply families now remain visible as named pseudocode intrinsics.",
    "DSP-oriented complex vector operations no longer fall through to opaque generic handling.",
    "AArch64 NEON reciprocal and reciprocal-square-root estimate/refinement instructions now remain visible as named pseudocode intrinsics.",
    "Common vector math approximation steps no longer fall through to opaque generic handling.",
    "JSON name restoration now uses one shared importer path for functions, exports, import slots, vtables, and explicit names.",
    "Interchange parsing is covered by a deterministic regression test and avoids duplicated collection-specific logic.",
    "AVX-512 mask-register logical, move, shift, and inversion families now remain visible as named pseudocode intrinsics.",
    "Mask operand groups are preserved instead of disappearing into generic handling.",
    "Added a deterministic JSON interchange regression covering function, export, import-slot, vtable, and explicit name records.",
    "The repeatable test suite now has 54 passing tests.",
    "Common AVX2 high-half, multiply-add, and saturating multiply families now remain visible as named pseudocode intrinsics.",
    "Fixed-point and crypto-oriented packed multiply operand groups are preserved in decompiler output.",
    "Common AVX2 packed absolute-value and signed/unsigned min/max families now remain visible as named pseudocode intrinsics.",
    "Vector bounds and absolute-value operations preserve their operand groups in decompiler output.",
    "Common AVX2 packed logical, arithmetic, and variable shift families now remain visible as named pseudocode intrinsics.",
    "Vector lane shifts preserve their operand groups instead of falling through to opaque generic handling.",
    "AArch64 NEON floating/integer conversion and rounding families now remain visible as named pseudocode intrinsics.",
    "Common lane-width conversion and rounding operations no longer fall through to opaque generic handling.",
    "AVX2 packed widening, narrowing, saturation, and mask-extraction move families now remain visible as named pseudocode intrinsics.",
    "Sign/zero-extension lane conversions preserve their operand groups in decompiler output.",
    "AArch64 NEON floating/integer conversion and rounding families now remain visible as named pseudocode intrinsics.",
    "Common lane-width conversion and rounding operations no longer fall through to opaque generic handling.",
    "AVX2 integer permute and gather families now remain visible as named pseudocode intrinsics.",
    "Vector lane-index and memory-gather operand groups are preserved in decompiler output.",
    "Common x86/x64 packed integer and floating-point comparison families now remain visible as named pseudocode intrinsics.",
    "AVX comparison masks preserve their operand groups instead of falling through to opaque generic handling.",
    "Common x86/x64 packed integer add/subtract, bitwise, and multiply families now remain visible as named pseudocode intrinsics.",
    "AVX2 integer vector operations preserve their operand groups instead of falling through to opaque generic handling.",
    "Common AVX/SSE blend, shuffle, permute, and lane-reordering instructions now remain visible as named pseudocode intrinsics.",
    "Vector layout operations no longer fall through to opaque generic handling.",
    "Lens JSON import now restores exported import-slot and recovered-vtable names.",
    "Richer database round-trips preserve more of the analysis names shown by Lists and JSON export.",
    "AVX/FMA3 negated fused multiply-add/subtract families now remain visible as named pseudocode intrinsics.",
    "vfnmadd* and vfnmsub* operand groups are preserved in decompiler output.",
    "Common AVX/FMA3 packed and scalar fused multiply-add/subtract instructions now remain visible as named pseudocode intrinsics.",
    "FMA operand groups are preserved instead of falling through to opaque generic handling.",
    "Documentation now reports the current 32% weighted breadth estimate and the implemented heuristic metadata coverage accurately.",
    "README and roadmap limitations are synchronized with the current vtable/RTTI, Objective-C, and Swift analysis behavior.",
    "AArch64 NEON variable, rounded, and narrowing shift operations now remain visible as named pseudocode intrinsics.",
    "Common vector shift and rescale operations no longer disappear in generic lifting.",
    "AArch64 NEON widening, narrowing, and high-half vector operations now remain visible as named pseudocode intrinsics.",
    "Common lane-width conversion and rounded narrowing operations no longer disappear in generic lifting.",
    "AArch64 NEON integer and floating-point comparison families now remain visible as named pseudocode intrinsics.",
    "Vector comparison operations no longer disappear in generic lifting.",
    "AArch64 NEON pairwise/reduction instructions now remain visible as named pseudocode intrinsics.",
    "Saturating and halving vector add/subtract operations no longer disappear in generic lifting.",
    "AArch64 NEON table, zip, unzip, and transpose instructions now remain visible as named pseudocode intrinsics.",
    "Vector lane rearrangement operations no longer disappear when the generic lifter encounters them.",
    "AArch64 SHA-1 and SHA-256 round/schedule instructions now preserve named cryptographic semantics and operands.",
    "Common AArch64 hashing instructions remain visible in pseudocode.",
    "x86/x64 BMI1 bextr now preserves named bit-field extraction semantics and control operands.",
    "Common x86/x64 bit-field operations remain readable in pseudocode.",
    "x86/x64 BMI1 blsi, blsr, and blsmsk now preserve named low-bit isolation and mask semantics.",
    "Common x86/x64 bit-manipulation idioms remain readable in pseudocode.",
    "MIPS rotr and rotrv now preserve rotate-right semantics and operands.",
    "MIPS rotate idioms remain readable in pseudocode.",
    "RISC-V clmul, clmulh, and clmulr now preserve carry-less multiplication semantics.",
    "RISC-V cryptographic bitmanip operations remain named and readable in pseudocode.",
    "AArch64 abs, sabd, and uabd now preserve absolute and signed/unsigned absolute-difference semantics.",
    "AArch64 DSP-style difference operations remain readable in pseudocode.",
    "AArch64 signed and unsigned min/max operations now decompile as readable conditional selections.",
    "AArch64 bounds and comparison idioms preserve signedness in pseudocode.",
    "AArch64 AES round, inverse/mix, and PMULL operations now preserve named crypto semantics and operands.",
    "Common AArch64 cryptographic instructions remain visible in pseudocode.",
    "PowerPC popcntw and popcntd now decompile as named population-count operations.",
    "PowerPC bit-count semantics remain readable across 32-bit and 64-bit forms.",
    "MIPS ext and ins now preserve explicit bitfield extraction and insertion operands.",
    "MIPS bitfield operations remain readable in pseudocode instead of opaque intrinsics.",
    "MIPS seb, seh, and wsbh now preserve sign-extension and byte-shuffle semantics.",
    "Common MIPS endian and narrow-integer idioms remain readable in pseudocode.",
    "MIPS clz and clo now decompile as named count-leading-zero and count-leading-one operations.",
    "MIPS bit-count idioms remain readable in pseudocode.",
    "AArch64 CRC32 and CRC32C instructions now preserve named checksum semantics and operands.",
    "Common AArch64 checksum idioms remain readable in pseudocode.",
    "AArch64 clz, cls, rbit, and byte-reversal instructions now decompile as named operations.",
    "AArch64 bit and endian idioms remain readable instead of opaque generic calls.",
    "x86/x64 BMI2 shlx, shrx, and sarx now preserve variable-shift semantics in pseudocode.",
    "Signed and unsigned variable right shifts remain distinguishable in decompilation.",
    "RISC-V bext, bdep, bcompress, and bdecompress now preserve named bit extract/deposit semantics.",
    "RISC-V bitmanip data flow remains visible in pseudocode.",
    "RISC-V rol, ror, word rotate forms, and rev8 now decompile as named rotate and byte-reverse operations.",
    "RISC-V bitmanip rotate semantics remain visible in pseudocode.",
    "x86/x64 adcx and adox now preserve named carry-chain arithmetic for multi-precision code.",
    "Carry-domain arithmetic remains visible instead of falling through to an opaque intrinsic.",
    "PowerPC cntlzw and cntlzd now decompile as named count-leading-zero operations.",
    "PowerPC bit-count semantics remain readable across 32-bit and 64-bit forms.",
    "RISC-V andn, orn, and xnor now decompile as explicit complement-and-combine expressions.",
    "RISC-V bit-manipulation extension semantics remain visible in pseudocode.",
    "RISC-V clz, ctz, and cpop now decompile as named bit-count operations, including word forms.",
    "RISC-V bit-manipulation idioms remain readable instead of falling through to opaque instructions.",
    "RISC-V min, max, minu, and maxu now decompile as signed or unsigned conditional selections.",
    "Common RISC-V bounds and comparison idioms remain readable in pseudocode.",
    "ARM/Thumb usat and ssat now preserve saturating arithmetic semantics with explicit value and limit operands.",
    "ARM/Thumb DSP-style saturation instructions no longer become opaque intrinsic calls.",
    "x86/x64 BMI2 mulx now preserves both low and high products from implicit RDX input.",
    "x86/x64 rorx now decompiles as a flag-independent rotate operation.",
    "PowerPC isel now preserves conditional selection operands in pseudocode.",
    "PowerPC conditional data flow remains visible through an explicit semantic helper.",
    "ARM/Thumb clz, rev, rev16, and revsh now decompile as named count-leading-zero and byte-reversal operations.",
    "Common ARM bit/byte idioms remain visible and readable instead of opaque intrinsic calls.",
    "MIPS movz and movn now decompile as conditional selections instead of opaque operations.",
    "MIPS register-dependent value flow is preserved in readable ternary expressions.",
    "ARM/Thumb mla and mls now lift to readable multiply-accumulate and multiply-subtract expressions.",
    "Common ARM arithmetic idioms no longer fall through to opaque intrinsic calls.",
    "PowerPC mulhw, mulhwu, mulhd, and mulhdu now preserve signed and unsigned high-half products in pseudocode.",
    "PowerPC wide multiplication is represented with explicit semantic helpers instead of an opaque instruction.",
    "RISC-V mulh, mulhu, and mulhsu now preserve signed and unsigned high-half product semantics in pseudocode.",
    "High-half multiplication is represented with named semantic helpers instead of an opaque unsupported instruction.",
    "MIPS signed and unsigned division now preserve quotient in LO and remainder in HI for mflo/mfhi consumers.",
    "MIPS division and multiply share explicit HI/LO data flow in pseudocode.",
    "MIPS mult, multu, dmult, and dmultu now preserve implicit HI/LO results through mfhi and mflo.",
    "MIPS wide multiply pseudocode no longer drops the architecture's hidden result pair.",
    "ARM/Thumb long multiply and accumulate instructions now preserve both low and high result registers in pseudocode.",
    "Long arithmetic is represented with explicit wide-value helpers instead of silently dropping the upper half.",
    "Stripped functions ending in an architectural stop/trap instruction are now conservatively inferred as no-return.",
    "Trap-terminated x86-64 functions now have regression coverage.",
    "ARM64 scaled switch-table offsets and halfword entries now honor big-endian binaries.",
    "Common switch-table support now spans x86, ARM, RISC-V, MIPS, and PowerPC, with remaining compiler idioms still tracked.",
    "Thumb indexed ldr pc, [pc, index, lsl #2] jump tables now recover bounded absolute targets.",
    "Recovered targets are validated against executable mappings and decoded instructions before becoming switch cases.",
    "Mach-O LC_DATA_IN_CODE ranges are excluded from executable discovery.",
    "Analysis notes record recognized embedded-data ranges in Mach-O files.",
    "Decompiler types survive unambiguous call-result copy chains and explicit casts.",
    "Conflicting or unknown repeated assignments remain conservatively untyped.",
    "The macOS release build now uses an explicit Apple Silicon runner with verbose diagnostics.",
    "Decompiler type propagation recognizes both internal and owned cast expressions.",
    "Dereferences of known pointer-returning calls and explicit pointer casts render their pointee types.",
    "Copied pointer temporaries retain inferred pointee types in subsequent memory reads.",
    "Versioned .lensproj manifests group multiple binaries and open the selected active file.",
    "File > Save Project creates or updates a .lensproj manifest from the current session.",
    "File > Add File to Project appends binaries with duplicate detection and persistence.",
    "Opening a project member keeps the workspace active and records the active file.",
    "Relative project members resolve from the .lensproj directory for portable projects.",
    "Resolved absolute paths continue to match relative project members when switching files.",
    "Save Project serializes in-project members as relative paths for portability.",
    "Decompiler branch structuring now preserves loop headers inside forward conditional regions.",
    "The Overview displays project members and opens them directly.",
    "The active project indicator resolves relative manifest paths correctly.",
];

pub fn current_release_title() -> String {
    format!("Lens {CURRENT} — {CODENAME}")
}

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub notes: String,
    pub url: String,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    assets: Vec<GhAsset>,
}
#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

pub enum Status {
    Idle,
    Checking(Receiver<Result<Option<Release>, String>>),
    Available(Release),
    Downloading(Release, Receiver<Result<(), String>>, Arc<Progress>),
    /// The new version is in place; the app closes itself and reopens.
    Restarting(Instant),
    Failed(String, Instant),
    UpToDate(Instant),
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(180)))
        .user_agent(concat!("Lens/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn parse_ver(s: &str) -> Vec<u64> {
    s.trim_start_matches('v').split(['.', '-', '+']).map(|p| p.parse().unwrap_or(0)).collect()
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (a, b) = (parse_ver(candidate), parse_ver(current));
    for i in 0..3 {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    false
}

pub fn check_async() -> Receiver<Result<Option<Release>, String>> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(check());
    });
    rx
}

fn check() -> Result<Option<Release>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let mut resp = agent().get(&url).header("Accept", "application/vnd.github+json").call().map_err(|e| match e {
        ureq::Error::StatusCode(404) => "No releases published yet".to_string(),
        e => format!("Couldn't reach GitHub: {e}"),
    })?;
    let r: GhRelease = resp.body_mut().read_json().map_err(|e| e.to_string())?;
    if !is_newer(&r.tag_name, CURRENT) {
        return Ok(None);
    }
    let asset = r.assets.iter().find(|a| a.name == ASSET).ok_or("The new release has no Apple Silicon download")?;
    Ok(Some(Release {
        version: r.tag_name.trim_start_matches('v').to_string(),
        notes: r.body.unwrap_or_default(),
        url: asset.browser_download_url.clone(),
    }))
}

/// The .app bundle we're running from, if any (a `cargo run` build has none and can't self-update).
pub fn bundle_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let app = exe.parent()?.parent()?.parent()?;
    app.extension().map(|e| e == "app").unwrap_or(false).then(|| app.to_path_buf())
}

pub fn install_async(rel: Release) -> (Receiver<Result<(), String>>, Arc<Progress>) {
    let (tx, rx) = channel();
    let prog = Arc::new(Progress::default());
    let p2 = prog.clone();
    std::thread::spawn(move || {
        let _ = tx.send(install(&rel, &p2));
    });
    (rx, prog)
}

fn install(rel: &Release, prog: &Progress) -> Result<(), String> {
    let app = bundle_path().ok_or("Lens isn't running from an installed app, so it can't update itself. Download the new version from the GitHub releases page.")?;
    let parent = app.parent().ok_or("bad app path")?;
    // make sure we can write next to the old app before downloading anything
    let probe = parent.join(".lens-write-test");
    std::fs::write(&probe, b"").map_err(|_| format!("No permission to replace {}. Move Lens to Applications or ~/Applications.", app.display()))?;
    let _ = std::fs::remove_file(probe);
    let work = std::env::temp_dir().join(format!("lens-update-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let zip = work.join(ASSET);
    let mut resp = agent().get(&rel.url).call().map_err(|e| format!("Download failed: {e}"))?;
    let total = resp.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    prog.total.store(total, Ordering::Relaxed);
    let mut f = std::fs::File::create(&zip).map_err(|e| e.to_string())?;
    {
        use std::io::{Read, Write};
        let mut r = resp.body_mut().as_reader();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = r.read(&mut buf).map_err(|e| format!("Download failed: {e}"))?;
            if n == 0 { break; }
            f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            prog.done.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
    drop(f);
    prog.phase.store(1, Ordering::Relaxed);
    let out = work.join("new");
    run("ditto", &["-x", "-k", zip.to_str().unwrap(), out.to_str().unwrap()])?;
    let new_app = out.join("Lens.app");
    if !new_app.join("Contents/MacOS/Lens").exists() {
        return Err("The download didn't contain Lens.app".into());
    }
    run("codesign", &["--verify", "--deep", new_app.to_str().unwrap()])?;
    let script = format!(
        r#"while kill -0 {pid} 2>/dev/null; do sleep 0.2; done
OLD={old}; NEW={new}
mv "$OLD" "$OLD.old" && mv "$NEW" "$OLD" || {{ mv "$OLD.old" "$OLD" 2>/dev/null; open "$OLD"; exit 1; }}
xattr -dr com.apple.quarantine "$OLD" 2>/dev/null
rm -rf "$OLD.old" {work}
open "$OLD"
"#,
        pid = std::process::id(),
        old = sh(&app),
        new = sh(&new_app),
        work = sh(&work)
    );
    let sp = work.join("swap.sh");
    std::fs::write(&sp, script).map_err(|e| e.to_string())?;
    std::process::Command::new("/bin/sh")
        .arg(&sp)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn sh(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', r"'\''"))
}

fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let o = std::process::Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if o.status.success() { Ok(()) } else { Err(format!("{cmd} failed: {}", String::from_utf8_lossy(&o.stderr).trim())) }
}

#[cfg(test)]
mod tests {
    use super::is_newer;
    #[test]
    fn versions() {
        assert!(is_newer("v0.2.0", "0.1.9"));
        assert!(is_newer("0.1.10", "0.1.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
    }
}
