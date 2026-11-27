//! Works out what a program is: file kind, compiler / toolchain, language, packer, protections,
//! calling convention and where the real `main` is. Everything the decompiler needs is chosen
//! here, so the person only has to open a file.

use crate::analysis::{Analysis, Flow, FuncKind};
use crate::loader::{Arch, Binary};
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CallConv {
    /// Microsoft x64: rcx, rdx, r8, r9 + 32 bytes of shadow space.
    Win64,
    /// System V AMD64 (Linux, macOS, BSD): rdi, rsi, rdx, rcx, r8, r9.
    SysV64,
    /// 32-bit, every argument on the stack.
    Cdecl32,
    /// 32-bit MSVC fastcall / thiscall: ecx, edx then stack.
    Fastcall32,
    /// Delphi / Borland register convention: eax, edx, ecx then stack.
    Delphi32,
    /// Go register ABI (1.17+): rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11.
    GoAbi,
    /// Non-x86 CPUs: the standard ABI for that architecture (not used by the decompiler yet).
    Native(&'static str),
}

impl CallConv {
    pub fn arg_regs(self) -> &'static [&'static str] {
        match self {
            CallConv::Win64 => &["rcx", "rdx", "r8", "r9"],
            CallConv::SysV64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            CallConv::Cdecl32 => &[],
            CallConv::Fastcall32 => &["rcx", "rdx"],
            CallConv::Delphi32 => &["rax", "rdx", "rcx"],
            CallConv::GoAbi => &["rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11"],
            CallConv::Native(_) => &[],
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            CallConv::Win64 => "Microsoft x64 (rcx, rdx, r8, r9)",
            CallConv::SysV64 => "System V AMD64 (rdi, rsi, rdx, rcx, r8, r9)",
            CallConv::Cdecl32 => "32-bit cdecl / stdcall (arguments on the stack)",
            CallConv::Fastcall32 => "32-bit fastcall / thiscall (ecx, edx, then stack)",
            CallConv::Delphi32 => "Delphi register convention (eax, edx, ecx, then stack)",
            CallConv::GoAbi => "Go register ABI (rax, rbx, rcx, rdi, rsi, r8…)",
            CallConv::Native(l) => l,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Guess {
    pub name: String,
    /// 0.0 – 1.0
    pub score: f32,
    pub why: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Capability {
    pub name: &'static str,
    pub apis: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ThreatSignal {
    /// 1 = noteworthy, 2 = suspicious, 3 = high-risk heuristic.
    pub severity: u8,
    pub name: String,
    pub evidence: String,
}

#[derive(Clone, Debug)]
pub struct Detection {
    /// "Windows GUI program", "macOS app", "Linux program", …
    pub kind: String,
    pub os: String,
    pub arch: String,
    pub bits: u32,
    pub container: Vec<String>,
    pub compilers: Vec<Guess>,
    pub languages: Vec<Guess>,
    pub packers: Vec<Guess>,
    pub protections: Vec<(String, bool)>,
    pub stripped: bool,
    pub has_debug_info: bool,
    pub conv: CallConv,
    pub plan: Vec<String>,
    pub app_info: Vec<(String, String)>,
    pub capabilities: Vec<Capability>,
    /// Entropy (0–8) of 256 equal slices of the file.
    pub entropy: Vec<f32>,
    pub overall_entropy: f32,
    pub sha256: String,
    pub timestamp: Option<u64>,
    /// Address of the program's own `main` (not the C runtime start-up) and how it was found.
    pub main: Option<(u64, String)>,
    /// The program is managed code (.NET) or bytecode that a native lifter can't read.
    pub unsupported_note: Option<String>,
    /// Electron apps: the archive holding the real JavaScript.
    pub asar: Option<crate::source::AsarInfo>,
    /// Cryptographic constants found in the bytes: (address, constant, algorithm).
    pub crypto: Vec<(u64, String, String)>,
    /// Heuristic behavior signals; these are triage hints, not a malware verdict.
    pub threat_signals: Vec<ThreatSignal>,
}

impl Detection {
    pub fn compiler(&self) -> &str {
        self.compilers.first().map(|g| g.name.as_str()).unwrap_or("unknown")
    }
    pub fn language(&self) -> &str {
        self.languages.first().map(|g| g.name.as_str()).unwrap_or("unknown")
    }
}

fn threat_signals(capabilities: &[Capability], packers: &[Guess], protections: &[(String, bool)], entropy: f32) -> Vec<ThreatSignal> {
    let mut out = Vec::new();
    let has = |name: &str| capabilities.iter().find(|c| c.name == name);
    if let Some(c) = has("Processes") {
        out.push(ThreatSignal { severity: 2, name: "Process execution".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("Registry & settings") {
        out.push(ThreatSignal { severity: 3, name: "Persistence behavior".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("Keyboard & screen capture") {
        out.push(ThreatSignal { severity: 3, name: "Input or screen capture".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("Anti-debugging") {
        out.push(ThreatSignal { severity: 2, name: "Anti-analysis behavior".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("Memory tricks") {
        out.push(ThreatSignal { severity: 2, name: "Executable memory or process tampering".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("Loads code at run time") {
        out.push(ThreatSignal { severity: 2, name: "Runtime code loading".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("Network") {
        out.push(ThreatSignal { severity: 1, name: "Network communication".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("Files") {
        out.push(ThreatSignal { severity: 1, name: "Filesystem activity".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("System info") {
        out.push(ThreatSignal { severity: 1, name: "System information discovery".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("Threads & timing") {
        out.push(ThreatSignal { severity: 1, name: "Threading or timing behavior".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("Cryptography") {
        out.push(ThreatSignal { severity: 1, name: "Cryptographic activity".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if let Some(c) = has("Windows & UI") {
        out.push(ThreatSignal { severity: 1, name: "Desktop or UI interaction".into(), evidence: format!("imports: {}", c.apis.join(", ")) });
    }
    if capabilities.len() >= 3 {
        out.push(ThreatSignal {
            severity: 2,
            name: "Multiple behavior categories".into(),
            evidence: format!("{} capability categories detected; review the individual imports and execution paths", capabilities.len()),
        });
    }
    if capabilities.len() >= 6 {
        out.push(ThreatSignal {
            severity: 2,
            name: "Broad capability profile".into(),
            evidence: format!("{} capability categories detected; prioritize cross-category review", capabilities.len()),
        });
    }
    if !packers.is_empty() {
        out.push(ThreatSignal { severity: 2, name: "Packing or obfuscation".into(), evidence: packers.iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ") });
    }
    if entropy >= 7.4 {
        out.push(ThreatSignal { severity: 2, name: "High file entropy".into(), evidence: format!("overall entropy {:.2} of 8; compressed or encrypted content is possible", entropy) });
    }
    if protections.iter().any(|(name, enabled)| *enabled && name.to_ascii_lowercase().contains("aslr")) {
        out.push(ThreatSignal { severity: 1, name: "ASLR enabled".into(), evidence: "hardening context; not inherently suspicious".into() });
    }
    if protections.iter().any(|(name, enabled)| !*enabled && name.to_ascii_lowercase().contains("aslr")) {
        out.push(ThreatSignal { severity: 1, name: "ASLR disabled".into(), evidence: "weaker address-randomization posture; review with other evidence".into() });
    }
    if protections.iter().any(|(name, enabled)| !*enabled && (name.to_ascii_lowercase().contains("dep") || name.to_ascii_lowercase().contains("nx"))) {
        out.push(ThreatSignal { severity: 1, name: "DEP or NX disabled".into(), evidence: "executable-memory hardening is reduced; review with other evidence".into() });
    }
    if protections.iter().any(|(name, enabled)| !*enabled && name.to_ascii_lowercase().contains("stack")) {
        out.push(ThreatSignal { severity: 1, name: "Stack protection disabled".into(), evidence: "stack-hardening posture is reduced; review with other evidence".into() });
    }
    if protections.iter().any(|(name, enabled)| !*enabled && name.to_ascii_lowercase().contains("cfg")) {
        out.push(ThreatSignal { severity: 1, name: "Control-flow guard disabled".into(), evidence: "indirect-control-flow hardening is reduced; review with other evidence".into() });
    }
    if protections.iter().any(|(name, enabled)| !*enabled && (name.to_ascii_lowercase().contains("signature") || name.to_ascii_lowercase().contains("signed"))) {
        out.push(ThreatSignal { severity: 1, name: "Code signature unavailable".into(), evidence: "signature protection or validation is unavailable; review provenance separately".into() });
    }
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.name.cmp(&b.name)));
    out
}

#[derive(Default)]
struct Acc {
    m: BTreeMap<String, (f32, Vec<String>)>,
}

impl Acc {
    fn add(&mut self, name: &str, pts: f32, why: impl Into<String>) {
        let e = self.m.entry(name.to_string()).or_insert((0.0, vec![]));
        e.0 = (e.0 + pts).min(1.0);
        e.1.push(why.into());
    }
    fn done(self, min: f32) -> Vec<Guess> {
        let mut v: Vec<Guess> = self
            .m
            .into_iter()
            .filter(|(_, (s, _))| *s >= min)
            .map(|(name, (score, why))| Guess { name, score, why })
            .collect();
        v.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        v
    }
}

// ---------------------------------------------------------------- hashing / entropy

fn sha256(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut block = |chunk: &[u8]| {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    };
    let mut chunks = data.chunks_exact(64);
    for c in &mut chunks {
        block(c);
    }
    let rem = chunks.remainder();
    let mut tail = rem.to_vec();
    tail.push(0x80);
    while tail.len() % 64 != 56 {
        tail.push(0);
    }
    tail.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for c in tail.chunks_exact(64) {
        block(c);
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

fn entropy_of(b: &[u8]) -> f32 {
    if b.is_empty() {
        return 0.0;
    }
    let mut c = [0u32; 256];
    for x in b {
        c[*x as usize] += 1;
    }
    let n = b.len() as f32;
    c.iter().filter(|v| **v > 0).map(|v| {
        let p = *v as f32 / n;
        -p * p.log2()
    }).sum()
}

// ---------------------------------------------------------------- format specific readers

#[derive(Default)]
struct Raw {
    subsystem: Option<u16>,
    is_dll: bool,
    dll_chars: u16,
    clr: bool,
    signed: bool,
    rich: Vec<(u16, u16, u32)>,
    linker: Option<(u8, u8)>,
    os_version: Option<(u16, u16)>,
    timestamp: Option<u64>,
    comment: Vec<String>,
    interp: Option<String>,
    pie: bool,
    nx: Option<bool>,
    relro: Option<&'static str>,
    macho_flags: u32,
    macho_signed: bool,
    macho_min: Option<String>,
    macho_platform: Option<&'static str>,
    elf_abi: Option<String>,
    section_names: Vec<String>,
    debug_info: bool,
    stripped: bool,
}

fn parse_rich(bytes: &[u8]) -> Vec<(u16, u16, u32)> {
    let head = &bytes[..bytes.len().min(0x400)];
    let Some(rp) = head.windows(4).position(|w| w == b"Rich") else { return vec![] };
    if rp + 8 > head.len() {
        return vec![];
    }
    let key = u32::from_le_bytes([head[rp + 4], head[rp + 5], head[rp + 6], head[rp + 7]]);
    let mut vals = vec![];
    let mut i = rp;
    while i >= 4 {
        i -= 4;
        let v = u32::from_le_bytes([head[i], head[i + 1], head[i + 2], head[i + 3]]) ^ key;
        if v == 0x536e6144 {
            // "DanS"
            vals.reverse();
            // skip three padding dwords after DanS
            let mut out = vec![];
            for pair in vals.chunks_exact(2).skip(0) {
                let (cmp, cnt) = (pair[0], pair[1]);
                if cmp == 0 && cnt == 0 {
                    continue;
                }
                out.push(((cmp >> 16) as u16, (cmp & 0xffff) as u16, cnt));
            }
            return out;
        }
        vals.push(v);
    }
    vec![]
}

fn read_raw(bin: &Binary, bytes: &[u8]) -> Raw {
    use goblin::Object;
    let mut r = Raw::default();
    match Object::parse(bytes) {
        Ok(Object::PE(pe)) => {
            r.rich = parse_rich(bytes);
            r.is_dll = pe.is_lib;
            r.timestamp = Some(pe.header.coff_header.time_date_stamp as u64);
            if let Some(oh) = pe.header.optional_header {
                r.subsystem = Some(oh.windows_fields.subsystem);
                r.dll_chars = oh.windows_fields.dll_characteristics;
                r.linker = Some((oh.standard_fields.major_linker_version, oh.standard_fields.minor_linker_version));
                r.os_version = Some((oh.windows_fields.major_operating_system_version, oh.windows_fields.minor_operating_system_version));
                r.clr = oh.data_directories.get_clr_runtime_header().is_some();
                r.signed = oh.data_directories.get_certificate_table().is_some();
            }
            for s in &pe.sections {
                r.section_names.push(s.name().unwrap_or("").to_string());
            }
            r.debug_info = pe.debug_data.is_some();
            r.stripped = pe.exports.is_empty() && bin.symbols.is_empty() && !r.debug_info;
        }
        Ok(Object::Elf(elf)) => {
            use goblin::elf::program_header::*;
            r.pie = elf.header.e_type == goblin::elf::header::ET_DYN;
            r.interp = elf.interpreter.map(|s| s.to_string());
            for ph in &elf.program_headers {
                if ph.p_type == PT_GNU_STACK {
                    r.nx = Some(ph.p_flags & PF_X == 0);
                }
                if ph.p_type == PT_GNU_RELRO {
                    r.relro = Some("partial");
                }
            }
            if let Some(d) = &elf.dynamic {
                if d.info.flags & 0x8 != 0 || d.info.flags_1 & 0x1 != 0 {
                    if r.relro.is_some() {
                        r.relro = Some("full");
                    }
                }
            }
            r.elf_abi = Some(
                match elf.header.e_ident[7] {
                    0 => "System V",
                    3 => "GNU/Linux",
                    6 => "Solaris",
                    9 => "FreeBSD",
                    12 => "OpenBSD",
                    _ => "unknown",
                }
                .to_string(),
            );
            for sh in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                r.section_names.push(name.to_string());
                if name == ".comment" {
                    let s = sh.sh_offset as usize;
                    let e = (s + sh.sh_size as usize).min(bytes.len());
                    if let Some(c) = bytes.get(s..e) {
                        for part in c.split(|b| *b == 0) {
                            let t = String::from_utf8_lossy(part).trim().to_string();
                            if !t.is_empty() && !r.comment.contains(&t) {
                                r.comment.push(t);
                            }
                        }
                    }
                }
                if name.starts_with(".debug_") || name == ".zdebug_info" {
                    r.debug_info = true;
                }
            }
            r.stripped = elf.syms.is_empty();
        }
        Ok(Object::Mach(m)) => {
            use goblin::mach::{Mach, SingleArch};
            let single = match m {
                Mach::Binary(b) => Some(b),
                Mach::Fat(fat) => {
                    let mut pick = None;
                    if let Ok(arches) = fat.arches() {
                        for (i, a) in arches.iter().enumerate() {
                            if a.cputype == goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
                                pick = Some(i);
                            }
                        }
                    }
                    match fat.get(pick.unwrap_or(0)) {
                        Ok(SingleArch::MachO(m)) => Some(m),
                        _ => None,
                    }
                }
            };
            if let Some(m) = single {
                use goblin::mach::load_command::CommandVariant as C;
                r.macho_flags = m.header.flags;
                r.pie = m.header.flags & 0x200000 != 0;
                for lc in &m.load_commands {
                    match &lc.command {
                        C::CodeSignature(_) => r.macho_signed = true,
                        C::BuildVersion(b) => {
                            r.macho_min = Some(format!("{}.{}.{}", b.minos >> 16, (b.minos >> 8) & 0xff, b.minos & 0xff));
                            r.macho_platform = Some(match b.platform {
                                1 => "macOS",
                                2 => "iOS",
                                3 => "tvOS",
                                4 => "watchOS",
                                6 => "Mac Catalyst",
                                7 => "iOS Simulator",
                                _ => "Apple platform",
                            });
                        }
                        C::VersionMinMacosx(v) => {
                            r.macho_min = Some(format!("{}.{}.{}", v.version >> 16, (v.version >> 8) & 0xff, v.version & 0xff));
                            r.macho_platform = Some("macOS");
                        }
                        C::VersionMinIphoneos(v) => {
                            r.macho_min = Some(format!("{}.{}.{}", v.version >> 16, (v.version >> 8) & 0xff, v.version & 0xff));
                            r.macho_platform = Some("iOS");
                        }
                        _ => {}
                    }
                }
                r.stripped = m.symbols.as_ref().map(|s| s.iter().count() < 8).unwrap_or(true);
                r.debug_info = m.segments.iter().any(|s| s.name().map(|n| n == "__DWARF").unwrap_or(false));
                r.section_names = bin.segments.iter().map(|s| s.name.clone()).collect();
            }
        }
        _ => {}
    }
    r
}

// ---------------------------------------------------------------- app bundle

fn plist_value(xml: &str, key: &str) -> Option<String> {
    let k = format!("<key>{key}</key>");
    let i = xml.find(&k)? + k.len();
    let rest = &xml[i..];
    let a = rest.find("<string>")? + 8;
    let b = rest[a..].find("</string>")?;
    // make sure the value belongs to this key (no other <key> in between)
    if rest[..a].contains("<key>") {
        return None;
    }
    Some(rest[a..a + b].trim().to_string())
}

fn app_frameworks_has(path: &str, name: &str) -> bool {
    let p = std::path::Path::new(path);
    let Some(app) = p.ancestors().find(|a| a.extension().map(|e| e == "app").unwrap_or(false)) else { return false };
    app.join("Contents/Frameworks").join(format!("{name}.framework")).exists()
}

fn bundle_info(path: &str) -> (Vec<String>, Vec<(String, String)>) {
    let mut container = vec![];
    let mut info = vec![];
    let p = std::path::Path::new(path);
    let Some(app) = p.ancestors().find(|a| a.extension().map(|e| e == "app").unwrap_or(false)) else {
        return (container, info);
    };
    container.push(format!(
        "macOS application bundle {} — main program {}",
        app.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
        p.strip_prefix(app).map(|r| r.display().to_string()).unwrap_or_default()
    ));
    if let Ok(text) = std::fs::read(app.join("Contents/Info.plist")) {
        if text.starts_with(b"bplist") {
            info.push(("Info.plist".into(), "binary property list (not read)".into()));
        } else {
            let xml = String::from_utf8_lossy(&text);
            for (k, label) in [
                ("CFBundleIdentifier", "Bundle id"),
                ("CFBundleName", "Name"),
                ("CFBundleShortVersionString", "Version"),
                ("CFBundleVersion", "Build"),
                ("LSMinimumSystemVersion", "Needs macOS"),
                ("CFBundleExecutable", "Main program"),
                ("NSPrincipalClass", "Principal class"),
                ("DTXcode", "Built with Xcode"),
                ("DTSDKName", "SDK"),
            ] {
                if let Some(v) = plist_value(&xml, k) {
                    info.push((label.to_string(), v));
                }
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(app.join("Contents/Frameworks")) {
        let mut fw: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .map(|s| s.trim_end_matches(".framework").trim_end_matches(".dylib").to_string())
            .collect();
        fw.sort();
        if !fw.is_empty() {
            let n = fw.len();
            let shown: Vec<String> = fw.into_iter().take(8).collect();
            info.push(("Bundled frameworks".into(), format!("{n}: {}{}", shown.join(", "), if n > 8 { ", …" } else { "" })));
        }
    }
    (container, info)
}

// ---------------------------------------------------------------- capabilities

const CAPS: &[(&str, &[&str])] = &[
    ("Network", &["socket", "connect", "WSAStartup", "WSASocket", "InternetOpen", "InternetConnect", "WinHttp", "URLDownloadToFile", "getaddrinfo", "gethostbyname", "curl_easy", "CFNetwork", "NSURLSession", "NSURLConnection", "send", "recv", "bind", "listen", "accept", "SSL_", "inet_"]),
    ("Files", &["CreateFile", "ReadFile", "WriteFile", "DeleteFile", "FindFirstFile", "CopyFile", "MoveFile", "fopen", "fread", "fwrite", "unlink", "opendir", "readdir", "stat", "NSFileManager", "open", "rename", "mkdir"]),
    ("Processes", &["CreateProcess", "ShellExecute", "WinExec", "execve", "execl", "execv", "fork", "posix_spawn", "system", "popen", "NSTask", "OpenProcess", "TerminateProcess"]),
    ("Registry & settings", &["RegOpenKey", "RegSetValue", "RegQueryValue", "RegCreateKey", "RegDeleteKey", "NSUserDefaults", "CFPreferences", "GetPrivateProfile"]),
    ("Cryptography", &["Crypt", "BCrypt", "NCrypt", "EVP_", "AES_", "RSA_", "SHA256", "MD5", "CC_SHA", "CC_MD5", "CCCrypt", "SecKey", "SecRandom", "mbedtls", "sodium_", "gcry_"]),
    ("Memory tricks", &["VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "mprotect", "mmap", "ptrace", "task_for_pid", "mach_vm_"]),
    ("Anti-debugging", &["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString", "ptrace", "sysctl", "PT_DENY_ATTACH"]),
    ("Loads code at run time", &["LoadLibrary", "GetProcAddress", "LdrLoadDll", "dlopen", "dlsym", "NSBundle", "CFBundle"]),
    ("Windows & UI", &["CreateWindow", "MessageBox", "DialogBox", "RegisterClass", "GetMessage", "DispatchMessage", "NSWindow", "NSApplication", "NSView", "UIApplication", "gtk_", "SDL_", "glfw", "QApplication"]),
    ("Keyboard & screen capture", &["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetDC", "BitBlt", "CGEventTap", "CGWindowListCreateImage", "CGDisplayCreateImage"]),
    ("Threads & timing", &["CreateThread", "pthread_create", "WaitForSingleObject", "Sleep", "dispatch_async", "NSThread", "std::thread", "EnterCriticalSection", "pthread_mutex"]),
    ("System info", &["GetSystemInfo", "GetVersionEx", "GetComputerName", "GetUserName", "gethostname", "uname", "getpwuid", "NSProcessInfo", "sysconf"]),
];

fn capabilities(names: &[&str]) -> Vec<Capability> {
    let mut out = vec![];
    for (cat, keys) in CAPS {
        let mut hit: Vec<String> = vec![];
        for n in names {
            let clean = n.trim_start_matches('_');
            if keys.iter().any(|k| {
                // short generic words must match exactly, longer ones by prefix / containment
                if k.len() <= 6 {
                    clean == *k || clean.trim_end_matches(['A', 'W']) == *k
                } else {
                    clean.starts_with(k) || clean.contains(k)
                }
            }) && !hit.iter().any(|h| h == n)
            {
                hit.push(n.to_string());
            }
        }
        if !hit.is_empty() {
            hit.truncate(12);
            out.push(Capability { name: cat, apis: hit });
        }
    }
    out
}

// ---------------------------------------------------------------- the detector

pub fn detect(bin: &Binary, an: &Analysis) -> Detection {
    let bytes = std::fs::read(&bin.path).unwrap_or_default();
    let raw = read_raw(bin, &bytes);
    let is_pe = bin.format.starts_with("PE");
    let is_elf = bin.format.starts_with("ELF");
    let is_macho = bin.format.starts_with("Mach-O");

    // lower-cased pools to search
    let sym_names: Vec<&str> = bin
        .symbols
        .iter()
        .map(|s| s.1.as_str())
        .chain(bin.data_symbols.iter().map(|s| s.1.as_str()))
        .chain(bin.imports.iter().map(|i| i.name.as_str()))
        .chain(bin.exports.iter().map(|e| e.name.as_str()))
        .collect();
    let libs: Vec<String> = bin.libraries.iter().map(|l| l.to_lowercase()).collect();
    let strs: Vec<&str> = an.strings.iter().map(|s| s.text.as_str()).collect();
    let has_sym = |p: &str| sym_names.iter().any(|s| s.contains(p));
    let sym_count = |p: &str| sym_names.iter().filter(|s| s.contains(p)).count();
    let has_str = |p: &str| strs.iter().any(|s| s.contains(p));
    let has_lib = |p: &str| libs.iter().any(|l| l.contains(p));
    let has_sec = |p: &str| raw.section_names.iter().any(|s| s.to_lowercase().contains(p));

    let mut comp = Acc::default();
    let mut lang = Acc::default();
    let mut pack = Acc::default();

    // ---- Microsoft
    if is_pe {
        if !raw.rich.is_empty() {
            let max_build = raw.rich.iter().filter(|r| r.0 >= 0x80).map(|r| r.1).max().unwrap_or(0);
            let tools: Vec<u16> = raw.rich.iter().map(|r| r.0).collect();
            let vs = match max_build {
                b if b >= 33000 => "Visual Studio 2022 17.10+ (19.4x)",
                b if b >= 30000 => "Visual Studio 2022 (19.3x)",
                b if b >= 27000 => "Visual Studio 2019 (19.2x)",
                b if b >= 25000 => "Visual Studio 2017 (19.1x)",
                b if b >= 23000 => "Visual Studio 2015 (19.0)",
                b if b >= 21000 => "Visual Studio 2013 (18.0)",
                _ => "an older Visual Studio",
            };
            let cl = tools.iter().any(|t| (0x5d..=0x7f).contains(t) || *t >= 0x100);
            comp.add(
                &format!("Microsoft Visual C/C++ — {vs}"),
                0.85,
                format!("Rich header lists Microsoft build tools (newest build {max_build})"),
            );
            if cl {
                comp.add(&format!("Microsoft Visual C/C++ — {vs}"), 0.1, "Rich header contains cl.exe compiler records");
            }
        } else if let Some((a, b)) = raw.linker {
            if a >= 6 && a <= 14 && !has_str("GCC:") && !has_sym("__mingw") {
                comp.add("Microsoft Visual C/C++ (probable)", 0.3, format!("Linker version {a}.{b} is Microsoft's style"));
            }
        }
        if has_sym("__scrt_common_main") || has_sym("_initterm") || has_lib("vcruntime") || has_lib("msvcp") || has_lib("ucrtbase") {
            let top = comp.m.keys().find(|k| k.starts_with("Microsoft Visual C/C++")).cloned();
            match top {
                Some(k) => comp.add(&k, 0.1, "Links the Microsoft C runtime (vcruntime / ucrt / msvcp)"),
                None => comp.add("Microsoft Visual C/C++", 0.6, "Links the Microsoft C runtime (vcruntime / ucrt / msvcp)"),
            }
        }
        if has_str("GCC: (") || has_sym("__mingw") || has_sym("_pei386_runtime_relocator") || has_sec(".ctors") && has_sec(".eh_fram") {
            comp.add("MinGW-w64 (GCC)", 0.8, "GCC / MinGW runtime markers");
        }
        if has_str("clang version") {
            comp.add("LLVM Clang (MinGW or clang-cl)", 0.6, "Contains a clang version string");
        }
        if has_str("Borland") || has_str("Embarcadero") || has_sec("code") && has_sec("bss") && has_sec(".tls") && !has_sec(".text") {
            comp.add("Embarcadero / Borland Delphi or C++ Builder", 0.8, "Borland-style sections (CODE / DATA / BSS) or vendor text");
            lang.add("Delphi / Object Pascal", 0.7, "Borland-style section layout");
        }
        if raw.clr || has_lib("mscoree") {
            lang.add(".NET (managed code)", 1.0, "Has a CLR header / imports mscoree.dll");
            comp.add("Microsoft .NET compiler (C#, VB or F#)", 0.9, "Managed assembly");
        }
    }

    // ---- GCC / Clang (ELF, Mach-O, others)
    for c in &raw.comment {
        if c.starts_with("GCC:") {
            comp.add(&format!("GNU GCC — {}", c.trim_start_matches("GCC:").trim()), 0.9, format!(".comment says “{c}”"));
        } else if c.contains("clang version") {
            comp.add(&format!("LLVM Clang — {}", c.split("clang version").nth(1).unwrap_or("").split_whitespace().next().unwrap_or("")), 0.9, format!(".comment says “{c}”"));
        } else if c.starts_with("rustc") {
            comp.add("rustc", 0.9, format!(".comment says “{c}”"));
        } else if c.starts_with("Linker:") || c.contains("LLD") {
            comp.add("LLVM lld linker", 0.1, format!(".comment says “{c}”"));
        }
    }
    if !is_pe {
        if is_elf && has_str("GCC: (") {
            comp.add("GNU GCC", 0.6, "Contains a “GCC: (” build string");
        }
        if let Some(s) = strs.iter().find(|s| s.starts_with("Apple clang version") || s.starts_with("clang version")) {
            comp.add("LLVM Clang", 0.7, format!("Contains “{s}”"));
        }
        if is_macho && comp.m.is_empty() {
            comp.add("Apple clang / Xcode (probable)", 0.4, "Mach-O programs are almost always built with Xcode's clang");
        }
        if is_elf && comp.m.is_empty() && has_sym("__libc_start_main") {
            comp.add("GNU GCC or LLVM Clang (not recorded)", 0.3, "Standard glibc start-up, no compiler note kept");
        }
    }
    if has_sym("__gxx_personality") || has_sym("_ZNSt") || has_sym("__cxa_") || has_lib("libstdc++") || has_lib("libc++") || has_lib("msvcp") || has_sym("?") && is_pe && sym_count("@@") > 3 {
        lang.add("C++", 0.7, "C++ runtime, exceptions or mangled names");
    }
    if lang.m.get("C++").is_none() {
        lang.add("C", 0.4, "No higher-level runtime found");
    }

    // ---- Rust
    if has_str("/rustc/") || has_str("rustc version") || has_sym("rust_begin_unwind") || has_sym("core::panicking") || has_sym("_ZN4core") || has_sym("rust_eh_personality") || has_sec(".rustc") {
        lang.add("Rust", 0.95, "Rust panic / core library / personality symbols");
        comp.add("rustc (LLVM)", 0.85, "Rust runtime markers");
    }
    // ---- Go
    if has_sec("go.buildinf") || has_sec("gopclntab") || has_sym("runtime.main") || has_str("Go build ID") || has_sym("runtime.gopanic") || has_str("runtime.goexit") {
        lang.add("Go", 0.95, "Go runtime sections / symbols (gopclntab, runtime.main)");
        comp.add("Go toolchain (gc)", 0.9, "Go runtime sections / symbols");
    }
    // ---- Swift / Objective-C
    if has_lib("libswiftcore") || has_sec("__swift5") || has_sym("swift_retain") || has_sym("$s") && is_macho {
        lang.add("Swift", 0.95, "Swift runtime library / metadata sections");
        comp.add("Swift compiler (swiftc)", 0.9, "Swift metadata present");
    }
    if has_lib("libobjc") || has_sym("objc_msgSend") || has_sec("__objc_") || has_sec("__objc") {
        lang.add("Objective-C", 0.8, "Objective-C runtime (objc_msgSend, __objc_* sections)");
    }
    // ---- others
    if (has_str("PyInstaller") && has_str("_MEIPASS")) || has_lib("python3") || has_sym("Py_Initialize") {
        lang.add("Python (embedded or frozen)", 0.85, "Python runtime or PyInstaller bootloader");
    }
    let electron_bundle = app_frameworks_has(&bin.path, "Electron Framework");
    if electron_bundle || has_lib("electron framework") || has_sec("electron") {
        lang.add("JavaScript (Electron app)", 0.85, "Electron framework / app.asar");
    }
    if has_lib("qt5core") || has_lib("qt6core") || has_lib("libqt") || has_str("Qt_") && has_sym("QObject") || has_sym("_ZN7QObject") {
        lang.add("C++ with Qt", 0.8, "Links Qt");
    }
    if has_sym("nim") && has_sym("NimMain") || has_sym("NimMain") {
        lang.add("Nim", 0.9, "NimMain symbol");
        comp.add("Nim compiler", 0.8, "NimMain symbol");
    }
    if has_str("Zig") && has_sym("zig_") || has_sym("__zig_") {
        lang.add("Zig", 0.8, "Zig runtime symbols");
        comp.add("Zig compiler", 0.8, "Zig runtime symbols");
    }
    if has_sym("kotlin") || has_str("kotlin.") && has_str("Kotlin/Native") {
        lang.add("Kotlin/Native", 0.6, "Kotlin runtime strings");
    }
    if has_str("Lua ") && (has_sym("lua_") || has_sym("luaL_")) {
        lang.add("Embeds Lua", 0.5, "Lua API symbols");
    }

    // ---- packers
    for (sec, name) in [
        ("upx0", "UPX"),
        ("upx1", "UPX"),
        (".aspack", "ASPack"),
        (".adata", "ASPack"),
        (".petite", "Petite"),
        (".themida", "Themida"),
        (".vmp0", "VMProtect"),
        (".vmp1", "VMProtect"),
        ("mpress", "MPRESS"),
        (".enigma", "Enigma Protector"),
        (".nsp0", "NsPack"),
        ("pec1", "PECompact"),
        (".boom", "The Bat!/Boomerang"),
    ] {
        if has_sec(sec) {
            pack.add(name, 0.95, format!("Section named “{sec}”"));
        }
    }
    let overall = entropy_of(&bytes);
    if overall > 7.4 {
        pack.add("Compressed or encrypted payload (unidentified)", 0.55, format!("Whole-file entropy is {overall:.2} of 8"));
    }
    let code_ent = bin
        .segments
        .iter()
        .filter(|s| s.exec && s.data.len() > 4096)
        .map(|s| entropy_of(&s.data))
        .fold(0.0f32, f32::max);
    if code_ent > 7.2 {
        pack.add("Code section looks encrypted or packed", 0.6, format!("Executable section entropy is {code_ent:.2} of 8"));
    }

    let mut compilers = comp.done(0.25);
    let mut languages = lang.done(0.3);
    let packers = pack.done(0.4);
    // C / C++ are fallbacks: hide them if something more specific is certain
    if languages.len() > 1 && languages[0].score > 0.8 {
        languages.retain(|g| g.name != "C" || g.score > 0.8);
    }
    if compilers.is_empty() {
        compilers.push(Guess { name: "unknown".into(), score: 0.0, why: vec!["No compiler fingerprint was found".into()] });
    }
    if languages.is_empty() {
        languages.push(Guess { name: "C / C++ (assumed)".into(), score: 0.2, why: vec!["Nothing more specific was found".into()] });
    }

    // ---- kind / OS
    let (container, app_info) = bundle_info(&bin.path);
    let gui = raw.subsystem == Some(2);
    let os = if is_pe {
        let v = raw.os_version.map(|(a, b)| format!(" (needs {a}.{b}+)")).unwrap_or_default();
        format!("Windows{v}")
    } else if is_macho {
        format!("{}{}", raw.macho_platform.unwrap_or("macOS"), raw.macho_min.as_ref().map(|m| format!(" {m}+")).unwrap_or_default())
    } else if is_elf {
        format!("{}{}", raw.elf_abi.clone().unwrap_or_else(|| "Unix".into()), raw.interp.as_ref().map(|i| format!(" — loader {i}")).unwrap_or_default())
    } else {
        "unknown".into()
    };
    let kind = if is_pe {
        format!("Windows {} {}", if gui { "GUI program" } else if raw.subsystem == Some(3) { "console program" } else { "program" }, if raw.is_dll { "(DLL library)" } else { "(.exe)" })
    } else if is_macho && !container.is_empty() {
        "macOS application".to_string()
    } else if is_macho {
        bin.format.clone()
    } else {
        bin.format.clone()
    };
    let bits = bin.bitness();

    // ---- protections
    let mut prot = vec![];
    if is_pe {
        prot.push(("ASLR (random load address)".to_string(), raw.dll_chars & 0x40 != 0));
        prot.push(("DEP / NX (no code on the stack)".to_string(), raw.dll_chars & 0x100 != 0));
        prot.push(("Control Flow Guard".to_string(), raw.dll_chars & 0x4000 != 0));
        prot.push(("High-entropy ASLR".to_string(), raw.dll_chars & 0x20 != 0));
        prot.push(("Stack cookies (/GS)".to_string(), has_sym("__security_cookie") || has_sym("__security_check_cookie")));
        prot.push(("Digitally signed".to_string(), raw.signed));
    } else if is_elf {
        prot.push(("PIE (random load address)".to_string(), raw.pie));
        prot.push(("NX (no code on the stack)".to_string(), raw.nx.unwrap_or(false)));
        prot.push((format!("RELRO ({})", raw.relro.unwrap_or("none")), raw.relro == Some("full")));
        prot.push(("Stack canary".to_string(), has_sym("__stack_chk_fail")));
        prot.push(("FORTIFY_SOURCE".to_string(), has_sym("_chk")));
    } else if is_macho {
        prot.push(("PIE (random load address)".to_string(), raw.pie));
        prot.push(("Stack canary".to_string(), has_sym("__stack_chk_fail")));
        prot.push(("ARC (automatic reference counting)".to_string(), has_sym("objc_release") || has_sym("objc_retain")));
        prot.push(("Code signature present".to_string(), raw.macho_signed));
    }

    // ---- calling convention (the "how to decompile" decision)
    let comp_name = compilers.first().map(|g| g.name.clone()).unwrap_or_default();
    let lang_name = languages.first().map(|g| g.name.clone()).unwrap_or_default();
    let conv = if let Some(l) = native_conv(bin.arch, is_pe) {
        CallConv::Native(l)
    } else if lang_name == "Go" && bin.arch == Arch::X64 {
        CallConv::GoAbi
    } else if bin.arch == Arch::X64 {
        if is_pe { CallConv::Win64 } else { CallConv::SysV64 }
    } else if lang_name.starts_with("Delphi") {
        CallConv::Delphi32
    } else if is_pe && comp_name.contains("Visual C") && an.functions.values().any(|f| f.insn_count > 0 && uses_ecx_this(bin, an, f.start)) {
        CallConv::Fastcall32
    } else {
        CallConv::Cdecl32
    };

    // ---- capabilities & note on managed code
    let cap_names: Vec<&str> = bin
        .imports
        .iter()
        .map(|i| i.name.as_str())
        .chain(bin.symbols.iter().map(|s| s.1.as_str()).filter(|n| !n.starts_with("_Z") && !n.starts_with("__Z") && !n.starts_with("_R") && !n.starts_with("__R") && !n.starts_with("$s") && !n.starts_with("_$s")))
        .chain(sym_names.iter().filter_map(|n| n.strip_prefix("_OBJC_CLASS_$_")))
        .collect();
    let mut capabilities = capabilities(&cap_names);
    let crypto = crate::findcrypt::scan(bin);
    if !crypto.is_empty() {
        let mut algos: Vec<String> = crypto.iter().map(|c| c.2.clone()).collect();
        algos.sort();
        algos.dedup();
        capabilities.push(Capability { name: "Crypto constants", apis: algos });
    }
    let unsupported_note = if raw.clr {
        Some("This is a .NET program: it holds intermediate language, not machine code. Open it in ILSpy or dnSpy for real C#. Lens shows the native shell only.".to_string())
    } else if bin.arch == Arch::Other {
        Some(format!("This program is built for {}, which Lens can't decode yet, so only sections, strings, imports and exports can be shown.", bin.arch_name))
    } else if !bin.arch.is_x86() {
        Some(format!("This program is built for {}. Lens shows its disassembly, graph, strings, hex and pseudocode (pseudocode for this CPU is newer and less polished than for x86).", bin.arch.name()))
    } else if lang_name.starts_with("JavaScript") {
        Some("This is an Electron app: the interesting logic is JavaScript inside app.asar, not machine code. Lens can extract that JavaScript as real source (see Source code below).".to_string())
    } else {
        None
    };

    // ---- entropy chart and hash
    let nb = 256usize;
    let mut entropy = vec![];
    if !bytes.is_empty() {
        let step = (bytes.len() / nb).max(1);
        for i in 0..nb {
            let s = i * step;
            if s >= bytes.len() {
                break;
            }
            let e = if i == nb - 1 { bytes.len() } else { (s + step).min(bytes.len()) };
            entropy.push(entropy_of(&bytes[s..e]));
        }
    }
    let sha = sha256(&bytes);

    let mut det = Detection {
        kind,
        os,
        arch: bin.arch_name.clone(),
        bits,
        container,
        compilers,
        languages,
        packers,
        protections: prot,
        stripped: raw.stripped || bin.symbols.len() < 8,
        has_debug_info: raw.debug_info,
        conv,
        plan: vec![],
        app_info,
        capabilities,
        entropy,
        overall_entropy: overall,
        sha256: sha,
        timestamp: raw.timestamp.filter(|t| *t > 100_000 && *t < 4_000_000_000),
        main: None,
        unsupported_note,
        crypto,
        threat_signals: vec![],
        asar: crate::source::find_asar(&bin.path).and_then(|p| crate::source::asar_info(&p)),
    };
    det.threat_signals = threat_signals(&det.capabilities, &det.packers, &det.protections, det.overall_entropy);
    det.main = find_main(bin, an, &det);
    det.plan = plan(bin, &det);
    det
}

fn uses_ecx_this(bin: &Binary, an: &Analysis, start: u64) -> bool {
    // cheap check: first instruction mentions ecx as a source (mov [..], ecx / mov esi, ecx)
    let Some((i, _)) = crate::analysis::decode_at(bin, start) else { return false };
    let _ = an;
    use iced_x86::Register;
    (0..i.op_count()).skip(1).any(|k| i.op_kind(k) == iced_x86::OpKind::Register && i.op_register(k) == Register::ECX)
}

// ---------------------------------------------------------------- main finder

fn resolve_name(bin: &Binary, an: &Analysis, ins: &crate::analysis::Insn) -> String {
    let a = match ins.flow {
        Flow::Call | Flow::Jump => ins.target,
        _ => ins.mem,
    };
    if let Some((n, _)) = an.names.get(&a) {
        return n.to_lowercase();
    }
    if let Some(i) = an.import_slot.get(&a) {
        return bin.imports[*i].name.to_lowercase();
    }
    String::new()
}

pub fn find_main(bin: &Binary, an: &Analysis, det: &Detection) -> Option<(u64, String)> {
    for n in ["main", "_main", "wmain", "WinMain", "wWinMain", "_WinMain@16", "_main@0", "main.main"] {
        if let Some((a, _)) = bin.symbols.iter().find(|(_, s)| s == n) {
            if an.functions.contains_key(a) {
                return Some((*a, format!("symbol “{n}”")));
            }
        }
    }
    let entry = bin.entry?;
    let ef = an.functions.get(&entry)?;
    let insn_list = |f: &crate::analysis::Function| -> Vec<u64> { f.blocks.iter().flat_map(|b| b.insns.iter().copied()).collect() };

    // ELF: the first argument handed to __libc_start_main is main
    let mut order = insn_list(ef);
    order.sort();
    for (k, a) in order.iter().enumerate() {
        let ins = &an.insns[a];
        if matches!(ins.flow, Flow::Call | Flow::IndirectCall) {
            let n = resolve_name(bin, an, ins);
            if n.contains("libc_start_main") {
                for b in order[..k].iter().rev().take(14) {
                    let p = &an.insns[b];
                    let cand = if p.is_lea { p.mem } else { p.imm };
                    if cand != 0 && cand != entry {
                        if let Some(f) = an.functions.get(&cand) {
                            if f.kind == FuncKind::Normal {
                                return Some((cand, "passed to __libc_start_main".into()));
                            }
                        }
                    }
                }
            }
        }
    }
    // Mach-O: LC_MAIN already points at main
    if bin.format.starts_with("Mach-O") && ef.kind == FuncKind::Normal && !bin.symbols.iter().any(|(a, s)| *a == entry && s == "start") {
        return Some((entry, "LC_MAIN entry point".into()));
    }
    // PE / others: walk the start-up code; main is the internal call right before an exit call
    let mut seen = std::collections::HashSet::new();
    let mut work = vec![(entry, 0u32)];
    while let Some((fa, depth)) = work.pop() {
        if !seen.insert(fa) || depth > 3 {
            continue;
        }
        let Some(f) = an.functions.get(&fa) else { continue };
        let mut order = insn_list(f);
        order.sort();
        for (k, a) in order.iter().enumerate() {
            let ins = &an.insns[a];
            if ins.flow == Flow::Call && ins.target != 0 {
                if let Some(cf) = an.functions.get(&ins.target) {
                    if cf.kind == FuncKind::Normal && cf.insn_count > 3 {
                        let mut exits = false;
                        for b in order[k + 1..].iter().take(5) {
                            let n = resolve_name(bin, an, &an.insns[b]);
                            if matches!(an.insns[b].flow, Flow::Call | Flow::IndirectCall | Flow::Jump | Flow::IndirectJump)
                                && (n.contains("exit") || n.contains("cexit"))
                            {
                                exits = true;
                            }
                        }
                        if exits && ins.target != entry {
                            // the callee itself might be a wrapper; accept only if it isn't start-up code
                            return Some((ins.target, format!("call just before exit() in the start-up code at {fa:X}")));
                        }
                    }
                }
            }
            if matches!(ins.flow, Flow::Call | Flow::Jump) && ins.target != 0 && an.functions.contains_key(&ins.target) {
                work.push((ins.target, depth + 1));
            }
        }
    }
    let _ = det;
    None
}

fn plan(bin: &Binary, d: &Detection) -> Vec<String> {
    let mut p = vec![];
    if !d.container.is_empty() {
        p.push(d.container[0].clone());
    }
    if bin.slices.len() > 1 {
        p.push(format!(
            "Universal file with parts for {}; Lens reads the {} part.",
            bin.slices.join(", "),
            bin.arch_name
        ));
    }
    if let Some(n) = &d.unsupported_note {
        p.push(n.clone());
        return p;
    }
    p.push(format!("Machine code: {} ({}-bit) — decoded with the built-in x86 decoder.", d.arch, d.bits));
    p.push(format!("Toolchain guess: {}, language: {}.", d.compiler(), d.language()));
    p.push(format!("Calling convention chosen: {}.", d.conv.label()));
    if d.compiler().contains("Visual C") {
        p.push("Names: Microsoft mangling (?name@@…) kept as written; stack cookies and SEH set-up ignored.".into());
    } else if d.compiler().contains("GCC") || d.compiler().contains("Clang") {
        p.push("Names: Itanium C++ mangling (_Z…) is demangled; stack-protector code is ignored.".into());
    }
    if d.language() == "Rust" {
        p.push("Rust: panic and unwind helpers are treated as functions that never return.".into());
    }
    if d.language() == "Go" {
        p.push("Go: arguments travel in registers (ABIInternal); runtime helpers are not decompiled specially.".into());
    }
    if !d.packers.is_empty() {
        p.push(format!("Warning: looks packed ({}). Real code may only appear after unpacking.", d.packers[0].name));
    }
    match &d.main {
        Some((a, how)) => p.push(format!("Start-up code skipped: the program's own main is at {a:X} ({how}). Lens opens there.")),
        None => p.push("No clear main found — Lens opens at the entry point.".into()),
    }
    p.push(if d.stripped {
        "No symbols (stripped): functions are named sub_<address>; imports and strings are used to infer meaning.".into()
    } else {
        "Symbols found: functions keep their original names.".into()
    });
    p.push("Decompiler: each function is lifted to pseudo-C (registers become variables, stack slots become locals, jumps become if / while).".into());
    p
}

fn native_conv(arch: Arch, is_pe: bool) -> Option<&'static str> {
    Some(match arch {
        Arch::Arm64 if is_pe => "Windows ARM64 (x0–x7)",
        Arch::Arm64 => "AAPCS64 (x0–x7, result in x0)",
        Arch::Arm32 | Arch::Thumb => "AAPCS (r0–r3, then stack)",
        Arch::RiscV32 | Arch::RiscV64 => "RISC-V psABI (a0–a7)",
        Arch::Mips32 | Arch::Mips64 => "MIPS o32/n64 ($a0–$a3)",
        Arch::Ppc32 | Arch::Ppc64 => "PowerPC ABI (r3–r10)",
        Arch::M68k => "Motorola 68000 ABI (d0/d1 results, stack arguments)",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malware_signals_are_ranked_and_explainable() {
        let caps = vec![
            Capability { name: "Processes", apis: vec!["CreateProcess".into()] },
            Capability { name: "Anti-debugging", apis: vec!["IsDebuggerPresent".into()] },
            Capability { name: "Network", apis: vec!["connect".into()] },
        ];
        let signals = threat_signals(&caps, &[], &[], 4.0);
        assert_eq!(signals[0].severity, 2);
        assert!(signals.iter().any(|s| s.name == "Process execution" && s.evidence.contains("CreateProcess")));
        assert!(signals.iter().any(|s| s.name == "Network communication"));
        assert!(signals.windows(2).all(|pair| pair[0].severity >= pair[1].severity));
    }

    #[test]
    fn expanded_behavior_categories_remain_visible() {
        let names = ["Processes", "Files", "System info", "Loads code at run time", "Threads & timing", "Cryptography"];
        let caps = names.iter().map(|name| Capability { name: (*name).into(), apis: vec![format!("{name}_api")] }).collect::<Vec<_>>();
        let signals = threat_signals(&caps, &[], &[], 4.0);
        assert!(signals.iter().any(|s| s.name == "Runtime code loading"));
        assert!(signals.iter().any(|s| s.name == "Filesystem activity"));
        assert!(signals.iter().any(|s| s.name == "Broad capability profile"));
        assert!(signals.iter().any(|s| s.name == "Multiple behavior categories"));
    }
}
