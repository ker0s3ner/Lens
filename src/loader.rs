//! Reads a program file (ELF, PE, Mach-O, or plain bytes) into a simple memory image.

use goblin::Object;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    X86,
    X64,
    Other,
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub start: u64,
    pub data: Vec<u8>,
    /// Size in memory (may be larger than `data` for zero-filled sections).
    pub size: u64,
    pub exec: bool,
    pub write: bool,
    pub file_offset: Option<u64>,
}

impl Segment {
    pub fn end(&self) -> u64 {
        self.start + self.size
    }
    pub fn contains(&self, a: u64) -> bool {
        a >= self.start && a < self.end()
    }
}

#[derive(Clone, Debug)]
pub struct Import {
    /// Address of the pointer slot (GOT / IAT / lazy pointer).
    pub slot: u64,
    pub name: String,
    pub library: String,
}

#[derive(Clone, Debug)]
pub struct Export {
    pub addr: u64,
    pub name: String,
}

pub struct Binary {
    pub path: String,
    pub file_name: String,
    pub format: String,
    pub arch: Arch,
    pub arch_name: String,
    pub entry: Option<u64>,
    pub segments: Vec<Segment>,
    /// Function-like symbols (address, name).
    pub symbols: Vec<(u64, String)>,
    /// Data symbols (address, name).
    pub data_symbols: Vec<(u64, String)>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub libraries: Vec<String>,
    pub file_size: u64,
    pub notes: Vec<String>,
}

impl Binary {
    pub fn segment_of(&self, a: u64) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains(a))
    }
    pub fn read(&self, a: u64, len: usize) -> &[u8] {
        if let Some(s) = self.segment_of(a) {
            let off = (a - s.start) as usize;
            if off < s.data.len() {
                let end = (off + len).min(s.data.len());
                return &s.data[off..end];
            }
        }
        &[]
    }
    pub fn byte(&self, a: u64) -> Option<u8> {
        self.read(a, 1).first().copied()
    }
    pub fn is_mapped(&self, a: u64) -> bool {
        self.segment_of(a).is_some()
    }
    pub fn is_exec(&self, a: u64) -> bool {
        self.segment_of(a).map(|s| s.exec).unwrap_or(false)
    }
    pub fn read_ptr(&self, a: u64) -> Option<u64> {
        let w = if self.arch == Arch::X86 { 4 } else { 8 };
        let b = self.read(a, w);
        if b.len() < w {
            return None;
        }
        Some(if w == 4 {
            u32::from_le_bytes(b.try_into().ok()?) as u64
        } else {
            u64::from_le_bytes(b.try_into().ok()?)
        })
    }
    pub fn bitness(&self) -> u32 {
        if self.arch == Arch::X86 {
            32
        } else {
            64
        }
    }
    pub fn min_addr(&self) -> u64 {
        self.segments.iter().map(|s| s.start).min().unwrap_or(0)
    }
    pub fn max_addr(&self) -> u64 {
        self.segments.iter().map(|s| s.end()).max().unwrap_or(0)
    }
}

const MAX_ZERO_FILL: u64 = 64 * 1024 * 1024;

fn clean_symbol(name: &str) -> String {
    name.to_string()
}

/// Value of `<key>CFBundleExecutable</key><string>…</string>` in an XML Info.plist.
fn bundle_executable(plist: &Path) -> Option<String> {
    let text = std::fs::read_to_string(plist).ok()?;
    let k = text.find("<key>CFBundleExecutable</key>")?;
    let rest = &text[k..];
    let s = rest.find("<string>")? + "<string>".len();
    let e = rest[s..].find("</string>")?;
    Some(rest[s..s + e].trim().to_string())
}

fn looks_like_program(p: &Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 4];
    let Ok(mut f) = std::fs::File::open(p) else { return false };
    if f.read_exact(&mut b).is_err() {
        return false;
    }
    matches!(
        b,
        [0x7f, b'E', b'L', b'F'] | [b'M', b'Z', _, _] | [0xcf, 0xfa, 0xed, 0xfe] | [0xce, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe]
    )
}

/// The biggest program file in a folder (a few levels deep).
fn biggest_program(dir: &Path, depth: u32, best: &mut Option<(u64, PathBuf)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
        if md.is_dir() {
            if depth > 0 {
                biggest_program(&p, depth - 1, best);
            }
        } else if md.is_file() && md.len() > 1024 && best.as_ref().map(|b| md.len() > b.0).unwrap_or(true) && looks_like_program(&p) {
            *best = Some((md.len(), p));
        }
    }
}

/// Turns a folder (a macOS .app bundle or an install folder) into the program file inside it.
fn resolve_program(path: &Path, depth: u32) -> Result<PathBuf, String> {
    if !path.is_dir() {
        return Ok(path.to_path_buf());
    }
    if depth > 4 {
        return Err("This folder nests too many apps inside each other.".into());
    }
    let contents = path.join("Contents");
    if let Some(exe) = bundle_executable(&contents.join("Info.plist")) {
        // Usually Contents/MacOS/<name>; some apps point at a path relative to Contents.
        for cand in [contents.join("MacOS").join(&exe), contents.join(&exe)] {
            if cand.exists() {
                return resolve_program(&cand, depth + 1);
            }
        }
    }
    let mut best = None;
    let macos = contents.join("MacOS");
    if macos.is_dir() {
        biggest_program(&macos, 1, &mut best);
    }
    if best.is_none() {
        biggest_program(path, 4, &mut best);
    }
    best.map(|b| b.1).ok_or_else(|| {
        "This is a folder, and no program file (Windows, Linux or Mac) was found inside it. Pick the program file itself.".into()
    })
}

pub fn load(path: &str) -> Result<Binary, String> {
    let picked = Path::new(path);
    let real = resolve_program(picked, 0)?;
    let resolved_note = (real != picked).then(|| {
        let inside = picked.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let shown = real.strip_prefix(picked).unwrap_or(&real).display().to_string();
        format!("{inside} is a folder; opened the main program inside it: {shown}")
    });
    let path = real.to_str().ok_or("The file's path can't be read as text.")?;
    let bytes = std::fs::read(path).map_err(|e| format!("Couldn't read the file: {e}"))?;
    let file_name = std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());
    let mut bin = Binary {
        path: path.to_string(),
        file_name,
        format: String::new(),
        arch: Arch::Other,
        arch_name: String::new(),
        entry: None,
        segments: vec![],
        symbols: vec![],
        data_symbols: vec![],
        imports: vec![],
        exports: vec![],
        libraries: vec![],
        file_size: bytes.len() as u64,
        notes: resolved_note.into_iter().collect(),
    };
    match Object::parse(&bytes) {
        Ok(Object::Elf(elf)) => load_elf(&mut bin, &elf, &bytes),
        Ok(Object::PE(pe)) => load_pe(&mut bin, &pe, &bytes),
        Ok(Object::Mach(mach)) => load_mach(&mut bin, mach, &bytes)?,
        _ => load_raw(&mut bin, &bytes),
    }
    bin.symbols.sort();
    bin.symbols.dedup_by_key(|s| s.0);
    bin.segments.sort_by_key(|s| s.start);
    Ok(bin)
}

fn load_raw(bin: &mut Binary, bytes: &[u8]) {
    bin.format = "Raw binary".into();
    bin.arch = Arch::X64;
    bin.arch_name = "x86-64 (assumed)".into();
    bin.entry = Some(0);
    bin.notes
        .push("The file format wasn't recognised; it was loaded as raw x86-64 code at address 0.".into());
    bin.segments.push(Segment {
        name: "RAW".into(),
        start: 0,
        size: bytes.len() as u64,
        data: bytes.to_vec(),
        exec: true,
        write: false,
        file_offset: Some(0),
    });
}

fn load_elf(bin: &mut Binary, elf: &goblin::elf::Elf, bytes: &[u8]) {
    use goblin::elf::header::*;
    use goblin::elf::section_header::*;
    bin.format = format!(
        "ELF{} {}",
        if elf.is_64 { "64" } else { "32" },
        match elf.header.e_type {
            ET_EXEC => "executable",
            ET_DYN => "shared object",
            ET_REL => "object file",
            ET_CORE => "core dump",
            _ => "file",
        }
    );
    match elf.header.e_machine {
        EM_X86_64 => {
            bin.arch = Arch::X64;
            bin.arch_name = "x86-64".into()
        }
        EM_386 => {
            bin.arch = Arch::X86;
            bin.arch_name = "x86 (32-bit)".into()
        }
        m => bin.arch_name = goblin::elf::header::machine_to_str(m).to_string(),
    }
    bin.entry = if elf.entry != 0 { Some(elf.entry) } else { None };
    for sh in &elf.section_headers {
        if sh.sh_flags as u32 & SHF_ALLOC == 0 || sh.sh_size == 0 || sh.sh_addr == 0 {
            continue;
        }
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let (data, foff) = if sh.sh_type == SHT_NOBITS {
            (vec![0u8; sh.sh_size.min(MAX_ZERO_FILL) as usize], None)
        } else {
            let s = sh.sh_offset as usize;
            let e = (s + sh.sh_size as usize).min(bytes.len());
            (bytes.get(s..e).unwrap_or(&[]).to_vec(), Some(sh.sh_offset))
        };
        bin.segments.push(Segment {
            name,
            start: sh.sh_addr,
            size: sh.sh_size,
            data,
            exec: sh.sh_flags as u32 & SHF_EXECINSTR != 0,
            write: sh.sh_flags as u32 & SHF_WRITE != 0,
            file_offset: foff,
        });
    }
    if bin.segments.is_empty() {
        // No sections: fall back to program headers.
        for ph in &elf.program_headers {
            if ph.p_type != goblin::elf::program_header::PT_LOAD {
                continue;
            }
            let s = ph.p_offset as usize;
            let e = (s + ph.p_filesz as usize).min(bytes.len());
            let mut data = bytes.get(s..e).unwrap_or(&[]).to_vec();
            data.resize(ph.p_memsz.min(MAX_ZERO_FILL) as usize, 0);
            bin.segments.push(Segment {
                name: format!("LOAD{}", bin.segments.len()),
                start: ph.p_vaddr,
                size: ph.p_memsz,
                data,
                exec: ph.is_executable(),
                write: ph.is_write(),
                file_offset: Some(ph.p_offset),
            });
        }
    }
    for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if sym.st_value == 0 || sym.st_shndx == 0 {
            continue;
        }
        let name = elf
            .strtab
            .get_at(sym.st_name)
            .or_else(|| elf.dynstrtab.get_at(sym.st_name))
            .unwrap_or("");
        if name.is_empty() || name.starts_with('$') {
            continue;
        }
        if sym.is_function() {
            bin.symbols.push((sym.st_value, clean_symbol(name)));
        } else if sym.st_type() == goblin::elf::sym::STT_OBJECT {
            bin.data_symbols.push((sym.st_value, clean_symbol(name)));
        }
    }
    for sym in elf.dynsyms.iter() {
        if sym.st_value != 0 && sym.st_shndx != 0 && sym.st_bind() != goblin::elf::sym::STB_LOCAL {
            if let Some(n) = elf.dynstrtab.get_at(sym.st_name) {
                if !n.is_empty() {
                    bin.exports.push(Export { addr: sym.st_value, name: n.to_string() });
                }
            }
        }
    }
    let lib = elf.libraries.first().map(|s| s.to_string()).unwrap_or_default();
    bin.libraries = elf.libraries.iter().map(|s| s.to_string()).collect();
    for rel in elf.pltrelocs.iter().chain(elf.dynrelas.iter()).chain(elf.dynrels.iter()) {
        if rel.r_sym == 0 {
            continue;
        }
        if let Some(sym) = elf.dynsyms.get(rel.r_sym) {
            if sym.st_shndx != 0 {
                continue; // defined locally
            }
            if let Some(n) = elf.dynstrtab.get_at(sym.st_name) {
                if !n.is_empty() {
                    let n = n.split('@').next().unwrap_or(n).to_string();
                    bin.imports.push(Import { slot: rel.r_offset, name: n, library: lib.clone() });
                }
            }
        }
    }
    bin.imports.sort_by_key(|i| i.slot);
    bin.imports.dedup_by_key(|i| i.slot);
}

fn load_pe(bin: &mut Binary, pe: &goblin::pe::PE, bytes: &[u8]) {
    let base = pe.image_base as u64;
    bin.format = format!(
        "PE{} {}",
        if pe.is_64 { "32+" } else { "32" },
        if pe.is_lib { "DLL" } else { "executable" }
    );
    match pe.header.coff_header.machine {
        goblin::pe::header::COFF_MACHINE_X86_64 => {
            bin.arch = Arch::X64;
            bin.arch_name = "x86-64".into()
        }
        goblin::pe::header::COFF_MACHINE_X86 => {
            bin.arch = Arch::X86;
            bin.arch_name = "x86 (32-bit)".into()
        }
        m => bin.arch_name = format!("machine 0x{m:x}"),
    }
    if pe.entry != 0 {
        bin.entry = Some(base + pe.entry as u64);
    }
    for s in &pe.sections {
        let name = s.name().unwrap_or("?").to_string();
        let vsize = (s.virtual_size.max(s.size_of_raw_data)) as u64;
        let st = s.pointer_to_raw_data as usize;
        let en = (st + s.size_of_raw_data as usize).min(bytes.len());
        let mut data = bytes.get(st..en).unwrap_or(&[]).to_vec();
        data.resize(vsize.min(MAX_ZERO_FILL) as usize, 0);
        let ch = s.characteristics;
        bin.segments.push(Segment {
            name,
            start: base + s.virtual_address as u64,
            size: vsize,
            data,
            exec: ch & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0,
            write: ch & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0,
            file_offset: Some(s.pointer_to_raw_data as u64),
        });
    }
    for imp in &pe.imports {
        bin.imports.push(Import {
            slot: base + imp.rva as u64,
            name: imp.name.to_string(),
            library: imp.dll.to_string(),
        });
    }
    bin.libraries = pe.libraries.iter().map(|s| s.to_string()).collect();
    for e in &pe.exports {
        if let Some(n) = e.name {
            bin.exports.push(Export { addr: base + e.rva as u64, name: n.to_string() });
            bin.symbols.push((base + e.rva as u64, n.to_string()));
        }
    }
}

fn load_mach(bin: &mut Binary, mach: goblin::mach::Mach, bytes: &[u8]) -> Result<(), String> {
    use goblin::mach::{Mach, SingleArch};
    match mach {
        Mach::Binary(m) => {
            load_macho(bin, &m);
            Ok(())
        }
        Mach::Fat(fat) => {
            let arches = fat.arches().map_err(|e| e.to_string())?;
            let mut names = vec![];
            let mut pick = None;
            for (i, a) in arches.iter().enumerate() {
                let n = goblin::mach::constants::cputype::get_arch_name_from_types(a.cputype, a.cpusubtype)
                    .unwrap_or("unknown");
                names.push(n.to_string());
                if a.cputype == goblin::mach::constants::cputype::CPU_TYPE_X86_64 && pick.is_none() {
                    pick = Some(i);
                }
            }
            for (i, a) in arches.iter().enumerate() {
                if a.cputype == goblin::mach::constants::cputype::CPU_TYPE_X86 && pick.is_none() {
                    pick = Some(i);
                }
            }
            let idx = pick.unwrap_or(0);
            bin.notes.push(format!(
                "Universal program with {} parts ({}); showing the {} part.",
                names.len(),
                names.join(", "),
                names[idx]
            ));
            let _ = bytes;
            match fat.get(idx).map_err(|e| e.to_string())? {
                SingleArch::MachO(m) => {
                    load_macho(bin, &m);
                    Ok(())
                }
                SingleArch::Archive(_) => Err("This universal file holds a static library archive.".into()),
            }
        }
    }
}

fn load_macho(bin: &mut Binary, m: &goblin::mach::MachO) {
    use goblin::mach::constants::cputype::*;
    bin.format = format!(
        "Mach-O {}",
        match m.header.filetype {
            goblin::mach::header::MH_EXECUTE => "executable",
            goblin::mach::header::MH_DYLIB => "dynamic library",
            goblin::mach::header::MH_BUNDLE => "bundle",
            goblin::mach::header::MH_OBJECT => "object file",
            _ => "file",
        }
    );
    match m.header.cputype {
        CPU_TYPE_X86_64 => {
            bin.arch = Arch::X64;
            bin.arch_name = "x86-64".into()
        }
        CPU_TYPE_X86 => {
            bin.arch = Arch::X86;
            bin.arch_name = "x86 (32-bit)".into()
        }
        CPU_TYPE_ARM64 => bin.arch_name = "ARM64".into(),
        c => bin.arch_name = get_arch_name_from_types(c, m.header.cpusubtype).unwrap_or("unknown").to_string(),
    }
    let mut text_base = 0u64;
    for seg in m.segments.iter() {
        let segname = seg.name().unwrap_or("").to_string();
        if segname == "__TEXT" {
            text_base = seg.vmaddr;
        }
        if segname == "__PAGEZERO" {
            continue;
        }
        if let Ok(sections) = seg.sections() {
            for (sec, data) in sections {
                if sec.size == 0 {
                    continue;
                }
                let sname = sec.name().unwrap_or("").to_string();
                let zerofill = matches!(sec.flags & 0xff, 0x1 | 0xc | 0x12);
                let mut d = if zerofill { vec![] } else { data.to_vec() };
                d.resize(sec.size.min(MAX_ZERO_FILL) as usize, 0);
                let exec = sec.flags & 0x8000_0000 != 0 || sec.flags & 0x400 != 0;
                bin.segments.push(Segment {
                    name: format!("{segname},{sname}"),
                    start: sec.addr,
                    size: sec.size,
                    data: d,
                    exec,
                    write: seg.initprot & 2 != 0,
                    file_offset: if zerofill { None } else { Some(sec.offset as u64) },
                });
            }
        }
    }
    if m.entry != 0 {
        // goblin already turns LC_MAIN's file offset into a virtual address.
        bin.entry = Some(m.entry);
    }
    if let Some(syms) = &m.symbols {
        for (name, nl) in syms.iter().flatten() {
            if nl.is_stab() || nl.is_undefined() || nl.n_value == 0 || name.is_empty() {
                continue;
            }
            let a = nl.n_value;
            if bin.segments.iter().any(|s| s.exec && s.contains(a)) {
                bin.symbols.push((a, name.to_string()));
            } else {
                bin.data_symbols.push((a, name.to_string()));
            }
        }
    }
    if let Ok(imps) = m.imports() {
        for i in imps {
            bin.imports.push(Import {
                slot: i.address,
                name: i.name.to_string(),
                library: i.dylib.to_string(),
            });
        }
    }
    if let Ok(exps) = m.exports() {
        for e in exps {
            bin.exports.push(Export { addr: text_base + e.offset, name: e.name.clone() });
        }
    }
    bin.libraries = m.libs.iter().filter(|l| **l != "self").map(|s| s.to_string()).collect();
    bin.imports.sort_by_key(|i| i.slot);
    bin.imports.dedup_by_key(|i| i.slot);
}
