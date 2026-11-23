//! Reads a program file (ELF, PE, Mach-O, or plain bytes) into a simple memory image.

use goblin::Object;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Arch {
    X16,
    X86,
    X64,
    Arm64,
    Arm32,
    Thumb,
    RiscV32,
    RiscV64,
    Mips32,
    Mips64,
    Ppc32,
    Ppc64,
    M68k,
    Other,
}

impl Arch {
    pub fn is_x86(self) -> bool {
        matches!(self, Arch::X16 | Arch::X86 | Arch::X64)
    }
    pub fn bits(self) -> u32 {
        match self {
            Arch::X16 => 16,
            Arch::X86 | Arch::Arm32 | Arch::Thumb | Arch::RiscV32 | Arch::Mips32 | Arch::Ppc32 | Arch::M68k => 32,
            _ => 64,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Arch::X16 => "x86 (16-bit)",
            Arch::X86 => "x86 (32-bit)",
            Arch::X64 => "x86-64",
            Arch::Arm64 => "ARM64",
            Arch::Arm32 => "ARM (32-bit)",
            Arch::Thumb => "ARM Thumb",
            Arch::RiscV32 => "RISC-V 32",
            Arch::RiscV64 => "RISC-V 64",
            Arch::Mips32 => "MIPS32",
            Arch::Mips64 => "MIPS64",
            Arch::Ppc32 => "PowerPC",
            Arch::Ppc64 => "PowerPC 64",
            Arch::M68k => "Motorola 68000",
            Arch::Other => "unknown",
        }
    }
    pub fn all() -> [Arch; 13] {
        [Arch::X64, Arch::X86, Arch::X16, Arch::Arm64, Arch::Arm32, Arch::Thumb, Arch::RiscV64, Arch::RiscV32, Arch::Mips32, Arch::Mips64, Arch::Ppc32, Arch::Ppc64, Arch::M68k]
    }
    /// Fixed instruction size, when the architecture has one.
    pub fn fixed_width(self) -> Option<u64> {
        match self {
            Arch::Arm64 | Arch::Arm32 | Arch::Mips32 | Arch::Mips64 | Arch::Ppc32 | Arch::Ppc64 => Some(4),
            _ => None,
        }
    }
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

#[derive(Clone)]
pub struct Binary {
    pub path: String,
    pub file_name: String,
    pub format: String,
    pub arch: Arch,
    pub arch_name: String,
    pub entry: Option<u64>,
    pub segments: Vec<Segment>,
    /// Ranges inside executable sections that Mach-O marks as embedded data.
    pub data_ranges: Vec<(u64, u64)>,
    /// Function-like symbols (address, name).
    pub symbols: Vec<(u64, String)>,
    /// Data symbols (address, name).
    pub data_symbols: Vec<(u64, String)>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub libraries: Vec<String>,
    pub file_size: u64,
    pub notes: Vec<String>,
    /// CPU parts found in a universal (fat) Mach-O, e.g. ["x86_64", "arm64"].
    pub slices: Vec<String>,
    pub big_endian: bool,
    /// Name of the part opened from a universal file ("" otherwise).
    pub slice: String,
    /// Where this program starts inside its file (non-zero for one part of a universal Mach-O).
    pub file_base: u64,
    /// Function starts found in unwind / function-start tables (no names).
    pub func_hints: Vec<u64>,
    /// C prototypes taken from DWARF debug info (one per line).
    pub debug_protos: String,
    /// struct / union / enum definitions from DWARF, as C text.
    pub debug_types: String,
    /// Struct/union/enum layouts reconstructed from DWARF member offsets.
    pub debug_structs: Vec<crate::types::StructDef>,
}

fn is_elf_function_type(ty: u8) -> bool {
    ty == goblin::elf::sym::STT_FUNC || ty == goblin::elf::sym::STT_GNU_IFUNC
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
            && !self.data_ranges.iter().any(|(start, end)| a >= *start && a < *end)
    }
    pub fn read_ptr(&self, a: u64) -> Option<u64> {
        let w = (self.arch.bits() / 8) as usize;
        let b = self.read(a, w);
        if b.len() < w {
            return None;
        }
        Some(match (w, self.big_endian) {
            (4, false) => u32::from_le_bytes(b.try_into().ok()?) as u64,
            (4, true) => u32::from_be_bytes(b.try_into().ok()?) as u64,
            (_, false) => u64::from_le_bytes(b.try_into().ok()?),
            (_, true) => u64::from_be_bytes(b.try_into().ok()?),
        })
    }
    pub fn bitness(&self) -> u32 {
        self.arch.bits()
    }
    pub fn min_addr(&self) -> u64 {
        self.segments.iter().map(|s| s.start).min().unwrap_or(0)
    }
    pub fn max_addr(&self) -> u64 {
        self.segments.iter().map(|s| s.end()).max().unwrap_or(0)
    }
}

/// Which part of a universal (fat) Mach-O to open, e.g. "arm64". Set before calling `load`.
pub static SLICE_PREF: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

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
        data_ranges: vec![],
        symbols: vec![],
        data_symbols: vec![],
        imports: vec![],
        exports: vec![],
        libraries: vec![],
        file_size: bytes.len() as u64,
        notes: resolved_note.into_iter().collect(),
        slices: vec![],
        big_endian: false,
        slice: String::new(),
        file_base: 0,
        func_hints: vec![],
        debug_protos: String::new(),
        debug_types: String::new(),
        debug_structs: vec![],
    };
    match Object::parse(&bytes) {
        Ok(Object::Elf(elf)) => {
            load_elf(&mut bin, &elf, &bytes);
            bin.func_hints = crate::hints::eh_frame(&bin);
        }
        Ok(Object::PE(pe)) => {
            load_pe(&mut bin, &pe, &bytes);
            if bin.arch == Arch::X64 {
                bin.func_hints = crate::hints::pe_pdata(&bin, pe.image_base as u64);
            }
        }
        Ok(Object::Mach(mach)) => load_mach(&mut bin, mach, &bytes)?,
        _ => load_raw(&mut bin, &bytes),
    }
    crate::dwarf::apply(&mut bin);
    bin.symbols.sort();
    bin.symbols.dedup_by_key(|s| s.0);
    bin.segments.sort_by_key(|s| s.start);
    Ok(bin)
}

/// CPU, endianness and base address to use for files that aren't a known program format.
pub static RAW_PREF: std::sync::Mutex<Option<(Arch, bool, u64)>> = std::sync::Mutex::new(None);

fn load_raw(bin: &mut Binary, bytes: &[u8]) {
    let pref = RAW_PREF.lock().ok().and_then(|g| *g);
    let (arch, big, base) = pref.unwrap_or((Arch::X64, false, 0));
    bin.format = "Raw binary".into();
    bin.arch = arch;
    bin.big_endian = big;
    bin.arch_name = if pref.is_some() { arch.name().to_string() } else { "x86-64 (assumed)".into() };
    bin.entry = Some(base);
    bin.notes.push(if pref.is_some() {
        format!("Loaded as raw {} code at {base:X}.", arch.name())
    } else {
        "The file format wasn't recognised; it was loaded as raw x86-64 code at address 0. Use Tools > Hex to Code to pick another CPU.".into()
    });
    bin.segments.push(Segment {
        name: "RAW".into(),
        start: base,
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
    let relocatable = elf.header.e_type == ET_REL;
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
        EM_AARCH64 => bin.arch = Arch::Arm64,
        EM_ARM => bin.arch = Arch::Arm32,
        EM_RISCV => bin.arch = if elf.is_64 { Arch::RiscV64 } else { Arch::RiscV32 },
        EM_MIPS => bin.arch = if elf.is_64 { Arch::Mips64 } else { Arch::Mips32 },
        EM_PPC => bin.arch = Arch::Ppc32,
        EM_PPC64 => bin.arch = Arch::Ppc64,
        goblin::elf::header::EM_68K => { bin.arch = Arch::M68k; bin.arch_name = "Motorola 68000".into(); },
        _ => {}
    }
    bin.big_endian = !elf.little_endian;
    if bin.arch != Arch::X64 && bin.arch != Arch::X86 {
        bin.arch_name = if bin.arch == Arch::Other {
            goblin::elf::header::machine_to_str(elf.header.e_machine).to_string()
        } else {
            bin.arch.name().to_string()
        };
    }
    bin.entry = if elf.entry != 0 { Some(elf.entry) } else { None };
    let mut section_bases = vec![None; elf.section_headers.len()];
    let mut next_object_addr = 0x1000_0000u64;
    for (section_index, sh) in elf.section_headers.iter().enumerate() {
        if sh.sh_flags as u32 & SHF_ALLOC == 0 || sh.sh_size == 0 || (!relocatable && sh.sh_addr == 0) {
            continue;
        }
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let start_addr = if relocatable {
            let alignment = sh.sh_addralign.max(1).checked_next_power_of_two().unwrap_or(1 << 20).min(1 << 20);
            let start = next_object_addr.saturating_add(alignment - 1) & !(alignment - 1);
            section_bases[section_index] = Some(start);
            next_object_addr = start.saturating_add(sh.sh_size).saturating_add(0x1000);
            start
        } else { sh.sh_addr };
        let (data, foff) = if sh.sh_type == SHT_NOBITS {
            (vec![0u8; sh.sh_size.min(MAX_ZERO_FILL) as usize], None)
        } else {
            let s = sh.sh_offset as usize;
            let e = (s + sh.sh_size as usize).min(bytes.len());
            (bytes.get(s..e).unwrap_or(&[]).to_vec(), Some(sh.sh_offset))
        };
        bin.segments.push(Segment {
            name,
            start: start_addr,
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
    if relocatable {
        bin.entry = bin.segments.iter().find(|s| s.exec).map(|s| s.start);
        let (applied, skipped) = apply_elf_object_relocations(bin, elf, &section_bases);
        bin.notes.push(format!("Relocatable ELF object: alloc sections are mapped at synthetic addresses; applied {applied} supported relocations and skipped {skipped} unresolved or unsupported relocations."));
    }
    for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if sym.st_shndx == 0 {
            continue;
        }
        let sym_addr = if relocatable {
            section_bases.get(sym.st_shndx as usize).and_then(|base| *base).map(|base| base.saturating_add(sym.st_value))
        } else { Some(sym.st_value) };
        let Some(sym_addr) = sym_addr else { continue };
        if sym_addr == 0 { continue; }
        let name = elf
            .strtab
            .get_at(sym.st_name)
            .or_else(|| elf.dynstrtab.get_at(sym.st_name))
            .unwrap_or("");
        if name.is_empty() || name.starts_with('$') {
            continue;
        }
        // GNU IFUNC symbols resolve to executable implementations at runtime and
        // should seed the same function discovery path as ordinary STT_FUNC symbols.
        if is_elf_function_type(sym.st_type()) {
            bin.symbols.push((sym_addr, clean_symbol(name)));
        } else if sym.st_type() == goblin::elf::sym::STT_OBJECT {
            bin.data_symbols.push((sym_addr, clean_symbol(name)));
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

fn read_elf_word(bin: &Binary, addr: u64, width: usize) -> Option<i64> {
    let b = bin.read(addr, width);
    if b.len() != width { return None; }
    Some(match (width, bin.big_endian) {
        (1, _) => b[0] as i8 as i64,
        (2, false) => i16::from_le_bytes(b.try_into().ok()?) as i64,
        (2, true) => i16::from_be_bytes(b.try_into().ok()?) as i64,
        (4, false) => i32::from_le_bytes(b.try_into().ok()?) as i64,
        (4, true) => i32::from_be_bytes(b.try_into().ok()?) as i64,
        (8, false) => i64::from_le_bytes(b.try_into().ok()?),
        (8, true) => i64::from_be_bytes(b.try_into().ok()?),
        _ => return None,
    })
}

fn write_elf_word(bin: &mut Binary, addr: u64, width: usize, value: i64) -> bool {
    let Some(seg) = bin.segments.iter_mut().find(|s| s.contains(addr)) else { return false };
    let off = (addr - seg.start) as usize;
    if off.checked_add(width).is_none_or(|end| end > seg.data.len()) { return false; }
    let bytes = match (width, bin.big_endian) {
        (1, _) => vec![value as u8],
        (2, false) => (value as i16).to_le_bytes().to_vec(),
        (2, true) => (value as i16).to_be_bytes().to_vec(),
        (4, false) => (value as i32).to_le_bytes().to_vec(),
        (4, true) => (value as i32).to_be_bytes().to_vec(),
        (8, false) => value.to_le_bytes().to_vec(),
        (8, true) => value.to_be_bytes().to_vec(),
        _ => return false,
    };
    seg.data[off..off + width].copy_from_slice(&bytes);
    true
}

fn object_symbol_addr(sym: &goblin::elf::sym::Sym, bases: &[Option<u64>]) -> Option<u64> {
    if sym.st_shndx == goblin::elf::section_header::SHN_ABS as usize {
        Some(sym.st_value)
    } else {
        bases.get(sym.st_shndx as usize).and_then(|base| *base).map(|base| base.saturating_add(sym.st_value))
    }
}

/// Applies common static relocations to the synthetic memory image for ET_REL objects.
/// Relocations that need a linker-created GOT/PLT or paired instruction sequence are left intact.
fn apply_elf_object_relocations(bin: &mut Binary, elf: &goblin::elf::Elf, bases: &[Option<u64>]) -> (usize, usize) {
    use goblin::elf::header::*;
    use goblin::elf::reloc::*;
    let mut applied = 0usize;
    let mut skipped = 0usize;
    for (relsec_index, relocs) in &elf.shdr_relocs {
        let Some(relsec) = elf.section_headers.get(*relsec_index) else { continue };
        let target_index = relsec.sh_info as usize;
        let Some(target_base) = bases.get(target_index).and_then(|b| *b) else { skipped += relocs.len(); continue };
        let symtab_name = elf.section_headers.get(relsec.sh_link as usize)
            .and_then(|sh| elf.shdr_strtab.get_at(sh.sh_name)).unwrap_or("");
        let symtab = match symtab_name { ".symtab" => &elf.syms, ".dynsym" => &elf.dynsyms, _ => { skipped += relocs.len(); continue } };
        for rel in relocs.iter() {
            let Some(sym) = symtab.get(rel.r_sym) else { skipped += 1; continue };
            let Some(s) = object_symbol_addr(&sym, bases) else { skipped += 1; continue };
            let place = target_base.saturating_add(rel.r_offset);
            let (width, formula) = match (elf.header.e_machine, rel.r_type) {
                (EM_X86_64, R_X86_64_64) => (8, 0),
                (EM_X86_64, R_X86_64_PC32 | R_X86_64_PLT32) => (4, 1),
                (EM_X86_64, R_X86_64_32 | R_X86_64_32S) => (4, 0),
                (EM_386, R_386_32) => (4, 0),
                (EM_386, R_386_PC32) => (4, 1),
                (EM_AARCH64, R_AARCH64_ABS64) => (8, 0),
                (EM_AARCH64, R_AARCH64_ABS32) => (4, 0),
                (EM_AARCH64, R_AARCH64_PREL32) => (4, 1),
                (EM_AARCH64, R_AARCH64_ABS16) => (2, 0),
                (EM_AARCH64, R_AARCH64_PREL16) => (2, 1),
                (EM_AARCH64, R_AARCH64_CALL26 | R_AARCH64_JUMP26) if rel.r_addend.is_some() => (4, 2),
                (EM_ARM, R_ARM_ABS32) => (4, 0),
                (EM_ARM, R_ARM_REL32) => (4, 1),
                (EM_68K, 1) => (4, 0), // R_68K_32
                (EM_68K, 2) => (2, 0), // R_68K_16
                (EM_68K, 3) => (1, 0), // R_68K_8
                (EM_68K, 4) => (4, 1), // R_68K_PC32
                (EM_68K, 5) => (2, 1), // R_68K_PC16
                (EM_68K, 6) => (1, 1), // R_68K_PC8
                (EM_RISCV, R_RISCV_32) => (4, 0),
                (EM_RISCV, R_RISCV_64) => (8, 0),
                _ => { skipped += 1; continue; }
            };
            let addend = if formula == 2 { rel.r_addend.unwrap_or(0) }
                else { rel.r_addend.or_else(|| read_elf_word(bin, place, width)).unwrap_or(0) };
            let value = if formula == 0 || formula == 2 { (s as i128) + (addend as i128) }
                else { (s as i128) + (addend as i128) - (place as i128) };
            let ok = if formula == 2 {
                let aligned = value % 4 == 0;
                let in_range = (-(1i128 << 27)..(1i128 << 27)).contains(&value);
                if aligned && in_range {
                    if let Some(old) = read_elf_word(bin, place, 4) {
                        let instruction = old as u32;
                        let patched = (instruction & 0xfc00_0000) | (((value >> 2) as u32) & 0x03ff_ffff);
                        write_elf_word(bin, place, 4, patched as i32 as i64)
                    } else { false }
                } else { false }
            } else {
                write_elf_word(bin, place, width, value as i64)
            };
            if ok { applied += 1; } else { skipped += 1; }
        }
    }
    (applied, skipped)
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
        0xAA64 => {
            bin.arch = Arch::Arm64;
            bin.arch_name = "ARM64".into()
        }
        0x1C4 => {
            bin.arch = Arch::Thumb;
            bin.arch_name = "ARM Thumb-2".into()
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
    // TLS callbacks execute before the PE entry point and are often used for
    // runtime initialization or packer logic. Treat them as function starts.
    if let Some(tls) = &pe.tls_data {
        for &callback in &tls.callbacks {
            if callback >= base && bin.is_exec(callback) {
                bin.func_hints.push(callback);
            }
        }
        if !tls.callbacks.is_empty() {
            bin.notes.push(format!("PE TLS callbacks: {} function-start hint(s).", tls.callbacks.len()));
        }
    }
    for imp in &pe.imports {
        bin.imports.push(Import {
            slot: base + imp.rva as u64,
            name: imp.name.to_string(),
            library: imp.dll.to_string(),
        });
    }
    bin.libraries = pe.libraries.iter().map(|s| s.to_string()).collect();
    for library in add_pe_delay_imports(bin, pe, base) {
        if !bin.libraries.iter().any(|known| known.eq_ignore_ascii_case(&library)) {
            bin.libraries.push(library);
        }
    }
    for e in &pe.exports {
        if let Some(n) = e.name {
            bin.exports.push(Export { addr: base + e.rva as u64, name: n.to_string() });
            bin.symbols.push((base + e.rva as u64, n.to_string()));
        }
    }
}

fn add_pe_delay_imports(bin: &mut Binary, pe: &goblin::pe::PE, base: u64) -> Vec<String> {
    let Some(opt) = pe.header.optional_header.as_ref() else { return Vec::new() };
    let Some(dir) = opt.data_directories.get_delay_import_descriptor() else { return Vec::new() };
    let descriptor_base = base.saturating_add(dir.virtual_address as u64);
    let ptr_size = (bin.bitness() / 8) as u64;
    let is_rva = |attrs: u32, raw: u64| if attrs & 1 != 0 { base.saturating_add(raw) } else { raw };
    let read_u32 = |addr: u64| -> Option<u32> {
        let b = bin.read(addr, 4);
        if b.len() == 4 { Some(u32::from_le_bytes(b.try_into().ok()?)) } else { None }
    };
    let read_string = |addr: u64| -> Option<String> {
        let b = bin.read(addr, 512);
        let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
        (!b[..end].is_empty()).then(|| String::from_utf8_lossy(&b[..end]).into_owned())
    };
    let mut discovered = Vec::new();
    let mut libraries = Vec::new();
    for index in 0..1024u64 {
        let d = descriptor_base.saturating_add(index * 32);
        let attrs = match read_u32(d) { Some(v) => v, None => break };
        let fields = [
            read_u32(d + 4).unwrap_or(0) as u64,
            read_u32(d + 8).unwrap_or(0) as u64,
            read_u32(d + 12).unwrap_or(0) as u64,
            read_u32(d + 16).unwrap_or(0) as u64,
            read_u32(d + 20).unwrap_or(0) as u64,
        ];
        if attrs == 0 && fields.iter().all(|v| *v == 0) { break; }
        let name_addr = is_rva(attrs, fields[0]);
        let library = read_string(name_addr).unwrap_or_else(|| "delay-import".into());
        if !libraries.iter().any(|known: &String| known.eq_ignore_ascii_case(&library)) {
            libraries.push(library.clone());
        }
        let int_addr = is_rva(attrs, fields[3]);
        let iat_addr = is_rva(attrs, fields[2]);
        if int_addr == 0 || iat_addr == 0 { continue; }
        for slot in 0..65536u64 {
            let entry_addr = int_addr.saturating_add(slot * ptr_size);
            let Some(raw) = bin.read_ptr(entry_addr) else { break };
            if raw == 0 { break; }
            let ordinal_mask = if ptr_size == 8 { 1u64 << 63 } else { 1u64 << 31 };
            let name = if raw & ordinal_mask != 0 {
                format!("ordinal_{}", raw & 0xffff)
            } else {
                read_string(is_rva(attrs, raw & 0x7fff_ffff).saturating_add(2)).unwrap_or_else(|| "<unnamed>".into())
            };
            discovered.push(Import { slot: iat_addr.saturating_add(slot * ptr_size), name, library: library.clone() });
        }
    }
    bin.imports.extend(discovered);
    bin.imports.sort_by_key(|i| i.slot);
    bin.imports.dedup_by_key(|i| i.slot);
    libraries
}

fn load_mach(bin: &mut Binary, mach: goblin::mach::Mach, bytes: &[u8]) -> Result<(), String> {
    use goblin::mach::{Mach, SingleArch};
    match mach {
        Mach::Binary(m) => {
            load_macho(bin, &m, bytes);
            Ok(())
        }
        Mach::Fat(fat) => {
            let arches = fat.arches().map_err(|e| e.to_string())?;
            let mut names = vec![];
            let mut pick = None;
            for (i, a) in arches.iter().enumerate() {
                let n = goblin::mach::constants::cputype::get_arch_name_from_types(a.cputype, a.cpusubtype)
                    .unwrap_or(match a.cputype {
                        goblin::mach::constants::cputype::CPU_TYPE_ARM64 => "arm64",
                        goblin::mach::constants::cputype::CPU_TYPE_X86_64 => "x86_64",
                        goblin::mach::constants::cputype::CPU_TYPE_X86 => "i386",
                        _ => "unknown",
                    });
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
            let want = SLICE_PREF.lock().ok().and_then(|g| g.clone());
            if let Some(w) = want {
                if let Some(i) = names.iter().position(|n| *n == w) {
                    pick = Some(i);
                }
            }
            let idx = pick.unwrap_or(0);
            bin.slice = names[idx].clone();
            bin.file_base = arches.get(idx).map(|a| a.offset as u64).unwrap_or(0);
            bin.slices = names.clone();
            bin.notes.push(format!(
                "Universal program with {} parts ({}); showing the {} part.",
                names.len(),
                names.join(", "),
                names[idx]
            ));
            let _ = bytes;
            match fat.get(idx).map_err(|e| e.to_string())? {
                SingleArch::MachO(m) => {
                    let fb = bin.file_base as usize;
                    load_macho(bin, &m, bytes.get(fb..).unwrap_or(&[]));
                    Ok(())
                }
                SingleArch::Archive(_) => Err("This universal file holds a static library archive.".into()),
            }
        }
    }
}

fn load_macho(bin: &mut Binary, m: &goblin::mach::MachO, slice: &[u8]) {
    use goblin::mach::constants::cputype::*;
    let object_file = m.header.filetype == goblin::mach::header::MH_OBJECT;
    bin.big_endian = !m.little_endian;
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
        CPU_TYPE_ARM64 => {
            bin.arch = Arch::Arm64;
            bin.arch_name = "ARM64".into()
        }
        CPU_TYPE_ARM => {
            bin.arch = Arch::Arm32;
            bin.arch_name = "ARM (32-bit)".into()
        }
        6 => { // CPU_TYPE_MC680x0
            bin.arch = Arch::M68k;
            bin.arch_name = "Motorola 68000".into();
            bin.big_endian = true;
        }
        18 => { // CPU_TYPE_POWERPC
            bin.arch = Arch::Ppc32;
            bin.arch_name = "PowerPC".into();
            bin.big_endian = true;
        }
        0x0100_0012 => { // CPU_TYPE_POWERPC64
            bin.arch = Arch::Ppc64;
            bin.arch_name = "PowerPC 64".into();
            bin.big_endian = true;
        }
        c => bin.arch_name = get_arch_name_from_types(c, m.header.cpusubtype).unwrap_or("unknown").to_string(),
    }
    let mut text_base = 0u64;
    let mut section_bases = vec![None; 1];
    let mut section_ordinal = 0usize;
    let mut next_object_addr = 0x1000_0000u64;
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
                section_ordinal += 1;
                if section_bases.len() <= section_ordinal { section_bases.resize(section_ordinal + 1, None); }
                if sec.size == 0 {
                    continue;
                }
                let sname = sec.name().unwrap_or("").to_string();
                let start_addr = if object_file {
                    let align = 1u64.checked_shl(sec.align).unwrap_or(1).min(1 << 20);
                    let start = next_object_addr.saturating_add(align - 1) & !(align - 1);
                    section_bases[section_ordinal] = Some(start);
                    next_object_addr = start.saturating_add(sec.size).saturating_add(0x1000);
                    start
                } else { sec.addr };
                let zerofill = matches!(sec.flags & 0xff, 0x1 | 0xc | 0x12);
                let mut d = if zerofill { vec![] } else { data.to_vec() };
                d.resize(sec.size.min(MAX_ZERO_FILL) as usize, 0);
                let exec = sec.flags & 0x8000_0000 != 0 || sec.flags & 0x400 != 0;
                bin.segments.push(Segment {
                    name: format!("{segname},{sname}"),
                    start: start_addr,
                    size: sec.size,
                    data: d,
                    exec,
                    write: seg.initprot & 2 != 0,
                    file_offset: if zerofill { None } else { Some(sec.offset as u64) },
                });
            }
        }
    }
    if !object_file {
        for lc in &m.load_commands {
            let goblin::mach::load_command::CommandVariant::DataInCode(c) = &lc.command else { continue };
            let start = c.dataoff as usize;
            let end = start.saturating_add(c.datasize as usize).min(slice.len());
            let mut off = start;
            while off.saturating_add(8) <= end {
                let u32_at = |p: usize| -> u32 {
                    let b = &slice[p..p + 4];
                    if m.little_endian { u32::from_le_bytes(b.try_into().unwrap()) } else { u32::from_be_bytes(b.try_into().unwrap()) }
                };
                let u16_at = |p: usize| -> u16 {
                    let b = &slice[p..p + 2];
                    if m.little_endian { u16::from_le_bytes(b.try_into().unwrap()) } else { u16::from_be_bytes(b.try_into().unwrap()) }
                };
                let file_offset = u32_at(off) as u64;
                let length = u16_at(off + 4) as u64;
                if length != 0 {
                    if let Some(seg) = m.segments.iter().find(|seg| file_offset >= seg.fileoff && file_offset < seg.fileoff.saturating_add(seg.filesize)) {
                        let addr = seg.vmaddr.saturating_add(file_offset - seg.fileoff);
                        bin.data_ranges.push((addr, addr.saturating_add(length)));
                    }
                }
                off += 8;
            }
        }
        if !bin.data_ranges.is_empty() {
            bin.notes.push(format!("Mach-O LC_DATA_IN_CODE: {} embedded-data range(s) excluded from code discovery.", bin.data_ranges.len()));
        }
    }
    for lc in &m.load_commands {
        if let goblin::mach::load_command::CommandVariant::FunctionStarts(c) = &lc.command {
            let (o, n) = (c.dataoff as usize, c.datasize as usize);
            if let Some(blob) = slice.get(o..o + n) {
                bin.func_hints = crate::hints::macho_starts(blob, text_base);
            }
        }
    }
    if let Some(unwind) = bin.segments.iter().find(|s| s.name.ends_with(",__unwind_info")) {
        let mut starts = crate::hints::macho_unwind_info(&unwind.data, text_base, bin);
        bin.func_hints.append(&mut starts);
        bin.func_hints.sort_unstable();
        bin.func_hints.dedup();
    }
    if m.entry != 0 {
        // goblin already turns LC_MAIN's file offset into a virtual address.
        bin.entry = Some(m.entry);
    } else if object_file {
        bin.entry = bin.segments.iter().find(|s| s.exec).map(|s| s.start);
        let (applied, skipped) = apply_macho_object_relocations(bin, m, &section_bases);
        bin.notes.push(format!("Relocatable Mach-O object: sections and defined symbols are mapped at synthetic addresses; applied {applied} supported x86-64/ARM64 relocations and skipped {skipped} others."));
    }
    if let Some(syms) = &m.symbols {
        for (name, nl) in syms.iter().flatten() {
            if nl.is_stab() || nl.is_undefined() || (!object_file && nl.n_value == 0) || name.is_empty() {
                continue;
            }
            let a = if object_file {
                section_bases.get(nl.n_sect).and_then(|base| *base).map(|base| base.saturating_add(nl.n_value))
            } else { Some(nl.n_value) };
            let Some(a) = a else { continue };
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
    if bin.imports.is_empty() {
        chained_imports(bin, m);
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

fn apply_macho_object_relocations(
    bin: &mut Binary,
    macho: &goblin::mach::MachO<'_>,
    section_bases: &[Option<u64>],
) -> (usize, usize) {
    use goblin::mach::relocation::*;
    let Ok(relocation_sections) = macho.relocations() else { return (0, 0) };
    let mut applied = 0usize;
    let mut skipped = 0usize;
    for (_, relocs, section) in relocation_sections {
        let seg_name = section.segname().unwrap_or("");
        let sec_name = section.name().unwrap_or("");
        let source_name = format!("{seg_name},{sec_name}");
        let Some(source_base) = bin.segments.iter().find(|s| s.name == source_name).map(|s| s.start) else {
            skipped += section.nreloc as usize;
            continue;
        };
        for item in relocs {
            let Ok(reloc) = item else { skipped += 1; continue };
            if reloc.r_address < 0 { skipped += 1; continue; }
            let place = source_base.saturating_add(reloc.r_address as u64);
            let target = if reloc.is_extern() {
                let Some(symbols) = &macho.symbols else { skipped += 1; continue };
                let Ok((_, symbol)) = symbols.get(reloc.r_symbolnum()) else { skipped += 1; continue };
                if symbol.is_undefined() { skipped += 1; continue; }
                if symbol.n_sect == 0 { Some(symbol.n_value) }
                else { section_bases.get(symbol.n_sect).and_then(|base| *base).map(|base| base.saturating_add(symbol.n_value)) }
            } else {
                section_bases.get(reloc.r_symbolnum()).and_then(|base| *base)
            };
            let Some(target) = target else { skipped += 1; continue };
            let width = 1usize << reloc.r_length();
            let (formula, branch26) = match (macho.header.cputype, reloc.r_type()) {
                (0x0100_0007, X86_64_RELOC_UNSIGNED) if matches!(width, 4 | 8) => (0, false),
                (0x0100_0007, X86_64_RELOC_SIGNED | X86_64_RELOC_BRANCH) if width == 4 => (1, false),
                (0x0100_000c, ARM64_RELOC_UNSIGNED) if matches!(width, 4 | 8) => (0, false),
                (0x0100_000c, ARM64_RELOC_BRANCH26) if width == 4 => (1, true),
                _ => { skipped += 1; continue; }
            };
            let addend = if branch26 {
                let Some(raw) = read_elf_word(bin, place, 4) else { skipped += 1; continue };
                let imm = (raw as u32 & 0x03ff_ffff) as i32;
                ((imm << 6) >> 4) as i64
            } else {
                let Some(a) = read_elf_word(bin, place, width) else { skipped += 1; continue };
                a
            };
            let value = if formula == 0 { (target as i128) + (addend as i128) }
                else { (target as i128) + (addend as i128) - (place as i128) };
            let ok = if branch26 {
                if value % 4 != 0 || !(-(1i128 << 27)..(1i128 << 27)).contains(&value) { false }
                else if let Some(old) = read_elf_word(bin, place, 4) {
                    let insn = old as u32;
                    let patched = (insn & 0xfc00_0000) | (((value >> 2) as u32) & 0x03ff_ffff);
                    write_elf_word(bin, place, 4, patched as i32 as i64)
                } else { false }
            } else {
                write_elf_word(bin, place, width, value as i64)
            };
            if ok { applied += 1; } else { skipped += 1; }
        }
    }
    (applied, skipped)
}

/// Imports from `LC_DYLD_CHAINED_FIXUPS` (what current arm64 Mach-O files use instead of bind opcodes).
fn chained_imports(bin: &mut Binary, m: &goblin::mach::MachO) {
    use goblin::mach::load_command::CommandVariant;
    let Some((off, size)) = m.load_commands.iter().find_map(|lc| match &lc.command {
        CommandVariant::DyldChainedFixups(c) => Some((c.dataoff as usize, c.datasize as usize)),
        _ => None,
    }) else { return };
    let Some(le) = m.segments.iter().find(|s| s.name().map(|n| n == "__LINKEDIT").unwrap_or(false)) else { return };
    let Some(rel) = off.checked_sub(le.fileoff as usize) else { return };
    let Some(blob) = le.data.get(rel..rel + size) else { return };
    let u32_at = |o: usize| blob.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let u16_at = |o: usize| blob.get(o..o + 2).map(|b| u16::from_le_bytes(b.try_into().unwrap()));
    let u64_at = |o: usize| blob.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    let (Some(starts_off), Some(imports_off), Some(syms_off), Some(count), Some(fmt)) =
        (u32_at(4), u32_at(8), u32_at(12), u32_at(16), u32_at(20)) else { return };
    let (starts_off, imports_off, syms_off, count) = (starts_off as usize, imports_off as usize, syms_off as usize, count as usize);
    let sym = |name_off: usize| -> String {
        let s = syms_off + name_off;
        let end = blob[s.min(blob.len())..].iter().position(|b| *b == 0).map(|e| s + e).unwrap_or(blob.len());
        String::from_utf8_lossy(&blob[s.min(blob.len())..end]).to_string()
    };
    let mut imps: Vec<(String, String)> = vec![];
    for i in 0..count.min(200_000) {
        let (ord, name_off) = match fmt {
            1 | 2 => {
                let Some(v) = u32_at(imports_off + i * if fmt == 1 { 4 } else { 8 }) else { break };
                ((v & 0xFF) as usize, (v >> 9) as usize)
            }
            3 => {
                let Some(v) = u64_at(imports_off + i * 16) else { break };
                ((v & 0xFFFF) as usize, (v >> 32) as usize)
            }
            _ => return,
        };
        let lib = match ord {
            0xFF..=0xFFFF if ord >= 0xFE => String::new(),
            n => m.libs.get(n).map(|s| s.to_string()).unwrap_or_default(),
        };
        imps.push((sym(name_off), lib));
    }
    let Some(seg_count) = u32_at(starts_off) else { return };
    for si in 0..seg_count as usize {
        let Some(so) = u32_at(starts_off + 4 + si * 4) else { break };
        if so == 0 { continue; }
        let seg = starts_off + so as usize;
        let (Some(page_size), Some(ptr_fmt), Some(seg_off), Some(pages)) = (u16_at(seg + 4), u16_at(seg + 6), u64_at(seg + 8), u16_at(seg + 20)) else { continue };
        // find the segment this belongs to (offset is relative to the image's first segment address)
        let base = m.segments.iter().find(|s| s.name().map(|n| n == "__TEXT").unwrap_or(false)).map(|s| s.vmaddr).unwrap_or(0);
        let vm = base + seg_off;
        let Some(sg) = m.segments.iter().find(|s| s.vmaddr == vm) else { continue };
        let (stride, next_shift, next_bits) = match ptr_fmt { 1 | 9 | 12 => (8u64, 51u32, 11u32), 2 | 6 => (4, 51, 12), _ => continue };
        for p in 0..pages as usize {
            let Some(mut start) = u16_at(seg + 22 + p * 2) else { break };
            if start == 0xFFFF { continue; }
            let mut addr = vm + p as u64 * page_size as u64 + start as u64;
            for _ in 0..(page_size as usize / 4 + 1) {
                let o = (addr - sg.vmaddr) as usize;
                let Some(raw) = sg.data.get(o..o + 8) else { break };
                let v = u64::from_le_bytes(raw.try_into().unwrap());
                let (bind, ord) = match ptr_fmt {
                    1 | 9 | 12 => ((v >> 62) & 1 == 1, (v & 0xFFFF) as usize),
                    _ => ((v >> 63) & 1 == 1, (v & 0xFF_FFFF) as usize),
                };
                if bind {
                    if let Some((name, lib)) = imps.get(ord) {
                        bin.imports.push(Import { slot: addr, name: name.clone(), library: lib.clone() });
                    }
                }
                let next = (v >> next_shift) & ((1u64 << next_bits) - 1);
                if next == 0 { break; }
                addr += next * stride;
                start = 0;
                let _ = start;
            }
        }
    }
}

// ------------------------------------------------------------ raw bytes / hex input

/// A block of machine code that isn't wrapped in a program file (firmware, shellcode, pasted bytes).
#[derive(Clone)]
pub struct RawSpec {
    pub path: String,
    pub name: String,
    pub arch: Arch,
    pub big: bool,
    pub segs: Vec<(u64, Vec<u8>)>,
    pub entry: Option<u64>,
    pub format: String,
}

pub fn raw_binary(spec: &RawSpec) -> Binary {
    let total: u64 = spec.segs.iter().map(|s| s.1.len() as u64).sum();
    let mut bin = Binary {
        path: spec.path.clone(),
        file_name: spec.name.clone(),
        format: spec.format.clone(),
        arch: spec.arch,
        arch_name: spec.arch.name().to_string(),
        entry: spec.entry.or_else(|| spec.segs.first().map(|s| s.0)),
        segments: vec![],
        data_ranges: vec![],
        symbols: vec![],
        data_symbols: vec![],
        imports: vec![],
        exports: vec![],
        libraries: vec![],
        file_size: total,
        notes: vec![format!("Raw code loaded as {}{}.", spec.arch.name(), if spec.big { " (big-endian)" } else { "" })],
        slices: vec![],
        big_endian: spec.big,
        slice: String::new(),
        file_base: 0,
        func_hints: vec![],
        debug_protos: String::new(),
        debug_types: String::new(),
        debug_structs: vec![],
    };
    for (i, (start, data)) in spec.segs.iter().enumerate() {
        bin.segments.push(Segment {
            name: if spec.segs.len() == 1 { "RAW".into() } else { format!("RAW{}", i + 1) },
            start: *start,
            size: data.len() as u64,
            data: data.clone(),
            exec: true,
            write: false,
            file_offset: Some(0),
        });
    }
    bin.segments.sort_by_key(|s| s.start);
    bin
}

/// Pulls bytes out of pasted text: "48 8B EC", "0x48, 0x8b", "\x48\x8b", "488bec", or objdump-style columns.
pub fn parse_hex_text(text: &str) -> Vec<u8> {
    let cleaned = text.replace("0x", " ").replace("0X", " ").replace("\\x", " ");
    let mut digits = String::new();
    for tok in cleaned.split(|c: char| !c.is_ascii_hexdigit()) {
        digits.push_str(tok);
    }
    if digits.len() % 2 == 1 {
        digits.pop();
    }
    digits.as_bytes().chunks(2).filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok()).collect()
}

fn hexbyte(s: &str, i: usize) -> Option<u8> {
    u8::from_str_radix(s.get(i..i + 2)?, 16).ok()
}

/// Intel HEX (`:10010000214601360121470136007EFE09D2190140`), as (address, bytes) runs.
pub fn parse_ihex(text: &str) -> Option<Vec<(u64, Vec<u8>)>> {
    if !text.trim_start().starts_with(':') {
        return None;
    }
    let mut base = 0u64;
    let mut runs: Vec<(u64, Vec<u8>)> = vec![];
    for line in text.lines() {
        let l = line.trim();
        let Some(l) = l.strip_prefix(':') else { continue };
        let n = hexbyte(l, 0)? as usize;
        let addr = ((hexbyte(l, 2)? as u64) << 8) | hexbyte(l, 4)? as u64;
        let ty = hexbyte(l, 6)?;
        let data: Option<Vec<u8>> = (0..n).map(|i| hexbyte(l, 8 + i * 2)).collect();
        let data = data?;
        match ty {
            0 => {
                let a = base + addr;
                match runs.last_mut() {
                    Some((s, d)) if *s + d.len() as u64 == a => d.extend(data),
                    _ => runs.push((a, data)),
                }
            }
            1 => break,
            2 => base = (((data.first().copied()? as u64) << 8) | data.get(1).copied()? as u64) << 4,
            4 => base = (((data.first().copied()? as u64) << 8) | data.get(1).copied()? as u64) << 16,
            _ => {}
        }
    }
    (!runs.is_empty()).then_some(runs)
}

/// Motorola S-records (S1/S2/S3 data lines).
pub fn parse_srec(text: &str) -> Option<Vec<(u64, Vec<u8>)>> {
    let t = text.trim_start();
    if !(t.starts_with("S0") || t.starts_with("S1") || t.starts_with("S2") || t.starts_with("S3")) {
        return None;
    }
    let mut runs: Vec<(u64, Vec<u8>)> = vec![];
    for line in text.lines() {
        let l = line.trim();
        let b = l.as_bytes();
        if b.len() < 10 || b[0] != b'S' {
            continue;
        }
        let alen = match b[1] { b'1' => 2, b'2' => 3, b'3' => 4, _ => continue };
        let count = hexbyte(l, 2)? as usize;
        let mut addr = 0u64;
        for i in 0..alen {
            addr = (addr << 8) | hexbyte(l, 4 + i * 2)? as u64;
        }
        let dlen = count.checked_sub(alen + 1)?;
        let data: Option<Vec<u8>> = (0..dlen).map(|i| hexbyte(l, 4 + alen * 2 + i * 2)).collect();
        let data = data?;
        match runs.last_mut() {
            Some((s, d)) if *s + d.len() as u64 == addr => d.extend(data),
            _ => runs.push((addr, data)),
        }
    }
    (!runs.is_empty()).then_some(runs)
}

#[cfg(test)]
mod raw_tests {
    use super::*;
    #[test]
    fn hex_forms() {
        assert_eq!(parse_hex_text("48 8B EC"), vec![0x48, 0x8b, 0xec]);
        assert_eq!(parse_hex_text("{0x48, 0x8b, 0xec}"), vec![0x48, 0x8b, 0xec]);
        assert_eq!(parse_hex_text("\\x48\\x8b\\xec"), vec![0x48, 0x8b, 0xec]);
        assert_eq!(parse_hex_text("488bec"), vec![0x48, 0x8b, 0xec]);
    }
    #[test]
    fn ihex() {
        let r = parse_ihex(":0300300002337A1E\n:00000001FF\n").unwrap();
        assert_eq!(r, vec![(0x30, vec![0x02, 0x33, 0x7a])]);
    }
    #[test]
    fn ifunc_symbols_are_function_like() {
        assert!(is_elf_function_type(goblin::elf::sym::STT_FUNC));
        assert!(is_elf_function_type(goblin::elf::sym::STT_GNU_IFUNC));
        assert!(!is_elf_function_type(goblin::elf::sym::STT_OBJECT));
    }
}
