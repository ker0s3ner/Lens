//! Auto-analysis: decodes x86/x64 code by following control flow, finds functions,
//! basic blocks, cross-references, strings, and builds the listing lines.
//! Rules come from MECHANICS.md (naming prefixes, no-return names, string length, xref count).

use crate::loader::{Arch, Binary};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flow {
    Normal,
    Call,
    IndirectCall,
    Jump,
    IndirectJump,
    CondJump,
    Ret,
    Stop,
}

#[derive(Clone, Copy, Debug)]
pub struct Insn {
    pub len: u8,
    pub flow: Flow,
    /// Direct branch / call target (0 if none).
    pub target: u64,
    /// Memory operand address (RIP-relative or absolute), 0 if none.
    pub mem: u64,
    /// Size in bytes of the memory operand (0 if none).
    pub mem_size: u8,
    /// Immediate operand that points into the program, 0 if none.
    pub imm: u64,
    pub is_lea: bool,
    pub is_write: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EdgeKind {
    /// Conditional branch taken (green in the graph).
    Taken,
    /// Conditional branch not taken (red in the graph).
    NotTaken,
    /// Unconditional flow (blue in the graph).
    Always,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub start: u64,
    pub end: u64,
    pub insns: Vec<u64>,
    pub succs: Vec<(u64, EdgeKind)>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FuncKind {
    Normal,
    /// A stub that only jumps to an imported function.
    Import,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub start: u64,
    pub end: u64,
    pub blocks: Vec<Block>,
    pub insn_count: usize,
    pub kind: FuncKind,
    pub noreturn: bool,
    pub calls: Vec<u64>,
    pub has_symbol: bool,
    /// Direct forwarding target for a one-instruction thunk, when known.
    pub thunk_target: Option<u64>,
}

impl Function {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    pub fn block_of(&self, a: u64) -> Option<usize> {
        self.blocks.iter().position(|b| b.insns.contains(&a))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum XrefKind {
    Call,
    Jump,
    Switch,
    Read,
    Write,
    Offset,
    Data,
}

impl XrefKind {
    /// One-letter mark as IDA shows it (p = procedure call, j = jump, r/w = read/write, o = offset).
    pub fn mark(self) -> &'static str {
        match self {
            XrefKind::Call => "p",
            XrefKind::Jump => "j",
            XrefKind::Switch => "j",
            XrefKind::Read => "r",
            XrefKind::Write => "w",
            XrefKind::Offset => "o",
            XrefKind::Data => "o",
        }
    }
    pub fn is_code(self) -> bool {
        matches!(self, XrefKind::Call | XrefKind::Jump | XrefKind::Switch)
    }
    pub fn label(self) -> &'static str {
        match self {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
            XrefKind::Switch => "switch case",
            XrefKind::Read => "read",
            XrefKind::Write => "write",
            XrefKind::Offset => "address taken",
            XrefKind::Data => "pointer",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Xref {
    pub from: u64,
    pub kind: XrefKind,
}

#[derive(Clone, Debug)]
pub struct StrLit {
    pub addr: u64,
    /// Bytes including terminator.
    pub len: u32,
    pub wide: bool,
    pub text: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineKind {
    Segment,
    Blank,
    FuncSep,
    FuncStart,
    Label,
    Insn,
    FuncEnd,
    Str,
    Ptr,
    Data,
    Bytes,
    Zeros,
}

#[derive(Clone, Copy, Debug)]
pub struct Line {
    pub addr: u64,
    pub kind: LineKind,
    pub len: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameKind {
    Function,
    Import,
    Label,
    String,
    Data,
}

pub struct Analysis {
    pub insns: BTreeMap<u64, Insn>,
    pub functions: BTreeMap<u64, Function>,
    pub xrefs_to: HashMap<u64, Vec<Xref>>,
    pub strings: Vec<StrLit>,
    pub string_at: HashMap<u64, usize>,
    pub names: HashMap<u64, (String, NameKind)>,
    pub import_slot: HashMap<u64, usize>,
    pub lines: Vec<Line>,
    pub data_size: HashMap<u64, u8>,
    pub stats: String,
    /// Recovered jump tables: address of the indirect jump -> its case targets.
    pub switches: HashMap<u64, Vec<u64>>,
    /// Conservative vtable-like tables: table address -> consecutive code pointers.
    /// Only runs with at least two executable, mapped targets are reported.
    pub vtables: HashMap<u64, Vec<u64>>,
    /// Validated pointer tables in non-executable data, including data and code pointers.
    pub pointer_tables: HashMap<u64, Vec<u64>>,
}

pub struct Settings {
    pub min_string_len: usize,
    pub extra_functions: Vec<u64>,
    /// The person's own data definitions: address -> byte size (1/2/4/8, `| 0x80` for a pointer),
    /// `DEF_STRING` for a C string, `DEF_UNDEFINE` to drop whatever was guessed there.
    pub data_defs: HashMap<u64, u8>,
}

pub const DEF_STRING: u8 = 0x7E;
pub const DEF_UNDEFINE: u8 = 0x7F;

/// Names of functions that never return (from IDA's cfg/noret.cfg, leading underscores and dots stripped).
pub const NORETURN: &[&str] = &[
    "exit", "xexit", "abort", "errx", "err", "std::terminate", "std::unexpected", "terminate",
    "GI__exit", "GI_abort", "GI__assert_fail", "GI__libc_fatal", "invoke_watson",
    "invalid_parameter_noinfo_noreturn", "longjmp", "longjmp_chk", "siglongjmp", "ExitProcess",
    "ExitThread", "assert", "wassert", "assert_fail", "stack_chk_fail", "stack_chk_fail_local",
    "stack_smash_handler", "report_gsfailure", "report_rangecheckfailure", "report_securityfailure",
    "CxxThrowException", "Unwind_Resume", "Unwind_SjLj_Resume", "cxa_throw", "cxa_rethrow",
    "Exit", "exit_group", "pthread_exit", "assert_rtn", "libc_fatal", "fortify_fail", "chk_fail",
    "rust_begin_unwind", "rust_start_panic", "panic", "panic_fmt", "panic_nounwind", "panic_cannot_unwind",
    "swift_fatalError", "fatalError", "fatal", "builtin_trap", "trap", "cxa_pure_virtual",
    "ubsan_handle_builtin_unreachable", "ubsan_handle_type_mismatch_v1",
];

pub fn is_noreturn_name(name: &str) -> bool {
    let mut n = name.trim();
    // Strip common symbol decoration from Mach-O/COFF and ELF versioning.
    n = n.trim_start_matches(['_', '.']);
    n = n.split("@@").next().unwrap_or(n);
    n = n.split('@').next().unwrap_or(n);
    n = n.strip_suffix(".cold").unwrap_or(n);
    n = n.strip_suffix("() ").unwrap_or(n).trim_end_matches("()").trim();
    let short = n.rsplit("::").next().unwrap_or(n);
    NORETURN.iter().any(|x| *x == n || *x == short)
}

/// Arch-neutral summary of the instruction at `addr` (any supported CPU).
/// Finds the targets of a compiler-generated switch: `cmp idx, N; ja default; lea base,[table]; movsxd; add; jmp reg`
/// (position independent, 4-byte offsets) or `jmp [table + idx*8]` (absolute pointers).
/// ARM64 switch: `cmp w, #N; b.hi default; adrp/add table; ldrsw|ldrb|ldrh idx; add/adr base; br x`.
fn arm64_switch_targets(bin: &Binary, insns: &BTreeMap<u64, Insn>, at: u64, fstart: u64) -> Vec<u64> {
    use std::collections::HashMap as M;
    let num = |t: &str| -> Option<u64> {
        let t = t.trim().trim_start_matches('#');
        if let Some(h) = t.strip_prefix("0x") { u64::from_str_radix(h, 16).ok() } else { t.parse().ok() }
    };
    let reg = |t: &str| -> String { t.trim().trim_start_matches(['x', 'w']).to_string() };
    let mut back: Vec<u64> = insns.range(..at).rev().take(14).map(|(a, _)| *a).collect();
    back.reverse();
    let mut val: M<String, u64> = M::new();
    let mut table: Option<(u64, u8)> = None; // (table address, entry size; 4 = signed offsets from the table)
    let mut base: Option<u64> = None;
    let mut bound: Option<u64> = None;
    let mut shift = 2u32;
    let mut after_cmp_branch = false;
    let mut cmp_imm: Option<u64> = None;
    for a in back {
        let Some(i) = crate::multiarch::one(bin, a) else { continue };
        let ops: Vec<&str> = i.ops.split(", ").collect();
        match i.mnemonic.as_str() {
            "adrp" | "adr" => { if let Some(v) = ops.get(1).and_then(|o| num(o)) { val.insert(reg(ops[0]), v); } }
            "add" if ops.len() == 3 && ops[2].starts_with('#') => {
                if let (Some(b), Some(im)) = (val.get(&reg(ops[1])).copied(), num(ops[2])) { val.insert(reg(ops[0]), b + im); }
            }
            "add" if ops.len() == 3 => {
                // add xD, xBase, xOffset
                if let Some(b) = val.get(&reg(ops[1])).copied() { base = Some(b); }
            }
            "csel" => { if bound.is_none() { bound = cmp_imm; } }
            "add" if ops.len() >= 4 => {
                // add xB, xBase, xOff, lsl|sxtb|sxth #2
                if let Some(sh) = ops[3].rsplit('#').next().and_then(|x| x.trim().parse::<u32>().ok()) { shift = sh; }
                if let Some(b) = val.get(&reg(ops[1])).copied() { base = Some(b); }
            }
            "ldrsw" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" => {
                // ldrsw x8, [x9, x8, lsl #2]
                let m = i.ops.split('[').nth(1).unwrap_or("").trim_end_matches(']');
                let parts: Vec<&str> = m.split(", ").collect();
                if let Some(t) = parts.first().and_then(|r| val.get(&reg(r)).copied()) {
                    let size = match i.mnemonic.as_str() { "ldrsw" => 4, "ldrb" | "ldrsb" => 1, _ => 2 };
                    table = Some((t, size));
                }
            }
            "cmp" => { cmp_imm = ops.get(1).and_then(|o| num(o)); }
            m if m.starts_with("b.") && matches!(&m[2..], "hi" | "hs" | "ls" | "lo" | "cs" | "cc") => { after_cmp_branch = true; }
            _ => {}
        }
        if after_cmp_branch && bound.is_none() { bound = cmp_imm; }
    }
    let Some((tbl, size)) = table else { return vec![] };
    if !bin.is_mapped(tbl) { return vec![]; }
    let count = bound.map(|b| (b + 1) as usize).filter(|c| (2..=1024).contains(c)).unwrap_or(256);
    let mut out = vec![];
    for k in 0..count {
        let t = match size {
            4 => {
                let b = bin.read(tbl + 4 * k as u64, 4);
                if b.len() < 4 { break; }
                (base.unwrap_or(tbl) as i64 + i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64) as u64
            }
            1 => {
                let Some(bs) = bin.byte(tbl + k as u64) else { break };
                base.unwrap_or(tbl) + ((bs as u64) << shift)
            }
            _ => {
                let b = bin.read(tbl + 2 * k as u64, 2);
                if b.len() < 2 { break; }
                base.unwrap_or(tbl) + ((u16::from_le_bytes([b[0], b[1]]) as u64) << shift)
            }
        };
        if !bin.is_exec(t) || t.abs_diff(fstart) >= 0x40_0000 || decode_info(bin, t).is_none() { break; }
        out.push(t);
    }
    let uniq: HashSet<&u64> = out.iter().collect();
    if uniq.len() < 2 { vec![] } else { out }
}

/// Recover Thumb TBB/TBH tables. Those instructions encode each case as an
/// unsigned byte/halfword scaled by two and based from the instruction's PC.
fn arm_thumb_switch_targets(bin: &Binary, insns: &BTreeMap<u64, Insn>, at: u64, fstart: u64) -> Vec<u64> {
    let Some(raw) = crate::multiarch::one(bin, at) else { return vec![] };
    let raw_ops = raw.ops.to_ascii_lowercase();
    if raw.mnemonic == "add" && raw_ops.starts_with("pc, pc,") && raw_ops.contains("lsl #2") {
        let mut bound = None;
        for (&addr, _) in insns.range(..at).rev().take(20) {
            let Some(prev) = crate::multiarch::one(bin, addr) else { continue };
            if prev.mnemonic == "cmp" {
                let n = prev.ops.rsplit(',').next().and_then(|s| s.trim().trim_start_matches('#').parse::<u64>().ok());
                bound = n.map(|v| v.saturating_add(1));
                break;
            }
        }
        let count = bound.unwrap_or(256).clamp(2, 1024) as usize;
        let base = (at + 4) & !3;
        let mut out = Vec::new();
        for k in 0..count {
            let target = base.saturating_add((k * 4) as u64);
            if !bin.is_exec(target) || target.abs_diff(fstart) >= 0x40_0000 || decode_info(bin, target).is_none() { break; }
            out.push(target);
        }
        return if out.iter().collect::<HashSet<_>>().len() >= 2 { out } else { vec![] };
    }
    let width = match raw.mnemonic.as_str() { "tbb" => 1usize, "tbh" => 2, _ => return vec![] };
    let table_base = if raw.ops.to_ascii_lowercase().contains("pc") { (at + 4) & !3 } else { return vec![] };
    let parse = |s: &str| -> Option<u64> {
        let s = s.trim().trim_start_matches('#');
        s.strip_prefix("0x").and_then(|h| u64::from_str_radix(h, 16).ok()).or_else(|| s.parse().ok())
    };
    let mut bound = None;
    for (&addr, _) in insns.range(..at).rev().take(20) {
        let Some(prev) = crate::multiarch::one(bin, addr) else { continue };
        if prev.mnemonic == "cmp" {
            bound = prev.ops.rsplit(',').next().and_then(parse).map(|v| v.saturating_add(1));
        }
        if matches!(prev.mnemonic.as_str(), "bhi" | "bhs" | "bcs" | "bgt" | "bge") && bound.is_some() { break; }
    }
    let count = bound.unwrap_or(256).clamp(2, 1024) as usize;
    let mut targets = Vec::new();
    for index in 0..count {
        let addr = table_base.saturating_add((index * width) as u64);
        let bytes = bin.read(addr, width);
        if bytes.len() != width { break; }
        let value = if width == 1 { bytes[0] as u64 } else if bin.big_endian { u16::from_be_bytes([bytes[0], bytes[1]]) as u64 } else { u16::from_le_bytes([bytes[0], bytes[1]]) as u64 };
        let target = at.saturating_add(4).saturating_add(value.saturating_mul(2));
        if !bin.is_exec(target) || target.abs_diff(fstart) >= 0x40_0000 || decode_info(bin, target).is_none() { break; }
        targets.push(target);
    }
    let unique: HashSet<&u64> = targets.iter().collect();
    if unique.len() < 2 { vec![] } else { targets }
}

/// Recover the common ARM32 absolute jump table form:
/// `cmp rN, #bound; ...; ldr pc, [pc, rN, lsl #2]`.
fn arm32_switch_targets(bin: &Binary, insns: &BTreeMap<u64, Insn>, at: u64, fstart: u64) -> Vec<u64> {
    let Some(raw) = crate::multiarch::one(bin, at) else { return vec![] };
    let ops = raw.ops.to_ascii_lowercase();
    if raw.mnemonic == "add" && ops.starts_with("pc, pc,") && ops.contains("lsl #2") {
        let mut bound = None;
        for (&addr, _) in insns.range(..at).rev().take(24) {
            let Some(prev) = crate::multiarch::one(bin, addr) else { continue };
            if prev.mnemonic == "cmp" {
                let n = prev.ops.rsplit(',').next().unwrap_or("").trim().trim_start_matches('#');
                bound = n.strip_prefix("0x").and_then(|h| u64::from_str_radix(h, 16).ok()).or_else(|| n.parse().ok()).map(|v| v + 1);
                break;
            }
        }
        let count = bound.unwrap_or(256).clamp(2, 1024) as usize;
        let mut out = Vec::new();
        for k in 0..count {
            let target = at.saturating_add(8).saturating_add((k * 4) as u64);
            if !bin.is_exec(target) || target.abs_diff(fstart) >= 0x40_0000 || decode_info(bin, target).is_none() { break; }
            out.push(target);
        }
        return if out.iter().collect::<HashSet<_>>().len() >= 2 { out } else { vec![] };
    }
    if !raw.mnemonic.starts_with("ldr") || !raw.ops.to_ascii_lowercase().starts_with("pc,") {
        return vec![];
    }
    if !ops.contains("[pc,") || !ops.contains("lsl #2") { return vec![]; }
    let mut bound = None;
    for (&addr, _) in insns.range(..at).rev().take(24) {
        let Some(prev) = crate::multiarch::one(bin, addr) else { continue };
        if prev.mnemonic == "cmp" {
            let n = prev.ops.rsplit(',').next().unwrap_or("").trim().trim_start_matches('#');
            bound = n.strip_prefix("0x").and_then(|h| u64::from_str_radix(h, 16).ok()).or_else(|| n.parse().ok()).map(|v| v + 1);
            break;
        }
    }
    let count = bound.unwrap_or(256).clamp(2, 1024) as usize;
    // In ARM state the PC operand reads as address + 8.
    let table = at.saturating_add(8);
    let mut out = Vec::new();
    for k in 0..count {
        let b = bin.read(table + (k * 4) as u64, 4);
        if b.len() != 4 { break; }
        let t = if bin.big_endian { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64 } else { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64 };
        if !bin.is_exec(t) || t.abs_diff(fstart) >= 0x40_0000 || decode_info(bin, t).is_none() { break; }
        out.push(t);
    }
    if out.iter().collect::<HashSet<_>>().len() < 2 { vec![] } else { out }
}

/// Recover a common MIPS absolute jump table:
/// `lui t9, hi(table); addiu t9, t9, lo(table); lw t9, 0(t9); jr t9`.
fn mips_switch_targets(bin: &Binary, insns: &BTreeMap<u64, Insn>, at: u64, fstart: u64) -> Vec<u64> {
    let Some(last) = crate::multiarch::one(bin, at) else { return vec![] };
    if last.mnemonic != "jr" { return vec![]; }
    let reg = |s: &str| s.trim().trim_start_matches('$').to_ascii_lowercase();
    let target_reg = reg(last.ops.split(',').next().unwrap_or(""));
    if target_reg.is_empty() || target_reg == "ra" { return vec![]; }
    let num = |s: &str| -> Option<i64> {
        let s = s.trim().trim_start_matches('#');
        if let Some(h) = s.strip_prefix("0x") { i64::from_str_radix(h, 16).ok() }
        else { s.parse().ok() }
    };
    let mut table: Option<u64> = None;
    let mut bound: Option<usize> = None;
    let mut back: Vec<u64> = insns.range(..at).rev().take(18).map(|(addr, _)| *addr).collect();
    back.reverse();
    for addr in back {
        let Some(i) = crate::multiarch::one(bin, addr) else { continue };
        let ops: Vec<&str> = i.ops.split(',').map(str::trim).collect();
        match i.mnemonic.as_str() {
            "lui" if ops.len() >= 2 && reg(ops[0]) == target_reg => {
                if let Some(v) = num(ops[1]) { table = Some((v as u64) << 16); }
            }
            "addiu" | "daddiu" | "ori" if ops.len() >= 3 && reg(ops[0]) == target_reg && reg(ops[1]) == target_reg => {
                if let (Some(base), Some(delta)) = (table, num(ops[2])) { table = Some(base.wrapping_add(delta as u64)); }
            }
            "lw" | "ld" if ops.len() >= 2 && reg(ops[0]) == target_reg => {
                if let Some((off, base)) = ops[1].split_once('(') {
                    if reg(base.trim_end_matches(')')) == target_reg {
                        if let (Some(t), Some(d)) = (table, num(off)) { table = Some(t.wrapping_add(d as u64)); }
                    }
                }
            }
            "slti" | "sltiu" if ops.len() >= 3 => bound = num(ops[2]).and_then(|n| usize::try_from(n).ok()),
            _ => {}
        }
    }
    let Some(table) = table else { return vec![] };
    if !bin.is_mapped(table) { return vec![]; }
    let width = if bin.arch == Arch::Mips64 { 8 } else { 4 };
    let count = bound.unwrap_or(256).clamp(2, 1024);
    let mut out = Vec::new();
    for k in 0..count {
        let b = bin.read(table + (k * width) as u64, width);
        if b.len() != width { break; }
        let t = if width == 8 {
            if bin.big_endian { u64::from_be_bytes(b.try_into().unwrap()) } else { u64::from_le_bytes(b.try_into().unwrap()) }
        } else if bin.big_endian { u32::from_be_bytes(b.try_into().unwrap()) as u64 } else { u32::from_le_bytes(b.try_into().unwrap()) as u64 };
        if !bin.is_exec(t) || t.abs_diff(fstart) >= 0x40_0000 || decode_info(bin, t).is_none() { break; }
        out.push(t);
    }
    if out.iter().collect::<HashSet<_>>().len() < 2 { vec![] } else { out }
}

/// Recover a common PowerPC absolute jump table:
/// `lis rX, hi(table); addi rX, rX, lo(table); lwz rY, 0(rX); mtctr rY; bctr`.
fn ppc_switch_targets(bin: &Binary, insns: &BTreeMap<u64, Insn>, at: u64, fstart: u64) -> Vec<u64> {
    let Some(last) = crate::multiarch::one(bin, at) else { return vec![] };
    if last.mnemonic != "bctr" { return vec![]; }
    let reg = |s: &str| s.trim().to_ascii_lowercase();
    let mut table_reg = String::new();
    let mut target_reg = String::new();
    let mut table = None;
    let mut bound = None;
    let mut back: Vec<u64> = insns.range(..at).rev().take(20).map(|(addr, _)| *addr).collect();
    back.reverse();
    for addr in back {
        let Some(i) = crate::multiarch::one(bin, addr) else { continue };
        let ops: Vec<&str> = i.ops.split(',').map(str::trim).collect();
        let num = |s: &str| -> Option<i64> {
            let s = s.trim().trim_start_matches('#');
            if let Some(h) = s.strip_prefix("0x") { i64::from_str_radix(h, 16).ok().or_else(|| u64::from_str_radix(h, 16).ok().map(|v| v as i64)) }
            else { s.parse().ok() }
        };
        match i.mnemonic.as_str() {
            "lis" if ops.len() >= 2 => {
                table_reg = reg(ops[0]);
                table = num(ops[1]).map(|v| (v as u64) << 16);
            }
            "addi" | "addis" if ops.len() >= 3 && reg(ops[0]) == table_reg && reg(ops[1]) == table_reg => {
                if let (Some(base), Some(delta)) = (table, num(ops[2])) { table = Some(base.wrapping_add(delta as u64)); }
            }
            "lwz" | "lwzu" if ops.len() >= 2 => {
                target_reg = reg(ops[0]);
                if let Some((off, base)) = ops[1].split_once('(') {
                    if reg(base.trim_end_matches(')')) == table_reg {
                        if let (Some(t), Some(d)) = (table, num(off)) { table = Some(t.wrapping_add(d as u64)); }
                    }
                }
            }
            "mtctr" if ops.first().map(|x| reg(x)) == Some(target_reg.clone()) => {}
            "cmpwi" | "cmplwi" if ops.len() >= 3 => bound = num(ops[2]).and_then(|n| usize::try_from(n).ok()),
            _ => {}
        }
    }
    let Some(table) = table else { return vec![] };
    if !bin.is_mapped(table) { return vec![]; }
    let count = bound.unwrap_or(256).clamp(2, 1024);
    let mut out = Vec::new();
    for k in 0..count {
        let b = bin.read(table + (k * 4) as u64, 4);
        if b.len() != 4 { break; }
        let t = if bin.big_endian { u32::from_be_bytes(b.try_into().unwrap()) as u64 } else { u32::from_le_bytes(b.try_into().unwrap()) as u64 };
        if !bin.is_exec(t) || t.abs_diff(fstart) >= 0x40_0000 || decode_info(bin, t).is_none() { break; }
        out.push(t);
    }
    if out.iter().collect::<HashSet<_>>().len() < 2 { vec![] } else { out }
}

/// Recover a RISC-V absolute table used by compiler switches:
/// `auipc t, table; ...; lw t, offset(t); jr t`.
fn riscv_switch_targets(bin: &Binary, insns: &BTreeMap<u64, Insn>, at: u64, fstart: u64) -> Vec<u64> {
    let Some(last) = crate::multiarch::one(bin, at) else { return vec![] };
    if !matches!(last.mnemonic.as_str(), "jr" | "jalr") { return vec![]; }
    let reg = last.ops.split(',').next().unwrap_or("").trim();
    if reg.is_empty() || reg == "ra" { return vec![]; }
    let mut table = None;
    let mut bound = None;
    let mut back: Vec<u64> = insns.range(..at).rev().take(16).map(|(addr, _)| *addr).collect();
    back.reverse();
    for addr in back {
        let Some(i) = crate::multiarch::one(bin, addr) else { continue };
        let ops: Vec<&str> = i.ops.split(',').map(str::trim).collect();
        match i.mnemonic.as_str() {
            "auipc" if ops.len() >= 2 && ops[0] == reg => {
                table = parse_riscv_num(ops[1]);
            }
            "lw" | "ld" if ops.len() >= 2 && ops[0] == reg => {
                let mem = ops[1];
                if let Some((off, b)) = mem.split_once('(') {
                    if b.trim_end_matches(')') == reg {
                        if let (Some(base), Some(delta)) = (table, parse_riscv_num(off)) { table = Some(base.wrapping_add(delta)); }
                    }
                }
            }
            "sltiu" | "slti" if ops.len() >= 3 => bound = parse_riscv_num(ops[2]).map(|n| n as usize),
            _ => {}
        }
    }
    let Some(table) = table else { return vec![] };
    if !bin.is_mapped(table) { return vec![]; }
    let width = (bin.bitness() / 8) as usize;
    let count = bound.unwrap_or(256).clamp(2, 1024);
    let mut out = Vec::new();
    for k in 0..count {
        let b = bin.read(table + (k * width) as u64, width);
        if b.len() != width { break; }
        let target = if width == 8 {
            if bin.big_endian { u64::from_be_bytes(b.try_into().unwrap()) } else { u64::from_le_bytes(b.try_into().unwrap()) }
        } else if bin.big_endian { u32::from_be_bytes(b.try_into().unwrap()) as u64 } else { u32::from_le_bytes(b.try_into().unwrap()) as u64 };
        if !bin.is_exec(target) || target.abs_diff(fstart) >= 0x40_0000 || decode_info(bin, target).is_none() { break; }
        out.push(target);
    }
    if out.iter().collect::<HashSet<_>>().len() < 2 { vec![] } else { out }
}

fn parse_riscv_num(text: &str) -> Option<u64> {
    let t = text.trim().trim_start_matches('#');
    if let Some(h) = t.strip_prefix("0x") { u64::from_str_radix(h, 16).ok() } else { t.parse().ok() }
}

fn switch_targets(bin: &Binary, insns: &BTreeMap<u64, Insn>, at: u64, fstart: u64) -> Vec<u64> {
    if bin.arch == Arch::Arm64 {
        return arm64_switch_targets(bin, insns, at, fstart);
    }
    if matches!(bin.arch, Arch::Arm32 | Arch::Thumb) {
        if bin.arch == Arch::Arm32 {
            let targets = arm32_switch_targets(bin, insns, at, fstart);
            if !targets.is_empty() { return targets; }
        }
        return arm_thumb_switch_targets(bin, insns, at, fstart);
    }
    if matches!(bin.arch, Arch::RiscV32 | Arch::RiscV64) {
        return riscv_switch_targets(bin, insns, at, fstart);
    }
    if matches!(bin.arch, Arch::Mips32 | Arch::Mips64) {
        return mips_switch_targets(bin, insns, at, fstart);
    }
    if matches!(bin.arch, Arch::Ppc32 | Arch::Ppc64) {
        return ppc_switch_targets(bin, insns, at, fstart);
    }
    use iced_x86::Register;
    let Some((jmp, _)) = decode_at(bin, at) else { return vec![] };
    let ptr = (bin.bitness() / 8) as usize;
    let mut table = 0u64;
    let mut rel = false;
    let mut bound: Option<u64> = None;
    if jmp.op0_kind() == OpKind::Memory {
        if jmp.memory_index() == Register::None || jmp.memory_base() != Register::None {
            return vec![];
        }
        table = jmp.memory_displacement64();
    } else {
        let mut seen_idx_load = false;
        let mut prev: Vec<u64> = insns.range(..at).rev().take(16).map(|(a, _)| *a).collect();
        prev.sort_by(|a, b| b.cmp(a));
        let mut prev_cond = false;
        for pa in prev {
            let Some((i, _)) = decode_at(bin, pa) else { continue };
            match i.mnemonic() {
                Mnemonic::Lea if i.op1_kind() == OpKind::Memory && i.memory_base() == Register::RIP => {
                    if table == 0 {
                        table = i.memory_displacement64();
                        rel = true;
                    }
                }
                Mnemonic::Movsxd if i.op1_kind() == OpKind::Memory && i.memory_index() != Register::None => {
                    seen_idx_load = true;
                    rel = true;
                }
                Mnemonic::Mov if i.op1_kind() == OpKind::Memory && i.memory_index() != Register::None && i.memory_index_scale() == 8 && table == 0 => {
                    if i.memory_base() == Register::None {
                        table = i.memory_displacement64();
                        rel = false;
                    }
                }
                Mnemonic::Cmp if bound.is_none() && matches!(i.op1_kind(), OpKind::Immediate8 | OpKind::Immediate32 | OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32to64) && prev_cond => {
                    bound = Some(i.immediate(1));
                }
                _ => {}
            }
            prev_cond = matches!(i.mnemonic(), Mnemonic::Ja | Mnemonic::Jae | Mnemonic::Jb | Mnemonic::Jbe);
            if prev_cond {
                // the bound check sits just before this branch (we are walking backwards, so look at the next one we see)
            }
        }
        let _ = seen_idx_load;
        if table == 0 {
            return vec![];
        }
    }
    if !bin.is_mapped(table) {
        return vec![];
    }
    let count = bound.map(|b| (b + 1) as usize).filter(|c| (2..=1024).contains(c)).unwrap_or(256);
    let mut out: Vec<u64> = vec![];
    for k in 0..count {
        let t = if rel {
            let b = bin.read(table + 4 * k as u64, 4);
            if b.len() < 4 {
                break;
            }
            (table as i64 + i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64) as u64
        } else {
            let b = bin.read(table + (ptr * k) as u64, ptr);
            if b.len() < ptr {
                break;
            }
            if ptr == 8 { u64::from_le_bytes(b.try_into().unwrap()) } else { u32::from_le_bytes(b.try_into().unwrap()) as u64 }
        };
        let near = t.abs_diff(fstart) < 0x40_0000;
        if !bin.is_exec(t) || !near || decode_info(bin, t).is_none() {
            break;
        }
        out.push(t);
    }
    let uniq: HashSet<&u64> = out.iter().collect();
    if uniq.len() < 2 { vec![] } else { out }
}

pub fn decode_info(bin: &Binary, addr: u64) -> Option<Insn> {
    if !bin.is_exec(addr) {
        return None;
    }
    if bin.arch.is_x86() {
        decode_at(bin, addr).map(|x| x.1)
    } else {
        crate::multiarch::decode_info(bin, addr)
    }
}

pub fn decode_at(bin: &Binary, addr: u64) -> Option<(Instruction, Insn)> {
    if !bin.is_exec(addr) {
        return None;
    }
    let bytes = bin.read(addr, 16);
    if bytes.is_empty() {
        return None;
    }
    let mut dec = Decoder::with_ip(bin.bitness(), bytes, addr, DecoderOptions::NONE);
    let ins = dec.decode();
    if ins.is_invalid() {
        return None;
    }
    Some((ins, insn_info(bin, &ins)))
}

fn insn_info(bin: &Binary, ins: &Instruction) -> Insn {
    let mut target = 0;
    let flow = match ins.flow_control() {
        FlowControl::Next | FlowControl::XbeginXabortXend => Flow::Normal,
        FlowControl::UnconditionalBranch => {
            if matches!(ins.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                target = ins.near_branch_target();
                Flow::Jump
            } else {
                Flow::IndirectJump
            }
        }
        FlowControl::IndirectBranch => Flow::IndirectJump,
        FlowControl::ConditionalBranch => {
            target = ins.near_branch_target();
            Flow::CondJump
        }
        FlowControl::Return => Flow::Ret,
        FlowControl::Call => {
            target = ins.near_branch_target();
            Flow::Call
        }
        FlowControl::IndirectCall => Flow::IndirectCall,
        FlowControl::Interrupt => {
            if ins.mnemonic() == Mnemonic::Int3 {
                Flow::Stop
            } else {
                Flow::Normal
            }
        }
        FlowControl::Exception => Flow::Stop,
    };
    let flow = if ins.mnemonic() == Mnemonic::Hlt { Flow::Stop } else { flow };
    let mut mem = 0;
    let mut mem_size = 0;
    let mut imm = 0;
    for i in 0..ins.op_count() {
        match ins.op_kind(i) {
            OpKind::Memory => {
                let a = if ins.is_ip_rel_memory_operand() {
                    ins.ip_rel_memory_address()
                } else if ins.memory_base() == iced_x86::Register::None
                    && ins.memory_index() == iced_x86::Register::None
                {
                    ins.memory_displacement64()
                } else {
                    0
                };
                if a != 0 && bin.is_mapped(a) {
                    mem = a;
                    mem_size = ins.memory_size().size().min(255) as u8;
                }
            }
            OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64 => {
                let v = match ins.op_kind(i) {
                    OpKind::Immediate32 => ins.immediate32() as u64,
                    OpKind::Immediate32to64 => ins.immediate32to64() as u64,
                    _ => ins.immediate64(),
                };
                if v > 0x1000 && bin.is_mapped(v) {
                    imm = v;
                }
            }
            _ => {}
        }
    }
    let is_write = ins.op_count() > 0
        && ins.op0_kind() == OpKind::Memory
        && !matches!(ins.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Push | Mnemonic::Call | Mnemonic::Jmp);
    Insn {
        len: ins.len() as u8,
        flow,
        target,
        mem,
        mem_size,
        imm,
        is_lea: ins.mnemonic() == Mnemonic::Lea,
        is_write,
    }
}

/// Typical function entry sequences on other CPUs (little-endian words).
fn other_prologue(arch: Arch, b: &[u8]) -> bool {
    if b.len() < 4 {
        return false;
    }
    let w = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    match arch {
        // stp x29, x30, [sp, #-N]!   |  sub sp, sp, #N   |  pacibsp  |  bti c
        Arch::Arm64 => (w & 0xFFC0_7FFF) == 0xA980_7BFD || (w & 0xFF00_03FF) == 0xD100_03FF || w == 0xD503_237F || w == 0xD503_245F,
        // push {.., lr}
        Arch::Arm32 => (w & 0xFFFF_4000) == 0xE92D_4000,
        Arch::RiscV64 | Arch::RiscV32 => (w & 0x000F_FFFF) == 0x0001_0113 && (w >> 31) == 1,
        _ => false,
    }
}

fn looks_like_prologue(b: &[u8]) -> bool {
    b.starts_with(&[0xF3, 0x0F, 0x1E, 0xFA])
        || b.starts_with(&[0xF3, 0x0F, 0x1E, 0xFB])
        || b.starts_with(&[0x55, 0x48, 0x89, 0xE5])
        || b.starts_with(&[0x55, 0x89, 0xE5])
        || b.starts_with(&[0x55, 0x8B, 0xEC])
        || b.starts_with(&[0x48, 0x83, 0xEC])
        || b.starts_with(&[0x48, 0x81, 0xEC])
        || b.starts_with(&[0x48, 0x89, 0x5C, 0x24])
        || b.starts_with(&[0x40, 0x53])
        || b.starts_with(&[0x41, 0x57])
        || b.starts_with(&[0x41, 0x56])
        || b.starts_with(&[0x41, 0x55])
        || b.starts_with(&[0x41, 0x54])
}

pub fn demangle(name: &str) -> Option<String> {
    // Rust (legacy _ZN…17h<hash>E and v0 _R…) first; macOS adds one more underscore
    for cand in [name, name.strip_prefix('_').unwrap_or(name)] {
        if cand.starts_with("_R") || (cand.starts_with("_ZN") && cand.contains("17h")) {
            if let Ok(d) = rustc_demangle::try_demangle(cand) {
                return Some(format!("{d:#}"));
            }
        }
    }
    let n = if name.starts_with("__Z") { &name[1..] } else { name };
    if n.starts_with("_Z") {
        let sym = cpp_demangle::Symbol::new(n).ok()?;
        let opts = cpp_demangle::DemangleOptions::new().no_params().no_return_type();
        return sym.demangle_with_options(&opts).ok();
    }
    None
}

/// Short display form of a symbol: demangled when possible.
pub fn display_symbol(name: &str) -> String {
    demangle(name).unwrap_or_else(|| name.to_string())
}

/// IDA-style name for a string: "a" followed by the capitalised words of the text.
pub fn string_name(text: &str) -> String {
    let mut out = String::from("a");
    let mut cap = true;
    for ch in text.chars() {
        if out.len() >= 25 {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            if cap {
                out.extend(ch.to_uppercase());
            } else {
                out.push(ch);
            }
            cap = false;
        } else {
            cap = true;
        }
    }
    if out.len() == 1 {
        out.push_str("Str");
    }
    out
}

fn data_prefix(size: u8) -> &'static str {
    match size {
        1 => "byte",
        2 => "word",
        4 => "dword",
        8 => "qword",
        10 => "tbyte",
        16 => "xmmword",
        32 => "ymmword",
        64 => "zmmword",
        _ => "unk",
    }
}

pub fn analyze(bin: &Binary, settings: &Settings, progress: Arc<AtomicU32>) -> Analysis {
    let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
    let mut functions: BTreeMap<u64, Function> = BTreeMap::new();
    let supported = bin.arch != Arch::Other;

    let import_slot: HashMap<u64, usize> = bin.imports.iter().enumerate().map(|(i, im)| (im.slot, i)).collect();
    let sym_at: HashMap<u64, &str> = bin.symbols.iter().map(|(a, n)| (*a, n.as_str())).collect();

    // ---- function discovery (recursive descent) ----
    let mut queue: VecDeque<u64> = VecDeque::new();
    let mut queued: HashSet<u64> = HashSet::new();
    let mut push = |q: &mut VecDeque<u64>, a: u64| {
        if bin.is_exec(a) && queued.insert(a) {
            q.push_back(a);
        }
    };
    if supported {
        if let Some(e) = bin.entry {
            push(&mut queue, e);
        }
        for (a, _) in &bin.symbols {
            push(&mut queue, *a);
        }
        for e in &bin.exports {
            push(&mut queue, e.addr);
        }
        for a in &bin.func_hints {
            push(&mut queue, *a);
        }
        for a in &settings.extra_functions {
            push(&mut queue, *a);
        }
        // Pointers in init/fini arrays.
        for s in &bin.segments {
            let n = s.name.to_ascii_lowercase();
            if n.contains("init_array") || n.contains("fini_array") || n.contains("mod_init") || n.contains("ctors") {
                let w = (bin.bitness() / 8) as usize;
                for c in s.data.chunks_exact(w) {
                    let v = if w == 8 { u64::from_le_bytes(c.try_into().unwrap()) } else { u32::from_le_bytes(c.try_into().unwrap()) as u64 };
                    push(&mut queue, v);
                }
            }
        }
    }

    let callee_name = |t: u64, insns_dec: &dyn Fn(u64) -> Option<Insn>| -> Option<String> {
        if let Some(n) = sym_at.get(&t) {
            return Some(n.to_string());
        }
        if let Some(i) = insns_dec(t) {
            if i.flow == Flow::IndirectJump && i.mem != 0 {
                if let Some(ix) = import_slot.get(&i.mem) {
                    return Some(bin.imports[*ix].name.clone());
                }
            }
        }
        None
    };
    let dec_only = |a: u64| decode_info(bin, a);

    let mut noret_cache: HashMap<u64, bool> = HashMap::new();
    let mut switches: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut total = 0usize;
    let max_total = 6_000_000usize;
    let mut round = 0;
    loop {
        while let Some(fstart) = queue.pop_front() {
            if total > max_total {
                break;
            }
            if functions.contains_key(&fstart) {
                continue;
            }
            let mut local: BTreeSet<u64> = BTreeSet::new();
            let mut work = vec![fstart];
            let mut calls = vec![];
            let mut leaders: BTreeSet<u64> = BTreeSet::new();
            leaders.insert(fstart);
            while let Some(mut a) = work.pop() {
                loop {
                    if local.contains(&a) || local.len() > 200_000 {
                        break;
                    }
                    if a != fstart && functions.contains_key(&a) && !local.is_empty() {
                        break;
                    }
                    let info = match insns.get(&a) {
                        Some(i) => *i,
                        None => match decode_info(bin, a) {
                            Some(i) => {
                                insns.insert(a, i);
                                total += 1;
                                i
                            }
                            None => break,
                        },
                    };
                    local.insert(a);
                    let next = a + info.len as u64;
                    match info.flow {
                        Flow::Normal => a = next,
                        Flow::Ret | Flow::Stop => break,
                        Flow::IndirectJump => {
                            if (bin.arch.is_x86() || matches!(bin.arch, Arch::Arm64 | Arch::Arm32 | Arch::Thumb)) && (info.mem == 0 || !import_slot.contains_key(&info.mem)) {
                                let ts = switch_targets(bin, &insns, a, fstart);
                                for t in &ts {
                                    work.push(*t);
                                    leaders.insert(*t);
                                }
                                if !ts.is_empty() {
                                    switches.insert(a, ts);
                                } else if std::env::var("LENS_TRACE3").is_ok() && bin.arch == Arch::Arm64 {
                                    eprintln!("-- unresolved br at {a:X}");
                                    for (pa, _) in insns.range(..=a).rev().take(9).collect::<Vec<_>>().into_iter().rev() {
                                        if let Some(r) = crate::multiarch::one(bin, *pa) { eprintln!("   {pa:X} {} {}", r.mnemonic, r.ops); }
                                    }
                                }
                            }
                            break;
                        }
                        Flow::CondJump => {
                            if bin.is_exec(info.target) {
                                work.push(info.target);
                                leaders.insert(info.target);
                            }
                            leaders.insert(next);
                            a = next;
                        }
                        Flow::Jump => {
                            let t = info.target;
                            let is_func = functions.contains_key(&t) || sym_at.contains_key(&t) && t != fstart;
                            let is_stub = callee_name(t, &dec_only).is_some() && !sym_at.contains_key(&t);
                            // A jump to another known function has no return to this function:
                            // preserve it as a call-graph edge as well as a control-flow edge.
                            if t != fstart && (is_func || is_stub) {
                                calls.push(t);
                            }
                            if bin.is_exec(t) && !is_func && !is_stub {
                                work.push(t);
                                leaders.insert(t);
                            } else if bin.is_exec(t) {
                                push(&mut queue, t);
                            }
                            break;
                        }
                        Flow::Call => {
                            let t = info.target;
                            if bin.is_exec(t) {
                                calls.push(t);
                                push(&mut queue, t);
                            }
                            let nr = *noret_cache.entry(t).or_insert_with(|| {
                                callee_name(t, &dec_only).map(|n| is_noreturn_name(&n)).unwrap_or(false)
                            });
                            if nr {
                                break;
                            }
                            a = next;
                        }
                        Flow::IndirectCall => {
                            if info.mem != 0 {
                                if let Some(ix) = import_slot.get(&info.mem) {
                                    if is_noreturn_name(&bin.imports[*ix].name) {
                                        break;
                                    }
                                }
                            }
                            a = next;
                        }
                    }
                }
            }
            if local.is_empty() {
                continue;
            }
            // Basic blocks.
            let addrs: Vec<u64> = local.iter().copied().collect();
            let mut blocks: Vec<Block> = vec![];
            let mut cur: Option<Block> = None;
            let mut prev_end = u64::MAX;
            for &a in &addrs {
                let i = insns[&a];
                if leaders.contains(&a) || a != prev_end {
                    if let Some(mut b) = cur.take() {
                        if b.succs.is_empty() {
                            let last = insns[b.insns.last().unwrap()];
                            if matches!(last.flow, Flow::Normal | Flow::Call | Flow::IndirectCall) && local.contains(&b.end) {
                                b.succs.push((b.end, EdgeKind::Always));
                            }
                        }
                        blocks.push(b);
                    }
                    cur = Some(Block { start: a, end: a, insns: vec![], succs: vec![] });
                }
                let b = cur.as_mut().unwrap();
                b.insns.push(a);
                b.end = a + i.len as u64;
                prev_end = b.end;
                match i.flow {
                    Flow::CondJump => {
                        if local.contains(&i.target) {
                            b.succs.push((i.target, EdgeKind::Taken));
                        }
                        if local.contains(&b.end) {
                            b.succs.push((b.end, EdgeKind::NotTaken));
                        }
                        let done = cur.take().unwrap();
                        blocks.push(done);
                        prev_end = u64::MAX;
                    }
                    Flow::Jump => {
                        if local.contains(&i.target) {
                            b.succs.push((i.target, EdgeKind::Always));
                        }
                        let done = cur.take().unwrap();
                        blocks.push(done);
                        prev_end = u64::MAX;
                    }
                    Flow::IndirectJump => {
                        if let Some(ts) = switches.get(&a) {
                            for t in ts {
                                if local.contains(t) && !b.succs.iter().any(|x| x.0 == *t) {
                                    b.succs.push((*t, EdgeKind::Always));
                                }
                            }
                        }
                        let done = cur.take().unwrap();
                        blocks.push(done);
                        prev_end = u64::MAX;
                    }
                    Flow::Ret | Flow::Stop => {
                        let done = cur.take().unwrap();
                        blocks.push(done);
                        prev_end = u64::MAX;
                    }
                    _ => {}
                }
            }
            if let Some(b) = cur.take() {
                blocks.push(b);
            }
            let first = insns[&fstart];
            let kind = if addrs.len() == 1 && first.flow == Flow::IndirectJump && import_slot.contains_key(&first.mem) {
                FuncKind::Import
            } else {
                FuncKind::Normal
            };
            let end = addrs.iter().map(|a| a + insns[a].len as u64).max().unwrap_or(fstart);
            let noreturn = callee_name(fstart, &dec_only).map(|n| is_noreturn_name(&n)).unwrap_or(false);
            calls.sort();
            calls.dedup();
            functions.insert(
                fstart,
                Function {
                    start: fstart,
                    end,
                    blocks,
                    insn_count: addrs.len(),
                    kind,
                    noreturn,
                    calls,
                    has_symbol: sym_at.contains_key(&fstart),
                    thunk_target: None,
                },
            );
            progress.store(functions.len() as u32, Ordering::Relaxed);
        }
        // Look for typical function starts in code no one reached yet (once or twice).
        round += 1;
        if round > 2 || !supported {
            break;
        }
        let mut found = 0;
        for s in bin.segments.iter().filter(|s| s.exec) {
            // The very distinctive frame setups (endbr64; push rbp/mov rbp,rsp) are trusted at any
            // byte; the looser patterns only at 16-byte aligned spots.
            let mut a = s.start;
            let step = bin.arch.fixed_width().unwrap_or(1);
            while a < s.end() {
                let b = bin.read(a, 8);
                let hit = if bin.arch.is_x86() {
                    let strong = b.starts_with(&[0xF3, 0x0F, 0x1E, 0xFA]) || b.starts_with(&[0x55, 0x48, 0x89, 0xE5]);
                    strong || (a % 16 == 0 && looks_like_prologue(b))
                } else {
                    other_prologue(bin.arch, b)
                };
                if hit && !covered(&insns, a) {
                    push(&mut queue, a);
                    found += 1;
                }
                a += step;
            }
        }
        if found == 0 {
            break;
        }
    }

    // ---- strings ----
    let mut strings = find_strings(bin, settings.min_string_len.max(1));
    // The person's string / undefine choices come first, so everything after sees them.
    for (&a, &d) in &settings.data_defs {
        if d == DEF_UNDEFINE || (d != DEF_STRING) {
            strings.retain(|s| s.addr != a);
        }
        if d == DEF_STRING && !strings.iter().any(|s| s.addr == a) {
            let raw = bin.read(a, 4096);
            if let Some(n) = raw.iter().position(|b| *b == 0) {
                if n > 0 {
                    let text = String::from_utf8_lossy(&raw[..n]).to_string();
                    strings.push(StrLit { addr: a, len: (n + 1) as u32, wide: false, text });
                }
            }
        }
    }
    strings.sort_by_key(|s| s.addr);
    let string_at: HashMap<u64, usize> = strings.iter().enumerate().map(|(i, s)| (s.addr, i)).collect();

    // ---- cross references ----
    let mut xrefs_to: HashMap<u64, Vec<Xref>> = HashMap::new();
    let mut data_size: HashMap<u64, u8> = HashMap::new();
    for (&a, i) in &insns {
        match i.flow {
            Flow::Call => xrefs_to.entry(i.target).or_default().push(Xref { from: a, kind: XrefKind::Call }),
            Flow::Jump | Flow::CondJump => {
                xrefs_to.entry(i.target).or_default().push(Xref { from: a, kind: XrefKind::Jump })
            }
            _ => {}
        }
        if i.mem != 0 {
            let import_flow = import_slot.contains_key(&i.mem);
            let k = if import_flow && i.flow == Flow::IndirectCall {
                XrefKind::Call
            } else if import_flow && i.flow == Flow::IndirectJump {
                XrefKind::Jump
            } else if i.is_lea {
                XrefKind::Offset
            } else if i.is_write {
                XrefKind::Write
            } else {
                XrefKind::Read
            };
            xrefs_to.entry(i.mem).or_default().push(Xref { from: a, kind: k });
            if !i.is_lea && i.mem_size > 0 && !bin.is_exec(i.mem) {
                data_size.entry(i.mem).or_insert(i.mem_size);
            }
        }
        if i.imm != 0 {
            xrefs_to.entry(i.imm).or_default().push(Xref { from: a, kind: XrefKind::Offset });
        }
    }
    // Pointers stored in data that point into mapped program data/code. This catches
    // references to globals and vtables as well as the common function/string cases.
    let w = (bin.bitness() / 8) as usize;
    let mut vtables: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut pointer_tables: HashMap<u64, Vec<u64>> = HashMap::new();
    for s in bin.segments.iter().filter(|s| !s.exec && s.file_offset.is_some()) {
        let mut off = 0usize;
        while off + w <= s.data.len() {
            let from = s.start + off as u64;
            let v = bin.read_ptr(from).unwrap_or(0);
            if v != 0 && bin.is_mapped(v) {
                xrefs_to.entry(v).or_default().push(Xref { from, kind: XrefKind::Data });
                data_size.entry(from).or_insert(w as u8 | 0x80);
            }
            off += w;
        }

        // Tables are runs of at least two mapped pointers. Keep the executable
        // subset separately as vtables; isolated callbacks never qualify.
        let mut run_start = 0usize;
        let mut run: Vec<u64> = Vec::new();
        let flush = |start: &mut usize, entries: &mut Vec<u64>, all: &mut HashMap<u64, Vec<u64>>, code: &mut HashMap<u64, Vec<u64>>, seg_start: u64| {
            if entries.len() >= 2 {
                let addr = seg_start + *start as u64;
                all.insert(addr, entries.clone());
                if entries.iter().all(|v| bin.is_exec(*v)) {
                    code.insert(addr, entries.clone());
                }
            }
            entries.clear();
        };
        for off in (0..s.data.len()).step_by(w) {
            if off + w > s.data.len() { break; }
            let from = s.start + off as u64;
            let v = bin.read_ptr(from).unwrap_or(0);
            if v != 0 && bin.is_mapped(v) {
                if run.is_empty() { run_start = off; }
                run.push(v);
            } else {
                flush(&mut run_start, &mut run, &mut pointer_tables, &mut vtables, s.start);
            }
        }
        flush(&mut run_start, &mut run, &mut pointer_tables, &mut vtables, s.start);

        // Itanium C++ vtables normally begin with two non-function metadata
        // slots: offset-to-top and a pointer to the typeinfo object. The
        // function-pointer run starts after that header, so the conservative
        // all-executable scan above intentionally cannot see these tables.
        for off in (0..s.data.len()).step_by(w) {
            if off + 4 * w > s.data.len() { break; }
            let header = s.start + off as u64;
            let top = bin.read_ptr(header).unwrap_or(u64::MAX);
            let top_ok = top == 0 || (top as i64).unsigned_abs() <= 0x10_0000;
            let typeinfo = bin.read_ptr(header + w as u64).unwrap_or(0);
            if !top_ok || !bin.is_mapped(typeinfo) || bin.is_exec(typeinfo) { continue; }
            let mut funcs = Vec::new();
            let mut pos = off + 2 * w;
            while pos + w <= s.data.len() && funcs.len() < 256 {
                let target = bin.read_ptr(s.start + pos as u64).unwrap_or(0);
                if !bin.is_exec(target) || decode_info(bin, target).is_none() { break; }
                funcs.push(target);
                pos += w;
            }
            if funcs.len() >= 2 {
                vtables.entry(header).or_insert(funcs);
            }
        }
    }
    for (&a, &d) in &settings.data_defs {
        match d {
            DEF_UNDEFINE => {
                data_size.remove(&a);
            }
            DEF_STRING => {}
            n => {
                data_size.insert(a, n);
            }
        }
    }
    // Indirect switch targets are real code xrefs, but keeping them distinct
    // from ordinary direct jumps makes xref lists and exports explain why the
    // edge exists.
    for (&from, targets) in &switches {
        for &to in targets {
            xrefs_to.entry(to).or_default().push(Xref { from, kind: XrefKind::Switch });
        }
    }
    for v in xrefs_to.values_mut() {
        v.sort_by_key(|x| x.from);
        // A single instruction can refer to the same address in more than one
        // way (for example, an address-taking LEA that also has an immediate
        // operand). Keep the distinct relationship kinds while removing only
        // truly duplicated edges.
        v.dedup_by(|a, b| a.from == b.from && a.kind == b.kind);
    }

    // Mark direct one-instruction forwarding thunks after discovery is complete,
    // so targets reached later in the queue are visible too.
    let function_starts: HashSet<u64> = functions.keys().copied().collect();
    let import_starts: HashSet<u64> = functions.values().filter(|f| f.kind == FuncKind::Import).map(|f| f.start).collect();
    for f in functions.values_mut() {
        if f.insn_count == 1 {
            if let Some(&addr) = f.blocks.first().and_then(|b| b.insns.first()) {
                if let Some(i) = insns.get(&addr) {
                    if i.flow == Flow::Jump
                        && i.target != f.start
                        && (function_starts.contains(&i.target) || sym_at.contains_key(&i.target) || import_starts.contains(&i.target))
                    {
                        f.thunk_target = Some(i.target);
                    }
                }
            }
        }
    }

    // ---- names ----
    let mut names: HashMap<u64, (String, NameKind)> = HashMap::new();
    for (i, im) in bin.imports.iter().enumerate() {
        let _ = i;
        names.insert(im.slot, (format!("__imp_{}", im.name.trim_start_matches('_')), NameKind::Import));
    }
    for (a, n) in &bin.data_symbols {
        names.insert(*a, (display_symbol(n), NameKind::Data));
    }
    let mut nullsub = 0usize;
    for (a, f) in &functions {
        let name = if let Some(n) = sym_at.get(a) {
            display_symbol(n)
        } else if f.kind == FuncKind::Import {
            let ix = import_slot[&insns[a].mem];
            bin.imports[ix].name.clone()
        } else if f.insn_count == 1 && insns[a].flow == Flow::Ret {
            nullsub += 1;
            format!("nullsub_{nullsub}")
        } else if Some(*a) == bin.entry {
            "start".to_string()
        } else {
            format!("sub_{:X}", a)
        };
        let k = if f.kind == FuncKind::Import { NameKind::Import } else { NameKind::Function };
        names.insert(*a, (name, k));
    }
    // Labels for jump targets inside functions.
    for (t, xs) in &xrefs_to {
        if functions.contains_key(t) || names.contains_key(t) {
            continue;
        }
        if xs.iter().any(|x| x.kind == XrefKind::Jump) && insns.contains_key(t) {
            let pre = if insns[t].flow == Flow::Ret { "locret" } else { "loc" };
            names.insert(*t, (format!("{pre}_{:X}", t), NameKind::Label));
        }
    }
    // Strings and other referenced data.
    let mut used: HashSet<String> = names.values().map(|(n, _)| n.clone()).collect();
    for s in &strings {
        if names.contains_key(&s.addr) {
            continue;
        }
        if !xrefs_to.contains_key(&s.addr) {
            continue;
        }
        let base = string_name(&s.text);
        let mut n = base.clone();
        let mut k = 0;
        while used.contains(&n) {
            n = format!("{base}_{k}");
            k += 1;
        }
        used.insert(n.clone());
        names.insert(s.addr, (n, NameKind::String));
    }
    for (t, xs) in &xrefs_to {
        if names.contains_key(t) || bin.is_exec(*t) || string_at.contains_key(t) {
            continue;
        }
        let _ = xs;
        let pre = match data_size.get(t) {
            Some(sz) if sz & 0x80 != 0 => "off",
            Some(sz) => data_prefix(*sz),
            None => "unk",
        };
        names.insert(*t, (format!("{pre}_{:X}", t), NameKind::Data));
    }

    let mut a = Analysis {
        insns,
        functions,
        xrefs_to,
        strings,
        string_at,
        names,
        import_slot,
        lines: vec![],
        data_size,
        stats: String::new(),
        switches,
        vtables,
        pointer_tables,
    };
    a.lines = build_lines(bin, &a);
    a.stats = format!(
        "{} functions, {} instructions, {} strings, {} imports",
        a.functions.len(),
        a.insns.len(),
        a.strings.len(),
        bin.imports.len()
    );
    if !a.switches.is_empty() {
        a.stats.push_str(&format!(", {} switch tables", a.switches.len()));
    }
    if !a.vtables.is_empty() {
        a.stats.push_str(&format!(", {} vtable-like tables", a.vtables.len()));
    }
    if !a.pointer_tables.is_empty() {
        a.stats.push_str(&format!(", {} pointer tables", a.pointer_tables.len()));
    }
    if total > max_total {
        a.stats.push_str(" — very large program: analysis stopped early, so some code shows as unexplored (press P on it to make a function)");
    }
    a
}

fn covered(insns: &BTreeMap<u64, Insn>, a: u64) -> bool {
    if insns.contains_key(&a) {
        return true;
    }
    if let Some((s, i)) = insns.range(..a).next_back() {
        return s + i.len as u64 > a;
    }
    false
}

fn find_strings(bin: &Binary, min_len: usize) -> Vec<StrLit> {
    let mut out = vec![];
    let printable = |b: u8| (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r';
    for s in bin.segments.iter().filter(|s| !s.exec && s.file_offset.is_some()) {
        let d = &s.data;
        // 8-bit C strings
        let mut i = 0;
        while i < d.len() {
            if printable(d[i]) {
                let st = i;
                while i < d.len() && printable(d[i]) {
                    i += 1;
                }
                let n = i - st;
                if n >= min_len && i < d.len() && d[i] == 0 {
                    let text = String::from_utf8_lossy(&d[st..i]).to_string();
                    out.push(StrLit { addr: s.start + st as u64, len: (n + 1) as u32, wide: false, text });
                }
            }
            i += 1;
        }
        // UTF-16LE strings
        let mut i = 0;
        while i + 1 < d.len() {
            if printable(d[i]) && d[i + 1] == 0 {
                let st = i;
                while i + 1 < d.len() && printable(d[i]) && d[i + 1] == 0 {
                    i += 2;
                }
                let n = (i - st) / 2;
                if n >= min_len && i + 1 < d.len() && d[i] == 0 && d[i + 1] == 0 {
                    let text: String = d[st..i].chunks(2).map(|c| c[0] as char).collect();
                    out.push(StrLit { addr: s.start + st as u64, len: (n * 2 + 2) as u32, wide: true, text });
                }
                i += 2;
            } else {
                i += 2;
            }
        }
    }
    out
}

fn build_lines(bin: &Binary, a: &Analysis) -> Vec<Line> {
    let mut lines = Vec::new();
    let ptr = (bin.bitness() / 8) as u64;
    // Addresses where something starts; unexplored byte rows stop there.
    let mut stops: BTreeSet<u64> = BTreeSet::new();
    stops.extend(a.string_at.keys());
    stops.extend(a.import_slot.keys());
    stops.extend(a.names.keys());
    stops.extend(a.functions.keys());
    for (k, _) in a.data_size.iter() {
        stops.insert(*k);
    }
    let mut func_end_at: HashMap<u64, u64> = HashMap::new();
    for f in a.functions.values() {
        func_end_at.insert(f.end, f.start);
    }
    for s in &bin.segments {
        lines.push(Line { addr: s.start, kind: LineKind::Segment, len: 0 });
        let mut addr = s.start;
        let end = s.end();
        while addr < end {
            if let Some(i) = a.insns.get(&addr) {
                if a.functions.contains_key(&addr) {
                    lines.push(Line { addr, kind: LineKind::FuncSep, len: 0 });
                    lines.push(Line { addr, kind: LineKind::FuncStart, len: 0 });
                } else if a.names.contains_key(&addr) {
                    lines.push(Line { addr, kind: LineKind::Label, len: 0 });
                }
                lines.push(Line { addr, kind: LineKind::Insn, len: i.len as u32 });
                addr += i.len as u64;
                if func_end_at.contains_key(&addr) {
                    lines.push(Line { addr, kind: LineKind::FuncEnd, len: 0 });
                    lines.push(Line { addr, kind: LineKind::Blank, len: 0 });
                } else if matches!(i.flow, Flow::Ret | Flow::Jump | Flow::IndirectJump | Flow::Stop) {
                    lines.push(Line { addr, kind: LineKind::Blank, len: 0 });
                }
                continue;
            }
            if let Some(si) = a.string_at.get(&addr) {
                let l = a.strings[*si].len;
                lines.push(Line { addr, kind: LineKind::Str, len: l });
                addr += l as u64;
                continue;
            }
            if a.import_slot.contains_key(&addr) {
                lines.push(Line { addr, kind: LineKind::Ptr, len: ptr as u32 });
                addr += ptr;
                continue;
            }
            if let Some(sz) = a.data_size.get(&addr) {
                let n = (*sz & 0x7f).max(1) as u32;
                let kind = if sz & 0x80 != 0 { LineKind::Ptr } else { LineKind::Data };
                lines.push(Line { addr, kind, len: n });
                addr += n as u64;
                continue;
            }
            // Unexplored bytes up to the next thing.
            let next = stops.range(addr + 1..).next().copied().unwrap_or(end).min(end);
            let next_insn = a.insns.range(addr + 1..).next().map(|(k, _)| *k).unwrap_or(end).min(next);
            let run_end = next_insn;
            let data = bin.read(addr, (run_end - addr) as usize);
            let all_zero = data.iter().all(|b| *b == 0);
            if run_end - addr >= 64 && all_zero {
                lines.push(Line { addr, kind: LineKind::Zeros, len: (run_end - addr).min(u32::MAX as u64) as u32 });
                addr = run_end;
                continue;
            }
            let mut p = addr;
            while p < run_end {
                let n = (16 - (p % 16)).min(run_end - p);
                lines.push(Line { addr: p, kind: LineKind::Bytes, len: n as u32 });
                p += n;
            }
            addr = run_end;
        }
        lines.push(Line { addr: end, kind: LineKind::Blank, len: 0 });
    }
    lines
}

impl Analysis {
    pub fn function_containing(&self, a: u64) -> Option<&Function> {
        if let Some(f) = self.functions.get(&a) {
            return Some(f);
        }
        let (_, f) = self.functions.range(..=a).next_back()?;
        if a < f.end && f.blocks.iter().any(|b| a >= b.start && a < b.end) {
            return Some(f);
        }
        // Function chunks may be placed before the start (rare): search blocks of near functions.
        None
    }

    /// The listing line index best showing `addr`.
    pub fn line_of(&self, addr: u64) -> usize {
        let idx = self.lines.partition_point(|l| l.addr < addr);
        // Prefer the function header / label / item at exactly this address.
        let mut i = idx;
        while i < self.lines.len() && self.lines[i].addr == addr {
            match self.lines[i].kind {
                LineKind::FuncStart | LineKind::Label | LineKind::Insn | LineKind::Str | LineKind::Ptr | LineKind::Data
                | LineKind::Bytes | LineKind::Zeros => return i,
                _ => i += 1,
            }
        }
        // Inside an item: the previous content line.
        let mut j = idx.min(self.lines.len().saturating_sub(1));
        while j > 0 {
            let l = &self.lines[j];
            if l.addr <= addr && !matches!(l.kind, LineKind::Blank | LineKind::FuncEnd | LineKind::FuncSep) {
                return j;
            }
            j -= 1;
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::{raw_binary, RawSpec};

    #[test]
    fn recognises_decorated_noreturn_symbols() {
        assert!(is_noreturn_name("___stack_chk_fail@@GLIBC_2.4"));
        assert!(is_noreturn_name("std::__1::terminate()"));
        assert!(is_noreturn_name("abort.cold"));
        assert!(!is_noreturn_name("strerror"));
        assert!(is_noreturn_name("core::panicking::panic_fmt"));
        assert!(is_noreturn_name("__cxa_pure_virtual"));
        assert!(is_noreturn_name("panic"));
    }

    #[test]
    fn recovers_a_position_independent_switch() {
        let mut code: Vec<u8> = vec![
            0x83, 0xFF, 0x02, // cmp edi, 2
            0x77, 0x24, // ja default
            0x48, 0x8D, 0x15, 0x20, 0x00, 0x00, 0x00, // lea rdx, [rip+table]
            0x89, 0xF8, // mov eax, edi
            0x48, 0x63, 0x04, 0x82, // movsxd rax, [rdx+rax*4]
            0x48, 0x01, 0xD0, // add rax, rdx
            0xFF, 0xE0, // jmp rax
            0xB8, 1, 0, 0, 0, 0xC3, // case 0
            0xB8, 2, 0, 0, 0, 0xC3, // case 1
            0xB8, 3, 0, 0, 0, 0xC3, // case 2
            0x31, 0xC0, 0xC3, // default
        ];
        assert_eq!(code.len(), 0x2C);
        for off in [-21i32, -15, -9] {
            code.extend_from_slice(&off.to_le_bytes());
        }
        let spec = RawSpec { path: "t".into(), name: "t".into(), arch: Arch::X64, big: false, segs: vec![(0x1000, code)], entry: Some(0x1000), format: "test".into() };
        let bin = raw_binary(&spec);
        let an = analyze(&bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        let t = an.switches.get(&0x1015).expect("switch found");
        assert_eq!(t, &vec![0x1017, 0x101D, 0x1023]);
        assert!(an.xrefs_to.get(&0x1017).unwrap().iter().any(|x| x.from == 0x1015 && x.kind == XrefKind::Switch));
        let f = &an.functions[&0x1000];
        assert!(f.blocks.iter().any(|b| b.succs.len() == 3), "switch block has three successors");
    }

    #[test]
    fn recovers_arm32_absolute_switch_table() {
        // cmp r0, #2; ldr pc, [pc, r0, lsl #2]; table at PC+8.
        let mut code = vec![0x02, 0x00, 0x50, 0xE3, 0x00, 0xF1, 0x9F, 0xE7];
        code.extend_from_slice(&[0; 4]);
        for target in [0x101C_u32, 0x1020, 0x1024] { code.extend_from_slice(&target.to_le_bytes()); }
        code.extend_from_slice(&[0; 0x101C - 0x1000 - 20]);
        code.extend_from_slice(&[0x1E, 0xFF, 0x2F, 0xE1, 0x1E, 0xFF, 0x2F, 0xE1, 0x1E, 0xFF, 0x2F, 0xE1]);
        let spec = RawSpec { path: "arm".into(), name: "arm".into(), arch: Arch::Arm32, big: false, segs: vec![(0x1000, code)], entry: Some(0x1000), format: "test".into() };
        let an = analyze(&raw_binary(&spec), &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        assert_eq!(an.switches.get(&0x1004), Some(&vec![0x101C, 0x1020, 0x1024]));
    }

    #[test]
    fn classifies_direct_forwarding_thunks() {
        let spec = RawSpec {
            path: "t".into(), name: "t".into(), arch: Arch::X64, big: false,
            segs: vec![(0x1000, vec![0xE9, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xC3])],
            entry: Some(0x1000), format: "test".into(),
        };
        let mut bin = raw_binary(&spec);
        bin.symbols.push((0x1006, "target".into()));
        let an = analyze(&bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        assert_eq!(an.functions[&0x1000].thunk_target, Some(0x1006));
    }
}

#[cfg(test)]
mod idea_tests {
    use super::*;
    use crate::loader::{raw_binary, RawSpec};

    fn bin_of(code: Vec<u8>, data: Vec<u8>) -> Binary {
        let spec = RawSpec { path: "t".into(), name: "t".into(), arch: Arch::X64, big: false, segs: vec![(0x1000, code), (0x2000, data)], entry: Some(0x1000), format: "test".into() };
        raw_binary(&spec)
    }
    fn run(bin: &Binary, defs: HashMap<u64, u8>) -> Analysis {
        analyze(bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: defs }, Arc::new(AtomicU32::new(0)))
    }

    #[test]
    fn stack_slots_get_ida_names() {
        // push rbp; mov rbp,rsp; mov dword [rbp-8],1; mov eax,[rbp+10h]; pop rbp; ret
        let code = vec![0x55, 0x48, 0x89, 0xE5, 0xC7, 0x45, 0xF8, 1, 0, 0, 0, 0x8B, 0x45, 0x10, 0x5D, 0xC3];
        let bin = bin_of(code, vec![0; 16]);
        let an = run(&bin, Default::default());
        let mut f = crate::code::CodeFormatter::new(Arc::new(HashMap::new()));
        let frames: Vec<(u64, u64)> = an.functions.values().filter(|f| crate::code::has_frame_pointer(&bin, f.start)).map(|f| (f.start, f.end)).collect();
        assert_eq!(frames.len(), 1);
        f.set_frames(frames, HashMap::from([("1000:var_8".to_string(), "counter".to_string())]));
        assert!(f.clone_names_text(&bin, 0x1004).contains("[rbp+counter]"), "{}", f.clone_names_text(&bin, 0x1004));
        let mut g = crate::code::CodeFormatter::new(Arc::new(HashMap::new()));
        g.set_frames(an.functions.values().map(|f| (f.start, f.end)).collect(), HashMap::new());
        let t = g.format(&bin, 0x1004).unwrap().1.iter().map(|x| x.text.clone()).collect::<String>();
        assert!(t.contains("[rbp+var_8]"), "{t}");
        let t = g.format(&bin, 0x100B).unwrap().1.iter().map(|x| x.text.clone()).collect::<String>();
        assert!(t.contains("[rbp+arg_0]"), "{t}");
    }

    #[test]
    fn data_definitions_change_the_listing() {
        let code = vec![0xC3];
        let mut data = b"hello world\0".to_vec();
        data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let bin = bin_of(code, data);
        let an = run(&bin, HashMap::from([(0x200C, 4u8)]));
        assert!(an.lines.iter().any(|l| l.addr == 0x200C && l.kind == LineKind::Data && l.len == 4));
        let an = run(&bin, HashMap::from([(0x200C, 0x88u8)]));
        assert_eq!(an.data_size.get(&0x200C), Some(&0x88));
        // making a string out of non-string-looking bytes, and undefining the auto string
        let an = run(&bin, HashMap::from([(0x2000, DEF_UNDEFINE), (0x200C, DEF_STRING)]));
        assert!(!an.string_at.contains_key(&0x2000));
        let an = run(&bin, HashMap::from([(0x2002, DEF_STRING)]));
        assert!(an.string_at.contains_key(&0x2002));
    }

    #[test]
    fn discovers_consecutive_code_pointer_tables() {
        let code = vec![0xC3, 0xC3, 0xC3];
        let mut data = Vec::new();
        for target in [0x1000u64, 0x1001, 0x1002] {
            data.extend_from_slice(&target.to_le_bytes());
        }
        data.extend_from_slice(&0u64.to_le_bytes());
        let mut bin = bin_of(code, data);
        bin.segments[1].exec = false;
        let an = run(&bin, Default::default());
        assert_eq!(an.vtables.get(&0x2000), Some(&vec![0x1000, 0x1001, 0x1002]));
        assert_eq!(an.pointer_tables.get(&0x2000), Some(&vec![0x1000, 0x1001, 0x1002]));
    }

    #[test]
    fn discovers_itanium_vtable_with_metadata_header() {
        let code = vec![0xC3, 0xC3, 0xC3];
        let mut data = vec![0u8; 0x30];
        data[8..16].copy_from_slice(&0x2010u64.to_le_bytes()); // typeinfo pointer
        for (i, target) in [0x1000u64, 0x1001, 0x1002].into_iter().enumerate() {
            let off = 16 + i * 8;
            data[off..off + 8].copy_from_slice(&target.to_le_bytes());
        }
        let mut bin = bin_of(code, data);
        bin.segments[1].exec = false;
        let an = run(&bin, Default::default());
        assert_eq!(an.vtables.get(&0x2000), Some(&vec![0x1000, 0x1001, 0x1002]));
    }
}
