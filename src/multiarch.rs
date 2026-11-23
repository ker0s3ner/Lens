//! Non-x86 instruction decoding (ARM64, ARM, Thumb, RISC-V, MIPS, PowerPC) through Capstone.
//! Gives the analysis the same arch-neutral `Insn` summary the x86 path produces, and turns the
//! text into coloured tokens for the listing.

use crate::analysis::{Flow, Insn};
use crate::code::{Tok, Token};
use crate::loader::{Arch, Binary};
use capstone::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;

pub struct Raw {
    pub addr: u64,
    pub len: usize,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub ops: String,
}

fn build(arch: Arch, big: bool) -> Option<Capstone> {
    use capstone::arch::*;
    let endian = if big { capstone::Endian::Big } else { capstone::Endian::Little };
    let r = match arch {
        Arch::X16 => Capstone::new().x86().mode(x86::ArchMode::Mode16).syntax(x86::ArchSyntax::Intel).build(),
        Arch::X86 => Capstone::new().x86().mode(x86::ArchMode::Mode32).syntax(x86::ArchSyntax::Intel).build(),
        Arch::X64 => Capstone::new().x86().mode(x86::ArchMode::Mode64).syntax(x86::ArchSyntax::Intel).build(),
        Arch::Arm64 => Capstone::new().arm64().mode(arm64::ArchMode::Arm).build(),
        Arch::Arm32 => Capstone::new().arm().mode(arm::ArchMode::Arm).endian(endian).build(),
        Arch::Thumb => Capstone::new().arm().mode(arm::ArchMode::Thumb).endian(endian).build(),
        Arch::RiscV32 => Capstone::new().riscv().mode(riscv::ArchMode::RiscV32).extra_mode([riscv::ArchExtraMode::RiscVC].iter().copied()).build(),
        Arch::RiscV64 => Capstone::new().riscv().mode(riscv::ArchMode::RiscV64).extra_mode([riscv::ArchExtraMode::RiscVC].iter().copied()).build(),
        Arch::Mips32 => Capstone::new().mips().mode(mips::ArchMode::Mips32).endian(endian).build(),
        Arch::Mips64 => Capstone::new().mips().mode(mips::ArchMode::Mips64).endian(endian).build(),
        Arch::Ppc32 => Capstone::new().ppc().mode(ppc::ArchMode::Mode32).endian(endian).build(),
        Arch::Ppc64 => Capstone::new().ppc().mode(ppc::ArchMode::Mode64).endian(endian).build(),
        Arch::M68k => Capstone::new().m68k().mode(m68k::ArchMode::M68k000).build(),
        Arch::Other => return None,
    };
    r.ok()
}

thread_local! {
    static CS: RefCell<HashMap<(Arch, bool), Option<Capstone>>> = RefCell::new(HashMap::new());
}

/// Disassemble up to `max` instructions from `bytes` (which sits at `addr`).
pub fn disasm(arch: Arch, big: bool, bytes: &[u8], addr: u64, max: usize) -> Vec<Raw> {
    CS.with(|m| {
        let mut m = m.borrow_mut();
        let cs = m.entry((arch, big)).or_insert_with(|| build(arch, big));
        let Some(cs) = cs else { return vec![] };
        let Ok(list) = (if max == 0 { cs.disasm_all(bytes, addr) } else { cs.disasm_count(bytes, addr, max) }) else { return vec![] };
        list.iter()
            .map(|i| Raw {
                addr: i.address(),
                len: i.len(),
                bytes: i.bytes().to_vec(),
                mnemonic: i.mnemonic().unwrap_or("").to_string(),
                ops: i.op_str().unwrap_or("").to_string(),
            })
            .collect()
    })
}

pub fn one(bin: &Binary, addr: u64) -> Option<Raw> {
    if !bin.is_mapped(addr) {
        return None;
    }
    let bytes = bin.read(addr, 16);
    disasm(bin.arch, bin.big_endian, bytes, addr, 1).into_iter().next()
}

fn parse_num(t: &str) -> Option<u64> {
    let t = t.trim().trim_start_matches('#');
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t),
    };
    let v = if let Some(h) = t.strip_prefix("0x") { u64::from_str_radix(h, 16).ok()? } else { t.parse::<u64>().ok()? };
    Some(if neg { v.wrapping_neg() } else { v })
}

/// The last operand that is a plain number, e.g. the target of `b.eq 0x1000` or `tbz w0, #3, 0x1000`.
fn last_target(ops: &str) -> Option<u64> {
    let t = ops.rsplit(',').next()?.trim();
    if t.contains('[') {
        return None;
    }
    parse_num(t.split_whitespace().last()?)
}

fn first_reg(ops: &str) -> &str {
    ops.split(',').next().unwrap_or("").trim()
}

const ARM_CC: [&str; 15] = ["eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt"];

fn classify(arch: Arch, mn: &str, ops: &str) -> (Flow, u64) {
    let tgt = last_target(ops).unwrap_or(0);
    let direct = tgt != 0;
    let pick = |direct_flow: Flow, indirect_flow: Flow| if direct { (direct_flow, tgt) } else { (indirect_flow, 0) };
    match arch {
        Arch::Arm64 => match mn {
            "ret" | "retaa" | "retab" | "eret" | "eretaa" | "eretab" => (Flow::Ret, 0),
            "bl" => pick(Flow::Call, Flow::IndirectCall),
            "blr" | "blraa" | "blraaz" | "blrab" | "blrabz" => (Flow::IndirectCall, 0),
            "b" => pick(Flow::Jump, Flow::IndirectJump),
            "br" | "braa" | "braaz" | "brab" | "brabz" => (Flow::IndirectJump, 0),
            "cbz" | "cbnz" | "tbz" | "tbnz" => pick(Flow::CondJump, Flow::Normal),
            "brk" | "udf" | "hlt" => (Flow::Stop, 0),
            _ if mn.starts_with("b.") => pick(Flow::CondJump, Flow::Normal),
            _ => (Flow::Normal, 0),
        },
        Arch::Arm32 | Arch::Thumb => {
            if mn == "tbb" || mn == "tbh" { return (Flow::IndirectJump, 0); }
            if mn == "bx" && ops.trim() == "lr" {
                return (Flow::Ret, 0);
            }
            if (mn.starts_with("pop") || mn.starts_with("ldm")) && ops.split(|c: char| !c.is_alphanumeric()).any(|t| t == "pc") {
                return (Flow::Ret, 0);
            }
            if mn.starts_with("mov") && ops.trim_start().starts_with("pc,") && ops.contains("lr") {
                return (Flow::Ret, 0);
            }
            if mn.starts_with("ldr") && first_reg(ops) == "pc" {
                return (Flow::IndirectJump, 0);
            }
            let base = mn.trim_end_matches(".w").trim_end_matches(".n");
            match base {
                "bl" | "blx" => pick(Flow::Call, Flow::IndirectCall),
                "b" => pick(Flow::Jump, Flow::IndirectJump),
                "bx" | "bxj" => (Flow::IndirectJump, 0),
                "cbz" | "cbnz" => pick(Flow::CondJump, Flow::Normal),
                "udf" | "bkpt" => (Flow::Stop, 0),
                _ => {
                    if let Some(cc) = base.strip_prefix('b') {
                        let cc2 = cc.strip_prefix('l').unwrap_or(cc);
                        if ARM_CC.contains(&cc) { return pick(Flow::CondJump, Flow::Normal); }
                        if ARM_CC.contains(&cc2) && direct && cc.starts_with('l') && !ARM_CC.contains(&cc) { return (Flow::Call, tgt); }
                    }
                    (Flow::Normal, 0)
                }
            }
        }
        Arch::RiscV32 | Arch::RiscV64 => match mn {
            "ret" | "mret" | "sret" | "uret" | "c.ret" => (Flow::Ret, 0),
            "j" | "c.j" | "jal" if mn != "jal" || !(ops.contains("ra") || ops.split(',').count() == 1) => pick(Flow::Jump, Flow::IndirectJump),
            "jal" | "c.jal" => pick(Flow::Call, Flow::IndirectCall),
            "jr" | "c.jr" => if ops.trim() == "ra" { (Flow::Ret, 0) } else { (Flow::IndirectJump, 0) },
            "jalr" | "c.jalr" => (Flow::IndirectCall, 0),
            "ebreak" | "c.ebreak" | "unimp" | "c.unimp" => (Flow::Stop, 0),
            _ if matches!(mn.trim_start_matches("c."), "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "beqz" | "bnez" | "blez" | "bgez" | "bltz" | "bgtz" | "bgt" | "ble" | "bgtu" | "bleu") => pick(Flow::CondJump, Flow::Normal),
            _ => (Flow::Normal, 0),
        },
        Arch::Mips32 | Arch::Mips64 => match mn {
            "jal" | "bal" => pick(Flow::Call, Flow::IndirectCall),
            "jalr" | "jalr.hb" => (Flow::IndirectCall, 0),
            "j" | "b" => pick(Flow::Jump, Flow::IndirectJump),
            "jr" | "jr.hb" => if ops.contains("ra") { (Flow::Ret, 0) } else { (Flow::IndirectJump, 0) },
            "eret" | "deret" => (Flow::Ret, 0),
            "break" | "teq" | "tne" => (Flow::Stop, 0),
            _ if matches!(mn, "beq" | "bne" | "beqz" | "bnez" | "bgez" | "bgtz" | "blez" | "bltz" | "bgezal" | "bltzal" | "beql" | "bnel" | "bc1t" | "bc1f") => pick(Flow::CondJump, Flow::Normal),
            _ => (Flow::Normal, 0),
        },
        Arch::Ppc32 | Arch::Ppc64 => match mn {
            "blr" => (Flow::Ret, 0),
            "bctr" => (Flow::IndirectJump, 0),
            "bctrl" | "blrl" => (Flow::IndirectCall, 0),
            "bl" | "bla" => pick(Flow::Call, Flow::IndirectCall),
            "b" | "ba" => pick(Flow::Jump, Flow::IndirectJump),
            "trap" | "tw" | "td" => (Flow::Stop, 0),
            _ if mn.starts_with('b') && !mn.ends_with("ctr") && direct && matches!(mn.trim_end_matches(['+', '-']), "beq" | "bne" | "blt" | "bgt" | "ble" | "bge" | "bdnz" | "bdz" | "bso" | "bns" | "bc" | "bdnzt" | "bdnzf" | "bdzt" | "bdzf" | "bnl" | "bng" | "bun" | "bnu") => (Flow::CondJump, tgt),
            _ => (Flow::Normal, 0),
        },
        Arch::M68k => match mn.split('.').next().unwrap_or(mn) {
            "rts" | "rte" | "rtr" => (Flow::Ret, 0),
            "jsr" | "bsr" => pick(Flow::Call, Flow::IndirectCall),
            "jmp" => pick(Flow::Jump, Flow::IndirectJump),
            "bra" => pick(Flow::Jump, Flow::IndirectJump),
            "bcc" | "bcs" | "beq" | "bge" | "bgt" | "bhi" | "bhs" | "blo" | "ble" | "bls" | "blt" | "bmi" | "bne" | "bpl" | "bvc" | "bvs" | "bt" | "bf" => pick(Flow::CondJump, Flow::Normal),
            _ => (Flow::Normal, 0),
        },
        _ => (Flow::Normal, 0),
    }
}

fn reg_width(r: &str) -> u8 {
    if r.starts_with('w') { 4 } else { 8 }
}

/// `adrp xN, 0xPAGE` followed by add/ldr/str using xN (and the `adrp; ldr; br` import stubs).
fn arm64_adrp(bin: &Binary, a: &Raw) -> Option<(Insn, usize)> {
    let page = last_target(&a.ops)?;
    let reg = first_reg(&a.ops).to_string();
    let rest = disasm(Arch::Arm64, false, bin.read(a.addr + 4, 12), a.addr + 4, 3);
    let n1 = rest.first()?;
    let base = |ops: &str| -> Option<(String, u64)> {
        // "[x16, #0x18]" or "[x16]"
        let i = ops.find('[')?;
        let inner = ops[i + 1..].split(']').next()?;
        let mut it = inner.split(',');
        let b = it.next()?.trim().to_string();
        let off = it.next().and_then(parse_num).unwrap_or(0);
        Some((b, off))
    };
    let mut insn = Insn { len: 4, flow: Flow::Normal, target: 0, mem: 0, mem_size: 0, imm: 0, is_lea: false, is_write: false };
    if n1.mnemonic == "add" {
        let parts: Vec<&str> = n1.ops.split(',').map(|s| s.trim()).collect();
        if parts.len() >= 3 && parts[1] == reg && !parts[2].starts_with('x') && !parts[2].starts_with('w') {
            if let Some(off) = parse_num(parts[2]) {
                let t = page.wrapping_add(off);
                if bin.is_mapped(t) { insn.imm = t; insn.is_lea = true; }
            }
        }
    } else if n1.mnemonic.starts_with("ldr") || n1.mnemonic.starts_with("str") {
        if let Some((b, off)) = base(&n1.ops) {
            if b == reg {
                let t = page.wrapping_add(off);
                if bin.is_mapped(t) {
                    insn.mem = t;
                    insn.mem_size = reg_width(first_reg(&n1.ops));
                    insn.is_write = n1.mnemonic.starts_with("str");
                }
                // import stub: adrp; ldr xM,[xN,#off]; (add xN,xN,#off;) br xM
                if n1.mnemonic == "ldr" && !insn.is_write && insn.mem != 0 {
                    let dest = first_reg(&n1.ops).to_string();
                    let mut k = 1;
                    if rest.get(k).map(|r| r.mnemonic == "add").unwrap_or(false) { k += 1; }
                    if let Some(br) = rest.get(k) {
                        if br.mnemonic == "br" && br.ops.trim() == dest {
                            insn.flow = Flow::IndirectJump;
                            insn.len = (4 * (k + 2)) as u8;
                        }
                    }
                }
            }
        }
    }
    Some((insn, insn.len as usize))
}

/// Arch-neutral summary of the instruction at `addr`.
pub fn decode_info(bin: &Binary, addr: u64) -> Option<Insn> {
    let a = one(bin, addr)?;
    if a.len == 0 {
        return None;
    }
    if bin.arch == Arch::Arm64 && a.mnemonic == "adrp" {
        if let Some((i, _)) = arm64_adrp(bin, &a) {
            return Some(i);
        }
    }
    let (flow, target) = classify(bin.arch, &a.mnemonic, &a.ops);
    let mut mem = 0;
    let mut mem_size = 0;
    let mut imm = 0;
    let mut is_lea = false;
    let m = a.mnemonic.as_str();
    // PC-relative literal loads and address formation
    if matches!(bin.arch, Arch::Arm64 | Arch::Arm32) && (m.starts_with("ldr")) && !a.ops.contains('[') {
        if let Some(t) = last_target(&a.ops) {
            if bin.is_mapped(t) { mem = t; mem_size = 8; }
        }
    }
    if bin.arch == Arch::Arm64 && m == "adr" {
        if let Some(t) = last_target(&a.ops) {
            if bin.is_mapped(t) { imm = t; is_lea = true; }
        }
    }
    if matches!(bin.arch, Arch::Arm32 | Arch::Thumb) && matches!(m, "adr" | "adr.w") {
        if let Some(t) = last_target(&a.ops) {
            if bin.is_mapped(t) { imm = t; is_lea = true; }
        }
    }
    Some(Insn { len: a.len as u8, flow, target, mem, mem_size, imm, is_lea, is_write: false })
}

// ------------------------------------------------------------------ tokens

fn is_reg(arch: Arch, t: &str) -> bool {
    let t = t.trim_start_matches('{').trim_end_matches('}');
    let b = t.as_bytes();
    if b.is_empty() { return false; }
    match arch {
        Arch::Arm64 => {
            matches!(t, "sp" | "wsp" | "xzr" | "wzr" | "lr" | "fp" | "pc") || (b.len() >= 2 && matches!(b[0], b'x' | b'w' | b'v' | b'q' | b'd' | b's' | b'h' | b'b') && t[1..].chars().all(|c| c.is_ascii_digit()))
        }
        Arch::Arm32 | Arch::Thumb => matches!(t, "sp" | "lr" | "pc" | "fp" | "ip" | "sb" | "sl" | "cpsr" | "spsr") || (b.len() >= 2 && matches!(b[0], b'r' | b'd' | b'q' | b's') && t[1..].chars().all(|c| c.is_ascii_digit())),
        Arch::RiscV32 | Arch::RiscV64 => matches!(t, "zero" | "ra" | "sp" | "gp" | "tp") || (b.len() >= 2 && matches!(b[0], b'a' | b't' | b's' | b'x' | b'f') && t[1..].chars().all(|c| c.is_ascii_digit())) || (t.len() == 3 && t.starts_with("fa") || t.starts_with("ft") || t.starts_with("fs")),
        Arch::Mips32 | Arch::Mips64 => b[0] == b'$',
        Arch::Ppc32 | Arch::Ppc64 => (b.len() >= 2 && matches!(b[0], b'r' | b'f' | b'v' | b'c') && t[1..].chars().all(|c| c.is_ascii_digit())) || t.starts_with("cr"),
        Arch::M68k => matches!(t, "sp" | "pc" | "sr" | "ccr") || (b.len() == 2 && matches!(b[0], b'd' | b'a') && b[1].is_ascii_digit()),
        _ => false,
    }
}

/// Coloured tokens for one instruction. Branch targets and addresses that have names are replaced by the name.
pub fn tokens(bin: &Binary, a: &Raw, names: &crate::code::NameTable, fused: Option<u64>) -> Vec<Token> {
    let mut out = vec![];
    if let Some(slot) = fused {
        out.push(Token { text: format!("{:<7}", "br"), kind: Tok::Mnemonic, target: None });
        out.push(Token { text: "[".into(), kind: Tok::Punct, target: None });
        match names.get(&slot) {
            Some((n, k)) => out.push(Token { text: n.clone(), kind: Tok::Name(*k), target: Some(slot) }),
            None => out.push(Token { text: format!("{slot:X}h"), kind: Tok::Number, target: Some(slot) }),
        }
        out.push(Token { text: "]".into(), kind: Tok::Punct, target: None });
        return out;
    }
    out.push(Token { text: format!("{:<7}", a.mnemonic), kind: Tok::Mnemonic, target: None });
    let _ = bin;
    let s = a.ops.as_str();
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<Token>| {
        if cur.is_empty() { return; }
        let t = std::mem::take(cur);
        let bare = t.trim_start_matches('#');
        if t.contains('-') {
            out.push(Token { text: t, kind: Tok::Number, target: None });
        } else if let Some(v) = parse_num(&t) {
            if let Some((n, k)) = names.get(&v) {
                out.push(Token { text: n.clone(), kind: Tok::Name(*k), target: Some(v) });
            } else if t.contains("0x") && v > 0x1000 {
                out.push(Token { text: format!("{}{:X}h", if t.starts_with('#') { "#" } else { "" }, v), kind: Tok::Number, target: Some(v) });
            } else {
                out.push(Token { text: t, kind: Tok::Number, target: None });
            }
        } else if is_reg(bin.arch, bare) {
            out.push(Token { text: t, kind: Tok::Register, target: None });
        } else if matches!(t.as_str(), "lsl" | "lsr" | "asr" | "ror" | "sxtw" | "uxtw" | "sxtb" | "uxtb" | "sxth" | "uxth" | "msl" | "rrx" | "ptr") {
            out.push(Token { text: t, kind: Tok::Keyword, target: None });
        } else {
            out.push(Token { text: t, kind: Tok::Plain, target: None });
        }
    };
    for ch in s.chars() {
        if matches!(ch, ',' | '[' | ']' | '{' | '}' | '(' | ')' | '!' | ' ') {
            flush(&mut cur, &mut out);
            out.push(Token { text: ch.to_string(), kind: Tok::Punct, target: None });
        } else {
            cur.push(ch);
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// Text of an instruction for search and export.
pub fn text(a: &Raw) -> String {
    if a.ops.is_empty() { a.mnemonic.clone() } else { format!("{} {}", a.mnemonic, a.ops) }
}
