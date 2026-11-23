//! Front-end for the decompiler on non-x86 CPUs (ARM64, ARM, RISC-V, MIPS, PowerPC).
//!
//! It reads the Capstone text of each instruction, runs it symbolically exactly like the x86 path does
//! (registers become expressions, stack slots become locals) and hands the same `BlockOut`s to the shared
//! liveness / structuring / printing stages. It covers the integer core of each instruction set; anything
//! else becomes a visible `__mnemonic(...)` intrinsic so nothing is dropped silently.

use super::*;
use crate::analysis::decode_info;
use crate::loader::Arch;
use crate::multiarch;
use iced_x86::ConditionCode as CC;

const ZERO: u8 = 254;
// Synthetic front-end registers for MIPS' implicit HI/LO multiply-divide pair.
const MIPS_HI: u8 = 252;
const MIPS_LO: u8 = 253;

#[derive(Clone, Copy, PartialEq, Debug)]
struct R {
    i: u8,
    w: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a64_vector_registers_and_names_them() {
        let r = parse_reg(Fam::A64, "v7.4s").expect("vector register");
        assert_eq!(r.i, 39);
        assert_eq!(r.w, 16);
        assert_eq!(abi_for(Arch::Arm64).names[r.i as usize], "v7");
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fam {
    A64,
    A32,
    Rv,
    Mips,
    Ppc,
}

fn fam(a: Arch) -> Fam {
    match a {
        Arch::Arm64 => Fam::A64,
        Arch::Arm32 | Arch::Thumb => Fam::A32,
        Arch::RiscV32 | Arch::RiscV64 => Fam::Rv,
        Arch::Mips32 | Arch::Mips64 => Fam::Mips,
        _ => Fam::Ppc,
    }
}

const RV: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
];
const MIPS: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
];

pub fn abi_for(arch: Arch) -> Abi {
    let (names, ret, sp, args, caller, callee): (Vec<String>, u8, u8, Vec<u8>, Vec<u8>, Vec<u8>) = match fam(arch) {
        Fam::A64 => {
            let mut n: Vec<String> = (0..29).map(|i| format!("x{i}")).collect();
            n.extend(["fp".into(), "lr".into(), "sp".into()]);
            n.extend((0..32).map(|i| format!("v{i}")));
            (n, 0, 31, (0..8).collect(), (0..=17).collect(), (19..=30).collect())
        }
        Fam::A32 => {
            let mut n: Vec<String> = (0..11).map(|i| format!("r{i}")).collect();
            n.extend(["fp", "ip", "sp", "lr", "pc"].map(String::from));
            (n, 0, 13, (0..4).collect(), vec![0, 1, 2, 3, 12], (4..=11).chain([14]).collect())
        }
        Fam::Rv => (RV.map(String::from).to_vec(), 10, 2, (10..18).collect(), [1, 5, 6, 7, 28, 29, 30, 31].into_iter().chain(10..18).collect(), [8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27].to_vec()),
        Fam::Mips => (MIPS.map(String::from).to_vec(), 2, 29, (4..8).collect(), (1..=15).chain([24, 25, 31]).collect(), (16..=23).chain([30]).collect()),
        Fam::Ppc => {
            let mut n: Vec<String> = (0..32).map(|i| format!("r{i}")).collect();
            n[1] = "sp".into();
            (n, 3, 1, (3..11).collect(), (3..=12).collect(), (14..=31).collect())
        }
    };
    Abi { names, ret, sp, args, caller_saved: caller, callee_saved: callee, x86: false }
}

fn parse_imm(s: &str) -> Option<i64> {
    let t = s.trim().trim_start_matches('#');
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t),
    };
    let v = if let Some(h) = t.strip_prefix("0x") { i64::from_str_radix(h, 16).ok().or_else(|| u64::from_str_radix(h, 16).ok().map(|x| x as i64))? } else { t.parse::<i64>().ok()? };
    Some(if neg { v.wrapping_neg() } else { v })
}

fn parse_reg(f: Fam, tok: &str) -> Option<R> {
    let t = tok.trim().trim_end_matches('!').split('.').next().unwrap_or(tok.trim());
    let num = |p: &str, max: u8| t.strip_prefix(p).and_then(|d| if d.is_empty() || !d.chars().all(|c| c.is_ascii_digit()) { None } else { d.parse::<u8>().ok() }).filter(|n| *n <= max);
    match f {
        Fam::A64 => match t {
            "sp" | "wsp" => Some(R { i: 31, w: if t == "wsp" { 4 } else { 8 } }),
            "xzr" => Some(R { i: ZERO, w: 8 }),
            "wzr" => Some(R { i: ZERO, w: 4 }),
            "fp" => Some(R { i: 29, w: 8 }),
            "lr" => Some(R { i: 30, w: 8 }),
            _ => num("x", 30).map(|i| R { i, w: 8 })
                .or_else(|| num("w", 30).map(|i| R { i, w: 4 }))
                .or_else(|| num("v", 31).map(|i| R { i: 32 + i, w: 16 })),
        },
        Fam::A32 => match t {
            "sp" => Some(R { i: 13, w: 4 }),
            "lr" => Some(R { i: 14, w: 4 }),
            "pc" => Some(R { i: 15, w: 4 }),
            "fp" => Some(R { i: 11, w: 4 }),
            "ip" => Some(R { i: 12, w: 4 }),
            "sl" => Some(R { i: 10, w: 4 }),
            "sb" => Some(R { i: 9, w: 4 }),
            _ => num("r", 15).map(|i| R { i, w: 4 }),
        },
        Fam::Rv => RV.iter().position(|n| *n == t).map(|i| R { i: if i == 0 { ZERO } else { i as u8 }, w: 8 }).or_else(|| if t == "fp" { Some(R { i: 8, w: 8 }) } else { num("x", 31).map(|i| R { i: if i == 0 { ZERO } else { i }, w: 8 }) }),
        Fam::Mips => {
            if !t.starts_with('$') {
                return None;
            }
            let t = t.trim_start_matches('$');
            MIPS.iter().position(|n| *n == t).map(|i| R { i: if i == 0 { ZERO } else { i as u8 }, w: 4 })
        }
        Fam::Ppc => num("r", 31).map(|i| R { i, w: 4 }),
    }
}

/// Split operands at top-level commas.
fn split_ops(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut depth = 0;
    for c in s.chars() {
        match c {
            '[' | '{' | '(' => { depth += 1; cur.push(c) }
            ']' | '}' | ')' => { depth -= 1; cur.push(c) }
            ',' if depth == 0 => { out.push(cur.trim().to_string()); cur.clear() }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

#[derive(Clone, Debug)]
struct M {
    base: R,
    disp: i64,
    idx: Option<(R, u32)>,
    pre: bool,
    post: Option<i64>,
}

fn parse_mem(f: Fam, ops: &[String], k: usize) -> Option<(M, usize)> {
    let t = ops.get(k)?;
    if let Some(open) = t.find('(') {
        // imm(reg) — MIPS, RISC-V, PowerPC
        let disp = if open == 0 { 0 } else { parse_imm(&t[..open])? };
        let base = parse_reg(f, t[open + 1..].trim_end_matches(')'))?;
        return Some((M { base, disp, idx: None, pre: false, post: None }, 1));
    }
    let inner = t.strip_prefix('[')?;
    let (body, tail) = inner.split_once(']')?;
    let parts: Vec<&str> = body.split(',').map(|s| s.trim()).collect();
    let base = parse_reg(f, parts[0])?;
    let mut disp = 0;
    let mut idx = None;
    if let Some(p) = parts.get(1) {
        if let Some(r) = parse_reg(f, p.trim_start_matches('-')) {
            let sh = parts.get(2).and_then(|s| s.split_whitespace().last()).and_then(|x| parse_imm(x)).unwrap_or(0) as u32;
            idx = Some((r, sh));
        } else {
            disp = parse_imm(p)?;
        }
    }
    let pre = tail.contains('!');
    let mut used = 1;
    let mut post = None;
    if !pre {
        if let Some(n) = ops.get(k + 1) {
            if let Some(v) = parse_imm(n) {
                post = Some(v);
                used = 2;
            }
        }
    }
    Some((M { base, disp, idx, pre, post }, used))
}

fn cc_of(n: &str) -> Option<CC> {
    Some(match n {
        "eq" => CC::e,
        "ne" => CC::ne,
        "cs" | "hs" => CC::ae,
        "cc" | "lo" => CC::b,
        "mi" => CC::s,
        "pl" => CC::ns,
        "vs" => CC::o,
        "vc" => CC::no,
        "hi" => CC::a,
        "ls" => CC::be,
        "ge" => CC::ge,
        "lt" => CC::l,
        "gt" => CC::g,
        "le" => CC::le,
        _ => return None,
    })
}

/// Change of the stack pointer caused by an instruction (negative = frame grows).
fn sp_delta(f: Fam, mn: &str, ops: &[String]) -> i64 {
    let spn = |s: &str| parse_reg(f, s).map(|r| r.i == abi_sp()).unwrap_or(false);
    match f {
        Fam::A64 => {
            if matches!(mn, "sub" | "add") && ops.len() >= 3 && spn(&ops[0]) && spn(&ops[1]) {
                let v = parse_imm(&ops[2]).unwrap_or(0);
                return if mn == "sub" { -v } else { v };
            }
            if matches!(mn, "stp" | "ldp" | "str" | "ldr" | "strb" | "strh") {
                if let Some(k) = ops.iter().position(|o| o.starts_with('[')) {
                    if let Some((m, _)) = parse_mem(f, ops, k) {
                        if spn(&ops[k][1..].split([',', ']']).next().unwrap_or("")) {
                            if m.pre { return m.disp; }
                            if let Some(p) = m.post { return p; }
                        }
                    }
                }
            }
            0
        }
        Fam::A32 => {
            let regs = |o: &String| o.trim_matches(|c| c == '{' || c == '}').split(',').filter(|x| !x.trim().is_empty()).count() as i64;
            match mn {
                "push" | "push.w" => ops.first().map(|o| -4 * regs(o)).unwrap_or(0),
                "pop" | "pop.w" => ops.first().map(|o| 4 * regs(o)).unwrap_or(0),
                "sub" | "add" | "sub.w" | "add.w" | "subw" | "addw" if ops.len() >= 2 && spn(&ops[0]) && ops.last().map(|o| parse_imm(o).is_some()).unwrap_or(false) && (ops.len() == 2 || spn(&ops[1])) => {
                    let v = parse_imm(ops.last().unwrap()).unwrap_or(0);
                    if mn.starts_with("sub") { -v } else { v }
                }
                _ => 0,
            }
        }
        Fam::Rv => {
            if matches!(mn, "addi" | "addiw" | "c.addi") && ops.len() == 3 && spn(&ops[0]) && spn(&ops[1]) {
                return parse_imm(&ops[2]).unwrap_or(0);
            }
            if mn == "c.addi16sp" {
                return ops.last().and_then(|o| parse_imm(o)).unwrap_or(0);
            }
            0
        }
        Fam::Mips => {
            if matches!(mn, "addiu" | "addi" | "daddiu") && ops.len() == 3 && spn(&ops[0]) && spn(&ops[1]) {
                return parse_imm(&ops[2]).unwrap_or(0);
            }
            0
        }
        Fam::Ppc => {
            if matches!(mn, "stwu" | "stdu") {
                if let Some((m, _)) = parse_mem(f, ops, 1) {
                    if m.base.i == abi_sp() { return m.disp; }
                }
            }
            if mn == "addi" && ops.len() == 3 && spn(&ops[0]) && spn(&ops[1]) {
                return parse_imm(&ops[2]).unwrap_or(0);
            }
            0
        }
    }
}

/// `fp = sp + N` (frame pointer set-up) — returns N.
fn fp_set(f: Fam, mn: &str, ops: &[String]) -> Option<i64> {
    let is_fp = |s: &str| matches!(parse_reg(f, s), Some(r) if match f { Fam::A64 => r.i == 29, Fam::A32 => r.i == 11, Fam::Rv => r.i == 8, Fam::Mips => r.i == 30, Fam::Ppc => r.i == 31 });
    let is_sp = |s: &str| parse_reg(f, s).map(|r| r.i == abi_sp()).unwrap_or(false);
    if ops.is_empty() || !is_fp(&ops[0]) {
        return None;
    }
    match mn {
        "mov" | "move" | "mr" | "or" | "c.mv" | "mv" if ops.len() >= 2 && is_sp(&ops[1]) => Some(0),
        "add" | "addi" | "addiu" | "add.w" | "addw" if ops.len() == 3 && is_sp(&ops[1]) => parse_imm(&ops[2]),
        _ => None,
    }
}

/// Stack pointer (and frame pointer) at the start of each block.
pub(super) fn sp_pass(dc: &Dc, f: &Function, idx: &HashMap<u64, usize>) -> Vec<Option<(i64, Option<i64>)>> {
    let n = f.blocks.len();
    let fm = fam(dc.bin.arch);
    let mut sp_in: Vec<Option<(i64, Option<i64>)>> = vec![None; n];
    if n == 0 {
        return sp_in;
    }
    sp_in[0] = Some((0, None));
    let mut work = vec![0usize];
    while let Some(b) = work.pop() {
        let (mut sp, mut bp) = sp_in[b].unwrap();
        for a in &f.blocks[b].insns {
            let Some(r) = multiarch::one(dc.bin, *a) else { continue };
            let ops = split_ops(&r.ops);
            if let Some(n) = fp_set(fm, &r.mnemonic, &ops) {
                bp = Some(sp + n);
            }
            sp += sp_delta(fm, &r.mnemonic, &ops);
        }
        for (t, _) in &f.blocks[b].succs {
            if let Some(&ti) = idx.get(t) {
                if sp_in[ti].is_none() {
                    sp_in[ti] = Some((sp, bp));
                    work.push(ti);
                }
            }
        }
    }
    sp_in
}

fn frame_off(e: &Ex) -> Option<i64> {
    match e {
        Ex::Raw(r) if r == "frame" => Some(0),
        Ex::Bin("+", a, b) => match (&**a, &**b) {
            (Ex::Raw(r), Ex::Num(k)) if r == "frame" => Some(*k),
            _ => None,
        },
        _ => None,
    }
}

fn is_named_addr(dc: &Dc, a: u64) -> bool {
    a > 0xFFF && (dc.names.contains_key(&a) || dc.an.string_at.contains_key(&a))
}

impl<'a> Dc<'a> {
    fn g_rd_raw(&mut self, st: &mut St, r: R) -> Ex {
        if r.i == ZERO {
            return Ex::Num(0);
        }
        if r.i == abi_sp() {
            return bin("+", Ex::Raw("frame".into()), Ex::Num(st.sp));
        }
        if r.i == self.g_fp_idx() && !st.env.contains_key(&r.i) {
            if let Some(b) = st.bp {
                return bin("+", Ex::Raw("frame".into()), Ex::Num(b));
            }
        }
        match st.env.get(&r.i) {
            Some(e) => e.clone(),
            None => {
                st.uses.insert(r.i);
                Ex::Var(reg_name(r.i))
            }
        }
    }

    fn g_fp_idx(&self) -> u8 {
        match fam(self.bin.arch) { Fam::A64 => 29, Fam::A32 => 11, Fam::Rv => 8, Fam::Mips => 30, Fam::Ppc => 31 }
    }

    fn g_rd(&mut self, st: &mut St, r: R) -> Ex {
        match self.g_rd_raw(st, r) {
            Ex::Num(n) if n > 0xFFF && is_named_addr(self, n as u64) => self.global_addr(n as u64),
            e => e,
        }
    }

    /// Frame-relative addresses that survive to the output become `&local`.
    fn g_fix(&mut self, e: &Ex) -> Ex {
        if let Some(k) = frame_off(e) {
            let slot = self.g_slot(k, 1);
            return Ex::Un("&", Box::new(slot));
        }
        match e {
            Ex::Bin(op, a, b) => Ex::Bin(op, Box::new(self.g_fix(a)), Box::new(self.g_fix(b))),
            Ex::Un(op, a) => Ex::Un(op, Box::new(self.g_fix(a))),
            Ex::Deref(a, n) => Ex::Deref(Box::new(self.g_fix(a)), *n),
            Ex::Cast(t, a) => Ex::Cast(t, Box::new(self.g_fix(a))),
            Ex::Call(f, args) => Ex::Call(Box::new(self.g_fix(f)), args.iter().map(|x| self.g_fix(x)).collect()),
            Ex::Tern(a, b, c) => Ex::Tern(Box::new(self.g_fix(a)), Box::new(self.g_fix(b)), Box::new(self.g_fix(c))),
            other => other.clone(),
        }
    }

    fn g_wr(&mut self, st: &mut St, r: R, v: Ex, addr: u64) {
        if r.i == ZERO || r.i == abi_sp() {
            return;
        }
        let v = if ex_size(&v) > 16 {
            self.tmp += 1;
            let t = format!("t{}", self.tmp);
            st.stmts.push((addr, Stmt::Assign(var(&t), v)));
            var(&t)
        } else {
            v
        };
        st.env.insert(r.i, v);
        st.modified.insert(r.i);
        st.dirty.insert(r.i);
    }

    fn g_slot(&mut self, off: i64, size: u8) -> Ex {
        if off >= 0 {
            let k = self.bin.arch.bits() as usize / 8;
            let nregs = ABI.with(|a| a.borrow().as_ref().map(|x| x.args.len()).unwrap_or(0));
            let k = nregs + (off as usize / k.max(1)) + 1;
            self.stack_args.insert(k);
            return Ex::Var(format!("a{k}"));
        }
        let name = format!("var_{:X}", -off);
        let e = self.locals.entry(name.clone()).or_insert(size.max(1));
        if size > *e {
            *e = size;
        }
        Ex::Var(name)
    }

    /// Effective address of a memory operand.
    fn g_addr(&mut self, st: &mut St, m: &M) -> Ex {
        let mut addr = self.g_rd_raw(st, m.base);
        if let Some((ir, sh)) = m.idx {
            let ix = self.g_rd(st, ir);
            addr = bin("+", addr, if sh == 0 { ix } else { bin("<<", ix, Ex::Num(sh as i64)) });
        }
        bin("+", addr, Ex::Num(m.disp))
    }

    /// The lvalue a memory operand names, and its frame offset when it is a stack slot.
    fn g_mem(&mut self, st: &mut St, m: &M, size: u8) -> (Ex, Option<i64>) {
        let addr = self.g_addr(st, m);
        if let Some(off) = frame_off(&addr) {
            return (self.g_slot(off, size), Some(off));
        }
        if let Ex::Num(a) = addr {
            if self.names.contains_key(&(a as u64)) {
                return (self.global(a as u64), None);
            }
        }
        (Ex::Deref(Box::new(addr), size), None)
    }

    fn g_writeback(&mut self, st: &mut St, m: &M, addr: u64) {
        let delta = if m.pre { Some(m.disp) } else { m.post };
        let Some(d) = delta else { return };
        if m.base.i == abi_sp() {
            return; // tracked through sp_delta
        }
        let b = self.g_rd_raw(st, m.base);
        self.g_wr(st, m.base, bin("+", b, Ex::Num(d)), addr);
    }

    fn g_is_spill_reg(&self, r: R) -> bool {
        ABI.with(|a| a.borrow().as_ref().map(|x| x.callee_saved.contains(&r.i)).unwrap_or(false))
    }

    fn g_load(&mut self, st: &mut St, rd: Option<R>, m: &M, size: u8, signed: bool, addr: u64) {
        let pre = self.g_addr(st, m);
        if let (Some(off), Some(r)) = (frame_off(&pre), rd) {
            if self.spills.contains(&off) && self.g_is_spill_reg(r) {
                self.g_writeback(st, m, addr);
                return;
            }
        }
        let (lv, _slot) = self.g_mem(st, m, size);
        let lv = if signed && size < 8 { Ex::Cast(match size { 1 => "int8_t", 2 => "int16_t", _ => "int32_t" }, Box::new(lv)) } else { lv };
        if let Some(r) = rd {
            self.g_wr(st, r, lv, addr);
        }
        self.g_writeback(st, m, addr);
    }

    fn g_store(&mut self, st: &mut St, val: Ex, src: Option<R>, m: &M, size: u8, addr: u64) {
        let pre = self.g_addr(st, m);
        if let (Some(off), Some(r)) = (frame_off(&pre), src) {
            let unmodified = matches!(&val, Ex::Var(v) if *v == reg_name(r.i)) && !st.env.contains_key(&r.i);
            if off < 0 && unmodified && self.g_is_spill_reg(r) {
                self.spills.insert(off);
                self.g_writeback(st, m, addr);
                return;
            }
        }
        let (lv, _slot) = self.g_mem(st, m, size);
        self.store(st, addr, lv, val);
        self.g_writeback(st, m, addr);
    }

    fn g_val(&mut self, st: &mut St, op: &str, shift: Option<&str>) -> Ex {
        let v = if let Some(r) = parse_reg(fam(self.bin.arch), op) {
            self.g_rd(st, r)
        } else if let Some(n) = parse_imm(op) {
            let u = n as u64;
            if n > 0xFFF && is_named_addr(self, u) { self.global_addr(u) } else { Ex::Num(n) }
        } else {
            Ex::Raw(op.to_string())
        };
        match shift {
            Some(s) => {
                let mut it = s.split_whitespace();
                let kind = it.next().unwrap_or("");
                let amt = it.next().and_then(parse_imm).unwrap_or(0);
                match kind {
                    "lsl" => bin("<<", v, Ex::Num(amt)),
                    "lsr" => bin(">>", v, Ex::Num(amt)),
                    "asr" => bin(">>", Ex::Cast("int64_t", Box::new(v)), Ex::Num(amt)),
                    "sxtw" => Ex::Cast("int32_t", Box::new(v)),
                    "uxtw" => Ex::Cast("uint32_t", Box::new(v)),
                    _ => v,
                }
            }
            None => v,
        }
    }

    fn g_call(&mut self, st: &mut St, addr: u64, callee: Ex, noret: bool) {
        let (arg_regs, caller): (Vec<u8>, Vec<u8>) = ABI.with(|a| a.borrow().as_ref().map(|x| (x.args.clone(), x.caller_saved.clone())).unwrap_or_default());
        let ret = abi_ret();
        let mut n_regs = 0;
        for (k, r) in arg_regs.iter().enumerate() {
            if st.dirty.contains(r) {
                n_regs = k + 1;
            }
        }
        let mut args = vec![];
        for r in arg_regs.iter().take(n_regs) {
            args.push(match st.env.get(r) {
                Some(e) => e.clone(),
                None => {
                    st.uses.insert(*r);
                    Ex::Var(reg_name(*r))
                }
            });
        }
        for d in &caller {
            st.env.remove(d);
        }
        self.freeze(st, addr, true, None);
        let call = Ex::Call(Box::new(callee), args);
        if noret {
            st.stmts.push((addr, Stmt::Expr(call)));
            st.stmts.push((addr, Stmt::Comment("does not return".into())));
            st.flags = Flags::None;
            st.out_args_used = true;
            return;
        }
        self.tmp += 1;
        let t = format!("v{}", self.tmp);
        st.stmts.push((addr, Stmt::Assign(var(&t), call)));
        st.env.insert(ret, var(&t));
        st.modified.insert(ret);
        st.modified.extend(caller.iter().copied());
        st.dirty.clear();
        st.dirty.insert(ret);
        st.flags = Flags::None;
    }

    fn g_target_call(&mut self, info: &crate::analysis::Insn) -> (Ex, bool, bool) {
        let n = self.callee_name(info.target);
        let nr = self.an.functions.get(&info.target).map(|f| f.noreturn).unwrap_or(false) || is_noreturn_name(&n);
        let skip = matches!(n.as_str(), "chkstk" | "alloca_probe" | "security_check_cookie" | "__chkstk");
        (Ex::Var(n), nr, skip)
    }
}

fn mem_size_of(fm: Fam, mn: &str, reg: Option<R>) -> (u8, bool) {
    let signed = mn.contains("ls") && fm == Fam::Rv || mn.starts_with("ldrs") || mn.starts_with("ldursw") || matches!(mn, "lb" | "lh" | "lw" | "lha" | "lwa" | "ldrsb" | "ldrsh" | "ldrsw" | "lb.w") && fm != Fam::Ppc && !matches!(mn, "lw" if fm == Fam::Rv);
    let by_name = if mn.ends_with('b') || mn.contains("lb") || mn.contains("sb") || mn.starts_with("lbz") || mn.starts_with("stb") { Some(1) } else if mn.ends_with('h') || mn.contains("lh") || mn.contains("sh") && fm != Fam::A64 || mn.starts_with("lhz") || mn.starts_with("lha") || mn.starts_with("sth") { Some(2) } else if mn.ends_with('w') || mn.contains("lw") || mn.starts_with("sw") || mn.starts_with("lwz") || mn.starts_with("stw") || mn == "ldrsw" || mn.starts_with("ldursw") { Some(4) } else if mn.ends_with('d') || mn.starts_with("ld") && fm == Fam::Rv || mn.starts_with("sd") || mn == "std" || mn.starts_with("ldu") && fm == Fam::Ppc { Some(8) } else { None };
    let size = match (fm, mn) {
        (Fam::A64, m) if m.ends_with('b') || m.starts_with("ldrsb") || m.starts_with("ldurb") || m.starts_with("sturb") => 1,
        (Fam::A64, m) if m.ends_with('h') || m.starts_with("ldrsh") => 2,
        (Fam::A64, m) if m.starts_with("ldrsw") || m.starts_with("ldursw") => 4,
        (Fam::A64, _) => reg.map(|r| r.w).unwrap_or(8),
        (Fam::A32, m) if m.contains('b') => 1,
        (Fam::A32, m) if m.contains('h') => 2,
        (Fam::A32, _) => 4,
        _ => by_name.unwrap_or(reg.map(|r| r.w).unwrap_or(4)),
    };
    (size, signed)
}

pub(super) fn exec(dc: &mut Dc, f: &Function, bi: usize, sp_in: i64, bp_in: Option<i64>) -> BlockOut {
    let blk = &f.blocks[bi];
    let fm = fam(dc.bin.arch);
    let ret_idx = abi_ret();
    let mut st = St {
        env: HashMap::new(),
        flags: Flags::None,
        sp: sp_in,
        bp: bp_in,
        pending: vec![],
        dirty: BTreeSet::new(),
        uses: BTreeSet::new(),
        modified: BTreeSet::new(),
        stmts: vec![],
        out_args_used: false,
    };
    let mut term = Term::Fall(blk.end);
    let mut term_addr = blk.end;
    let fp_idx: u8 = match fm { Fam::A64 => 29, Fam::A32 => 11, Fam::Rv => 8, Fam::Mips => 30, Fam::Ppc => 31 };
    'insns: for a in &blk.insns {
        let addr = *a;
        let Some(raw) = multiarch::one(dc.bin, addr) else { continue };
        let Some(info) = decode_info(dc.bin, addr) else { continue };
        let mn = raw.mnemonic.as_str();
        let ops = split_ops(&raw.ops);
        let o = |k: usize| ops.get(k).map(|s| s.as_str()).unwrap_or("");
        let reg = |k: usize| parse_reg(fm, o(k));
        // ---- stack frame housekeeping: skipped, only tracked
        if let Some(n) = fp_set(fm, mn, &ops) {
            st.bp = Some(st.sp + n);
            continue;
        }
        let spd = sp_delta(fm, mn, &ops);
        let adjusts = spd != 0 && matches!(mn, "sub" | "add" | "addi" | "addiu" | "addiw" | "addw" | "sub.w" | "add.w" | "subw" | "c.addi" | "c.addi16sp" | "push" | "pop" | "push.w" | "pop.w");
        if adjusts {
            st.sp += spd;
            if !(matches!(mn, "pop" | "pop.w") && ops.first().map(|x| x.contains("pc")).unwrap_or(false)) {
                continue;
            }
        }
        let spd = if adjusts { 0 } else { spd };
        if reg(0).map(|r| r.i == abi_sp()).unwrap_or(false) && matches!(mn, "mov" | "move" | "mr" | "or" | "c.mv" | "mv" | "add" | "addi") && !matches!(mn, "push") {
            continue; // sp = fp (frame teardown)
        }
        let is_fn_flow = info.flow != Flow::Normal;
        match info.flow {
            Flow::Ret => {
                let set_here = st.modified.contains(&ret_idx) || st.env.contains_key(&ret_idx);
                let v = if set_here { Some(dc.g_rd(&mut st, R { i: ret_idx, w: 8 })) } else { None };
                term = Term::Ret(v);
                term_addr = addr;
                break 'insns;
            }
            Flow::Call | Flow::IndirectCall => {
                let (callee, nr, skip) = if info.flow == Flow::Call && info.target != 0 {
                    dc.g_target_call(&info)
                } else if info.mem != 0 && (dc.names.contains_key(&info.mem) || dc.an.import_slot.contains_key(&info.mem)) {
                    let n = dc.callee_name(info.mem);
                    let nr = is_noreturn_name(&n);
                    (Ex::Var(n), nr, false)
                } else if let Some(r) = reg(0) {
                    (dc.g_rd(&mut st, r), false, false)
                } else {
                    (Ex::Raw(raw.ops.clone()), false, false)
                };
                if !skip {
                    dc.g_call(&mut st, addr, callee, nr);
                }
                if st.out_args_used {
                    term = Term::Stop;
                    term_addr = addr;
                    break 'insns;
                }
                // a link-register write by the call itself isn't interesting
                continue;
            }
            Flow::CondJump => {
                let cond = g_condition(dc, &mut st, fm, mn, &ops);
                term = Term::Cond { cond, taken: info.target, fall: addr + info.len as u64 };
                term_addr = addr;
                break 'insns;
            }
            Flow::Jump => {
                term = Term::Jmp(info.target);
                term_addr = addr;
                break 'insns;
            }
            Flow::IndirectJump => {
                let v = match reg(0) {
                    Some(r) => dc.g_rd(&mut st, r),
                    None => Ex::Raw(raw.ops.clone()),
                };
                term = Term::Indirect(v);
                term_addr = addr;
                break 'insns;
            }
            Flow::Stop => {
                st.stmts.push((addr, Stmt::Comment(mn.to_string())));
                term = Term::Stop;
                term_addr = addr;
                break 'insns;
            }
            Flow::Normal => {}
        }
        let _ = is_fn_flow;
        g_data(dc, &mut st, fm, addr, mn, &ops, fp_idx);
        st.sp += spd; // pre/post-indexed stores and loads move sp after the access
    }
    // tail call: a jump to another function is `return f(args)`
    if let Term::Jmp(t) = &term {
        if !f.blocks.iter().any(|b| b.start == *t) && dc.an.functions.contains_key(t) {
            let callee = Ex::Var(dc.callee_name(*t));
            let arg_regs: Vec<u8> = ABI.with(|a| a.borrow().as_ref().map(|x| x.args.clone()).unwrap_or_default());
            let mut args = vec![];
            for r in &arg_regs {
                if st.dirty.contains(r) {
                    args.push(st.env.get(r).cloned().unwrap_or_else(|| var(&reg_name(*r))));
                }
            }
            term = Term::Ret(Some(Ex::Call(Box::new(callee), args)));
        }
    }
    if let Term::Fall(_) = term {
        term = match blk.succs.first().map(|s| s.0) {
            Some(n) => Term::Fall(n),
            None => Term::Stop,
        };
    }
    let defs: BTreeMap<u8, Ex> = st.modified.iter().filter_map(|r| st.env.get(r).map(|e| (*r, e.clone()))).filter(|(r, e)| *e != Ex::Var(reg_name(*r))).collect();
    let stmts: Vec<(u64, Stmt)> = st
        .stmts
        .into_iter()
        .map(|(a, s)| {
            let s = match s {
                Stmt::Assign(l, r) => Stmt::Assign(dc.g_fix(&l), dc.g_fix(&r)),
                Stmt::Expr(e) => Stmt::Expr(dc.g_fix(&e)),
                c => c,
            };
            (a, s)
        })
        .collect();
    let defs: BTreeMap<u8, Ex> = defs.into_iter().map(|(r, e)| (r, dc.g_fix(&e))).collect();
    let term = match term {
        Term::Ret(Some(e)) => Term::Ret(Some(dc.g_fix(&e))),
        Term::Indirect(e) => Term::Indirect(dc.g_fix(&e)),
        Term::Cond { cond, taken, fall } => Term::Cond { cond: dc.g_fix(&cond), taken, fall },
        t => t,
    };
    BlockOut { stmts, defs, uses: st.uses, term, term_addr }
}

/// Condition expression for a conditional branch.
fn g_condition(dc: &mut Dc, st: &mut St, fm: Fam, mn: &str, ops: &[String]) -> Ex {
    let reg = |k: usize| ops.get(k).and_then(|s| parse_reg(fm, s));
    let cmp = |op: &'static str, a: Ex, b: Ex| Ex::Bin(op, Box::new(a), Box::new(b));
    match fm {
        Fam::A64 | Fam::A32 | Fam::Ppc => {
            if matches!(mn, "cbz" | "cbnz") {
                let v = reg(0).map(|r| dc.g_rd(st, r)).unwrap_or(Ex::Raw("?".into()));
                return cmp(if mn == "cbz" { "==" } else { "!=" }, v, Ex::Num(0));
            }
            if matches!(mn, "tbz" | "tbnz") {
                let v = reg(0).map(|r| dc.g_rd(st, r)).unwrap_or(Ex::Raw("?".into()));
                let n = ops.get(1).and_then(|s| parse_imm(s)).unwrap_or(0);
                return cmp(if mn == "tbz" { "==" } else { "!=" }, bin("&", bin(">>", v, Ex::Num(n)), Ex::Num(1)), Ex::Num(0));
            }
            let c = mn.strip_prefix("b.").or_else(|| mn.strip_prefix('b')).unwrap_or(mn).trim_end_matches(['+', '-']);
            let c = match c { "z" => "eq", "nz" => "ne", "lo" | "cc" => "lo", "nl" => "ge", "ng" => "le", other => other };
            let cc = cc_of(c).or(match c { "nl" => Some(CC::ge), _ => None });
            match cc {
                Some(cc) => cc_expr(cc, &st.flags),
                None => Ex::Raw(format!("/* {mn} */ cond")),
            }
        }
        Fam::Rv | Fam::Mips => {
            // branches compare registers directly
            let a = reg(0).map(|r| dc.g_rd(st, r)).unwrap_or(Ex::Raw("?".into()));
            let b = ops.get(1).and_then(|s| parse_reg(fm, s)).map(|r| dc.g_rd(st, r)).unwrap_or(Ex::Num(0));
            match mn.trim_start_matches("c.") {
                "beq" => cmp("==", a, b),
                "bne" => cmp("!=", a, b),
                "blt" | "bltu" => cmp("<", a, b),
                "bge" | "bgeu" => cmp(">=", a, b),
                "bgt" | "bgtu" => cmp(">", a, b),
                "ble" | "bleu" => cmp("<=", a, b),
                "beqz" => cmp("==", a, Ex::Num(0)),
                "bnez" => cmp("!=", a, Ex::Num(0)),
                "bltz" => cmp("<", a, Ex::Num(0)),
                "bgez" => cmp(">=", a, Ex::Num(0)),
                "blez" => cmp("<=", a, Ex::Num(0)),
                "bgtz" => cmp(">", a, Ex::Num(0)),
                _ => Ex::Raw(format!("/* {mn} */ cond")),
            }
        }
    }
}

fn g_data(dc: &mut Dc, st: &mut St, fm: Fam, addr: u64, mn: &str, ops: &[String], _fp_idx: u8) {
    let o = |k: usize| ops.get(k).map(|s| s.as_str()).unwrap_or("");
    let reg = |k: usize| parse_reg(fm, o(k));
    let base_mn = mn.trim_end_matches(".w").trim_end_matches(".n");
    // shifted last operand: ["x1", "lsl #3"]
    let shifted = |dc: &mut Dc, st: &mut St, k: usize| -> Ex {
        match ops.get(k + 1) {
            Some(s) if s.starts_with("lsl") || s.starts_with("lsr") || s.starts_with("asr") || s.starts_with("sxt") || s.starts_with("uxt") => dc.g_val(st, o(k), Some(s)),
            _ => dc.g_val(st, o(k), None),
        }
    };
    let set = |dc: &mut Dc, st: &mut St, k: usize, v: Ex| {
        if let Some(r) = parse_reg(fm, ops.get(k).map(|s| s.as_str()).unwrap_or("")) {
            dc.g_wr(st, r, v, addr);
        }
    };
    // ARM condition suffix on data ops (movne, addeq …): only `mov` family is lifted conditionally
    if fm == Fam::A32 {
        for cc in ["eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"] {
            if let Some(b) = base_mn.strip_suffix(cc) {
                if matches!(b, "mov" | "mvn" | "add" | "sub" | "and" | "orr" | "eor" | "ldr" | "str") && !(b == "mov" && cc == "ne" && false) {
                    let cond = cc_expr(cc_of(cc).unwrap(), &st.flags);
                    let old = reg(0).map(|r| dc.g_rd(st, r)).unwrap_or(Ex::Raw("?".into()));
                    let newv = match b {
                        "mov" => dc.g_val(st, o(1), None),
                        "mvn" => Ex::Un("~", Box::new(dc.g_val(st, o(1), None))),
                        "add" => bin("+", dc.g_val(st, o(1), None), dc.g_val(st, o(2), None)),
                        "sub" => bin("-", dc.g_val(st, o(1), None), dc.g_val(st, o(2), None)),
                        "and" => bin("&", dc.g_val(st, o(1), None), dc.g_val(st, o(2), None)),
                        "orr" => bin("|", dc.g_val(st, o(1), None), dc.g_val(st, o(2), None)),
                        "eor" => bin("^", dc.g_val(st, o(1), None), dc.g_val(st, o(2), None)),
                        _ => {
                            st.stmts.push((addr, Stmt::Comment(format!("{mn} {}", ops.join(", ")))));
                            return;
                        }
                    };
                    set(dc, st, 0, Ex::Tern(Box::new(cond), Box::new(newv), Box::new(old)));
                    return;
                }
            }
        }
    }
    // three-operand arithmetic: dest, a, b (two-operand forms reuse dest as a)
    let arith = |dc: &mut Dc, st: &mut St, op: &'static str, flags_set: bool| {
        let (a, b) = if ops.len() >= 3 {
            (dc.g_val(st, o(1), None), shifted(dc, st, 2))
        } else {
            (dc.g_val(st, o(0), None), shifted(dc, st, 1))
        };
        let v = bin(op, a.clone(), b.clone());
        if flags_set {
            st.flags = if op == "-" { Flags::Cmp(a, b) } else { Flags::Op(v.clone()) };
        }
        set(dc, st, 0, v);
    };
    match (fm, base_mn) {
        // ---------------------------------------------------------- moves
        (_, "nop" | "pacibsp" | "paciasp" | "autiasp" | "autibsp" | "bti" | "hint" | "c.nop" | "dmb" | "dsb" | "isb" | "fence" | "sync" | "isync") => {}
        (Fam::A64, "mov" | "movz" | "fmov") | (Fam::A32, "mov" | "movw") | (Fam::Rv, "mv" | "c.mv" | "li" | "c.li") | (Fam::Mips, "move" | "li") | (Fam::Ppc, "mr" | "li" | "lis") => {
            let mut v = dc.g_val(st, o(1), None);
            if base_mn == "lis" {
                v = bin("<<", v, Ex::Num(16));
            }
            if base_mn == "movz" {
                if let Some(sh) = ops.get(2).and_then(|s| s.split_whitespace().last()).and_then(parse_imm) {
                    v = bin("<<", v, Ex::Num(sh));
                }
            }
            set(dc, st, 0, v);
        }
        // Common scalar and NEON floating-point arithmetic.  Vector registers
        // are represented as 128-bit values, so preserving the operation as a
        // binary expression is more useful than hiding it behind a comment.
        (Fam::A64, "fadd" | "fsub" | "fmul" | "fdiv") => {
            let op = match base_mn { "fadd" => "+", "fsub" => "-", "fmul" => "*", _ => "/" };
            arith(dc, st, op, false);
        }
        (Fam::A64, "fneg" | "fabs" | "fsqrt") => {
            let a = dc.g_val(st, o(1), None);
            let v = match base_mn {
                "fneg" => Ex::Un("-", Box::new(a)),
                "fabs" => Ex::Call(Box::new(var("fabs")), vec![a]),
                _ => Ex::Call(Box::new(var("sqrt")), vec![a]),
            };
            set(dc, st, 0, v);
        }
        (Fam::A64, "scvtf" | "ucvtf" | "fcvtzs" | "fcvtzu" | "fcvt") => {
            let a = dc.g_val(st, o(1), None);
            let ty = if base_mn == "scvtf" { "double" } else if base_mn == "ucvtf" { "double" } else { "int64_t" };
            set(dc, st, 0, Ex::Cast(ty, Box::new(a)));
        }
        (Fam::A64, "fcmp" | "fcmpe") if ops.len() >= 2 => {
            let a = dc.g_val(st, o(0), None);
            let b = dc.g_val(st, o(1), None);
            st.flags = Flags::Cmp(a, b);
        }
        (Fam::A64, "fcsel") if ops.len() >= 4 => {
            let c = ops.last().and_then(|s| cc_of(s)).unwrap_or(CC::e);
            let cond = cc_expr(c, &st.flags);
            let yes = dc.g_val(st, o(1), None);
            let no = dc.g_val(st, o(2), None);
            set(dc, st, 0, Ex::Tern(Box::new(cond), Box::new(yes), Box::new(no)));
        }
        (Fam::A64, "csel" | "csinc" | "csinv" | "csneg") if ops.len() >= 4 => {
            let c = ops.last().and_then(|s| cc_of(s)).unwrap_or(CC::e);
            let cond = cc_expr(c, &st.flags);
            let yes = dc.g_val(st, o(1), None);
            let no0 = dc.g_val(st, o(2), None);
            let no = match base_mn {
                "csinc" => bin("+", no0, Ex::Num(1)),
                "csinv" => Ex::Un("~", Box::new(no0)),
                "csneg" => Ex::Un("-", Box::new(no0)),
                _ => no0,
            };
            set(dc, st, 0, Ex::Tern(Box::new(cond), Box::new(yes), Box::new(no)));
        }
        (Fam::A64, "cset" | "csetm") if ops.len() >= 2 => {
            let c = ops.last().and_then(|s| cc_of(s)).unwrap_or(CC::e);
            let cond = cc_expr(c, &st.flags);
            let no = if base_mn == "csetm" { -1 } else { 0 };
            set(dc, st, 0, Ex::Tern(Box::new(cond), Box::new(Ex::Num(1)), Box::new(Ex::Num(no))));
        }
        // AArch64 bitfield aliases are common in compiler-generated masking,
        // packed-struct access, and sign-extension sequences.  Render the
        // ordinary non-wrapping forms as C-like shifts and masks instead of
        // hiding them behind an intrinsic call.
        (Fam::A64, "ubfx" | "sbfx" | "ubfm" | "sbfm") if ops.len() >= 4 => {
            let src = dc.g_val(st, o(1), None);
            let lsb = parse_imm(o(2)).unwrap_or(0).clamp(0, 63) as u32;
            let end = parse_imm(o(3)).unwrap_or(63).clamp(0, 63) as u32;
            let width = if matches!(base_mn, "ubfx" | "sbfx") { end.min(64) } else if end >= lsb { end - lsb + 1 } else { 0 };
            if width > 0 && lsb + width <= 64 {
                let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
                let mut v = bin("&", bin(">>", src, Ex::Num(lsb as i64)), Ex::Num(mask as i64));
                if matches!(base_mn, "sbfx" | "sbfm") && width < 64 {
                    let shift = 64 - width;
                    v = bin(">>", bin("<<", v, Ex::Num(shift as i64)), Ex::Num(shift as i64));
                }
                set(dc, st, 0, v);
            } else {
                st.stmts.push((addr, Stmt::Comment(format!("{mn} {}", ops.join(", ")))));
            }
        }
        (Fam::A64, "bfi" | "bfxil" | "bfm") if ops.len() >= 4 => {
            let dst = dc.g_val(st, o(0), None);
            let src = dc.g_val(st, o(1), None);
            let lsb = parse_imm(o(2)).unwrap_or(0).clamp(0, 63) as u32;
            let width = parse_imm(o(3)).unwrap_or(0).clamp(0, 64) as u32;
            if width > 0 && lsb + width <= 64 {
                let mask = if width == 64 { u64::MAX } else { ((1u64 << width) - 1) << lsb };
                let low_mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
                let inserted = bin("<<", bin("&", src, Ex::Num(low_mask as i64)), Ex::Num(lsb as i64));
                set(dc, st, 0, bin("|", bin("&", dst, Ex::Num(!(mask) as i64)), bin("&", inserted, Ex::Num(mask as i64))));
            } else {
                st.stmts.push((addr, Stmt::Comment(format!("{mn} {}", ops.join(", ")))));
            }
        }
        (Fam::A64, "extr") if ops.len() >= 4 => {
            let left = dc.g_val(st, o(1), None);
            let right = dc.g_val(st, o(2), None);
            let shift = parse_imm(o(3)).unwrap_or(0).clamp(0, 63) as u32;
            let width = reg(0).map(|r| if r.w <= 4 { 32 } else { 64 }).unwrap_or(64);
            if shift == 0 {
                set(dc, st, 0, right);
            } else if shift < width {
                set(dc, st, 0, bin("|", bin("<<", left, Ex::Num((width - shift) as i64)), bin(">>", right, Ex::Num(shift as i64))));
            } else {
                st.stmts.push((addr, Stmt::Comment(format!("{mn} {}", ops.join(", ")))));
            }
        }
        (Fam::A64, "ror") if ops.len() >= 3 => {
            let value = dc.g_val(st, o(1), None);
            let shift = parse_imm(o(2)).unwrap_or(0).clamp(0, 63) as u32;
            let width = reg(0).map(|r| if r.w <= 4 { 32 } else { 64 }).unwrap_or(64);
            if shift == 0 || shift >= width {
                set(dc, st, 0, value);
            } else {
                set(dc, st, 0, bin("|", bin(">>", value.clone(), Ex::Num(shift as i64)), bin("<<", value, Ex::Num((width - shift) as i64))));
            }
        }
        (Fam::A64, "fmla" | "fmls") if ops.len() >= 3 => {
            let a = dc.g_val(st, o(1), None);
            let b = dc.g_val(st, o(2), None);
            let c = dc.g_val(st, o(0), None);
            let product = bin("*", b, c);
            set(dc, st, 0, if base_mn == "fmla" { bin("+", a, product) } else { bin("-", a, product) });
        }
        (Fam::A64, "movk") => {
            let old = reg(0).map(|r| dc.g_rd_raw(st, r)).unwrap_or(Ex::Num(0));
            let imm = o(1).trim_start_matches('#');
            let sh = ops.get(2).and_then(|s| s.split_whitespace().last()).and_then(parse_imm).unwrap_or(0);
            let v = parse_imm(imm).unwrap_or(0);
            let r = bin("|", bin("&", old, Ex::Num(!(0xFFFFi64 << sh))), Ex::Num(v << sh));
            set(dc, st, 0, r);
        }
        (Fam::A64, "movn") => {
            let v = parse_imm(o(1)).unwrap_or(0);
            let sh = ops.get(2).and_then(|s| s.split_whitespace().last()).and_then(parse_imm).unwrap_or(0);
            set(dc, st, 0, Ex::Num(!(v << sh)));
        }
        (Fam::A64 | Fam::A32, "mvn") | (Fam::Rv | Fam::Mips, "not") => {
            let v = dc.g_val(st, o(1), None);
            set(dc, st, 0, Ex::Un("~", Box::new(v)));
        }
        (Fam::A64, "adrp" | "adr") | (Fam::A32, "adr") => {
            if let Some(n) = parse_imm(o(1)) {
                set(dc, st, 0, Ex::Num(n));
            }
        }
        (Fam::Rv, "auipc") => {
            if let Some(n) = parse_imm(o(1)) {
                set(dc, st, 0, Ex::Num(((n << 12) as i64).wrapping_add(addr as i64)));
            }
        }
        (Fam::Rv | Fam::Mips, "lui") => {
            if let Some(n) = parse_imm(o(1)) {
                set(dc, st, 0, Ex::Num(if fm == Fam::Rv { n << 12 } else { n << 16 }));
            }
        }
        // ---------------------------------------------------------- arithmetic
        (Fam::A64 | Fam::A32, "add") | (Fam::Rv, "add" | "addi" | "addw" | "addiw" | "c.add" | "c.addi") | (Fam::Mips, "add" | "addu" | "addi" | "addiu" | "daddu" | "daddiu") | (Fam::Ppc, "add" | "addi" | "addis") => {
            if fm == Fam::Ppc && base_mn == "addis" {
                let a = dc.g_val(st, o(1), None);
                let b = dc.g_val(st, o(2), None);
                let v = bin("+", a, match b { Ex::Num(n) => Ex::Num(n << 16), x => bin("<<", x, Ex::Num(16)) });
                set(dc, st, 0, v);
            } else {
                arith(dc, st, "+", false)
            }
        }
        (Fam::A64 | Fam::A32, "adds") => arith(dc, st, "+", true),
        (Fam::A64 | Fam::A32, "sub") | (Fam::Rv, "sub" | "subw") | (Fam::Mips, "sub" | "subu" | "dsubu") => arith(dc, st, "-", false),
        (Fam::A64 | Fam::A32, "subs") => arith(dc, st, "-", true),
        (Fam::Ppc, "subf") => {
            let a = dc.g_val(st, o(1), None);
            let b = dc.g_val(st, o(2), None);
            set(dc, st, 0, bin("-", b, a));
        }
        (Fam::Ppc, "sub") => arith(dc, st, "-", false),
        (Fam::A32, "rsb") => {
            let a = dc.g_val(st, o(1), None);
            let b = dc.g_val(st, o(2), None);
            set(dc, st, 0, bin("-", b, a));
        }
        (Fam::A64, "neg") | (Fam::Rv, "neg") | (Fam::Mips, "negu") | (Fam::Ppc, "neg") => {
            let v = dc.g_val(st, o(1), None);
            set(dc, st, 0, bin("-", Ex::Num(0), v));
        }
        (Fam::A64 | Fam::A32 | Fam::Mips | Fam::Rv, "mul" | "mulw" | "dmul") | (Fam::Ppc, "mullw" | "mulld" | "mulli") => arith(dc, st, "*", false),
        (Fam::Rv, "mulh" | "mulhu" | "mulhsu") if ops.len() >= 3 => {
            let a = dc.g_val(st, o(1), None);
            let b = dc.g_val(st, o(2), None);
            let helper = match base_mn {
                "mulhu" => "__riscv_mulhu",
                "mulhsu" => "__riscv_mulhsu",
                _ => "__riscv_mulh",
            };
            set(dc, st, 0, Ex::Call(Box::new(var(helper)), vec![a, b]));
        }
        (Fam::Ppc, "mulhw" | "mulhwu" | "mulhd" | "mulhdu") if ops.len() >= 3 => {
            let a = dc.g_val(st, o(1), None);
            let b = dc.g_val(st, o(2), None);
            let helper = if base_mn.ends_with('u') { "__ppc_mulhiu" } else { "__ppc_mulhi" };
            set(dc, st, 0, Ex::Call(Box::new(var(helper)), vec![a, b]));
        }
        (Fam::A32, "umull" | "smull" | "umlal" | "smlal") if ops.len() >= 4 => {
            let a = dc.g_val(st, o(2), None);
            let b = dc.g_val(st, o(3), None);
            let wide = Ex::Call(Box::new(var(if base_mn.starts_with('s') { "__smull" } else { "__umull" })), vec![a, b]);
            let low = Ex::Call(Box::new(var("__wide_low")), vec![wide.clone()]);
            let high = Ex::Call(Box::new(var("__wide_high")), vec![wide]);
            if matches!(base_mn, "umlal" | "smlal") {
                let old_low = dc.g_val(st, o(0), None);
                let old_high = dc.g_val(st, o(1), None);
                set(dc, st, 0, bin("+", old_low, low));
                set(dc, st, 1, bin("+", old_high, high));
            } else {
                set(dc, st, 0, low);
                set(dc, st, 1, high);
            }
        }
        (Fam::A64, "madd") => {
            let (a, b, c) = (dc.g_val(st, o(1), None), dc.g_val(st, o(2), None), dc.g_val(st, o(3), None));
            set(dc, st, 0, bin("+", bin("*", a, b), c));
        }
        (Fam::A32, "mla") if ops.len() >= 4 => {
            let a = dc.g_val(st, o(1), None);
            let b = dc.g_val(st, o(2), None);
            let c = dc.g_val(st, o(3), None);
            set(dc, st, 0, bin("+", bin("*", a, b), c));
        }
        (Fam::A32, "mls") if ops.len() >= 4 => {
            let a = dc.g_val(st, o(1), None);
            let b = dc.g_val(st, o(2), None);
            let c = dc.g_val(st, o(3), None);
            set(dc, st, 0, bin("-", c, bin("*", a, b)));
        }
        (Fam::A64, "msub") => {
            let (a, b, c) = (dc.g_val(st, o(1), None), dc.g_val(st, o(2), None), dc.g_val(st, o(3), None));
            set(dc, st, 0, bin("-", c, bin("*", a, b)));
        }
        (Fam::A64, "smull" | "umull") => arith(dc, st, "*", false),
        (Fam::Mips, "mult" | "multu" | "dmult" | "dmultu") if ops.len() >= 2 => {
            let a = dc.g_val(st, o(0), None);
            let b = dc.g_val(st, o(1), None);
            let wide = Ex::Call(Box::new(var(if base_mn.ends_with('u') { "__mips_multu" } else { "__mips_mult" })), vec![a, b]);
            st.env.insert(MIPS_LO, Ex::Call(Box::new(var("__wide_low")), vec![wide.clone()]));
            st.env.insert(MIPS_HI, Ex::Call(Box::new(var("__wide_high")), vec![wide]));
        }
        (Fam::Mips, "div" | "divu" | "ddiv" | "ddivu") if ops.len() >= 2 => {
            let a = dc.g_val(st, o(0), None);
            let b = dc.g_val(st, o(1), None);
            let signed = !base_mn.ends_with('u');
            let q = Ex::Call(Box::new(var(if signed { "__mips_div" } else { "__mips_divu" })), vec![a.clone(), b.clone()]);
            let r = Ex::Call(Box::new(var(if signed { "__mips_rem" } else { "__mips_remu" })), vec![a, b]);
            st.env.insert(MIPS_LO, q);
            st.env.insert(MIPS_HI, r);
        }
        (Fam::Mips, "mflo" | "mfhi") if !ops.is_empty() => {
            let v = st.env.get(if base_mn == "mflo" { &MIPS_LO } else { &MIPS_HI }).cloned()
                .unwrap_or_else(|| Ex::Call(Box::new(var(if base_mn == "mflo" { "__mips_lo" } else { "__mips_hi" })), vec![]));
            set(dc, st, 0, v);
        }
        (Fam::A64 | Fam::A32, "sdiv" | "udiv") | (Fam::Rv, "div" | "divu" | "divw" | "divuw") | (Fam::Ppc, "divw" | "divwu" | "divd") => arith(dc, st, "/", false),
        (Fam::Rv, "rem" | "remu" | "remw" | "remuw") => arith(dc, st, "%", false),
        (Fam::A64 | Fam::A32, "and") | (Fam::Rv | Fam::Mips, "and" | "andi") | (Fam::Ppc, "and" | "andi." | "andis.") => arith(dc, st, "&", false),
        (Fam::A64 | Fam::A32, "ands") => arith(dc, st, "&", true),
        (Fam::A64 | Fam::A32, "orr") | (Fam::Rv | Fam::Mips, "or" | "ori") | (Fam::Ppc, "or" | "ori" | "oris") => {
            if fm == Fam::Ppc && base_mn == "oris" {
                let a = dc.g_val(st, o(1), None);
                let b = dc.g_val(st, o(2), None);
                set(dc, st, 0, bin("|", a, match b { Ex::Num(n) => Ex::Num(n << 16), x => x }));
            } else {
                arith(dc, st, "|", false)
            }
        }
        (Fam::A64 | Fam::A32, "eor") | (Fam::Rv | Fam::Mips, "xor" | "xori") | (Fam::Ppc, "xor" | "xori") => arith(dc, st, "^", false),
        (Fam::A64 | Fam::A32, "bic") => {
            let a = dc.g_val(st, o(1), None);
            let b = shifted(dc, st, 2);
            set(dc, st, 0, bin("&", a, Ex::Un("~", Box::new(b))));
        }
        (Fam::A64, "lsl" | "lslv") | (Fam::A32, "lsl") | (Fam::Rv, "sll" | "slli" | "sllw" | "slliw") | (Fam::Mips, "sll" | "sllv" | "dsll") | (Fam::Ppc, "slw" | "slwi" | "sld") => arith(dc, st, "<<", false),
        (Fam::A64, "lsr" | "lsrv") | (Fam::A32, "lsr") | (Fam::Rv, "srl" | "srli" | "srlw" | "srliw") | (Fam::Mips, "srl" | "srlv" | "dsrl") | (Fam::Ppc, "srw" | "srwi" | "srd") => arith(dc, st, ">>", false),
        (Fam::A64, "asr" | "asrv") | (Fam::A32, "asr") | (Fam::Rv, "sra" | "srai" | "sraw" | "sraiw") | (Fam::Mips, "sra" | "srav") | (Fam::Ppc, "sraw" | "srawi" | "srad") => {
            let (a, b) = if ops.len() >= 3 { (dc.g_val(st, o(1), None), dc.g_val(st, o(2), None)) } else { (dc.g_val(st, o(0), None), dc.g_val(st, o(1), None)) };
            set(dc, st, 0, bin(">>", Ex::Cast("int64_t", Box::new(a)), b));
        }
        (Fam::A64, "sxtw" | "sxth" | "sxtb") | (Fam::A32, "sxtb" | "sxth") | (Fam::Rv, "sext.w" | "sext.b" | "sext.h") | (Fam::Ppc, "extsw" | "extsh" | "extsb") => {
            let v = dc.g_val(st, o(1), None);
            let t = if base_mn.ends_with('b') { "int8_t" } else if base_mn.ends_with('h') { "int16_t" } else { "int32_t" };
            set(dc, st, 0, Ex::Cast(t, Box::new(v)));
        }
        (Fam::A64, "uxtw" | "uxth" | "uxtb") | (Fam::A32, "uxtb" | "uxth") | (Fam::Rv, "zext.b" | "zext.h" | "zext.w") => {
            let v = dc.g_val(st, o(1), None);
            let t = if base_mn.ends_with('b') { "uint8_t" } else if base_mn.ends_with('h') { "uint16_t" } else { "uint32_t" };
            set(dc, st, 0, Ex::Cast(t, Box::new(v)));
        }
        (Fam::Rv | Fam::Mips, "slt" | "slti" | "sltu" | "sltiu") => {
            let (a, b) = (dc.g_val(st, o(1), None), dc.g_val(st, o(2), None));
            set(dc, st, 0, Ex::Bin("<", Box::new(a), Box::new(b)));
        }
        (Fam::Rv, "seqz") => {
            let a = dc.g_val(st, o(1), None);
            set(dc, st, 0, Ex::Bin("==", Box::new(a), Box::new(Ex::Num(0))));
        }
        (Fam::Rv, "snez") => {
            let a = dc.g_val(st, o(1), None);
            set(dc, st, 0, Ex::Bin("!=", Box::new(a), Box::new(Ex::Num(0))));
        }
        // ---------------------------------------------------------- flags
        (Fam::A64 | Fam::A32, "cmp") => {
            let (a, b) = (dc.g_val(st, o(0), None), shifted(dc, st, 1));
            st.flags = Flags::Cmp(a, b);
        }
        (Fam::A64 | Fam::A32, "cmn") => {
            let (a, b) = (dc.g_val(st, o(0), None), dc.g_val(st, o(1), None));
            st.flags = Flags::Op(bin("+", a, b));
        }
        (Fam::A64 | Fam::A32, "tst") => {
            let (a, b) = (dc.g_val(st, o(0), None), dc.g_val(st, o(1), None));
            st.flags = Flags::Op(if a == b { a } else { bin("&", a, b) });
        }
        (Fam::Ppc, "cmpwi" | "cmpw" | "cmplwi" | "cmplw" | "cmpdi" | "cmpd" | "cmpldi" | "cmpld") => {
            let n = ops.len();
            if n >= 2 {
                let (a, b) = (dc.g_val(st, &ops[n - 2], None), dc.g_val(st, &ops[n - 1], None));
                st.flags = Flags::Cmp(a, b);
            }
        }
        (Fam::A64, "csel" | "csinc" | "csinv" | "csneg" | "cinc" | "cset" | "csetm" | "cneg") => {
            let c = ops.last().and_then(|s| cc_of(s)).unwrap_or(CC::e);
            let cond = cc_expr(c, &st.flags);
            let v = match base_mn {
                "cset" => cond,
                "csetm" => Ex::Tern(Box::new(cond), Box::new(Ex::Num(-1)), Box::new(Ex::Num(0))),
                "csel" => Ex::Tern(Box::new(cond), Box::new(dc.g_val(st, o(1), None)), Box::new(dc.g_val(st, o(2), None))),
                "csinc" => Ex::Tern(Box::new(cond), Box::new(dc.g_val(st, o(1), None)), Box::new(bin("+", dc.g_val(st, o(2), None), Ex::Num(1)))),
                "cinc" => {
                    let a = dc.g_val(st, o(1), None);
                    Ex::Tern(Box::new(cond), Box::new(bin("+", a.clone(), Ex::Num(1))), Box::new(a))
                }
                "cneg" => {
                    let a = dc.g_val(st, o(1), None);
                    Ex::Tern(Box::new(cond), Box::new(bin("-", Ex::Num(0), a.clone())), Box::new(a))
                }
                "csinv" => Ex::Tern(Box::new(cond), Box::new(dc.g_val(st, o(1), None)), Box::new(Ex::Un("~", Box::new(dc.g_val(st, o(2), None))))),
                _ => Ex::Tern(Box::new(cond), Box::new(dc.g_val(st, o(1), None)), Box::new(Ex::Un("-", Box::new(dc.g_val(st, o(2), None))))),
            };
            set(dc, st, 0, v);
        }
        // ---------------------------------------------------------- memory
        (Fam::A64, "ldp" | "stp") | (Fam::A32, "ldrd" | "strd") => {
            let is_load = base_mn.starts_with("ld");
            let (r1, r2) = (reg(0), reg(1));
            if let Some((m, _)) = parse_mem(fm, ops, 2) {
                let size = r1.map(|r| r.w).unwrap_or(8);
                let m2 = M { disp: m.disp + size as i64, pre: false, post: None, ..m.clone() };
                if is_load {
                    let m1 = M { pre: false, post: None, ..m.clone() };
                    dc.g_load(st, r1, &m1, size, false, addr);
                    dc.g_load(st, r2, &m2, size, false, addr);
                    dc.g_writeback(st, &m, addr);
                } else {
                    let v1 = r1.map(|r| dc.g_rd(st, r)).unwrap_or(Ex::Num(0));
                    let v2 = r2.map(|r| dc.g_rd(st, r)).unwrap_or(Ex::Num(0));
                    let m1 = M { pre: false, post: None, ..m.clone() };
                    dc.g_store(st, v1, r1, &m1, size, addr);
                    dc.g_store(st, v2, r2, &m2, size, addr);
                    dc.g_writeback(st, &m, addr);
                }
            }
        }
        (Fam::A64, m) if m.starts_with("ldr") || m.starts_with("ldur") => {
            let rd = reg(0);
            if let Some((mm, _)) = parse_mem(fm, ops, 1) {
                let (size, signed) = mem_size_of(fm, m, rd);
                dc.g_load(st, rd, &mm, size, signed, addr);
            } else if let Some(n) = parse_imm(o(1)) {
                // literal load
                let v = Ex::Deref(Box::new(Ex::Num(n)), rd.map(|r| r.w).unwrap_or(8));
                if let Some(r) = rd { dc.g_wr(st, r, v, addr); }
            }
        }
        (Fam::A64, m) if m.starts_with("str") || m.starts_with("stur") => {
            let rs = reg(0);
            if let Some((mm, _)) = parse_mem(fm, ops, 1) {
                let (size, _) = mem_size_of(fm, m, rs);
                let v = rs.map(|r| dc.g_rd(st, r)).unwrap_or(Ex::Num(0));
                dc.g_store(st, v, rs, &mm, size, addr);
            }
        }
        (Fam::A32, m) if m.starts_with("ldr") || m.starts_with("str") => {
            let r0 = reg(0);
            if let Some((mm, _)) = parse_mem(fm, ops, 1) {
                let (size, signed) = (if m.contains('b') { 1 } else if m.contains('h') { 2 } else { 4 }, m.contains("sb") || m.contains("sh"));
                if m.starts_with("ldr") {
                    dc.g_load(st, r0, &mm, size, signed, addr);
                } else {
                    let v = r0.map(|r| dc.g_rd(st, r)).unwrap_or(Ex::Num(0));
                    dc.g_store(st, v, r0, &mm, size, addr);
                }
            } else if let Some(n) = parse_imm(o(1)) {
                if let Some(r) = r0 { dc.g_wr(st, r, Ex::Deref(Box::new(Ex::Num(n)), 4), addr); }
            }
        }
        (Fam::Rv | Fam::Mips | Fam::Ppc, m) if matches!(m.trim_start_matches("c."), "lw" | "ld" | "lb" | "lbu" | "lh" | "lhu" | "lwu" | "lwz" | "lbz" | "lhz" | "lha" | "lwa" | "lwzu" | "lbzu" | "ldu" | "lwsp" | "ldsp" | "ll" | "lwl" | "lwr") => {
            let rd = reg(0);
            if let Some((mm, _)) = parse_mem(fm, ops, 1) {
                let key = m.trim_start_matches("c.");
                let (size, signed) = mem_size_of(fm, key, rd);
                let signed = signed || matches!(key, "lb" | "lh" | "lw" | "lha" | "lwa") && fm != Fam::Ppc || key == "lha";
                dc.g_load(st, rd, &mm, size, signed && !key.ends_with('u'), addr);
            }
        }
        (Fam::Rv | Fam::Mips | Fam::Ppc, m) if matches!(m.trim_start_matches("c."), "sw" | "sd" | "sb" | "sh" | "stw" | "stb" | "sth" | "std" | "stwu" | "stdu" | "stbu" | "swsp" | "sdsp" | "sc") => {
            let rs = reg(0);
            if let Some((mm, _)) = parse_mem(fm, ops, 1) {
                let (size, _) = mem_size_of(fm, m.trim_start_matches("c."), rs);
                let v = rs.map(|r| dc.g_rd(st, r)).unwrap_or(Ex::Num(0));
                dc.g_store(st, v, rs, &mm, size, addr);
            }
        }
        (Fam::A32, "push" | "pop" | "push.w" | "pop.w") => {
            // callee-saved register save / restore: tracked through sp_delta
        }
        // ---------------------------------------------------------- everything else stays visible
        _ => {
            let name = format!("__{}", mn.replace('.', "_"));
            let writes = reg(0).is_some() && !mn.starts_with("st") && !mn.starts_with('b') && !matches!(mn, "cmp" | "tst" | "cmn");
            if writes {
                let args: Vec<Ex> = (1..ops.len()).map(|k| dc.g_val(st, o(k), None)).collect();
                let call = Ex::Call(Box::new(var(&name)), args);
                set(dc, st, 0, call);
            } else {
                st.stmts.push((addr, Stmt::Comment(format!("{mn} {}", ops.join(", ")).trim().to_string())));
            }
        }
    }
}
