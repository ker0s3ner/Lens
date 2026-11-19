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
            XrefKind::Read => "r",
            XrefKind::Write => "w",
            XrefKind::Offset => "o",
            XrefKind::Data => "o",
        }
    }
    pub fn is_code(self) -> bool {
        matches!(self, XrefKind::Call | XrefKind::Jump)
    }
    pub fn label(self) -> &'static str {
        match self {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
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
}

pub struct Settings {
    pub min_string_len: usize,
    pub extra_functions: Vec<u64>,
}

/// Names of functions that never return (from IDA's cfg/noret.cfg, leading underscores and dots stripped).
pub const NORETURN: &[&str] = &[
    "exit", "xexit", "abort", "errx", "err", "std::terminate", "std::unexpected", "terminate",
    "GI__exit", "GI_abort", "GI__assert_fail", "GI__libc_fatal", "invoke_watson",
    "invalid_parameter_noinfo_noreturn", "longjmp", "longjmp_chk", "siglongjmp", "ExitProcess",
    "ExitThread", "assert", "wassert", "assert_fail", "stack_chk_fail", "stack_chk_fail_local",
    "stack_smash_handler", "report_gsfailure", "report_rangecheckfailure", "report_securityfailure",
    "CxxThrowException", "Unwind_Resume", "Unwind_SjLj_Resume", "cxa_throw", "cxa_rethrow",
    "Exit", "exit_group", "pthread_exit", "assert_rtn", "libc_fatal", "fortify_fail", "chk_fail",
];

pub fn is_noreturn_name(name: &str) -> bool {
    let n = name.trim_start_matches(['_', '.']);
    let n = n.split('@').next().unwrap_or(n);
    NORETURN.iter().any(|x| *x == n)
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
    let dec_only = |a: u64| decode_at(bin, a).map(|x| x.1);

    let mut noret_cache: HashMap<u64, bool> = HashMap::new();
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
                        None => match decode_at(bin, a) {
                            Some((_, i)) => {
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
                        Flow::Ret | Flow::Stop | Flow::IndirectJump => break,
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
                    Flow::Ret | Flow::Stop | Flow::IndirectJump => {
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
            while a < s.end() {
                let b = bin.read(a, 8);
                let strong = b.starts_with(&[0xF3, 0x0F, 0x1E, 0xFA]) || b.starts_with(&[0x55, 0x48, 0x89, 0xE5]);
                if (strong || (a % 16 == 0 && looks_like_prologue(b))) && !covered(&insns, a) {
                    push(&mut queue, a);
                    found += 1;
                }
                a += 1;
            }
        }
        if found == 0 {
            break;
        }
    }

    // ---- strings ----
    let mut strings = find_strings(bin, settings.min_string_len.max(1));
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
            let k = if i.is_lea {
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
    // Pointers stored in data that point at functions or strings.
    let w = (bin.bitness() / 8) as usize;
    for s in bin.segments.iter().filter(|s| !s.exec && s.file_offset.is_some()) {
        let mut off = 0usize;
        while off + w <= s.data.len() {
            let c = &s.data[off..off + w];
            let v = if w == 8 { u64::from_le_bytes(c.try_into().unwrap()) } else { u32::from_le_bytes(c.try_into().unwrap()) as u64 };
            if v != 0 && (functions.contains_key(&v) || string_at.contains_key(&v)) {
                let from = s.start + off as u64;
                xrefs_to.entry(v).or_default().push(Xref { from, kind: XrefKind::Data });
                data_size.entry(from).or_insert(w as u8 | 0x80);
            }
            off += w;
        }
    }
    for v in xrefs_to.values_mut() {
        v.sort_by_key(|x| x.from);
        v.dedup_by_key(|x| x.from);
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
    };
    a.lines = build_lines(bin, &a);
    a.stats = format!(
        "{} functions, {} instructions, {} strings, {} imports",
        a.functions.len(),
        a.insns.len(),
        a.strings.len(),
        bin.imports.len()
    );
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
