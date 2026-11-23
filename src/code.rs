//! Turns instructions into coloured tokens (IDA-style Intel syntax: hex with an `h` suffix,
//! names instead of addresses).

use crate::analysis::NameKind;
use crate::loader::Binary;
use crate::theme::Palette;
use eframe::egui::Color32;
use iced_x86::{
    Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind, Instruction, IntelFormatter, SymbolResolver,
    SymbolResult,
};
use std::collections::HashMap;
use std::sync::Arc;

pub type NameTable = Arc<HashMap<u64, (String, NameKind)>>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tok {
    Mnemonic,
    Register,
    Number,
    Keyword,
    Punct,
    Name(NameKind),
    Plain,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub text: String,
    pub kind: Tok,
    /// Address a name token refers to.
    pub target: Option<u64>,
}

impl Token {
    pub fn color(&self, p: &Palette) -> Color32 {
        match self.kind {
            Tok::Mnemonic => p.mnemonic,
            Tok::Register => p.register,
            Tok::Number => p.number,
            Tok::Keyword => p.keyword,
            Tok::Punct => p.punct,
            Tok::Plain => p.text,
            Tok::Name(k) => name_color(k, p),
        }
    }
}

pub fn name_color(k: NameKind, p: &Palette) -> Color32 {
    match k {
        NameKind::Function => p.func_name,
        NameKind::Import => p.import_name,
        NameKind::Label => p.label_name,
        NameKind::String => p.data_name,
        NameKind::Data => p.data_name,
    }
}

struct Resolver {
    names: NameTable,
}

impl SymbolResolver for Resolver {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult<'_>> {
        self.names
            .get(&address)
            .map(|(n, _)| SymbolResult::with_str_kind(address, n.as_str(), FormatterTextKind::Label))
    }
}

struct Collect<'a> {
    toks: Vec<Token>,
    names: &'a NameTable,
}

impl FormatterOutput for Collect<'_> {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let k = match kind {
            FormatterTextKind::Mnemonic | FormatterTextKind::Prefix => Tok::Mnemonic,
            FormatterTextKind::Register => Tok::Register,
            FormatterTextKind::Number => Tok::Number,
            FormatterTextKind::Keyword | FormatterTextKind::Directive | FormatterTextKind::Decorator => Tok::Keyword,
            FormatterTextKind::Punctuation | FormatterTextKind::Operator => Tok::Punct,
            _ => Tok::Plain,
        };
        self.toks.push(Token { text: text.to_string(), kind: k, target: None });
    }
    fn write_symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _symbol: &SymbolResult<'_>,
    ) {
        if let Some((n, k)) = self.names.get(&address) {
            self.toks.push(Token { text: n.clone(), kind: Tok::Name(*k), target: Some(address) });
        }
    }
}

pub struct CodeFormatter {
    fmt: IntelFormatter,
    names: NameTable,
    /// Functions that keep a frame pointer: (start, end), sorted. Inside them `[rbp-8]` is shown as `[rbp+var_8]`.
    frames: Arc<Vec<(u64, u64)>>,
    /// The person's own variable names, "func_hex:var_8" -> name.
    vars: Arc<HashMap<String, String>>,
}

/// True when the function at `start` begins with `push rbp; mov rbp, rsp` (optionally after `endbr64`).
pub fn has_frame_pointer(bin: &Binary, start: u64) -> bool {
    if !bin.arch.is_x86() || bin.bitness() < 32 {
        return false;
    }
    let b = bin.read(start, 8);
    let b = if b.starts_with(&[0xF3, 0x0F, 0x1E, 0xFA]) { &b[4..] } else { &b[..] };
    b.starts_with(&[0x55, 0x48, 0x89, 0xE5]) || b.starts_with(&[0x55, 0x89, 0xE5]) || b.starts_with(&[0x55, 0x8B, 0xEC]) || b.starts_with(&[0x55, 0x48, 0x8B, 0xEC])
}

impl CodeFormatter {
    pub fn new(names: NameTable) -> Self {
        let mut fmt = IntelFormatter::with_options(Some(Box::new(Resolver { names: names.clone() })), None);
        let o = fmt.options_mut();
        o.set_hex_suffix("h");
        o.set_hex_prefix("");
        o.set_uppercase_hex(true);
        o.set_space_after_operand_separator(true);
        o.set_first_operand_char_index(8);
        o.set_show_branch_size(true);
        o.set_rip_relative_addresses(false);
        Self { fmt, names, frames: Arc::new(vec![]), vars: Arc::new(HashMap::new()) }
    }

    /// Plain text of the instruction at `addr`.
    pub fn clone_names_text(&self, bin: &Binary, addr: u64) -> String {
        let mut f = CodeFormatter::new(self.names.clone());
        f.frames = self.frames.clone();
        f.vars = self.vars.clone();
        f.format(bin, addr).map(|(_, t)| t.iter().map(|x| x.text.as_str()).collect::<String>()).unwrap_or_default()
    }

    pub fn set_frames(&mut self, frames: Vec<(u64, u64)>, vars: HashMap<String, String>) {
        self.frames = Arc::new(frames);
        self.vars = Arc::new(vars);
    }

    pub fn names(&self) -> &NameTable {
        &self.names
    }

    pub fn format(&mut self, bin: &Binary, addr: u64) -> Option<((), Vec<Token>)> {
        if !bin.arch.is_x86() {
            let a = crate::multiarch::one(bin, addr)?;
            let fused = crate::multiarch::decode_info(bin, addr).filter(|i| i.len > 4 && i.flow == crate::analysis::Flow::IndirectJump).map(|i| i.mem);
            let names = self.names.clone();
            return Some(((), crate::multiarch::tokens(bin, &a, &names, fused)));
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
        let names = self.names.clone();
        let mut out = Collect { toks: vec![], names: &names };
        self.fmt.format(&ins, &mut out);
        // Pad mnemonic so operands line up.
        let mut toks = out.toks;
        if let Some(pos) = toks.iter().position(|t| t.kind == Tok::Mnemonic && t.text.trim() != "") {
            let _ = pos;
        }
        self.name_stack_slots(bin, addr, &ins, &mut toks);
        merge_spaces(&mut toks);
        Some(((), toks))
    }
}

impl CodeFormatter {
    /// IDA style stack slots: `[rbp-8]` becomes `[rbp+var_8]`, `[rbp+10h]` becomes `[rbp+arg_0]`.
    fn name_stack_slots(&self, bin: &Binary, addr: u64, ins: &Instruction, toks: &mut Vec<Token>) {
        use iced_x86::{Register, OpKind};
        let Some(i) = self.frames.partition_point(|f| f.0 <= addr).checked_sub(1) else { return };
        let (fstart, fend) = self.frames[i];
        if addr >= fend {
            return;
        }
        let Some(mi) = (0..ins.op_count()).find(|k| ins.op_kind(*k) == OpKind::Memory) else { return };
        let _ = mi;
        let base = ins.memory_base();
        if !matches!(base, Register::RBP | Register::EBP) || ins.memory_index() != Register::None {
            return;
        }
        let d = if bin.bitness() == 64 { ins.memory_displacement64() as i64 } else { ins.memory_displacement32() as i32 as i64 };
        let ret = (bin.bitness() / 8) as i64 * 2;
        let old = if d < 0 {
            format!("var_{:X}", -d)
        } else if d >= ret {
            format!("arg_{:X}", d - ret)
        } else {
            return;
        };
        let Some(r) = toks.iter().position(|t| t.kind == Tok::Register && (t.text == "rbp" || t.text == "ebp")) else { return };
        // After the register come a sign and a number, e.g. "-" "8h".
        if toks.len() < r + 3 || toks[r + 1].kind != Tok::Punct || toks[r + 2].kind != Tok::Number {
            return;
        }
        let name = self.vars.get(&format!("{fstart:X}:{old}")).cloned().unwrap_or(old);
        toks[r + 1] = Token { text: "+".into(), kind: Tok::Punct, target: None };
        toks[r + 2] = Token { text: name, kind: Tok::Name(NameKind::Data), target: None };
    }
}

fn merge_spaces(toks: &mut [Token]) {
    for t in toks.iter_mut() {
        if t.kind == Tok::Plain && t.text.trim().is_empty() {
            t.kind = Tok::Punct;
        }
    }
}

pub fn escape_str(s: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if out.len() >= max {
            out.push('…');
            break;
        }
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out
}

pub fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
}
