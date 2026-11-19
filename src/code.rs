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
        Self { fmt, names }
    }

    pub fn names(&self) -> &NameTable {
        &self.names
    }

    pub fn format(&mut self, bin: &Binary, addr: u64) -> Option<(Instruction, Vec<Token>)> {
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
        merge_spaces(&mut toks);
        Some((ins, toks))
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
