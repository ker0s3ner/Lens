//! Pseudo-C decompiler for x86 / x64 functions.
//!
//! Steps: (1) per basic block, run the instructions symbolically so registers become
//! expressions; (2) work out which registers are still needed by later blocks (liveness);
//! (3) turn the jumps into `if` / `else` / `while` / `do … while` where the layout allows and
//! `goto` where it doesn't. The calling convention comes from `detect.rs`.
//!
//! It is a lifter, not a type recoverer: comparisons are printed without signedness and every
//! value is an integer. It is meant to be read next to the listing.

use crate::analysis::{decode_at, display_symbol, is_noreturn_name, Analysis, Flow, Function, NameKind};
use crate::detect::CallConv;
use crate::loader::Binary;
use iced_x86::{ConditionCode, Instruction, Mnemonic, OpKind, Register};

fn is_debug_noreturn(names: &[String], name: &str) -> bool {
    names.iter().any(|candidate| candidate == name)
}
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

mod generic;

// ------------------------------------------------------------------ expressions

#[derive(Clone, PartialEq, Debug)]
pub enum Ex {
    Num(i64),
    Var(String),
    Bin(&'static str, Box<Ex>, Box<Ex>),
    Un(&'static str, Box<Ex>),
    Deref(Box<Ex>, u8),
    Cast(&'static str, Box<Ex>),
    CastOwned(String, Box<Ex>),
    Call(Box<Ex>, Vec<Ex>),
    Tern(Box<Ex>, Box<Ex>, Box<Ex>),
    Raw(String),
}

fn var(s: &str) -> Ex {
    Ex::Var(s.to_string())
}

/// Recover a call prototype from an explicit C-style or normalized function-pointer cast.
fn function_pointer_proto(ty: &str) -> Option<crate::protos::Proto> {
    let t = ty.trim();
    let (ret, params) = if let Some(rest) = t.strip_prefix("fn(") {
        let close = rest.find(") -> ")?;
        let params = &rest[..close];
        let ret = rest[close + 5..].trim_end_matches('*').trim();
        (ret, params)
    } else {
        let (ret, tail) = t.split_once("(*")?;
        let (name, params) = tail.split_once(')')?;
        if !name.trim().is_empty() || !params.trim_start().starts_with('(') { return None; }
        (ret.trim(), params.trim().trim_start_matches('(').trim_end_matches(')'))
    };
    let (mut parsed, _) = crate::protos::parse(&format!("{ret} __indirect({params});"));
    parsed.pop()
}

fn call_return_type(callee: &Ex) -> Option<String> {
    match callee {
        Ex::Var(name) => crate::protos::find(name).map(|p| p.ret).filter(|ret| ret != "void"),
        Ex::Cast(ty, inner) => function_pointer_proto(ty)
            .map(|p| p.ret)
            .or_else(|| if matches!(inner.as_ref(), Ex::Call(_, _)) { Some(ty.trim().to_string()) } else { None })
            .filter(|ret| ret != "void"),
        Ex::CastOwned(ty, inner) => function_pointer_proto(ty)
            .map(|p| p.ret)
            .or_else(|| if matches!(inner.as_ref(), Ex::Call(_, _)) { Some(ty.trim().to_string()) } else { None })
            .filter(|ret| ret != "void"),
        Ex::Call(callee, _) => call_return_type(callee),
        Ex::Bin(op, base, _) if *op == "+" || *op == "-" => call_return_type(base),
        Ex::Tern(_, yes, no) => {
            let yes = call_return_type(yes)?;
            let no = call_return_type(no)?;
            (yes == no).then_some(yes)
        }
        _ => None,
    }
}

fn call_pointee_type(callee: &Ex) -> Option<String> {
    call_return_type(callee).and_then(|ret| ret.strip_suffix('*').map(str::trim).filter(|ty| !ty.is_empty()).map(str::to_string))
}

fn bin(op: &'static str, a: Ex, b: Ex) -> Ex {
    use Ex::*;
    match (op, &a, &b) {
        ("+", Num(x), Num(y)) => Num(x.wrapping_add(*y)),
        ("-", Num(x), Num(y)) => Num(x.wrapping_sub(*y)),
        ("*", Num(x), Num(y)) => Num(x.wrapping_mul(*y)),
        ("/", Num(x), Num(y)) if *y != 0 => Num(x.wrapping_div(*y)),
        ("%", Num(x), Num(y)) if *y != 0 => Num(x.wrapping_rem(*y)),
        ("==", Num(x), Num(y)) => Num((*x == *y) as i64),
        ("!=", Num(x), Num(y)) => Num((*x != *y) as i64),
        ("<", Num(x), Num(y)) => Num((*x < *y) as i64),
        ("<=", Num(x), Num(y)) => Num((*x <= *y) as i64),
        (">", Num(x), Num(y)) => Num((*x > *y) as i64),
        (">=", Num(x), Num(y)) => Num((*x >= *y) as i64),
        ("&&", Num(x), Num(y)) => Num(((*x != 0) && (*y != 0)) as i64),
        ("||", Num(x), Num(y)) => Num(((*x != 0) || (*y != 0)) as i64),
        ("&", Num(x), Num(y)) => Num(x & y),
        ("|", Num(x), Num(y)) => Num(x | y),
        ("^", Num(x), Num(y)) => Num(x ^ y),
        ("<<", Num(x), Num(y)) if *y < 64 => Num(x.wrapping_shl(*y as u32)),
        (">>", Num(x), Num(y)) if *y < 64 => Num(x.wrapping_shr(*y as u32)),
        (">>>", Num(x), Num(y)) if *y < 64 => Num((*x as u64).wrapping_shr(*y as u32) as i64),
        ("+", _, Num(0)) | ("-", _, Num(0)) | ("|", _, Num(0)) | ("^", _, Num(0)) | ("<<", _, Num(0)) | (">>", _, Num(0)) | (">>>", _, Num(0)) => a,
        ("+", Num(0), _) | ("|", Num(0), _) | ("^", Num(0), _) => b,
        ("*", _, Num(1)) | ("/", _, Num(1)) => a,
        ("%", _, Num(1)) => Num(0),
        ("*", Num(1), _) => b,
        ("*", _, Num(0)) | ("*", Num(0), _) | ("&", _, Num(0)) | ("&", Num(0), _) => Num(0),
        ("&", x, Num(-1)) | ("&", Num(-1), x) => x.clone(),
        ("|", _, Num(-1)) | ("|", Num(-1), _) => Num(-1),
        ("&&", _, Num(0)) | ("&&", Num(0), _) => Num(0),
        ("||", _, Num(1)) | ("||", Num(1), _) => Num(1),
        ("&&", x, Num(1)) | ("&&", Num(1), x) => bin("!=", x.clone(), Num(0)),
        ("||", x, Num(0)) | ("||", Num(0), x) => bin("!=", x.clone(), Num(0)),
        ("&&", x, y) if x == y && side_effect_free(x) => bin("!=", x.clone(), Num(0)),
        ("||", x, y) if x == y && side_effect_free(x) => bin("!=", x.clone(), Num(0)),
        ("||", x, Un("!", y)) | ("||", Un("!", y), x) if *x == **y && side_effect_free(x) => Num(1),
        ("&&", x, Un("!", y)) | ("&&", Un("!", y), x) if *x == **y && side_effect_free(x) => Num(0),
        ("^", x, y) if x == y => Num(0),
        ("-", x, y) if x == y => Num(0),
        ("==", x, y) if x == y && matches!(x, Var(_) | Num(_)) => Num(1),
        ("!=", x, y) if x == y && matches!(x, Var(_) | Num(_)) => Num(0),
        ("<=", x, y) | (">=", x, y) if x == y && matches!(x, Var(_) | Num(_)) => Num(1),
        ("<", x, y) | (">", x, y) if x == y && matches!(x, Var(_) | Num(_)) => Num(0),
        ("&", x, y) | ("|", x, y) if x == y => a.clone(),
        ("-", _, Num(c)) => bin("+", a, Num(c.wrapping_neg())),
        ("+", Bin("+", x, y), Num(c)) if matches!(**y, Num(_)) => {
            if let Num(d) = **y {
                bin("+", (**x).clone(), Num(d.wrapping_add(*c)))
            } else {
                unreachable!()
            }
        }
        ("+", Num(_), _) if !matches!(b, Num(_)) => bin("+", b, a),
        ("*", Num(_), _) if !matches!(b, Num(_)) => bin("*", b, a),
        _ => Bin(op, Box::new(a), Box::new(b)),
    }
}

fn un(op: &'static str, a: Ex) -> Ex {
    match (op, &a) {
        ("-", Ex::Num(x)) => Ex::Num(x.wrapping_neg()),
        ("~", Ex::Num(x)) => Ex::Num(!x),
        ("!", Ex::Num(x)) => Ex::Num((*x == 0) as i64),
        ("!", Ex::Un("!", value)) if side_effect_free(value) => bin("!=", (**value).clone(), Ex::Num(0)),
        _ => Ex::Un(op, Box::new(a)),
    }
}

fn side_effect_free(e: &Ex) -> bool {
    match e {
        Ex::Call(..) | Ex::Deref(..) => false,
        Ex::Bin(_, a, b) => side_effect_free(a) && side_effect_free(b),
        Ex::Un(_, a) | Ex::Cast(_, a) | Ex::CastOwned(_, a) => side_effect_free(a),
        Ex::Tern(a, b, c) => side_effect_free(a) && side_effect_free(b) && side_effect_free(c),
        _ => true,
    }
}

fn tern(c: Ex, a: Ex, b: Ex) -> Ex {
    if a == b && side_effect_free(&a) {
        return a;
    }
    if side_effect_free(&c) && a == Ex::Num(1) && b == Ex::Num(0) {
        return bin("!=", c, Ex::Num(0));
    }
    if side_effect_free(&c) && a == Ex::Num(0) && b == Ex::Num(1) {
        return bin("==", c, Ex::Num(0));
    }
    match c {
        Ex::Num(value) => if value != 0 { a } else { b },
        condition => Ex::Tern(Box::new(condition), Box::new(a), Box::new(b)),
    }
}

fn prec(e: &Ex) -> u8 {
    match e {
        Ex::Bin(op, _, _) => match *op {
            "*" | "/" | "%" => 5,
            "+" | "-" => 6,
            "<<" | ">>" | ">>>" => 7,
            "<" | "<=" | ">" | ">=" => 8,
            "==" | "!=" => 9,
            "&" => 10,
            "^" => 11,
            "|" => 12,
            "&&" => 13,
            "||" => 14,
            _ => 15,
        },
        Ex::Tern(..) => 16,
        Ex::Un(..) | Ex::Cast(..) => 3,
        Ex::Deref(..) => 3,
        Ex::Num(n) if *n < 0 => 3,
        _ => 0,
    }
}

fn int_type(size: u8) -> &'static str {
    match size {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        16 => "__m128",
        _ => "uint8_t",
    }
}

struct Fmt<'a> {
    rename: &'a HashMap<String, String>,
    types: &'a HashMap<String, String>,
    structs: &'a [crate::types::StructDef],
}

impl Fmt<'_> {
    fn struct_def(&self, ty: &str) -> Option<&crate::types::StructDef> {
        let mut qualified = ty.trim().to_string();
        for qualifier in ["const ", "volatile ", "restrict "] {
            qualified = qualified.trim_start_matches(qualifier).trim().to_string();
        }
        for qualifier in [" const", " volatile", " restrict"] {
            qualified = qualified.trim_end_matches(qualifier).trim().to_string();
        }
        let mut name = qualified.as_str();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..=self.structs.len() {
            name = name.strip_prefix("struct ").or_else(|| name.strip_prefix("union ")).unwrap_or(name).trim();
            if !seen.insert(name.to_string()) { return None; }
            let def = self.structs.iter().find(|candidate| candidate.name == name && !candidate.is_enum)?;
            if !def.fields.is_empty() { return Some(def); }
            let Some(alias) = def.alias_of.as_deref() else { return Some(def); };
            if alias.starts_with("fn(") { return None; }
            name = alias;
        }
        None
    }

    fn pointer_target(&self, ty: &str) -> Option<String> {
        let mut current = ty.trim().to_string();
        for qualifier in ["const ", "volatile ", "restrict "] {
            current = current.trim_start_matches(qualifier).trim().to_string();
        }
        let mut seen = std::collections::HashSet::new();
        let mut pointer = false;
        for _ in 0..=self.structs.len() {
            for qualifier in [" const", " volatile", " restrict"] {
                current = current.trim_end_matches(qualifier).trim().to_string();
            }
            if let Some(target) = current.strip_suffix('*') {
                pointer = true;
                current = target.trim().to_string();
                let lookup = current.trim_start_matches("struct ").trim_start_matches("union ").trim();
                if !lookup.starts_with("struct ") && !lookup.starts_with("union ") && !self.structs.iter().any(|def| def.name == lookup) {
                    return Some(current);
                }
                continue;
            }
            if !seen.insert(current.clone()) { return None; }
            let name = current.trim_start_matches("struct ").trim_start_matches("union ").trim();
            let Some(def) = self.structs.iter().find(|candidate| candidate.name == name) else {
                return pointer.then_some(current);
            };
            if pointer && !def.fields.is_empty() { return Some(current); }
            current = def.alias_of.as_deref()?.trim().to_string();
            for qualifier in ["const ", "volatile ", "restrict "] {
                current = current.trim_start_matches(qualifier).trim().to_string();
            }
        }
        None
    }

    fn resolve_struct_path(&self, def: &crate::types::StructDef, offset: i64, depth: usize) -> Option<String> {
        if depth > self.structs.len() { return None; }
        let field = def.fields.iter().find(|field| {
            let end = field.off as i64 + field.size as i64;
            offset >= field.off as i64 && offset < end
        })?;
        let relative = offset - field.off as i64;
        if relative == 0 && !field.ty.contains('[') { return Some(field.name.clone()); }
        let ty = field.ty.trim().trim_start_matches("const ").trim();
        let named = ty.strip_prefix("struct ").or_else(|| ty.strip_prefix("union ")).unwrap_or(ty);
        if !named.contains('[') {
            if let Some(nested) = self.struct_def(named) {
                if let Some(path) = self.resolve_struct_path(nested, relative, depth + 1) {
                    return Some(format!("{}.{}", field.name, path));
                }
            }
        }
        let open = field.ty.rfind('[')?;
        let close = field.ty[open..].find(']')?;
        let count = field.ty[open + 1..open + close].parse::<i64>().ok()?;
        if count <= 0 || field.size as i64 % count != 0 { return None; }
        let element_size = field.size as i64 / count;
        let index = relative / element_size;
        let element_ty = field.ty[..open].trim().trim_start_matches("const ").trim();
        let element_name = element_ty.strip_prefix("struct ").or_else(|| element_ty.strip_prefix("union ")).unwrap_or(element_ty);
        if element_size > 0 && relative % element_size >= 0 {
            if let Some(element_def) = self.struct_def(element_name) {
                let within = relative % element_size;
                if let Some(path) = self.resolve_struct_path(element_def, within, depth + 1) {
                    if index >= 0 && index < count { return Some(format!("{}[{}].{}", field.name, index, path)); }
                }
            }
        }
        (element_size > 0 && relative % element_size == 0 && index >= 0 && index < count)
            .then(|| format!("{}[{index}]", field.name))
    }

    fn struct_field(&self, address: &Ex) -> Option<String> {
        let Ex::Bin(op, base, offset) = address else { return None };
        if *op != "+" && *op != "-" { return None; }
        let Ex::Num(raw) = &**offset else { return None };
        let byte_offset = if *op == "+" { *raw } else { raw.wrapping_neg() };
        if byte_offset < 0 { return None; }
        let ty_owned = match &**base {
            Ex::Var(name) => self.types.get(name).cloned(),
            Ex::CastOwned(ty, _) => Some(ty.clone()),
            Ex::Cast(ty, _) => Some((*ty).to_string()),
            Ex::Tern(_, _, _) => call_return_type(base),
            Ex::Call(callee, _) => match &**callee {
                Ex::Var(name) => crate::protos::find(name).map(|proto| proto.ret),
                Ex::Cast(ty, _) => function_pointer_proto(ty).map(|proto| proto.ret),
                Ex::CastOwned(ty, _) => function_pointer_proto(ty).map(|proto| proto.ret),
                _ => None,
            },
            _ => None,
        }?;
        let ty = self.pointer_target(&ty_owned)?;
        let ty = ty.trim().trim_start_matches("const ").trim();
        if !ty.starts_with("struct ") && !ty.starts_with("union ") {
            let element_size = match ty {
                "char" | "int8_t" | "uint8_t" | "u8" | "i8" => 1,
                "short" | "int16_t" | "uint16_t" | "u16" | "i16" => 2,
                "int" | "int32_t" | "uint32_t" | "u32" | "i32" | "float" => 4,
                "long" | "long long" | "int64_t" | "uint64_t" | "u64" | "i64" | "double" => 8,
                "__int128" | "__uint128" | "__int128_t" | "__uint128_t" => 16,
                _ => 0,
            };
            if element_size > 0 && byte_offset % element_size == 0 {
                return Some(format!("{}[{}]", self.at(base, 99), byte_offset / element_size));
            }
        }
        let def = self.struct_def(ty)?;
        let rendered_base = self.at(base, 99);
        let base_text = if matches!(&**base, Ex::Tern(_, _, _)) { format!("({rendered_base})") } else { rendered_base };
        let path = self.resolve_struct_path(def, byte_offset, 0)?;
        Some(format!("{base_text}->{path}"))
    }

    fn num(n: i64) -> String {
        if (-9..=9).contains(&n) {
            n.to_string()
        } else if n < 0 && n > -0x10000 {
            format!("-0x{:X}", -n)
        } else {
            format!("0x{:X}", n as u64)
        }
    }

    fn show(&self, e: &Ex) -> String {
        self.at(e, 99)
    }

    fn pointee_type(&self, e: &Ex, size: u8) -> String {
        let ty = match e {
            Ex::Cast(t, _) => Some((*t).to_string()),
            Ex::CastOwned(t, _) => Some(t.clone()),
            Ex::Call(f, _) => match &**f {
                Ex::Var(n) => crate::protos::find(n).map(|p| p.ret),
                _ => None,
            },
            Ex::Tern(_, _, _) => call_return_type(e),
            Ex::Bin(op, base, _) if *op == "+" || *op == "-" => call_return_type(base),
            _ => None,
        };
        let ty = ty.or_else(|| match e {
            Ex::Var(v) => self.types.get(v).cloned(),
            _ => None,
        });
        ty.and_then(|t| self.pointer_target(&t))
            .unwrap_or_else(|| int_type(size).to_string())
    }

    fn pointer_index(&self, address: &Ex) -> Option<(String, String)> {
        let (base, offset, reverse) = match address {
            Ex::Bin("+", base, offset) => (base, offset, false),
            Ex::Bin("-", base, offset) => (base, offset, true),
            _ => return None,
        };
        let (index, stride) = match &**offset {
            Ex::Bin("*", left, right) => match (&**left, &**right) {
                (index, Ex::Num(stride)) => (index, *stride),
                (Ex::Num(stride), index) => (index, *stride),
                _ => return None,
            },
            Ex::Bin("<<", index, shift) => {
                let Ex::Num(shift) = **shift else { return None };
                if !(0..=6).contains(&shift) { return None; }
                (&**index, 1_i64 << shift as u32)
            }
            _ => return None,
        };
        if stride <= 0 || stride > u8::MAX as i64 { return None; }
        let pointer = match &**base {
            Ex::Var(name) => self.types.get(name).is_some_and(|ty| self.pointer_target(ty).is_some()),
            Ex::Call(callee, _) => call_return_type(callee).is_some_and(|ty| self.pointer_target(&ty).is_some()),
            Ex::Tern(_, _, _) | Ex::Bin(_, _, _) => call_return_type(base).is_some_and(|ty| self.pointer_target(&ty).is_some()),
            Ex::Cast(ty, _) => self.pointer_target(ty).is_some(),
            Ex::CastOwned(ty, _) => self.pointer_target(ty).is_some(),
            _ => false,
        };
        let index = if reverse { Ex::Un("-", Box::new(index.clone())) } else { index.clone() };
        pointer.then(|| (self.at(base, 3), self.at(&index, 99)))
    }

    fn variable_struct_field(&self, address: &Ex) -> Option<String> {
        let (scaled, tail, reverse) = match address {
            Ex::Bin("+", scaled, tail) => (scaled, tail, false),
            Ex::Bin("-", scaled, tail) => (scaled, tail, true),
            _ => return None,
        };
        let (base, index, stride, inner_reverse) = match (&**scaled, &**tail) {
            (Ex::Bin(op @ ("+" | "-"), base, scaled), Ex::Num(offset)) => (base, scaled, *offset, *op == "-"),
            (Ex::Num(offset), Ex::Bin(op @ ("+" | "-"), base, scaled)) => (base, scaled, *offset, *op == "-"),
            _ => return None,
        };
        let (index, element_size) = match &**index {
            Ex::Bin("*", left, right) => match (&**left, &**right) {
                (index, Ex::Num(size)) => (index, *size),
                (Ex::Num(size), index) => (index, *size),
                _ => return None,
            },
            Ex::Bin("<<", index, shift) => {
                let Ex::Num(shift) = **shift else { return None };
                if !(0..=6).contains(&shift) { return None; }
                (&**index, 1_i64 << shift as u32)
            }
            _ => return None,
        };
        if element_size <= 0 || stride < 0 { return None; }
        let ty = match &**base {
            Ex::Var(name) => self.types.get(name).cloned(),
            Ex::Call(callee, _) => call_return_type(callee),
            Ex::Tern(_, _, _) | Ex::Bin(_, _, _) => call_return_type(base),
            Ex::Cast(t, _) => Some((*t).to_string()),
            Ex::CastOwned(t, _) => Some(t.clone()),
            _ => None,
        }?;
        let target = self.pointer_target(&ty)?;
        let name = target.trim().trim_start_matches("const ").trim();
        let name = name.strip_prefix("struct ").or_else(|| name.strip_prefix("union ")).unwrap_or(name);
        let def = self.struct_def(name)?;
        if def.size as i64 != element_size { return None; }
        let field = self.resolve_struct_path(def, stride, 0)?;
        let index = if reverse ^ inner_reverse { Ex::Un("-", Box::new(index.clone())) } else { index.clone() };
        Some(format!("{}[{}].{field}", self.at(base, 3), self.at(&index, 99)))
    }

    fn at(&self, e: &Ex, ctx: u8) -> String {
        let s = match e {
            Ex::Num(n) => Self::num(*n),
            Ex::Var(v) => self.rename.get(v).cloned().unwrap_or_else(|| v.clone()),
            Ex::Raw(s) => s.clone(),
        Ex::Un(op, a) => format!("{op}{}", self.at(a, 3)),
            Ex::Cast(t, a) => format!("({t}){}", self.at(a, 3)),
            Ex::CastOwned(t, a) => format!("({t}){}", self.at(a, 3)),
            Ex::Deref(a, sz) => {
                if let Some(field) = self.struct_field(a) {
                    return field;
                }
                if let Some(field) = self.variable_struct_field(a) {
                    return field;
                }
                if let Some((base, index)) = self.pointer_index(a) {
                    return format!("{base}[{index}]");
                }
                let address = match &**a {
                    Ex::Cast(_, inner) | Ex::CastOwned(_, inner) => self.at(inner, 3),
                    _ => self.at(a, 3),
                };
                format!("*({}*){}", self.pointee_type(a, *sz), address)
            }
            Ex::Call(f, args) => {
                let callee = match &**f {
                    Ex::Var(_) => self.at(f, 0),
                    other => format!("(*{})", self.at(other, 3)),
                };
                let a: Vec<String> = args.iter().map(|x| self.at(x, 99)).collect();
                format!("{callee}({})", a.join(", "))
            }
            Ex::Tern(_, a, b) if a == b => self.at(a, ctx),
            Ex::Tern(c, a, b) => format!("{} ? {} : {}", self.at(c, 15), self.at(a, 15), self.at(b, 15)),
            Ex::Bin(op, a, b) => {
                // x + -4  →  x - 4
                if *op == "+" {
                    if let Ex::Num(n) = **b {
                        if n < 0 && n > i64::MIN {
                            let p = prec(e);
                            let s = format!("{} - {}", self.at(a, p), Self::num(-n));
                            return if p >= ctx { format!("({s})") } else { s };
                        }
                    }
                }
                let p = prec(e);
                let s = format!("{} {op} {}", self.at(a, p), self.at(b, p - 1));
                if p >= ctx {
                    return format!("({s})");
                }
                s
            }
        };
        if prec(e) >= ctx && prec(e) != 0 && !matches!(e, Ex::Bin(..)) {
            format!("({s})")
        } else {
            s
        }
    }
}

fn is_narrow(e: &Ex) -> bool {
    match e {
        Ex::Bin("==" | "!=" | "<" | ">=" | ">" | "<=", ..) => true,
        Ex::Cast("uint8_t" | "uint16_t", _) => true,
        Ex::Num(n) => (0..256).contains(n),
        Ex::Bin("&", a, b) => is_narrow(a) || is_narrow(b),
        Ex::Bin("|" | "^", a, b) => is_narrow(a) && is_narrow(b),
        Ex::Tern(_, a, b) => is_narrow(a) && is_narrow(b),
        Ex::Un("!", _) => true,
        _ => false,
    }
}

fn negate(e: Ex) -> Ex {
    match e {
        Ex::Bin("==", a, b) => Ex::Bin("!=", a, b),
        Ex::Bin("!=", a, b) => Ex::Bin("==", a, b),
        Ex::Bin("<", a, b) => Ex::Bin(">=", a, b),
        Ex::Bin(">=", a, b) => Ex::Bin("<", a, b),
        Ex::Bin(">", a, b) => Ex::Bin("<=", a, b),
        Ex::Bin("<=", a, b) => Ex::Bin(">", a, b),
        Ex::Un("!", a) => *a,
        other => un("!", other),
    }
}

fn mentions(e: &Ex, target: &Ex) -> bool {
    if e == target {
        return true;
    }
    match e {
        Ex::Bin(_, a, b) => mentions(a, target) || mentions(b, target),
        Ex::Un(_, a) | Ex::Cast(_, a) | Ex::CastOwned(_, a) => mentions(a, target),
        Ex::Deref(a, _) => matches!(target, Ex::Deref(..)) || mentions(a, target),
        Ex::Call(f, args) => mentions(f, target) || args.iter().any(|a| mentions(a, target)),
        Ex::Tern(a, b, c) => mentions(a, target) || mentions(b, target) || mentions(c, target),
        _ => false,
    }
}

fn ex_size(e: &Ex) -> usize {
    match e {
        Ex::Bin(_, a, b) => 1 + ex_size(a) + ex_size(b),
        Ex::Un(_, a) | Ex::Cast(_, a) | Ex::CastOwned(_, a) | Ex::Deref(a, _) => 1 + ex_size(a),
        Ex::Call(f, args) => 1 + ex_size(f) + args.iter().map(ex_size).sum::<usize>(),
        Ex::Tern(a, b, c) => 1 + ex_size(a) + ex_size(b) + ex_size(c),
        _ => 1,
    }
}

fn has_deref(e: &Ex) -> bool {
    match e {
        Ex::Deref(..) => true,
        Ex::Bin(_, a, b) => has_deref(a) || has_deref(b),
        Ex::Un(_, a) | Ex::Cast(_, a) | Ex::CastOwned(_, a) => has_deref(a),
        Ex::Call(f, args) => has_deref(f) || args.iter().any(has_deref),
        Ex::Tern(a, b, c) => has_deref(a) || has_deref(b) || has_deref(c),
        _ => false,
    }
}

fn subst(e: &Ex, from: &Ex, to: &Ex) -> Ex {
    if e == from {
        return to.clone();
    }
    match e {
        Ex::Bin(o, a, b) => Ex::Bin(o, Box::new(subst(a, from, to)), Box::new(subst(b, from, to))),
        Ex::Un(o, a) => Ex::Un(o, Box::new(subst(a, from, to))),
        Ex::Cast(t, a) => Ex::Cast(t, Box::new(subst(a, from, to))),
        Ex::CastOwned(t, a) => Ex::CastOwned(t.clone(), Box::new(subst(a, from, to))),
        Ex::Deref(a, s) => Ex::Deref(Box::new(subst(a, from, to)), *s),
        Ex::Call(f, args) => Ex::Call(Box::new(subst(f, from, to)), args.iter().map(|a| subst(a, from, to)).collect()),
        Ex::Tern(a, b, c) => Ex::Tern(Box::new(subst(a, from, to)), Box::new(subst(b, from, to)), Box::new(subst(c, from, to))),
        other => other.clone(),
    }
}

/// Check the remaining uses of this definition after substitution. When it
/// reaches a CFG edge, leave deletion to the function-wide use count.
fn definition_still_needed(o: &BlockOut, start: usize, dst: &Ex, has_successors: bool) -> bool {
    for (_, stmt) in &o.stmts[start..] {
        match stmt {
            Stmt::Assign(left, right) => {
                if mentions(right, dst) { return true; }
                if left == dst { return false; }
                if mentions(left, dst) { return true; }
            }
            Stmt::Expr(e) if mentions(e, dst) => return true,
            _ => {}
        }
    }
    has_successors || o.defs.values().any(|e| mentions(e, dst)) || match &o.term {
        Term::Ret(Some(e)) | Term::Indirect(e) => mentions(e, dst),
        Term::Cond { cond, .. } => mentions(cond, dst),
        _ => false,
    }
}

fn propagate_adjacent_copy(o: &mut BlockOut, has_successors: bool) {
    let mut i = 0;
    while i + 1 < o.stmts.len() {
        let (dst, src) = match &o.stmts[i].1 {
            Stmt::Assign(Ex::Var(dst), Ex::Var(src)) if (dst.starts_with('v') || dst.starts_with('t')) && dst != src => (dst.clone(), src.clone()),
            _ => { i += 1; continue; }
        };
        let from = Ex::Var(dst);
        let replacement = Ex::Var(src);
        let replace_read = |expr: &mut Ex| {
            let new = subst(expr, &from, &replacement);
            let changed = new != *expr;
            *expr = new;
            changed
        };
        let changed = {
            let next = &mut o.stmts[i + 1].1;
            match next {
                Stmt::Assign(left, right) => {
                    // A store reads its address. A direct assignment defines its target.
                    let address_changed = match left {
                        Ex::Deref(address, _) => replace_read(address),
                        _ => false,
                    };
                    replace_read(right) || address_changed
                }
                Stmt::Expr(expr) => replace_read(expr),
                Stmt::Comment(_) => false,
            }
        };
        if changed && !definition_still_needed(o, i + 1, &from, has_successors) {
            o.stmts.remove(i);
        } else {
            i += 1;
        }
    }
    if let Some((_, Stmt::Assign(Ex::Var(dst), Ex::Var(src)))) = o.stmts.last() {
        let dst = Ex::Var(dst.clone());
        let src = Ex::Var(src.clone());
        let replace = |e: &Ex| subst(e, &dst, &src);
        let changed = match &mut o.term {
            Term::Ret(Some(e)) => { let n = replace(e); let changed = n != *e; *e = n; changed }
            Term::Indirect(e) => { let n = replace(e); let changed = n != *e; *e = n; changed }
            Term::Cond { cond, .. } => { let n = replace(cond); let changed = n != *cond; *cond = n; changed }
            _ => false,
        };
        if changed && !definition_still_needed(o, o.stmts.len(), &dst, has_successors) {
            o.stmts.pop();
        }
    }
}

/// Propagate a compiler-generated temporary holding a literal constant through
/// the next safe use.  Keeping this separate from copy propagation avoids
/// rewriting symbolic values whose meaning may change across a block.
fn propagate_adjacent_constant(o: &mut BlockOut, has_successors: bool) {
    let mut i = 0;
    while i < o.stmts.len() {
        let (dst, value) = match &o.stmts[i].1 {
            Stmt::Assign(Ex::Var(dst), value)
                if (dst.starts_with('v') || dst.starts_with('t'))
                    && constant_value(value).is_some() => (dst.clone(), constant_value(value).unwrap()),
            _ => { i += 1; continue; }
        };
        let mut changed = false;
        let mut j = i + 1;
        while j < o.stmts.len() {
            if writes_var(&o.stmts[j].1, &dst) { break; }
            let old = std::mem::replace(&mut o.stmts[j].1, Stmt::Comment(String::new()));
            let (new, did_change) = match old {
                Stmt::Assign(left, right) => {
                    let l = subst(&left, &Ex::Var(dst.clone()), &value);
                    let r = subst(&right, &Ex::Var(dst.clone()), &value);
                    (Stmt::Assign(l.clone(), r.clone()), l != left || r != right)
                }
                Stmt::Expr(expr) => {
                    let n = subst(&expr, &Ex::Var(dst.clone()), &value);
                    (Stmt::Expr(n.clone()), n != expr)
                }
                Stmt::Comment(text) => (Stmt::Comment(text), false),
            };
            o.stmts[j].1 = new;
            changed |= did_change;
            j += 1;
        }
        if j == o.stmts.len() {
            let old = std::mem::replace(&mut o.term, Term::Stop);
            let (new, did_change) = match old {
                Term::Ret(Some(expr)) => { let n = subst(&expr, &Ex::Var(dst.clone()), &value); (Term::Ret(Some(n.clone())), n != expr) }
                Term::Indirect(expr) => { let n = subst(&expr, &Ex::Var(dst.clone()), &value); (Term::Indirect(n.clone()), n != expr) }
                Term::Cond { cond, taken, fall } => { let n = subst(&cond, &Ex::Var(dst.clone()), &value); (Term::Cond { cond: n.clone(), taken, fall }, n != cond) }
                other => (other, false),
            };
            o.term = new;
            changed |= did_change;
        }
        if changed && !definition_still_needed(o, j, &Ex::Var(dst), has_successors) {
            o.stmts.remove(i);
        } else {
            i += 1;
        }
    }
}

fn writes_var(s: &Stmt, name: &str) -> bool {
    matches!(s, Stmt::Assign(Ex::Var(dst), _) if dst == name)
}

fn constant_value(e: &Ex) -> Option<Ex> {
    let value = match e {
        Ex::Num(_) => e.clone(),
        Ex::Un(op, value) => un(op, constant_value(value)?),
        Ex::Bin(op, left, right) => bin(op, constant_value(left)?, constant_value(right)?),
        Ex::Tern(cond, yes, no) => match constant_value(cond)? {
            Ex::Num(value) => constant_value(if value != 0 { yes } else { no })?,
            _ => return None,
        },
        Ex::Cast(_, value) | Ex::CastOwned(_, value) => constant_value(value)?,
        _ => return None,
    };
    matches!(value, Ex::Num(_)).then_some(value)
}

fn fold_expression(e: Ex) -> Ex {
    let folded = match e {
        Ex::Bin(op, left, right) => bin(op, fold_expression(*left), fold_expression(*right)),
        Ex::Un(op, value) => un(op, fold_expression(*value)),
        Ex::Cast(ty, value) => Ex::Cast(ty, Box::new(fold_expression(*value))),
        Ex::CastOwned(ty, value) => Ex::CastOwned(ty, Box::new(fold_expression(*value))),
        Ex::Deref(value, size) => Ex::Deref(Box::new(fold_expression(*value)), size),
        Ex::Call(func, args) => Ex::Call(Box::new(fold_expression(*func)), args.into_iter().map(fold_expression).collect()),
        Ex::Tern(cond, yes, no) => tern(fold_expression(*cond), fold_expression(*yes), fold_expression(*no)),
        other => other,
    };
    constant_value(&folded).unwrap_or(folded)
}

/// Propagate a temporary copy across safe intervening statements. Stop before
/// either side is reassigned so the pass never crosses a value-version change.
fn propagate_forward_copy(o: &mut BlockOut, has_successors: bool) {
    let mut i = 0;
    while i < o.stmts.len() {
        let (dst, src) = match &o.stmts[i].1 {
            Stmt::Assign(Ex::Var(dst), Ex::Var(src)) if (dst.starts_with('v') || dst.starts_with('t')) && dst != src => (dst.clone(), src.clone()),
            _ => { i += 1; continue; }
        };
        let mut changed = false;
        let mut j = i + 1;
        while j < o.stmts.len() {
            if writes_var(&o.stmts[j].1, &dst) || writes_var(&o.stmts[j].1, &src) { break; }
            let old = std::mem::replace(&mut o.stmts[j].1, Stmt::Comment(String::new()));
            let (new, did_change) = match old {
                Stmt::Assign(left, right) => {
                    let new_left = subst(&left, &Ex::Var(dst.clone()), &Ex::Var(src.clone()));
                    let new_right = subst(&right, &Ex::Var(dst.clone()), &Ex::Var(src.clone()));
                    (Stmt::Assign(new_left.clone(), new_right.clone()), new_left != left || new_right != right)
                }
                Stmt::Expr(expr) => { let new = subst(&expr, &Ex::Var(dst.clone()), &Ex::Var(src.clone())); (Stmt::Expr(new.clone()), new != expr) }
                Stmt::Comment(text) => (Stmt::Comment(text), false),
            };
            o.stmts[j].1 = new;
            changed |= did_change;
            j += 1;
        }
        if j == o.stmts.len() {
            let old = std::mem::replace(&mut o.term, Term::Stop);
            let (new, did_change) = match old {
                Term::Ret(Some(expr)) => { let new = subst(&expr, &Ex::Var(dst.clone()), &Ex::Var(src.clone())); (Term::Ret(Some(new.clone())), new != expr) }
                Term::Indirect(expr) => { let new = subst(&expr, &Ex::Var(dst.clone()), &Ex::Var(src.clone())); (Term::Indirect(new.clone()), new != expr) }
                Term::Cond { cond, taken, fall } => { let new = subst(&cond, &Ex::Var(dst.clone()), &Ex::Var(src.clone())); (Term::Cond { cond: new.clone(), taken, fall }, new != cond) }
                other => (other, false),
            };
            o.term = new;
            changed |= did_change;
        }
        if changed && !definition_still_needed(o, j, &Ex::Var(dst), has_successors) {
            o.stmts.remove(i);
        } else {
            i += 1;
        }
    }
}

/// Propagate a final temporary copy across an unambiguous control-flow edge.
/// This is a deliberately conservative SSA step: the destination block must
/// have exactly one predecessor, and propagation stops at either variable's
/// next assignment.
fn propagate_single_predecessor_copy(outs: &mut [BlockOut], f: &Function) {
    let index: HashMap<u64, usize> = f.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
    let mut pred_count = vec![0usize; f.blocks.len()];
    for block in &f.blocks {
        for (target, _) in &block.succs {
            if let Some(&i) = index.get(target) { pred_count[i] += 1; }
        }
    }
    for source in 0..f.blocks.len() {
        let Some((dst, src)) = outs[source].stmts.last().and_then(|(_, stmt)| match stmt {
            Stmt::Assign(Ex::Var(dst), Ex::Var(src)) if (dst.starts_with('v') || dst.starts_with('t')) && dst != src => Some((dst.clone(), src.clone())),
            _ => None,
        }) else { continue };
        let mut propagated = false;
        for (target, _) in &f.blocks[source].succs {
            let Some(&ti) = index.get(target) else { continue };
            if pred_count[ti] != 1 { continue; }
            let mut stopped = false;
            for (_, stmt) in &mut outs[ti].stmts {
                if writes_var(stmt, &dst) || writes_var(stmt, &src) { stopped = true; break; }
                let old = std::mem::replace(stmt, Stmt::Comment(String::new()));
                let (new, changed) = match old {
                    Stmt::Assign(left, right) => {
                        let l = subst(&left, &Ex::Var(dst.clone()), &Ex::Var(src.clone()));
                        let r = subst(&right, &Ex::Var(dst.clone()), &Ex::Var(src.clone()));
                        (Stmt::Assign(l.clone(), r.clone()), l != left || r != right)
                    }
                    Stmt::Expr(expr) => { let n = subst(&expr, &Ex::Var(dst.clone()), &Ex::Var(src.clone())); (Stmt::Expr(n.clone()), n != expr) }
                    Stmt::Comment(text) => (Stmt::Comment(text), false),
                };
                *stmt = new;
                propagated |= changed;
            }
            if !stopped {
                let old = std::mem::replace(&mut outs[ti].term, Term::Stop);
                let (new, changed) = match old {
                    Term::Ret(Some(expr)) => { let n = subst(&expr, &Ex::Var(dst.clone()), &Ex::Var(src.clone())); (Term::Ret(Some(n.clone())), n != expr) }
                    Term::Indirect(expr) => { let n = subst(&expr, &Ex::Var(dst.clone()), &Ex::Var(src.clone())); (Term::Indirect(n.clone()), n != expr) }
                    Term::Cond { cond, taken, fall } => { let n = subst(&cond, &Ex::Var(dst.clone()), &Ex::Var(src.clone())); (Term::Cond { cond: n.clone(), taken, fall }, n != cond) }
                    other => (other, false),
                };
                outs[ti].term = new;
                propagated |= changed;
            }
        }
        if propagated && f.blocks[source].succs.len() == 1 {
            outs[source].stmts.pop();
        }
    }
}

/// Carry a literal temporary across a single-predecessor edge.  This is the
/// constant analogue of the copy pass above and deliberately stops at any
/// reassignment of the temporary.
fn propagate_single_predecessor_constant(outs: &mut [BlockOut], f: &Function) {
    let index: HashMap<u64, usize> = f.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
    let mut pred_count = vec![0usize; f.blocks.len()];
    for block in &f.blocks {
        for (target, _) in &block.succs {
            if let Some(&i) = index.get(target) { pred_count[i] += 1; }
        }
    }
    for source in 0..f.blocks.len() {
        let Some((dst, value)) = outs[source].stmts.last().and_then(|(_, stmt)| match stmt {
            Stmt::Assign(Ex::Var(dst), value)
                if (dst.starts_with('v') || dst.starts_with('t'))
                    && constant_value(value).is_some() => Some((dst.clone(), constant_value(value).unwrap())),
            _ => None,
        }) else { continue };
        for (target, _) in &f.blocks[source].succs {
            let Some(&ti) = index.get(target) else { continue };
            if pred_count[ti] != 1 { continue; }
            let mut stopped = false;
            for (_, stmt) in &mut outs[ti].stmts {
                if writes_var(stmt, &dst) { stopped = true; break; }
                let old = std::mem::replace(stmt, Stmt::Comment(String::new()));
                *stmt = match old {
                    Stmt::Assign(left, right) => Stmt::Assign(subst(&left, &Ex::Var(dst.clone()), &value), subst(&right, &Ex::Var(dst.clone()), &value)),
                    Stmt::Expr(expr) => Stmt::Expr(subst(&expr, &Ex::Var(dst.clone()), &value)),
                    Stmt::Comment(text) => Stmt::Comment(text),
                };
            }
            if !stopped {
                let term = std::mem::replace(&mut outs[ti].term, Term::Stop);
                outs[ti].term = match term {
                    Term::Ret(Some(expr)) => Term::Ret(Some(subst(&expr, &Ex::Var(dst.clone()), &value))),
                    Term::Indirect(expr) => Term::Indirect(subst(&expr, &Ex::Var(dst.clone()), &value)),
                    Term::Cond { cond, taken, fall } => Term::Cond { cond: subst(&cond, &Ex::Var(dst.clone()), &value), taken, fall },
                    other => other,
                };
                if f.blocks[source].succs.len() == 1 { outs[source].stmts.pop(); }
            }
        }
    }
}

/// Fold a copy through a merge block when every incoming edge carries the
/// identical temporary-to-source assignment. This is the small, safe subset
/// of phi propagation that does not require constructing a full SSA graph.
fn propagate_convergent_copy(outs: &mut [BlockOut], f: &Function) {
    let index: HashMap<u64, usize> = f.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
    let mut incoming: Vec<Vec<usize>> = vec![vec![]; f.blocks.len()];
    for (source, block) in f.blocks.iter().enumerate() {
        for (target, _) in &block.succs {
            if let Some(&ti) = index.get(target) { incoming[ti].push(source); }
        }
    }
    for (target, preds) in incoming.iter().enumerate() {
        if preds.len() < 2 { continue; }
        let Some((dst, src)) = preds.iter().map(|&p| outs[p].stmts.last().and_then(|(_, stmt)| match stmt {
            Stmt::Assign(Ex::Var(dst), Ex::Var(src)) if (dst.starts_with('v') || dst.starts_with('t')) && dst != src => Some((dst.clone(), src.clone())),
            _ => None,
        })).try_fold(None, |same: Option<(String, String)>, copy| match (same, copy) {
            (Some(a), Some(b)) if a == b => Some(Some(a)),
            (None, Some(b)) => Some(Some(b)),
            _ => None,
        }).flatten() else { continue };
        let mut stopped = false;
        for (_, stmt) in &mut outs[target].stmts {
            if writes_var(stmt, &dst) || writes_var(stmt, &src) { stopped = true; break; }
            let old = std::mem::replace(stmt, Stmt::Comment(String::new()));
            let new = match old {
                Stmt::Assign(left, right) => Stmt::Assign(subst(&left, &Ex::Var(dst.clone()), &Ex::Var(src.clone())), subst(&right, &Ex::Var(dst.clone()), &Ex::Var(src.clone()))),
                Stmt::Expr(expr) => Stmt::Expr(subst(&expr, &Ex::Var(dst.clone()), &Ex::Var(src.clone()))),
                Stmt::Comment(text) => Stmt::Comment(text),
            };
            *stmt = new;
        }
        if !stopped {
            let term = std::mem::replace(&mut outs[target].term, Term::Stop);
            outs[target].term = match term {
                Term::Ret(Some(expr)) => Term::Ret(Some(subst(&expr, &Ex::Var(dst.clone()), &Ex::Var(src.clone())))),
                Term::Indirect(expr) => Term::Indirect(subst(&expr, &Ex::Var(dst.clone()), &Ex::Var(src.clone()))),
                Term::Cond { cond, taken, fall } => Term::Cond { cond: subst(&cond, &Ex::Var(dst), &Ex::Var(src)), taken, fall },
                other => other,
            };
        }
    }
}

/// Fold an identical literal assignment through a merge block.  All incoming
/// predecessors must agree on both the temporary and its value.
fn propagate_convergent_constant(outs: &mut [BlockOut], f: &Function) {
    let index: HashMap<u64, usize> = f.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
    let mut incoming: Vec<Vec<usize>> = vec![vec![]; f.blocks.len()];
    for (source, block) in f.blocks.iter().enumerate() {
        for (target, _) in &block.succs {
            if let Some(&ti) = index.get(target) { incoming[ti].push(source); }
        }
    }
    for (target, preds) in incoming.iter().enumerate() {
        if preds.len() < 2 { continue; }
        let Some((dst, value)) = preds.iter().map(|&p| outs[p].stmts.last().and_then(|(_, stmt)| match stmt {
            Stmt::Assign(Ex::Var(dst), value)
                if (dst.starts_with('v') || dst.starts_with('t'))
                    && constant_value(value).is_some() => Some((dst.clone(), constant_value(value).unwrap())),
            _ => None,
        })).try_fold(None, |same: Option<(String, Ex)>, item| match (same, item) {
            (Some(a), Some(b)) if a == b => Some(Some(a)),
            (None, Some(b)) => Some(Some(b)),
            _ => None,
        }).flatten() else { continue };
        let mut stopped = false;
        for (_, stmt) in &mut outs[target].stmts {
            if writes_var(stmt, &dst) { stopped = true; break; }
            let old = std::mem::replace(stmt, Stmt::Comment(String::new()));
            *stmt = match old {
                Stmt::Assign(left, right) => Stmt::Assign(subst(&left, &Ex::Var(dst.clone()), &value), subst(&right, &Ex::Var(dst.clone()), &value)),
                Stmt::Expr(expr) => Stmt::Expr(subst(&expr, &Ex::Var(dst.clone()), &value)),
                Stmt::Comment(text) => Stmt::Comment(text),
            };
        }
        if !stopped {
            let term = std::mem::replace(&mut outs[target].term, Term::Stop);
            outs[target].term = match term {
                Term::Ret(Some(expr)) => Term::Ret(Some(subst(&expr, &Ex::Var(dst.clone()), &value))),
                Term::Indirect(expr) => Term::Indirect(subst(&expr, &Ex::Var(dst.clone()), &value)),
                Term::Cond { cond, taken, fall } => Term::Cond { cond: subst(&cond, &Ex::Var(dst), &value), taken, fall },
                other => other,
            };
        }
    }
}

fn inline_adjacent_call_temp(o: &mut BlockOut) {
    let mut i = 0;
    while i + 1 < o.stmts.len() {
        let (tmp, call) = match &o.stmts[i].1 {
            Stmt::Assign(Ex::Var(tmp), Ex::Call(_, _)) if tmp.starts_with('v') || tmp.starts_with('t') => (tmp.clone(), o.stmts[i].1.clone()),
            _ => { i += 1; continue; }
        };
        let (left, used) = match &o.stmts[i + 1].1 {
            Stmt::Assign(left, Ex::Var(used)) if used == &tmp && !mentions(left, &Ex::Var(tmp.clone())) => (left.clone(), used.clone()),
            _ => { i += 1; continue; }
        };
        let later_use = o.stmts[i + 2..].iter().any(|(_, stmt)| match stmt {
            Stmt::Assign(l, r) => mentions(l, &Ex::Var(tmp.clone())) || mentions(r, &Ex::Var(tmp.clone())),
            Stmt::Expr(e) => mentions(e, &Ex::Var(tmp.clone())),
            Stmt::Comment(_) => false,
        }) || match &o.term {
            Term::Ret(Some(e)) | Term::Indirect(e) => mentions(e, &Ex::Var(tmp.clone())),
            Term::Cond { cond, .. } => mentions(cond, &Ex::Var(tmp.clone())),
            _ => false,
        };
        if later_use {
            i += 1;
            continue;
        }
        o.stmts[i].1 = Stmt::Comment(String::new());
        o.stmts[i + 1].1 = Stmt::Assign(left, match call { Stmt::Assign(_, rhs) => rhs, _ => unreachable!() });
        let _ = used;
        i += 1;
    }
}

fn fold_constant_term(o: &mut BlockOut) {
    if let Term::Cond { cond, taken, fall } = &o.term {
        if let Some(Ex::Num(value)) = constant_value(cond) {
            o.term = Term::Jmp(if value != 0 { *taken } else { *fall });
        }
    }
}

fn typed_call_value(proto: Option<&crate::protos::Proto>, call: Ex) -> Ex {
    match proto.map(|p| p.ret.trim()) {
        Some(ret) if ret.ends_with('*') => Ex::CastOwned(ret.to_string(), Box::new(call)),
        _ => call,
    }
}

fn count_vars(e: &Ex, m: &mut HashMap<String, usize>) {
    match e {
        Ex::Var(v) => *m.entry(v.clone()).or_default() += 1,
        Ex::Bin(_, a, b) => {
            count_vars(a, m);
            count_vars(b, m)
        }
        Ex::Un(_, a) | Ex::Cast(_, a) | Ex::CastOwned(_, a) | Ex::Deref(a, _) => count_vars(a, m),
        Ex::Call(f, args) => {
            count_vars(f, m);
            args.iter().for_each(|a| count_vars(a, m))
        }
        Ex::Tern(a, b, c) => {
            count_vars(a, m);
            count_vars(b, m);
            count_vars(c, m)
        }
        _ => {}
    }
}

// ------------------------------------------------------------------ registers

const GPR: [&str; 16] =
    ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const RAX: u8 = 0;
const RDX: u8 = 2;
const RSP: u8 = 4;
const RBP: u8 = 5;

fn reg_index(r: Register) -> Option<u8> {
    if r == Register::None {
        return None;
    }
    if r.is_gpr() {
        return Some(r.full_register().number() as u8);
    }
    if r.is_xmm() || r.is_ymm() || r.is_zmm() {
        return Some(16 + (r.number() as u8 % 16));
    }
    None
}

/// Register file of the CPU being decompiled (x86 by default).
#[derive(Clone)]
pub struct Abi {
    pub names: Vec<String>,
    pub word_bytes: u8,
    pub ret: u8,
    pub sp: u8,
    pub args: Vec<u8>,
    pub caller_saved: Vec<u8>,
    pub callee_saved: Vec<u8>,
    pub x86: bool,
}

thread_local! {
    static ABI: std::cell::RefCell<Option<Abi>> = const { std::cell::RefCell::new(None) };
}

fn abi_ret() -> u8 {
    ABI.with(|a| a.borrow().as_ref().map(|x| x.ret).unwrap_or(RAX))
}
fn abi_sp() -> u8 {
    ABI.with(|a| a.borrow().as_ref().map(|x| x.sp).unwrap_or(RSP))
}
fn reg_by_name(n: &str) -> Option<u8> {
    ABI.with(|a| match a.borrow().as_ref() {
        Some(x) if !x.x86 => x.names.iter().position(|g| g == n).map(|i| i as u8),
        _ => GPR.iter().position(|g| *g == n).map(|i| i as u8),
    })
}

fn reg_name(i: u8) -> String {
    let custom = ABI.with(|a| a.borrow().as_ref().filter(|x| !x.x86).and_then(|x| x.names.get(i as usize).cloned()));
    if let Some(n) = custom {
        return n;
    }
    if i < 16 {
        GPR[i as usize].to_string()
    } else {
        format!("xmm{}", i - 16)
    }
}

fn is_callee_saved(i: u8, conv: CallConv) -> bool {
    match conv {
        CallConv::Win64 => matches!(i, 3 | 5 | 6 | 7 | 12 | 13 | 14 | 15),
        _ => matches!(i, 3 | 5 | 12 | 13 | 14 | 15) || (matches!(conv, CallConv::Cdecl32 | CallConv::Fastcall32 | CallConv::Delphi32) && matches!(i, 6 | 7)),
    }
}

// ------------------------------------------------------------------ statements

#[derive(Clone, Debug)]
enum Stmt {
    Assign(Ex, Ex),
    Expr(Ex),
    Comment(String),
}

#[derive(Clone, Debug)]
enum Flags {
    None,
    Cmp(Ex, Ex),
    /// Result of an operation: zero / sign tests apply to it.
    Op(Ex),
}

#[derive(Clone, Debug)]
enum Term {
    Ret(Option<Ex>),
    Jmp(u64),
    Cond { cond: Ex, taken: u64, fall: u64 },
    Indirect(Ex),
    Fall(u64),
    Stop,
}

struct BlockOut {
    stmts: Vec<(u64, Stmt)>,
    defs: BTreeMap<u8, Ex>,
    uses: BTreeSet<u8>,
    term: Term,
    term_addr: u64,
}

fn enum_const_int(e: &Ex) -> Option<i64> {
    match e {
        Ex::Num(value) => Some(*value),
        Ex::Cast(_, value) | Ex::CastOwned(_, value) => enum_const_int(value),
        Ex::Un("+", value) => enum_const_int(value),
        Ex::Un("-", value) => enum_const_int(value)?.checked_neg(),
        Ex::Un("~", value) => Some(!enum_const_int(value)?),
        Ex::Un("!", value) => Some((enum_const_int(value)? == 0) as i64),
        Ex::Tern(condition, yes, no) => if enum_const_int(condition)? != 0 { enum_const_int(yes) } else { enum_const_int(no) },
        Ex::Bin(op, left, right) => {
            let (left, right) = (enum_const_int(left)?, enum_const_int(right)?);
            match *op {
                "+" => left.checked_add(right),
                "-" => left.checked_sub(right),
                "|" => Some(left | right),
                "&" => Some(left & right),
                "^" => Some(left ^ right),
                "*" => left.checked_mul(right),
                "/" => left.checked_div(right),
                "%" => left.checked_rem(right),
                "<<" => left.checked_shl(right.try_into().ok()?),
                ">>" => left.checked_shr(right.try_into().ok()?),
                "&&" => Some((left != 0 && right != 0) as i64),
                "||" => Some((left != 0 || right != 0) as i64),
                "==" => Some((left == right) as i64),
                "!=" => Some((left != right) as i64),
                "<" => Some((left < right) as i64),
                "<=" => Some((left <= right) as i64),
                ">" => Some((left > right) as i64),
                ">=" => Some((left >= right) as i64),
                _ => None,
            }
        }
        _ => None,
    }
}

fn enum_var_source(e: &Ex, vars: &HashMap<String, String>, current_name: &str, enum_return: Option<&str>) -> Option<String> {
    match e {
        Ex::Var(name) => vars.get(name).cloned(),
        Ex::Cast(_, inner) | Ex::CastOwned(_, inner) => enum_var_source(inner, vars, current_name, enum_return),
        Ex::Tern(_, yes, no) => {
            let ty = enum_var_source(yes, vars, current_name, enum_return)?;
            (enum_var_source(no, vars, current_name, enum_return).as_deref() == Some(ty.as_str())).then_some(ty)
        }
        Ex::Bin(op, left, right) if matches!(*op, "+" | "-" | "|" | "&" | "^" | "<<" | ">>") => {
            if let Some(ty) = enum_var_source(left, vars, current_name, enum_return) {
                enum_const_int(right).is_some().then_some(ty)
            } else if let Some(ty) = enum_var_source(right, vars, current_name, enum_return) {
                enum_const_int(left).is_some().then_some(ty)
            } else { None }
        }
        Ex::Call(function, _) => match &**function {
            Ex::Var(name) => crate::protos::find(name).and_then(|p| p.ret.trim().strip_prefix("enum ").map(str::to_string)).or_else(|| (name == current_name).then(|| enum_return.map(str::to_string)).flatten()),
            _ => None,
        },
        _ => None,
    }
}

fn infer_enum_vars(outs: &[BlockOut], seed: &HashMap<String, String>, current_name: &str, enum_return: Option<&str>) -> HashMap<String, String> {
    let mut vars = seed.clone();
    for _ in 0..outs.len().max(1) {
        let mut changed = false;
        for block in outs {
            for (_, stmt) in &block.stmts {
                if let Stmt::Assign(Ex::Var(dst), rhs) = stmt {
                    let source = enum_var_source(rhs, &vars, current_name, enum_return);
                    if let Some(ty) = source {
                        let old = vars.insert(dst.clone(), ty.clone());
                        changed |= old.as_ref() != Some(&ty);
                    } else {
                        changed |= vars.remove(dst).is_some();
                    }
                }
            }
        }
        if !changed { break; }
    }
    vars
}

#[derive(Clone)]
pub struct DLine {
    pub text: String,
    pub addr: u64,
    pub indent: usize,
}

pub struct Decompiled {
    pub lines: Vec<DLine>,
}

fn cc_expr(cc: ConditionCode, fl: &Flags) -> Ex {
    use ConditionCode as C;
    let (a, b): (Ex, Ex) = match fl {
        Flags::Cmp(x, y) => (x.clone(), y.clone()),
        Flags::Op(r) => (r.clone(), Ex::Num(0)),
        Flags::None => return Ex::Raw(format!("/* flags {:?} */ cond", cc)),
    };
    let is_cmp = matches!(fl, Flags::Cmp(..));
    let op = |o: &'static str| Ex::Bin(o, Box::new(a.clone()), Box::new(b.clone()));
    match cc {
        C::e => op("=="),
        C::ne => op("!="),
        C::l => op("<"),
        C::ge => op(">="),
        C::le => op("<="),
        C::g => op(">"),
        C::b => if is_cmp { op("<") } else { Ex::Raw("CF".into()) },
        C::ae => if is_cmp { op(">=") } else { Ex::Un("!", Box::new(Ex::Raw("CF".into()))) },
        C::be => if is_cmp { op("<=") } else { Ex::Raw("CF || ZF".into()) },
        C::a => if is_cmp { op(">") } else { op("!=") },
        C::s => Ex::Bin("<", Box::new(bin("-", a.clone(), b.clone())), Box::new(Ex::Num(0))),
        C::ns => Ex::Bin(">=", Box::new(bin("-", a.clone(), b.clone())), Box::new(Ex::Num(0))),
        C::o => Ex::Raw("OF".into()),
        C::no => Ex::Raw("!OF".into()),
        C::p => Ex::Raw("PF".into()),
        C::np => Ex::Raw("!PF".into()),
        _ => Ex::Raw("cond".into()),
    }
}

// ------------------------------------------------------------------ the decompiler

struct Dc<'a> {
    bin: &'a Binary,
    an: &'a Analysis,
    names: &'a HashMap<u64, (String, NameKind)>,
    conv: CallConv,
    word: i64,
    fp: bool,
    locals: BTreeMap<String, u8>,
    stack_args: BTreeSet<usize>,
    tmp: usize,
    dem: std::cell::RefCell<HashMap<u64, String>>,
    /// Stack slots that only hold saved registers (non-x86 front-end).
    spills: BTreeSet<i64>,
    enum_constants: &'a HashMap<String, HashMap<i64, String>>,
}

#[derive(Clone)]
struct St {
    env: HashMap<u8, Ex>,
    flags: Flags,
    sp: i64,
    bp: Option<i64>,
    pending: Vec<Ex>,
    dirty: BTreeSet<u8>,
    uses: BTreeSet<u8>,
    modified: BTreeSet<u8>,
    stmts: Vec<(u64, Stmt)>,
    out_args_used: bool,
}

impl<'a> Dc<'a> {
    fn disp(&self, a: u64, raw: &str) -> String {
        if let Some(s) = self.dem.borrow().get(&a) {
            return s.clone();
        }
        let s = display_symbol(raw);
        self.dem.borrow_mut().insert(a, s.clone());
        s
    }

    fn callee_name(&self, a: u64) -> String {
        match self.names.get(&a) {
            Some((n, _)) => self.disp(a, n).trim_start_matches("__imp_").trim_start_matches('_').to_string(),
            None => format!("sub_{a:X}"),
        }
        .pipe_nonempty(a)
    }

    fn global(&self, a: u64) -> Ex {
        if let Some(i) = self.an.string_at.get(&a) {
            return Ex::Raw(format!("\"{}\"", crate::code::escape_str(&self.an.strings[*i].text, 60)));
        }
        match self.names.get(&a) {
            Some((n, _)) => Ex::Var(self.disp(a, n)),
            None => Ex::Num(a as i64),
        }
    }

    fn rd_reg(&self, st: &mut St, r: Register) -> Ex {
        let Some(i) = reg_index(r) else { return Ex::Raw(format!("{r:?}").to_lowercase()) };
        if i == RSP && !(r.size() < 4) {
            return Ex::Raw("sp".into());
        }
        if i == RBP && self.fp && !st.env.contains_key(&RBP) {
            return Ex::Raw("fp".into());
        }
        let base = match st.env.get(&i) {
            Some(e) => e.clone(),
            None => {
                st.uses.insert(i);
                Ex::Var(reg_name(i))
            }
        };
        let sz = r.size();
        if r.is_gpr() && sz < 4 {
            if r == Register::AH || r == Register::BH || r == Register::CH || r == Register::DH {
                return Ex::Cast("uint8_t", Box::new(bin(">>>", base, Ex::Num(8))));
            }
            let t = if sz == 1 { "uint8_t" } else { "uint16_t" };
            if is_narrow(&base) {
                return base;
            }
            return Ex::Cast(t, Box::new(base));
        }
        base
    }

    fn wr_reg(&mut self, st: &mut St, r: Register, v: Ex, addr: u64) {
        let Some(i) = reg_index(r) else { return };
        if i == RSP {
            return;
        }
        if i == RBP && self.fp {
            return;
        }
        // writing al / ax keeps the rest of the register
        let v = if r.is_gpr() && r.size() < 4 && !is_narrow(&v) {
            let old = self.rd_reg(st, r.full_register());
            let mask: i64 = if r.size() == 1 { 0xFF } else { 0xFFFF };
            if matches!(old, Ex::Num(0)) {
                bin("&", v, Ex::Num(mask))
            } else {
                bin("|", bin("&", old, Ex::Num(!mask)), bin("&", v, Ex::Num(mask)))
            }
        } else {
            v
        };
        // keep expressions small: long chains become a named temporary
        let v = if ex_size(&v) > 16 {
            self.tmp += 1;
            let t = format!("t{}", self.tmp);
            st.stmts.push((addr, Stmt::Assign(var(&t), v)));
            var(&t)
        } else {
            v
        };
        st.env.insert(i, v);
        st.modified.insert(i);
        st.dirty.insert(i);
    }

    fn frame_slot(&mut self, off: i64, size: u8, bp: Option<i64>) -> Ex {
        let w = self.word;
        if off >= w && off < 0x400 {
            // arguments
            match self.conv {
                CallConv::Win64 if off < 8 + 32 => {
                    let idx = ((off - 8) / 8) as usize;
                    return Ex::Var(GPR[[1usize, 2, 8, 9][idx.min(3)]].to_string());
                }
                CallConv::Win64 => {
                    let k = ((off - 40) / 8) as usize + 5;
                    self.stack_args.insert(k);
                    return Ex::Var(format!("a{k}"));
                }
                CallConv::SysV64 | CallConv::GoAbi => {
                    let k = ((off - 8) / 8) as usize + self.conv.arg_regs().len() + 1;
                    self.stack_args.insert(k);
                    return Ex::Var(format!("a{k}"));
                }
                _ => {
                    let k = ((off - 4) / 4) as usize + 1 + self.conv.arg_regs().len();
                    self.stack_args.insert(k);
                    return Ex::Var(format!("a{k}"));
                }
            }
        }
        if off >= 0 {
            return Ex::Var("retaddr".into());
        }
        let name = match (self.fp, bp) {
            (true, Some(b)) => format!("var_{:X}", (b - off).max(0)),
            _ => format!("var_{:X}", -off),
        };
        let e = self.locals.entry(name.clone()).or_insert(size.max(1));
        if size > *e {
            *e = size;
        }
        Ex::Var(name)
    }

    /// Value of a memory operand's address, and the lvalue it names.
    fn mem_operand(&mut self, st: &mut St, ins: &Instruction, size: u8) -> (Ex, Ex) {
        if ins.is_ip_rel_memory_operand() {
            let a = ins.ip_rel_memory_address();
            let lv = match self.names.get(&a) {
                Some(_) => self.global(a),
                None => Ex::Deref(Box::new(Ex::Num(a as i64)), size),
            };
            return (self.global_addr(a), lv);
        }
        let seg = ins.memory_segment();
        let base = ins.memory_base();
        let index = ins.memory_index();
        let disp = ins.memory_displacement64() as i64;
        let disp = if self.word == 4 { disp as i32 as i64 } else { disp };
        if matches!(seg, Register::FS | Register::GS) {
            let s = if seg == Register::FS { "fs" } else { "gs" };
            let lv = Ex::Raw(format!("__{s}[{}]", Fmt::num(disp)));
            return (Ex::Raw(format!("&__{s}[{}]", Fmt::num(disp))), lv);
        }
        // stack-frame slots
        if index == Register::None {
            let bi = reg_index(base);
            if bi == Some(RSP) {
                let off = st.sp + disp;
                let slot = self.frame_slot(off, size, st.bp);
                return (Ex::Un("&", Box::new(slot.clone())), slot);
            }
            if bi == Some(RBP) && self.fp {
                if let Some(b) = st.bp {
                    let off = b + disp;
                    let slot = self.frame_slot(off, size, st.bp);
                    return (Ex::Un("&", Box::new(slot.clone())), slot);
                }
            }
        }
        let mut addr = if base != Register::None { self.rd_reg(st, base) } else { Ex::Num(0) };
        if index != Register::None {
            let ix = self.rd_reg(st, index);
            let sc = ins.memory_index_scale() as i64;
            addr = bin("+", addr, if sc == 1 { ix } else { bin("*", ix, Ex::Num(sc)) });
        }
        addr = bin("+", addr, Ex::Num(disp));
        if let Ex::Num(a) = addr {
            let a = a as u64;
            if self.names.contains_key(&a) {
                return (self.global_addr(a), self.global(a));
            }
        }
        (addr.clone(), Ex::Deref(Box::new(addr), size))
    }

    fn global_addr(&self, a: u64) -> Ex {
        if let Some(i) = self.an.string_at.get(&a) {
            return Ex::Raw(format!("\"{}\"", crate::code::escape_str(&self.an.strings[*i].text, 60)));
        }
        match self.names.get(&a) {
            Some((n, k)) => {
                let d = Ex::Var(self.disp(a, n));
                if *k == NameKind::Function || *k == NameKind::Import {
                    d
                } else {
                    Ex::Un("&", Box::new(d))
                }
            }
            None => Ex::Num(a as i64),
        }
    }

    fn read_op(&mut self, st: &mut St, ins: &Instruction, i: u32) -> Ex {
        match ins.op_kind(i) {
            OpKind::Register => self.rd_reg(st, ins.op_register(i)),
            OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate8to16
            | OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate8_2nd => {
                let v = ins.immediate(i);
                let n = match ins.op_kind(i) {
                    OpKind::Immediate8 => v as u8 as i8 as i64,
                    OpKind::Immediate16 => v as u16 as i16 as i64,
                    OpKind::Immediate32 if self.word == 4 => v as u32 as i32 as i64,
                    OpKind::Immediate32 => v as u32 as i64,
                    _ => v as i64,
                };
                // an immediate that is a known address reads better as its name
                let u = v as u64;
                if u > 0xFFF && (self.names.contains_key(&u) || self.an.string_at.contains_key(&u)) {
                    return self.global_addr(u);
                }
                Ex::Num(n)
            }
            OpKind::Memory => {
                let sz = ins.memory_size().size() as u8;
                let (_, lv) = self.mem_operand(st, ins, sz.max(1));
                lv
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => self.global_addr(ins.near_branch_target()),
            _ => Ex::Raw("?".into()),
        }
    }

    fn freeze(&mut self, st: &mut St, addr: u64, only_deref: bool, lv: Option<&Ex>) {
        let keys: Vec<u8> = st.env.keys().copied().collect();
        for k in keys {
            let e = st.env[&k].clone();
            if matches!(e, Ex::Var(_) | Ex::Num(_)) {
                // plain variables are only a problem when that variable is being overwritten
                if let (Some(l), Ex::Var(_)) = (lv, &e) {
                    if &e == l {
                        self.tmp += 1;
                        let t = format!("t{}", self.tmp);
                        st.stmts.push((addr, Stmt::Assign(var(&t), e)));
                        st.env.insert(k, var(&t));
                    }
                }
                continue;
            }
            let bad = match lv {
                Some(l) => mentions(&e, l),
                None => has_deref(&e),
            };
            if bad || (only_deref && has_deref(&e) && lv.is_none()) {
                self.tmp += 1;
                let t = format!("t{}", self.tmp);
                st.stmts.push((addr, Stmt::Assign(var(&t), e)));
                st.env.insert(k, var(&t));
            }
        }
    }

    fn store(&mut self, st: &mut St, addr: u64, lv: Ex, v: Ex) {
        if lv == v {
            return;
        }
        self.freeze(st, addr, false, Some(&lv));
        // a call's return value stored directly keeps a single statement
        st.stmts.push((addr, Stmt::Assign(lv, v)));
    }

    fn write_op(&mut self, st: &mut St, ins: &Instruction, i: u32, v: Ex) {
        let addr = ins.ip();
        match ins.op_kind(i) {
            OpKind::Register => self.wr_reg(st, ins.op_register(i), v, addr),
            OpKind::Memory => {
                let sz = ins.memory_size().size() as u8;
                let (_, lv) = self.mem_operand(st, ins, sz.max(1));
                self.store(st, addr, lv, v);
            }
            _ => {}
        }
    }

    fn do_call(&mut self, st: &mut St, ins: &Instruction, info: &crate::analysis::Insn) {
        let addr = ins.ip();
        let (callee, noret, skip): (Ex, bool, bool) = match info.flow {
            Flow::Call if info.target != 0 => {
                let n = self.callee_name(info.target);
                let nr = self.an.functions.get(&info.target).map(|f| f.noreturn).unwrap_or(false)
                    || is_noreturn_name(&n)
                    || is_debug_noreturn(&self.bin.debug_noreturn, &n);
                let skip = matches!(n.as_str(), "chkstk" | "alloca_probe" | "security_check_cookie" | "__chkstk" | "_alloca_probe" | "_chkstk" | "__security_check_cookie");
                (Ex::Var(n), nr, skip)
            }
            _ => {
                if info.mem != 0 && (self.names.contains_key(&info.mem) || self.an.import_slot.contains_key(&info.mem)) {
                    let n = self.callee_name(info.mem);
                    let nr = is_noreturn_name(&n) || is_debug_noreturn(&self.bin.debug_noreturn, &n);
                    (Ex::Var(n), nr, false)
                } else if ins.op_kind(0) == OpKind::Register {
                    (self.rd_reg(st, ins.op_register(0)), false, false)
                } else {
                    let v = self.read_op(st, ins, 0);
                    (v, false, false)
                }
            }
        };
        if skip {
            return;
        }
        let regs = self.conv.arg_regs();
        let idx = |r: &&str| GPR.iter().position(|g| g == r).unwrap() as u8;
        let mut n_regs = 0;
        for (k, r) in regs.iter().enumerate() {
            if st.dirty.contains(&idx(r)) {
                n_regs = k + 1;
            }
        }
        // a known prototype tells us exactly how many arguments the call takes
        let proto = match &callee {
            Ex::Var(n) => crate::protos::find(n),
            Ex::Cast(ty, _) => function_pointer_proto(ty),
            Ex::CastOwned(ty, _) => function_pointer_proto(ty),
            _ => None,
        };
        if let Some(p) = &proto {
            let np = p.params.len().min(regs.len());
            n_regs = if p.variadic { n_regs.max(np) } else { np };
        }
        let noret = noret || proto.as_ref().map(|p| p.noreturn).unwrap_or(false);
        let mut args: Vec<Ex> = vec![];
        for r in regs.iter().take(n_regs) {
            let i = idx(r);
            args.push(match st.env.get(&i) {
                Some(e) => e.clone(),
                None => {
                    st.uses.insert(i);
                    Ex::Var(GPR[i as usize].to_string())
                }
            });
        }
        // short strings ("r", "w+") are below the string-detection length, but a char* parameter tells us what they are
        if let Some(p) = &proto {
            for (k, a) in args.iter_mut().enumerate() {
                let is_cstr = p.params.get(k).map(|(t, _)| t.contains("char") && t.contains('*')).unwrap_or(false);
                if !is_cstr { continue; }
                let addr = match a {
                    Ex::Un("&", inner) => match &**inner {
                        Ex::Var(v) => v.strip_prefix("unk_").and_then(|h| u64::from_str_radix(h, 16).ok()),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(ad) = addr {
                    let b = self.bin.read(ad, 8);
                    if let Some(end) = b.iter().position(|c| *c == 0) {
                        if end >= 1 && b[..end].iter().all(|c| (0x20..0x7f).contains(c)) {
                            *a = Ex::Raw(format!("\"{}\"", crate::code::escape_str(&String::from_utf8_lossy(&b[..end]), 8)));
                        }
                    }
                }
            }
        }
        if let Ex::Var(fname) = &callee {
            let literal = |a: &Ex| -> Option<String> {
                let Ex::Raw(raw) = a else { return None };
                raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')).map(str::to_string)
            };
            if fname == "objc_msgSend" {
                if let Some(arg) = args.get_mut(1) {
                    if let Some(selector) = literal(arg) { *arg = Ex::Raw(format!("@selector({selector})")); }
                }
            } else if fname == "objc_getClass" {
                if let Some(arg) = args.get_mut(0) {
                    if let Some(class_name) = literal(arg) { *arg = Ex::Raw(format!("@class({class_name})")); }
                }
            }
        }
        if let Some(p) = &proto {
            for (k, a) in args.iter_mut().enumerate() {
                let Some(ty) = p.params.get(k).map(|(t, _)| t.trim_start_matches("enum ")) else { continue };
                if let Ex::Num(v) = a {
                    if let Some(member) = self.enum_constants.get(ty).and_then(|values| values.get(v)) {
                        *a = Ex::Var(format!("{ty}::{member}"));
                    }
                }
            }
        }
        // magic numbers in arguments become the constant names they stand for
        if let Ex::Var(fname) = &callee {
            let os = crate::consts::os_of(&self.bin.format);
            for (k, a) in args.iter_mut().enumerate() {
                if let Ex::Num(v) = a {
                    if let Some(sym) = crate::consts::symbolize(os, fname, k, *v) {
                        *a = Ex::Var(sym);
                    }
                }
            }
        }
        // Preserve an explicit pointer prototype at known call boundaries. The
        // prototype is authoritative here, so inferred values can retain their
        // pointer type instead of losing it at the call expression.
        if let Some(p) = &proto {
            for (k, a) in args.iter_mut().enumerate() {
                let Some(ty) = p.params.get(k).map(|(t, _)| t.as_str()) else { continue };
                let pointer_like = ty.ends_with('*') || ty.contains("(*") || ty.starts_with("fn(") || ty.contains('[');
                if pointer_like && !matches!(a, Ex::Cast(_, _) | Ex::CastOwned(_, _)) {
                    let old = std::mem::replace(a, Ex::Num(0));
                    *a = Ex::CastOwned(ty.to_string(), Box::new(old));
                }
            }
        }
        let mut pend = std::mem::take(&mut st.pending);
        pend.reverse();
        args.extend(pend);
        // caller-saved registers die with the call
        let dead: Vec<u8> = match self.conv {
            CallConv::Win64 => vec![0, 1, 2, 8, 9, 10, 11],
            _ => vec![0, 1, 2, 6, 7, 8, 9, 10, 11],
        };
        for d in &dead {
            st.env.remove(d);
        }
        // everything else that reads memory must be read before the callee can change it
        self.freeze(st, addr, true, None);
        let call = Ex::Call(Box::new(callee), args);
        if noret {
            st.stmts.push((addr, Stmt::Expr(call)));
            st.stmts.push((addr, Stmt::Comment("does not return".into())));
            st.flags = Flags::None;
            // mark so the terminator becomes Stop
            st.out_args_used = true;
            return;
        }
        self.tmp += 1;
        let t = format!("v{}", self.tmp);
        let call_value = typed_call_value(proto.as_ref(), call);
        st.stmts.push((addr, Stmt::Assign(var(&t), call_value)));
        st.env.insert(RAX, var(&t));
        st.modified.insert(RAX);
        st.modified.extend(dead.iter().copied());
        st.dirty.clear();
        st.dirty.insert(RAX);
        st.flags = Flags::None;
    }

    fn exec(&mut self, f: &Function, bi: usize, sp_in: i64, bp_in: Option<i64>, is_entry: bool) -> BlockOut {
        let blk = &f.blocks[bi];
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
        let decoded: Vec<(u64, Instruction, crate::analysis::Insn)> =
            blk.insns.iter().filter_map(|a| decode_at(self.bin, *a).map(|(i, info)| (*a, i, info))).collect();
        // epilogue = trailing pops / leave / add rsp before ret
        let mut epi_from = decoded.len();
        if decoded.last().map(|d| d.2.flow == Flow::Ret).unwrap_or(false) {
            let mut k = decoded.len() - 1;
            while k > 0 {
                let m = decoded[k - 1].1.mnemonic();
                let ins = &decoded[k - 1].1;
                let ok = matches!(m, Mnemonic::Pop | Mnemonic::Leave | Mnemonic::Nop)
                    || (matches!(m, Mnemonic::Add | Mnemonic::Mov | Mnemonic::Lea) && ins.op_kind(0) == OpKind::Register && ins.op0_register() == if self.word == 8 { Register::RSP } else { Register::ESP });
                if ok {
                    k -= 1;
                } else {
                    break;
                }
            }
            epi_from = k;
        }
        let mut in_prologue = is_entry;
        let mut term = Term::Fall(blk.end);
        let mut term_addr = blk.end;
        let mut ret_val_known = false;
        for (k, (addr, ins, info)) in decoded.iter().enumerate() {
            let addr = *addr;
            let m = ins.mnemonic();
            let in_epi = k >= epi_from;
            // prologue: push regs, mov rbp,rsp, sub rsp
            if in_prologue {
                let pro = match m {
                    Mnemonic::Push => ins.op_kind(0) == OpKind::Register,
                    Mnemonic::Mov => ins.op_kind(0) == OpKind::Register && ins.op0_register() == Register::RBP && ins.op_kind(1) == OpKind::Register && ins.op1_register() == Register::RSP
                        || ins.op_kind(0) == OpKind::Register && ins.op0_register() == Register::EBP && ins.op_kind(1) == OpKind::Register && ins.op1_register() == Register::ESP,
                    Mnemonic::Sub | Mnemonic::Endbr64 | Mnemonic::Endbr32 | Mnemonic::Nop => true,
                    _ => false,
                };
                if !pro {
                    in_prologue = false;
                }
            }
            match m {
                Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 | Mnemonic::Int3 | Mnemonic::Ud2 | Mnemonic::Hlt if m != Mnemonic::Ud2 && m != Mnemonic::Hlt => {}
                Mnemonic::Ud2 | Mnemonic::Hlt => {
                    st.stmts.push((addr, Stmt::Comment(format!("{}", format!("{m:?}").to_lowercase()))));
                    st.out_args_used = true;
                }
                Mnemonic::Push => {
                    st.sp -= self.word;
                    if in_prologue && ins.op_kind(0) == OpKind::Register {
                        continue;
                    }
                    let v = self.read_op(&mut st, ins, 0);
                    if self.word == 4 {
                        st.pending.push(v);
                    } else {
                        st.stmts.push((addr, Stmt::Expr(Ex::Call(Box::new(var("push")), vec![v]))));
                    }
                }
                Mnemonic::Pop => {
                    st.sp += self.word;
                    if in_epi {
                        continue;
                    }
                    let v = if self.word == 4 && !st.pending.is_empty() { st.pending.pop().unwrap() } else { Ex::Call(Box::new(var("pop")), vec![]) };
                    self.write_op(&mut st, ins, 0, v);
                }
                Mnemonic::Leave => {
                    if let Some(b) = st.bp {
                        st.sp = b + self.word;
                    }
                }
                Mnemonic::Mov if ins.op_kind(0) == OpKind::Register && ins.op0_register().full_register() == Register::RSP => {
                    if ins.op_kind(1) == OpKind::Register && ins.op1_register().full_register() == Register::RBP {
                        if let Some(b) = st.bp {
                            st.sp = b;
                        }
                    } else if ins.op_kind(1) == OpKind::Register && ins.op1_register().full_register() == Register::RSP {
                        st.bp = Some(st.sp);
                    }
                }
                Mnemonic::Mov if ins.op_kind(0) == OpKind::Register && ins.op0_register().full_register() == Register::RBP && ins.op_kind(1) == OpKind::Register && ins.op1_register().full_register() == Register::RSP && self.fp => {
                    st.bp = Some(st.sp);
                }
                Mnemonic::Sub | Mnemonic::Add if ins.op_kind(0) == OpKind::Register && ins.op0_register().full_register() == Register::RSP => {
                    if ins.op_kind(1) != OpKind::Register {
                        let v = ins.immediate(1) as i64;
                        let v = if ins.op_kind(1) == OpKind::Immediate32 && self.word == 4 { v as u32 as i32 as i64 } else { v };
                        if m == Mnemonic::Sub {
                            st.sp -= v;
                        } else {
                            st.sp += v;
                        }
                    }
                }
                Mnemonic::Lea if ins.op_kind(0) == OpKind::Register && ins.op0_register().full_register() == Register::RSP => {
                    if ins.memory_base().full_register() == Register::RBP {
                        if let Some(b) = st.bp {
                            st.sp = b + ins.memory_displacement64() as i64;
                        }
                    }
                }
                Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movaps | Mnemonic::Movups | Mnemonic::Movapd | Mnemonic::Movupd | Mnemonic::Movdqa
                | Mnemonic::Movdqu | Mnemonic::Movq | Mnemonic::Movd | Mnemonic::Movss | Mnemonic::Movsd
                | Mnemonic::Vmovaps | Mnemonic::Vmovups | Mnemonic::Vmovapd | Mnemonic::Vmovupd | Mnemonic::Vmovdqa | Mnemonic::Vmovdqu => {
                    if m == Mnemonic::Movsd && ins.op_count() == 0 {
                        continue;
                    }
                    let v = self.read_op(&mut st, ins, 1);
                    self.write_op(&mut st, ins, 0, v);
                }
                Mnemonic::Movsx | Mnemonic::Movsxd => {
                    let v = self.read_op(&mut st, ins, 1);
                    let sz = if ins.op_kind(1) == OpKind::Register { ins.op1_register().size() } else { ins.memory_size().size() };
                    let t = match sz {
                        1 => "int8_t",
                        2 => "int16_t",
                        _ => "int32_t",
                    };
                    let v = match v {
                        Ex::Cast(_, inner) => *inner,
                        v => v,
                    };
                    self.write_op(&mut st, ins, 0, Ex::Cast(t, Box::new(v)));
                }
                Mnemonic::Cdqe => {
                    let v = self.rd_reg(&mut st, Register::EAX);
                    self.wr_reg(&mut st, Register::RAX, Ex::Cast("int32_t", Box::new(v)), addr);
                }
                Mnemonic::Cdq | Mnemonic::Cqo | Mnemonic::Cwd => {
                    let value = self.rd_reg(&mut st, Register::RAX);
                    self.wr_reg(&mut st, Register::RDX, Ex::Call(Box::new(var("__sign_extend_high")), vec![value]), addr);
                }
                Mnemonic::Vfmadd132ps | Mnemonic::Vfmadd132pd | Mnemonic::Vfmadd132ss | Mnemonic::Vfmadd132sd
                | Mnemonic::Vfmadd213ps | Mnemonic::Vfmadd213pd | Mnemonic::Vfmadd213ss | Mnemonic::Vfmadd213sd
                | Mnemonic::Vfmadd231ps | Mnemonic::Vfmadd231pd | Mnemonic::Vfmadd231ss | Mnemonic::Vfmadd231sd
                | Mnemonic::Vfmsub132ps | Mnemonic::Vfmsub132pd | Mnemonic::Vfmsub132ss | Mnemonic::Vfmsub132sd
                | Mnemonic::Vfmsub213ps | Mnemonic::Vfmsub213pd | Mnemonic::Vfmsub213ss | Mnemonic::Vfmsub213sd
                | Mnemonic::Vfmsub231ps | Mnemonic::Vfmsub231pd | Mnemonic::Vfmsub231ss | Mnemonic::Vfmsub231sd
                | Mnemonic::Vfnmadd132ps | Mnemonic::Vfnmadd132pd | Mnemonic::Vfnmadd132ss | Mnemonic::Vfnmadd132sd
                | Mnemonic::Vfnmadd213ps | Mnemonic::Vfnmadd213pd | Mnemonic::Vfnmadd213ss | Mnemonic::Vfnmadd213sd
                | Mnemonic::Vfnmadd231ps | Mnemonic::Vfnmadd231pd | Mnemonic::Vfnmadd231ss | Mnemonic::Vfnmadd231sd
                | Mnemonic::Vfnmsub132ps | Mnemonic::Vfnmsub132pd | Mnemonic::Vfnmsub132ss | Mnemonic::Vfnmsub132sd
                | Mnemonic::Vfnmsub213ps | Mnemonic::Vfnmsub213pd | Mnemonic::Vfnmsub213ss | Mnemonic::Vfnmsub213sd
                | Mnemonic::Vfnmsub231ps | Mnemonic::Vfnmsub231pd | Mnemonic::Vfnmsub231ss | Mnemonic::Vfnmsub231sd
                if ins.op_count() >= 3 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Vblendvps | Mnemonic::Vblendvpd | Mnemonic::Vpermilps | Mnemonic::Vpermilpd
                | Mnemonic::Vpshufb | Mnemonic::Vpshufd | Mnemonic::Vpshufhw | Mnemonic::Vpshuflw
                | Mnemonic::Vshufps | Mnemonic::Vshufpd
                if ins.op_count() >= 2 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Paddb | Mnemonic::Paddw | Mnemonic::Paddd | Mnemonic::Paddq
                | Mnemonic::Psubb | Mnemonic::Psubw | Mnemonic::Psubd | Mnemonic::Psubq
                | Mnemonic::Vpaddb | Mnemonic::Vpaddw | Mnemonic::Vpaddd | Mnemonic::Vpaddq
                | Mnemonic::Vpsubb | Mnemonic::Vpsubw | Mnemonic::Vpsubd | Mnemonic::Vpsubq
                | Mnemonic::Vpand | Mnemonic::Vpandd | Mnemonic::Vpandq | Mnemonic::Vpandn
                | Mnemonic::Vpor | Mnemonic::Vpord | Mnemonic::Vporq | Mnemonic::Vpxor | Mnemonic::Vpxord | Mnemonic::Vpxorq
                | Mnemonic::Vpmulld | Mnemonic::Vpmullq
                if ins.op_count() >= 2 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Pcmpeqb | Mnemonic::Pcmpeqw | Mnemonic::Pcmpeqd | Mnemonic::Pcmpeqq
                | Mnemonic::Pcmpgtb | Mnemonic::Pcmpgtw | Mnemonic::Pcmpgtd | Mnemonic::Pcmpgtq
                | Mnemonic::Vpcmpeqb | Mnemonic::Vpcmpeqw | Mnemonic::Vpcmpeqd | Mnemonic::Vpcmpeqq
                | Mnemonic::Vpcmpgtb | Mnemonic::Vpcmpgtw | Mnemonic::Vpcmpgtd | Mnemonic::Vpcmpgtq
                | Mnemonic::Vcmpps | Mnemonic::Vcmppd | Mnemonic::Vcmpss | Mnemonic::Vcmpsd
                if ins.op_count() >= 2 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Vpermd | Mnemonic::Vpermq | Mnemonic::Vpermps | Mnemonic::Vpermpd
                | Mnemonic::Vgatherdpd | Mnemonic::Vgatherdps | Mnemonic::Vgatherqpd | Mnemonic::Vgatherqps
                | Mnemonic::Vpgatherdd | Mnemonic::Vpgatherdq | Mnemonic::Vpgatherqd | Mnemonic::Vpgatherqq
                if ins.op_count() >= 2 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Vpmovdb | Mnemonic::Vpmovdw | Mnemonic::Vpmovqb | Mnemonic::Vpmovqd | Mnemonic::Vpmovqw
                | Mnemonic::Vpmovsdb | Mnemonic::Vpmovsdw | Mnemonic::Vpmovsqb | Mnemonic::Vpmovsqd | Mnemonic::Vpmovsqw | Mnemonic::Vpmovswb
                | Mnemonic::Vpmovusdb | Mnemonic::Vpmovusdw | Mnemonic::Vpmovusqb | Mnemonic::Vpmovusqd | Mnemonic::Vpmovusqw | Mnemonic::Vpmovuswb
                | Mnemonic::Vpmovsxbd | Mnemonic::Vpmovsxbq | Mnemonic::Vpmovsxbw | Mnemonic::Vpmovsxdq | Mnemonic::Vpmovsxwd | Mnemonic::Vpmovsxwq
                | Mnemonic::Vpmovzxbd | Mnemonic::Vpmovzxbq | Mnemonic::Vpmovzxbw | Mnemonic::Vpmovzxdq | Mnemonic::Vpmovzxwd | Mnemonic::Vpmovzxwq
                | Mnemonic::Vpmovmskb
                if ins.op_count() >= 2 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Vpsllw | Mnemonic::Vpslld | Mnemonic::Vpsllq | Mnemonic::Vpsllvd | Mnemonic::Vpsllvq
                | Mnemonic::Vpsrlw | Mnemonic::Vpsrld | Mnemonic::Vpsrlq | Mnemonic::Vpsrlvd | Mnemonic::Vpsrlvq
                | Mnemonic::Vpsraw | Mnemonic::Vpsrad | Mnemonic::Vpsravd
                if ins.op_count() >= 2 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Vpabsb | Mnemonic::Vpabsw | Mnemonic::Vpabsd | Mnemonic::Vpabsq
                | Mnemonic::Vpmaxsb | Mnemonic::Vpmaxsw | Mnemonic::Vpmaxsd | Mnemonic::Vpmaxsq
                | Mnemonic::Vpmaxub | Mnemonic::Vpmaxuw | Mnemonic::Vpmaxud | Mnemonic::Vpmaxuq
                | Mnemonic::Vpminsb | Mnemonic::Vpminsw | Mnemonic::Vpminsd | Mnemonic::Vpminsq
                | Mnemonic::Vpminub | Mnemonic::Vpminuw | Mnemonic::Vpminud | Mnemonic::Vpminuq
                if ins.op_count() >= 2 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Vpmulhw | Mnemonic::Vpmulhuw | Mnemonic::Vpmulhrsw | Mnemonic::Vpmaddubsw | Mnemonic::Vpmaddwd
                | Mnemonic::Vpmadd52huq | Mnemonic::Vpmadd52luq | Mnemonic::Vpmulhd | Mnemonic::Vpmulhud
                if ins.op_count() >= 2 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Kandb | Mnemonic::Kandd | Mnemonic::Kandnb | Mnemonic::Kandnd | Mnemonic::Kandnq | Mnemonic::Kandnw | Mnemonic::Kandq | Mnemonic::Kandw
                | Mnemonic::Kmovb | Mnemonic::Kmovd | Mnemonic::Kmovq | Mnemonic::Kmovw
                | Mnemonic::Knotb | Mnemonic::Knotd | Mnemonic::Knotq | Mnemonic::Knotw
                | Mnemonic::Korb | Mnemonic::Kord | Mnemonic::Korq | Mnemonic::Korw
                | Mnemonic::Kshiftlb | Mnemonic::Kshiftld | Mnemonic::Kshiftlq | Mnemonic::Kshiftlw
                | Mnemonic::Kshiftrb | Mnemonic::Kshiftrd | Mnemonic::Kshiftrq | Mnemonic::Kshiftrw
                | Mnemonic::Kxorb | Mnemonic::Kxord | Mnemonic::Kxorq | Mnemonic::Kxorw
                if ins.op_count() >= 1 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Vpdpbusd | Mnemonic::Vpdpbusds | Mnemonic::Vpdpwssd | Mnemonic::Vpdpwssds
                | Mnemonic::Vpdpbssd | Mnemonic::Vpdpbssds | Mnemonic::Vpdpbsud | Mnemonic::Vpdpbsuds
                | Mnemonic::Vpdpbuud | Mnemonic::Vpdpbuuds | Mnemonic::Vpdpwsud | Mnemonic::Vpdpwsuds
                | Mnemonic::Vpdpwusd | Mnemonic::Vpdpwusds | Mnemonic::Vpdpwuud | Mnemonic::Vpdpwuuds
                | Mnemonic::V4fmaddps | Mnemonic::V4fmaddss
                if ins.op_count() >= 2 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Vpternlogd | Mnemonic::Vpternlogq
                if ins.op_count() >= 3 => {
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(&format!("__{:?}", m))), args));
                }
                Mnemonic::Lea => {
                    let sz = 1;
                    let (a, _) = self.mem_operand(&mut st, ins, sz);
                    self.write_op(&mut st, ins, 0, a);
                }
                Mnemonic::Xchg => {
                    let a = self.read_op(&mut st, ins, 0);
                    let b = self.read_op(&mut st, ins, 1);
                    self.write_op(&mut st, ins, 0, b);
                    self.write_op(&mut st, ins, 1, a);
                }
                Mnemonic::Add | Mnemonic::Sub | Mnemonic::And | Mnemonic::Or | Mnemonic::Xor | Mnemonic::Shl | Mnemonic::Sal | Mnemonic::Shr
                | Mnemonic::Sar | Mnemonic::Addss | Mnemonic::Addsd | Mnemonic::Subss | Mnemonic::Subsd | Mnemonic::Mulss | Mnemonic::Mulsd
                | Mnemonic::Divss | Mnemonic::Divsd | Mnemonic::Addps | Mnemonic::Addpd | Mnemonic::Subps | Mnemonic::Subpd
                | Mnemonic::Mulps | Mnemonic::Mulpd | Mnemonic::Divps | Mnemonic::Divpd
                | Mnemonic::Vaddps | Mnemonic::Vaddpd | Mnemonic::Vsubps | Mnemonic::Vsubpd | Mnemonic::Vmulps | Mnemonic::Vmulpd | Mnemonic::Vdivps | Mnemonic::Vdivpd
                | Mnemonic::Minss | Mnemonic::Minsd | Mnemonic::Minps | Mnemonic::Minpd | Mnemonic::Maxss | Mnemonic::Maxsd | Mnemonic::Maxps | Mnemonic::Maxpd
                | Mnemonic::Vminss | Mnemonic::Vminsd | Mnemonic::Vminps | Mnemonic::Vminpd | Mnemonic::Vmaxss | Mnemonic::Vmaxsd | Mnemonic::Vmaxps | Mnemonic::Vmaxpd
                | Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Andps | Mnemonic::Andpd
                | Mnemonic::Orps | Mnemonic::Paddd | Mnemonic::Paddq | Mnemonic::Psubd | Mnemonic::Adc | Mnemonic::Sbb if ins.op_count() >= 2 => {
                    let a = self.read_op(&mut st, ins, 0);
                    let b = self.read_op(&mut st, ins, 1);
                    let same = ins.op_kind(0) == OpKind::Register && ins.op_kind(1) == OpKind::Register && ins.op0_register() == ins.op1_register();
                    let r = match m {
                        Mnemonic::Xor | Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd if same => Ex::Num(0),
                        Mnemonic::Add | Mnemonic::Addss | Mnemonic::Addsd | Mnemonic::Addps | Mnemonic::Addpd | Mnemonic::Vaddps | Mnemonic::Vaddpd | Mnemonic::Paddd | Mnemonic::Paddq => bin("+", a.clone(), b),
                        Mnemonic::Adc => bin("+", bin("+", a.clone(), b), Ex::Raw("CF".into())),
                        Mnemonic::Sub | Mnemonic::Subss | Mnemonic::Subsd | Mnemonic::Subps | Mnemonic::Subpd | Mnemonic::Vsubps | Mnemonic::Vsubpd | Mnemonic::Psubd => bin("-", a.clone(), b),
                        Mnemonic::Sbb => bin("-", bin("-", a.clone(), b), Ex::Raw("CF".into())),
                        Mnemonic::And | Mnemonic::Andps | Mnemonic::Andpd => bin("&", a.clone(), b),
                        Mnemonic::Or | Mnemonic::Orps => bin("|", a.clone(), b),
                        Mnemonic::Xor | Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd => bin("^", a.clone(), b),
                        Mnemonic::Shl | Mnemonic::Sal => bin("<<", a.clone(), b),
                        Mnemonic::Shr => bin(">>>", a.clone(), b),
                        Mnemonic::Sar => bin(">>", a.clone(), b),
                        Mnemonic::Mulss | Mnemonic::Mulsd | Mnemonic::Mulps | Mnemonic::Mulpd | Mnemonic::Vmulps | Mnemonic::Vmulpd => bin("*", a.clone(), b),
                        Mnemonic::Minss | Mnemonic::Minsd | Mnemonic::Minps | Mnemonic::Minpd | Mnemonic::Vminss | Mnemonic::Vminsd | Mnemonic::Vminps | Mnemonic::Vminpd => Ex::Call(Box::new(var("fmin")), vec![a.clone(), b]),
                        Mnemonic::Maxss | Mnemonic::Maxsd | Mnemonic::Maxps | Mnemonic::Maxpd | Mnemonic::Vmaxss | Mnemonic::Vmaxsd | Mnemonic::Vmaxps | Mnemonic::Vmaxpd => Ex::Call(Box::new(var("fmax")), vec![a.clone(), b]),
                        _ => bin("/", a.clone(), b),
                    };
                    st.flags = match m {
                        Mnemonic::Sub => Flags::Cmp(a, self.read_op(&mut st, ins, 1)),
                        _ => Flags::Op(r.clone()),
                    };
                    self.write_op(&mut st, ins, 0, r);
                }
                Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg | Mnemonic::Not => {
                    let a = self.read_op(&mut st, ins, 0);
                    let r = match m {
                        Mnemonic::Inc => bin("+", a, Ex::Num(1)),
                        Mnemonic::Dec => bin("-", a, Ex::Num(1)),
                        Mnemonic::Neg => {
                            st.flags = Flags::Cmp(Ex::Num(0), a.clone());
                            un("-", a)
                        }
                        _ => un("~", a),
                    };
                    if m != Mnemonic::Neg && m != Mnemonic::Not {
                        st.flags = Flags::Op(r.clone());
                    }
                    self.write_op(&mut st, ins, 0, r);
                }
                Mnemonic::Imul if ins.op_count() >= 2 => {
                    let (a, b) = if ins.op_count() == 3 {
                        (self.read_op(&mut st, ins, 1), self.read_op(&mut st, ins, 2))
                    } else {
                        (self.read_op(&mut st, ins, 0), self.read_op(&mut st, ins, 1))
                    };
                    let r = bin("*", a, b);
                    st.flags = Flags::Op(r.clone());
                    self.write_op(&mut st, ins, 0, r);
                }
                Mnemonic::Imul | Mnemonic::Mul => {
                    let a = self.rd_reg(&mut st, Register::RAX);
                    let b = self.read_op(&mut st, ins, 0);
                    self.wr_reg(&mut st, Register::RDX, Ex::Call(Box::new(var("__mulhi")), vec![a.clone(), b.clone()]), addr);
                    self.wr_reg(&mut st, Register::RAX, bin("*", a, b), addr);
                }
                Mnemonic::Rol | Mnemonic::Ror if ins.op_count() >= 2 && matches!(ins.op_kind(1), OpKind::Immediate8 | OpKind::Register) => {
                    let value = self.read_op(&mut st, ins, 0);
                    let bits = (ins.op0_register().size() as u32 * 8).clamp(8, 64);
                    let shift = if ins.op_kind(1) == OpKind::Immediate8 { Ex::Num((ins.immediate8() as u32 % bits) as i64) } else { self.read_op(&mut st, ins, 1) };
                    let zero = matches!(shift, Ex::Num(0));
                    let opposite = if let Ex::Num(n) = &shift { Ex::Num((bits as i64 - *n).rem_euclid(bits as i64)) } else { bin("-", Ex::Num(bits as i64), shift.clone()) };
                    let r = if zero {
                        value
                    } else if m == Mnemonic::Rol {
                        bin("|", bin("<<", value.clone(), shift), bin(">>>", value, opposite))
                    } else {
                        bin("|", bin(">>>", value.clone(), shift), bin("<<", value, opposite))
                    };
                    self.write_op(&mut st, ins, 0, r);
                }
                Mnemonic::Shld | Mnemonic::Shrd if ins.op_count() >= 3 && matches!(ins.op_kind(2), OpKind::Immediate8 | OpKind::Register) => {
                    let dst = self.read_op(&mut st, ins, 0);
                    let src = self.read_op(&mut st, ins, 1);
                    let bits = (ins.op0_register().size() as u32 * 8).clamp(8, 64);
                    let shift = if ins.op_kind(2) == OpKind::Immediate8 { Ex::Num((ins.immediate8() as u32 % bits) as i64) } else { self.read_op(&mut st, ins, 2) };
                    let opposite = if let Ex::Num(n) = &shift { Ex::Num((bits as i64 - *n).rem_euclid(bits as i64)) } else { bin("-", Ex::Num(bits as i64), shift.clone()) };
                    let r = if ins.mnemonic() == Mnemonic::Shld {
                        bin("|", bin("<<", dst, shift), bin(">>>", src, opposite))
                    } else {
                        bin("|", bin(">>>", dst, shift), bin("<<", src, opposite))
                    };
                    self.write_op(&mut st, ins, 0, r);
                }
                Mnemonic::Popcnt | Mnemonic::Tzcnt | Mnemonic::Lzcnt | Mnemonic::Bsf | Mnemonic::Bsr if ins.op_count() >= 2 => {
                    let value = self.read_op(&mut st, ins, 1);
                    let name = match m {
                        Mnemonic::Popcnt => "popcount",
                        Mnemonic::Tzcnt | Mnemonic::Bsf => "ctz",
                        Mnemonic::Lzcnt => "clz",
                        Mnemonic::Bsr => "msb_index",
                        _ => "bitop",
                    };
                    let value = if m == Mnemonic::Bsr {
                        bin("-", Ex::Num((ins.op0_register().size() as i64 * 8) - 1), Ex::Call(Box::new(var("clz")), vec![value]))
                    } else {
                        Ex::Call(Box::new(var(name)), vec![value])
                    };
                    self.write_op(&mut st, ins, 0, value);
                }
                Mnemonic::Pext | Mnemonic::Pdep | Mnemonic::Bzhi if ins.op_count() >= 3 => {
                    let name = match m { Mnemonic::Pext => "pext", Mnemonic::Pdep => "pdep", _ => "bzhi" };
                    let args = (1..ins.op_count()).map(|i| self.read_op(&mut st, ins, i)).collect();
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(name)), args));
                }
                Mnemonic::Bswap if ins.op_count() >= 1 => {
                    let value = self.read_op(&mut st, ins, 0);
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var("byteswap")), vec![value]));
                }
                Mnemonic::Blsi | Mnemonic::Blsr | Mnemonic::Blsmsk if ins.op_count() >= 2 => {
                    let value = self.read_op(&mut st, ins, 1);
                    let helper = match m { Mnemonic::Blsi => "blsi", Mnemonic::Blsr => "blsr", _ => "blsmsk" };
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(helper)), vec![value]));
                }
                Mnemonic::Bextr if ins.op_count() >= 3 => {
                    let value = self.read_op(&mut st, ins, 1);
                    let control = self.read_op(&mut st, ins, 2);
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var("bextr")), vec![value, control]));
                }
                Mnemonic::Mulx if ins.op_count() >= 3 => {
                    let a = self.rd_reg(&mut st, Register::RDX);
                    let b = self.read_op(&mut st, ins, 2);
                    let wide = Ex::Call(Box::new(var("mulx")), vec![a, b]);
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var("mulx_low")), vec![wide.clone()]));
                    self.write_op(&mut st, ins, 1, Ex::Call(Box::new(var("mulx_high")), vec![wide]));
                }
                Mnemonic::Rorx if ins.op_count() >= 3 => {
                    let value = self.read_op(&mut st, ins, 1);
                    let amount = self.read_op(&mut st, ins, 2);
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var("rorx")), vec![value, amount]));
                }
                Mnemonic::Adcx | Mnemonic::Adox if ins.op_count() >= 2 => {
                    let acc = self.read_op(&mut st, ins, 0);
                    let value = self.read_op(&mut st, ins, 1);
                    let helper = if m == Mnemonic::Adcx { "adcx" } else { "adox" };
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(helper)), vec![acc, value]));
                }
                Mnemonic::Shlx | Mnemonic::Shrx | Mnemonic::Sarx if ins.op_count() >= 3 => {
                    let value = self.read_op(&mut st, ins, 1);
                    let amount = self.read_op(&mut st, ins, 2);
                    let helper = match m { Mnemonic::Shlx => "shlx", Mnemonic::Shrx => "shrx", _ => "sarx" };
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var(helper)), vec![value, amount]));
                }
                Mnemonic::Idiv | Mnemonic::Div => {
                    let a = Ex::Call(Box::new(var("__wide_dividend")), vec![
                        self.rd_reg(&mut st, Register::RDX),
                        self.rd_reg(&mut st, Register::RAX),
                    ]);
                    let b = self.read_op(&mut st, ins, 0);
                    self.wr_reg(&mut st, Register::RDX, Ex::Bin("%", Box::new(a.clone()), Box::new(b.clone())), addr);
                    self.wr_reg(&mut st, Register::RAX, Ex::Bin("/", Box::new(a), Box::new(b)), addr);
                }
                Mnemonic::Cmp | Mnemonic::Ucomiss | Mnemonic::Ucomisd | Mnemonic::Comiss | Mnemonic::Comisd => {
                    let a = self.read_op(&mut st, ins, 0);
                    let b = self.read_op(&mut st, ins, 1);
                    st.flags = Flags::Cmp(a, b);
                }
                Mnemonic::Test => {
                    let a = self.read_op(&mut st, ins, 0);
                    let b = self.read_op(&mut st, ins, 1);
                    st.flags = if a == b { Flags::Op(a) } else { Flags::Op(bin("&", a, b)) };
                }
                Mnemonic::Cvtsi2sd | Mnemonic::Cvtsi2ss | Mnemonic::Cvtss2sd | Mnemonic::Cvtsd2ss | Mnemonic::Cvttsd2si | Mnemonic::Cvttss2si
                | Mnemonic::Cvtsd2si | Mnemonic::Cvtss2si => {
                    let t = match m {
                        Mnemonic::Cvtsi2sd | Mnemonic::Cvtss2sd => "double",
                        Mnemonic::Cvtsi2ss | Mnemonic::Cvtsd2ss => "float",
                        _ => "int64_t",
                    };
                    let v = self.read_op(&mut st, ins, 1);
                    self.write_op(&mut st, ins, 0, Ex::Cast(t, Box::new(v)));
                }
                Mnemonic::Sqrtss | Mnemonic::Sqrtsd => {
                    let v = self.read_op(&mut st, ins, 1);
                    self.write_op(&mut st, ins, 0, Ex::Call(Box::new(var("sqrt")), vec![v]));
                }
                Mnemonic::Call => {
                    self.do_call(&mut st, ins, info);
                    if st.out_args_used {
                        term = Term::Stop;
                        term_addr = addr;
                        break;
                    }
                }
                Mnemonic::Ret | Mnemonic::Retf => {
                    let rax_set = st.modified.contains(&RAX) || st.env.contains_key(&RAX);
                    let v = if rax_set || ret_val_known {
                        Some(self.rd_reg(&mut st, Register::RAX))
                    } else {
                        None
                    };
                    term = Term::Ret(v);
                    term_addr = addr;
                }
                _ => {
                    let ms = format!("{m:?}");
                    if info.flow == Flow::CondJump {
                        let cc = ins.condition_code();
                        let cond = cc_expr(cc, &st.flags);
                        let fall = ins.next_ip();
                        term = Term::Cond { cond, taken: info.target, fall };
                        term_addr = addr;
                    } else if info.flow == Flow::Jump {
                        term = Term::Jmp(info.target);
                        term_addr = addr;
                    } else if info.flow == Flow::IndirectJump {
                        let v = self.read_op(&mut st, ins, 0);
                        term = Term::Indirect(v);
                        term_addr = addr;
                    } else if ms.starts_with("Set") && ins.op_count() == 1 {
                        let cond = cc_expr(ins.condition_code(), &st.flags);
                        self.write_op(&mut st, ins, 0, cond);
                    } else if ms.starts_with("Cmov") && ins.op_count() == 2 {
                        let cond = cc_expr(ins.condition_code(), &st.flags);
                        let a = self.read_op(&mut st, ins, 1);
                        let old = self.read_op(&mut st, ins, 0);
                        self.write_op(&mut st, ins, 0, tern(cond, a, old));
                    } else {
                        // anything else becomes an intrinsic so nothing is silently dropped
                        let name = format!("__{}", ms.to_lowercase());
                        let n = ins.op_count();
                        if n == 0 {
                            st.stmts.push((addr, Stmt::Comment(ms.to_lowercase())));
                            continue;
                        }
                        let writes_op0 = !matches!(m, Mnemonic::Bt | Mnemonic::Ptest | Mnemonic::Prefetcht0 | Mnemonic::Prefetchnta | Mnemonic::Clflush);
                        let args: Vec<Ex> = (if writes_op0 { 1 } else { 0 }..n).map(|i| self.read_op(&mut st, ins, i)).collect();
                        let mut args = args;
                        if writes_op0 && matches!(ins.op_kind(0), OpKind::Register | OpKind::Memory) && (matches!(m, Mnemonic::Rol | Mnemonic::Ror | Mnemonic::Bswap | Mnemonic::Bsf | Mnemonic::Bsr | Mnemonic::Popcnt) || n == 1) {
                            let a = self.read_op(&mut st, ins, 0);
                            if matches!(m, Mnemonic::Rol | Mnemonic::Ror | Mnemonic::Bswap) || n == 1 {
                                args.insert(0, a);
                            }
                        }
                        let call = Ex::Call(Box::new(var(&name)), args);
                        if writes_op0 && matches!(ins.op_kind(0), OpKind::Register | OpKind::Memory) {
                            self.write_op(&mut st, ins, 0, call);
                        } else {
                            st.flags = Flags::Op(call);
                        }
                    }
                }
            }
        }
        let _ = &mut ret_val_known;
        // fall-through block end: a block that ends because the next one starts
        if let Term::Fall(_) = term {
            let next = blk.succs.first().map(|s| s.0);
            term = match next {
                Some(n) => Term::Fall(n),
                None => Term::Stop,
            };
        }
        // direct-jump terminators found through block successors (jmp to an import etc. = tail call)
        if let Term::Jmp(t) = &term {
            if !f.blocks.iter().any(|b| b.start == *t) && self.an.functions.contains_key(t) {
                // tail call: call then return
                let fake = Ex::Call(Box::new(Ex::Var(self.callee_name(*t))), vec![]);
                let regs = self.conv.arg_regs();
                let mut args = vec![];
                for r in regs {
                    let i = GPR.iter().position(|g| g == r).unwrap() as u8;
                    if st.dirty.contains(&i) {
                        args.push(st.env.get(&i).cloned().unwrap_or(var(r)));
                    }
                }
                let call = if let Ex::Call(f, _) = fake { Ex::Call(f, args) } else { fake };
                term = Term::Ret(Some(call));
            }
        }
        let defs: BTreeMap<u8, Ex> = st.modified.iter().filter_map(|r| st.env.get(r).map(|e| (*r, e.clone()))).filter(|(r, e)| *e != Ex::Var(reg_name(*r))).collect();
        // ret uses rax (resolved later)
        BlockOut { stmts: st.stmts, defs, uses: st.uses, term, term_addr }
    }
}

trait PipeNonEmpty {
    fn pipe_nonempty(self, a: u64) -> String;
}
impl PipeNonEmpty for String {
    fn pipe_nonempty(self, a: u64) -> String {
        if self.is_empty() {
            format!("sub_{a:X}")
        } else {
            self
        }
    }
}

// ------------------------------------------------------------------ structuring

struct Emit<'a> {
    f: &'a Function,
    outs: &'a [BlockOut],
    mat: Vec<Vec<(u8, Ex)>>,
    idx: HashMap<u64, usize>,
    fmt: Fmt<'a>,
    lines: Vec<DLine>,
    labels: HashSet<u64>,
    suppress: HashSet<usize>,
    open: HashSet<usize>,
    loops: HashMap<usize, Vec<usize>>,
    done: HashSet<usize>,
    switches: &'a HashMap<u64, Vec<u64>>,
    switch_case_indices: &'a HashMap<u64, Vec<i64>>,
    enum_constants: &'a HashMap<String, HashMap<i64, String>>,
    enum_return: Option<String>,
    enum_vars: HashMap<String, String>,
}

impl Emit<'_> {
    fn line(&mut self, ind: usize, addr: u64, text: String) {
        self.lines.push(DLine { text, addr, indent: ind });
    }

    fn block_stmts(&mut self, b: usize, ind: usize) {
        let blk_start = self.f.blocks[b].start;
        if self.labels.contains(&blk_start) {
            // labels are printed at indent-1 so they stand out
            self.line(ind.saturating_sub(1), blk_start, format!("L_{blk_start:X}:"));
        }
        let outs = self.outs;
        let o = &outs[b];
        for (addr, s) in &o.stmts {
            let t = match s {
                Stmt::Assign(l, r) => format!("{} = {};", self.fmt.show(l), self.fmt.show(r)),
                Stmt::Expr(e) => format!("{};", self.fmt.show(e)),
                Stmt::Comment(c) => format!("// {c}"),
            };
            self.line(ind, *addr, t);
        }
        for (r, e) in self.mat[b].clone() {
            let n = self.fmt.show(&var(&reg_name(r)));
            let v = self.fmt.show(&e);
            if n != v {
                self.line(ind, o.term_addr, format!("{n} = {v};"));
            }
        }
    }

    fn stmts_empty(&self, b: usize) -> bool {
        self.outs[b].stmts.is_empty() && self.mat[b].is_empty()
    }

    fn cond_for(&self, b: usize) -> Option<Ex> {
        let o = &self.outs[b];
        if let Term::Cond { cond, .. } = &o.term {
            let mut c = cond.clone();
            for (r, e) in &self.mat[b] {
                if *e != Ex::Var(reg_name(*r)) {
                    c = subst(&c, e, &Ex::Var(reg_name(*r)));
                }
            }
            return Some(self.enumize(c));
        }
        None
    }

    fn enumize(&self, e: Ex) -> Ex {
        match e {
            Ex::Bin(op, left, right) => {
                let left = self.enumize(*left);
                let right = self.enumize(*right);
                let named = |param: &Ex, value: &Ex| -> Option<Ex> {
                    let value = enum_const_int(value)?;
                    let ty = self.enum_type(param)?;
                    let values = self.enum_constants.get(&ty)?;
                    if let Some(member) = values.get(&value) {
                        return Some(Ex::Var(format!("{ty}::{member}")));
                    }
                    if value <= 0 { return None; }
                    let mut parts: Vec<(i64, Ex)> = values.iter()
                        .filter(|(candidate, _)| **candidate > 0 && (**candidate & (**candidate - 1)) == 0 && (**candidate & value) != 0)
                        .map(|(candidate, member)| (*candidate, Ex::Var(format!("{ty}::{member}"))))
                        .collect();
                    parts.sort_by_key(|(candidate, _)| std::cmp::Reverse(*candidate));
                    let mut remaining = value;
                    let mut named = vec![];
                    for (candidate, member) in parts {
                        if remaining & candidate == candidate {
                            remaining &= !candidate;
                            named.push(member);
                        }
                    }
                    if remaining == 0 && named.len() > 1 {
                        let mut out = named.into_iter();
                        let first = out.next().unwrap();
                        Some(out.fold(first, |left, right| Ex::Bin("|", Box::new(left), Box::new(right))))
                    } else {
                        None
                    }
                };
                if let Some(value) = named(&left, &right) { return Ex::Bin(op, Box::new(left), Box::new(value)); }
                if let Some(value) = named(&right, &left) { return Ex::Bin(op, Box::new(value), Box::new(right)); }
                Ex::Bin(op, Box::new(left), Box::new(right))
            }
            Ex::Un(op, value) => Ex::Un(op, Box::new(self.enumize(*value))),
            Ex::Cast(op, value) => Ex::Cast(op, Box::new(self.enumize(*value))),
            Ex::CastOwned(op, value) => Ex::CastOwned(op, Box::new(self.enumize(*value))),
            Ex::Deref(value, size) => Ex::Deref(Box::new(self.enumize(*value)), size),
            Ex::Tern(a, b, c) => Ex::Tern(Box::new(self.enumize(*a)), Box::new(self.enumize(*b)), Box::new(self.enumize(*c))),
            Ex::Call(f, args) => Ex::Call(Box::new(self.enumize(*f)), args.into_iter().map(|a| self.enumize(a)).collect()),
            other => other,
        }
    }

    fn enum_type(&self, e: &Ex) -> Option<String> {
        match e {
            Ex::Var(name) => self.enum_vars.get(name).cloned().or_else(|| {
                let (ty, member) = name.split_once("::")?;
                self.enum_constants.get(ty)?.values().any(|known| known == member).then(|| ty.to_string())
            }),
            Ex::Cast(_, inner) | Ex::CastOwned(_, inner) => self.enum_type(inner),
            Ex::Tern(_, yes, no) => {
                let yes_ty = self.enum_type(yes)?;
                (self.enum_type(no).as_deref() == Some(yes_ty.as_str())).then_some(yes_ty)
            }
            Ex::Un("+" | "-" | "~", inner) => self.enum_type(inner),
            Ex::Bin(op, left, right) if matches!(*op, "+" | "-" | "|" | "&" | "^" | "<<" | ">>") => {
                if self.enum_type(left).is_some() && (enum_const_int(right).is_some() || self.enum_type(right).is_some()) {
                    self.enum_type(left)
                } else if self.enum_type(right).is_some() && (enum_const_int(left).is_some() || self.enum_type(left).is_some()) {
                    self.enum_type(right)
                } else {
                    None
                }
            }
            Ex::Call(function, _) => match &**function {
                Ex::Var(name) => crate::protos::find(name).and_then(|p| p.ret.trim().strip_prefix("enum ").map(str::to_string)),
                _ => None,
            },
            _ => None,
        }
    }

    fn goto(&mut self, ind: usize, addr: u64, target: u64, lp: Option<(usize, usize)>, cond: Option<String>) {
        let pre = match &cond {
            Some(c) => format!("if ({c}) "),
            None => String::new(),
        };
        if let (Some((head, exit)), Some(&ti)) = (lp, self.idx.get(&target)) {
            if ti == head {
                self.line(ind, addr, format!("{pre}continue;"));
                return;
            }
            if ti == exit {
                self.line(ind, addr, format!("{pre}break;"));
                return;
            }
        }
        self.labels.insert(target);
        self.line(ind, addr, format!("{pre}goto L_{target:X};"));
    }

    fn emit(&mut self, mut i: usize, hi: usize, ind: usize, lp: Option<(usize, usize)>) {
        while i < hi {
            if let Some(latches) = self.loops.get(&i).cloned() {
                if !self.open.contains(&i) {
                    i = self.emit_loop(i, latches, hi, ind, lp);
                    continue;
                }
            }
            i = self.emit_one(i, hi, ind, lp);
        }
    }

    fn emit_loop(&mut self, h: usize, latches: Vec<usize>, hi: usize, ind: usize, outer: Option<(usize, usize)>) -> usize {
        let k = *latches.iter().max().unwrap();
        if k >= hi {
            // the loop runs past the current region: fall back to goto
            self.open.insert(h);
            let n = self.emit_one(h, hi, ind, outer);
            self.open.remove(&h);
            return n;
        }
        let exit = k + 1;
        let lp = Some((h, exit));
        self.open.insert(h);
        let latch_term = self.outs[k].term.clone();
        let entered_at_latch = h > 0
            && matches!(&self.outs[h - 1].term, Term::Jmp(t) if self.idx.get(t) == Some(&k))
            && matches!(&latch_term, Term::Cond { taken, .. } if self.idx.get(taken) == Some(&h));
        let ba = self.f.blocks[h].start;
        if entered_at_latch {
            self.suppress.insert(h - 1);
            let c = self.cond_for(k).unwrap();
            if self.stmts_empty(k) {
                self.line(ind, ba, format!("while ({}) {{", self.fmt.show(&c)));
                self.emit(h, k, ind + 1, lp);
                self.line(ind, ba, "}".into());
            } else {
                self.line(ind, ba, "while (1) {".into());
                self.block_stmts(k, ind + 1);
                self.line(ind + 1, ba, format!("if (!({})) break;", self.fmt.show(&c)));
                self.emit(h, k, ind + 1, lp);
                self.line(ind, ba, "}".into());
            }
            self.done.insert(k);
        } else if matches!(&latch_term, Term::Cond { taken, .. } if self.idx.get(taken) == Some(&h)) {
            self.line(ind, ba, "do {".into());
            self.emit(h, k, ind + 1, lp);
            self.block_stmts(k, ind + 1);
            let c = self.cond_for(k).unwrap();
            self.line(ind, ba, format!("}} while ({});", self.fmt.show(&c)));
            self.done.insert(k);
        } else {
            // header-tested or plain infinite loop
            let head_exit = matches!(&self.outs[h].term, Term::Cond { taken, .. } if self.idx.get(taken).map(|t| *t >= exit).unwrap_or(false));
            if head_exit && h < k && matches!(&latch_term, Term::Jmp(t) if self.idx.get(t) == Some(&h)) {
                let c = self.cond_for(h).unwrap();
                if self.stmts_empty(h) {
                    self.line(ind, ba, format!("while ({}) {{", self.fmt.show(&negate(c))));
                } else {
                    self.line(ind, ba, "while (1) {".into());
                    self.block_stmts(h, ind + 1);
                    self.line(ind + 1, ba, format!("if ({}) break;", self.fmt.show(&c)));
                }
                self.suppress.insert(k);
                self.done.insert(h);
                self.emit(h + 1, k + 1, ind + 1, lp);
                self.line(ind, ba, "}".into());
            } else {
                self.line(ind, ba, "while (1) {".into());
                self.suppress.insert(k);
                let tmp_open = self.open.clone();
                self.open.insert(h);
                // emit the header as an ordinary block (it is `open`, so no re-entry)
                self.emit(h, k + 1, ind + 1, lp);
                self.open = tmp_open;
                self.line(ind, ba, "}".into());
            }
        }
        self.open.remove(&h);
        let _ = outer;
        exit
    }

    fn emit_one(&mut self, i: usize, hi: usize, ind: usize, lp: Option<(usize, usize)>) -> usize {
        if self.done.contains(&i) {
            return i + 1;
        }
        self.done.insert(i);
        self.block_stmts(i, ind);
        let o = &self.outs[i];
        let term = o.term.clone();
        let ta = o.term_addr;
        let next_start = self.f.blocks.get(i + 1).map(|b| b.start);
        match term {
            Term::Ret(v) => {
                let t = match v {
                    Some(Ex::Num(value)) => {
                        let rendered = self.enum_return.as_ref().and_then(|ty| self.enum_constants.get(ty).and_then(|values| values.get(&value)).map(|member| format!("{ty}::{member}"))).unwrap_or_else(|| self.fmt.show(&Ex::Num(value)));
                        format!("return {rendered};")
                    }
                    Some(e) => format!("return {};", self.fmt.show(&e)),
                    None => "return;".into(),
                };
                self.line(ind, ta, t);
                i + 1
            }
            Term::Stop => i + 1,
            Term::Indirect(e) => {
                if let Some(ts) = self.switches.get(&ta).cloned() {
                    let enum_ty = self.enum_type(&e);
                    self.line(ind, ta, format!("switch ({}) {{ // jump table, {} targets", self.fmt.at(&e, 3), ts.len()));
                    let indices = self.switch_case_indices.get(&ta);
                    for (k, t) in ts.iter().enumerate() {
                        self.labels.insert(*t);
                        let case_value = indices.and_then(|values| values.get(k).copied()).unwrap_or(k as i64);
                        let label = enum_ty.as_ref().and_then(|ty| self.enum_constants.get(ty).and_then(|values| values.get(&case_value).map(|member| format!("{ty}::{member}")))).unwrap_or_else(|| case_value.to_string());
                        self.line(ind + 1, ta, format!("case {label}: goto L_{t:X};"));
                    }
                    self.line(ind, ta, "}".into());
                } else {
                    self.line(ind, ta, format!("goto *{}; // indirect jump (switch table?)", self.fmt.at(&e, 3)));
                }
                i + 1
            }
            Term::Fall(t) => {
                if Some(t) != next_start {
                    self.goto(ind, ta, t, lp, None);
                }
                i + 1
            }
            Term::Jmp(t) => {
                if self.suppress.contains(&i) || Some(t) == next_start {
                    return i + 1;
                }
                self.goto(ind, ta, t, lp, None);
                i + 1
            }
            Term::Cond { taken, fall, .. } => {
                let c = self.cond_for(i).unwrap();
                let ti = self.idx.get(&taken).copied();
                let fi = self.idx.get(&fall).copied();
                // forward skip inside this region: if (!c) { fallthrough part }
                if let (Some(t), Some(fi)) = (ti, fi) {
                    if fi == i + 1 && t > i + 1 && t <= hi && !self.has_back_target(i + 1, t) {
                        let last = t - 1;
                        let else_end = match &self.outs[last].term {
                            Term::Jmp(e) if last > i => self.idx.get(e).copied().filter(|e| *e > t && *e <= hi && !self.suppress.contains(&last)),
                            _ => None,
                        };
                        if let Some(e) = else_end {
                            self.line(ind, ta, format!("if ({}) {{", self.fmt.show(&negate(c.clone()))));
                            self.suppress.insert(last);
                            self.emit(i + 1, t, ind + 1, lp);
                            self.line(ind, ta, "} else {".into());
                            self.emit(t, e, ind + 1, lp);
                            self.line(ind, ta, "}".into());
                            return e;
                        }
                        self.line(ind, ta, format!("if ({}) {{", self.fmt.show(&negate(c))));
                        self.emit(i + 1, t, ind + 1, lp);
                        self.line(ind, ta, "}".into());
                        return t;
                    }
                }
                // otherwise: conditional jump out
                self.goto(ind, ta, taken, lp, Some(self.fmt.show(&c)));
                if Some(fall) != next_start {
                    self.goto(ind, ta, fall, lp, None);
                }
                i + 1
            }
        }
    }

    fn has_back_target(&self, from: usize, to: usize) -> bool {
        // A forward conditional can look like a simple guarded block even when
        // its body contains a loop header. Keep the generic branch emission in
        // that case so the back edge is not hidden inside an `if`.
        self.loops.keys().any(|target| *target >= from && *target < to)
    }
}

pub fn decompile(
    bin: &Binary,
    an: &Analysis,
    names: &HashMap<u64, (String, NameKind)>,
    f: &Function,
    conv: CallConv,
    comp_note: &str,
) -> Decompiled {
    let enums = HashMap::new();
    decompile_inner(bin, an, names, f, conv, comp_note, &enums, &[])
}

pub fn decompile_with_types(
    bin: &Binary,
    an: &Analysis,
    names: &HashMap<u64, (String, NameKind)>,
    f: &Function,
    conv: CallConv,
    comp_note: &str,
    structs: &[crate::types::StructDef],
) -> Decompiled {
    let mut all_structs = structs.to_vec();
    for debug in &bin.debug_structs {
        if !all_structs.iter().any(|existing| existing.name == debug.name) {
            all_structs.push(debug.clone());
        }
    }
    let enums = crate::types::enum_constants(&all_structs);
    decompile_inner(bin, an, names, f, conv, comp_note, &enums, &all_structs)
}

fn decompile_inner(
    bin: &Binary,
    an: &Analysis,
    names: &HashMap<u64, (String, NameKind)>,
    f: &Function,
    conv: CallConv,
    comp_note: &str,
    enum_constants: &HashMap<String, HashMap<i64, String>>,
    structs: &[crate::types::StructDef],
) -> Decompiled {
    let word: i64 = if bin.bitness() == 64 { 8 } else { 4 };
    let x86 = bin.arch.is_x86();
    ABI.with(|a| *a.borrow_mut() = Some(if x86 { Abi { names: vec![], word_bytes: (bin.arch.bits() / 8) as u8, ret: RAX, sp: RSP, args: vec![], caller_saved: vec![], callee_saved: vec![], x86: true } } else { generic::abi_for(bin.arch) }));
    let mut dc = Dc { bin, an, names, conv, word, fp: false, locals: BTreeMap::new(), stack_args: BTreeSet::new(), tmp: 0, dem: Default::default(), spills: BTreeSet::new(), enum_constants };
    let name = names.get(&f.start).map(|n| display_symbol(&n.0)).unwrap_or_else(|| format!("sub_{:X}", f.start));
    if f.blocks.is_empty() {
        return Decompiled { lines: vec![DLine { text: format!("// {name}: no code to show"), addr: f.start, indent: 0 }] };
    }
    // frame pointer?
    if let Some(first) = f.blocks.first().filter(|_| x86) {
        let ins: Vec<Instruction> = first.insns.iter().take(6).filter_map(|a| decode_at(bin, *a).map(|x| x.0)).collect();
        let (pb, mb) = if word == 8 { (Register::RBP, Register::RSP) } else { (Register::EBP, Register::ESP) };
        dc.fp = ins.iter().any(|i| i.mnemonic() == Mnemonic::Push && i.op_kind(0) == OpKind::Register && i.op0_register() == pb)
            && ins.iter().any(|i| i.mnemonic() == Mnemonic::Mov && i.op_kind(0) == OpKind::Register && i.op0_register() == pb && i.op_kind(1) == OpKind::Register && i.op1_register() == mb);
    }
    let n = f.blocks.len();
    let idx: HashMap<u64, usize> = f.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();

    // pass 1: stack pointer at the start of each block
    let mut sp_in: Vec<Option<(i64, Option<i64>)>> = vec![None; n];
    sp_in[0] = Some((0, None));
    let mut work = if x86 { vec![0usize] } else { vec![] };
    if !x86 {
        sp_in = generic::sp_pass(&dc, f, &idx);
    }
    while let Some(b) = work.pop() {
        let (mut sp, mut bp) = sp_in[b].unwrap();
        for a in &f.blocks[b].insns {
            let Some((ins, _)) = decode_at(bin, *a) else { continue };
            let sp_r = if word == 8 { Register::RSP } else { Register::ESP };
            let bp_r = if word == 8 { Register::RBP } else { Register::EBP };
            match ins.mnemonic() {
                Mnemonic::Push => sp -= word,
                Mnemonic::Pop => sp += word,
                Mnemonic::Leave => {
                    if let Some(b) = bp {
                        sp = b + word;
                    }
                }
                Mnemonic::Mov if ins.op_kind(0) == OpKind::Register && ins.op_kind(1) == OpKind::Register => {
                    if ins.op0_register() == bp_r && ins.op1_register() == sp_r {
                        bp = Some(sp);
                    } else if ins.op0_register() == sp_r && ins.op1_register() == bp_r {
                        if let Some(b) = bp {
                            sp = b;
                        }
                    }
                }
                Mnemonic::Lea if ins.op_kind(0) == OpKind::Register && ins.op0_register() == sp_r && ins.memory_base() == bp_r => {
                    if let Some(b) = bp {
                        sp = b + ins.memory_displacement64() as i64;
                    }
                }
                Mnemonic::Sub | Mnemonic::Add if ins.op_kind(0) == OpKind::Register && ins.op0_register() == sp_r && ins.op_kind(1) != OpKind::Register => {
                    let v = ins.immediate(1) as i64;
                    let v = if ins.op_kind(1) == OpKind::Immediate32 && word == 4 { v as u32 as i32 as i64 } else { v };
                    if ins.mnemonic() == Mnemonic::Sub {
                        sp -= v;
                    } else {
                        sp += v;
                    }
                }
                _ => {}
            }
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

    // pass 2: symbolic execution of each block
    let mut outs: Vec<BlockOut> = vec![];
    for b in 0..n {
        let (sp, bp) = sp_in[b].unwrap_or((0, None));
        outs.push(if x86 { dc.exec(f, b, sp, bp, b == 0) } else { generic::exec(&mut dc, f, b, sp, bp) });
    }
    for out in &mut outs {
        for (_, stmt) in &mut out.stmts {
            match stmt {
                Stmt::Assign(left, right) => {
                    *left = fold_expression(std::mem::replace(left, Ex::Num(0)));
                    *right = fold_expression(std::mem::replace(right, Ex::Num(0)));
                }
                Stmt::Expr(expr) => {
                    *expr = fold_expression(std::mem::replace(expr, Ex::Num(0)));
                }
                Stmt::Comment(_) => {}
            }
        }
        out.term = match std::mem::replace(&mut out.term, Term::Stop) {
            Term::Ret(Some(expr)) => Term::Ret(Some(fold_expression(expr))),
            Term::Indirect(expr) => Term::Indirect(fold_expression(expr)),
            Term::Cond { cond, taken, fall } => Term::Cond { cond: fold_expression(cond), taken, fall },
            other => other,
        };
        propagate_adjacent_copy(out, false);
        propagate_adjacent_constant(out, false);
        propagate_forward_copy(out, false);
        inline_adjacent_call_temp(out);
        fold_constant_term(out);
    }
    propagate_single_predecessor_copy(&mut outs, f);
    propagate_single_predecessor_constant(&mut outs, f);
    propagate_convergent_copy(&mut outs, f);
    propagate_convergent_constant(&mut outs, f);
    for out in &mut outs {
        fold_constant_term(out);
    }

    // pass 3: liveness of registers
    let mut live_in: Vec<BTreeSet<u8>> = vec![BTreeSet::new(); n];
    let rax_defined = outs.iter().any(|o| o.defs.contains_key(&abi_ret()));
    // `ret` that returns rax from an earlier block needs it live
    let ret_needs_rax: Vec<bool> = outs.iter().map(|o| matches!(&o.term, Term::Ret(Some(Ex::Var(v))) if *v == reg_name(abi_ret()))).collect();
    let mut changed = true;
    let succ_idx: Vec<Vec<usize>> = f.blocks.iter().map(|b| b.succs.iter().filter_map(|(t, _)| idx.get(t).copied()).collect()).collect();
    while changed {
        changed = false;
        for b in (0..n).rev() {
            let mut out: BTreeSet<u8> = BTreeSet::new();
            for s in &succ_idx[b] {
                out.extend(live_in[*s].iter().copied());
            }
            if ret_needs_rax[b] && rax_defined {
                out.insert(abi_ret());
            }
            let mut li: BTreeSet<u8> = out.into_iter().filter(|r| !outs[b].defs.contains_key(r)).collect();
            li.extend(outs[b].uses.iter().copied());
            if li != live_in[b] {
                live_in[b] = li;
                changed = true;
            }
        }
    }
    // registers to write out at the end of each block
    let mut mat: Vec<Vec<(u8, Ex)>> = vec![];
    for b in 0..n {
        let mut out: BTreeSet<u8> = BTreeSet::new();
        for s in &succ_idx[b] {
            out.extend(live_in[*s].iter().copied());
        }
        if ret_needs_rax[b] {
            out.insert(abi_ret());
        }
        let mut v = vec![];
        for (r, e) in &outs[b].defs {
            if out.contains(r) && *r != abi_sp() {
                v.push((*r, e.clone()));
            }
        }
        mat.push(v);
    }
    // parameters
    let mut rename: HashMap<String, String> = HashMap::new();
    let arg_regs: Vec<String> = if x86 { conv.arg_regs().iter().map(|s| s.to_string()).collect() } else { ABI.with(|a| a.borrow().as_ref().map(|x| x.args.iter().map(|i| x.names[*i as usize].clone()).collect()).unwrap_or_default()) };
    let mut nparams = 0;
    for (k, r) in arg_regs.iter().enumerate() {
        let i = reg_by_name(r.as_str()).unwrap_or(255);
        if live_in[0].contains(&i) {
            nparams = k + 1;
        }
    }
    for (k, r) in arg_regs.iter().enumerate().take(nparams) {
        rename.insert(r.to_string(), format!("a{}", k + 1));
    }
    let stack_max = dc.stack_args.iter().max().copied().unwrap_or(0);
    let total_params = nparams.max(stack_max).min(48);
    if word == 4 && x86 {
        for (i, g) in GPR.iter().enumerate().take(8) {
            if !rename.contains_key(*g) {
                rename.insert(g.to_string(), format!("e{}", &g[1..]));
            }
            let _ = i;
        }
    }
    if dc.fp {
        rename.insert("fp".into(), "frame".into());
    }
    // `v5 = f(); … rax = v5;` at the end of a block reads better as `rax = f();`
    for b in 0..n {
        for (r, e) in mat[b].clone() {
            let Ex::Var(v) = &e else { continue };
            if !(v.starts_with('v') && v[1..].chars().all(|c| c.is_ascii_digit())) {
                continue;
            }
            let target = Ex::Var(reg_name(r));
            let clash = mat[b].iter().any(|(r2, e2)| *r2 != r && mentions(e2, &target));
            if clash {
                continue;
            }
            // statements after the call must not read the old value of the register
            let call_pos = outs[b].stmts.iter().position(|(_, s)| matches!(s, Stmt::Assign(Ex::Var(x), _) if x == v));
            let late_use = call_pos.map(|p| outs[b].stmts[p + 1..].iter().any(|(_, s)| match s {
                Stmt::Assign(l, r2) => mentions(l, &target) || mentions(r2, &target),
                Stmt::Expr(x) => mentions(x, &target),
                _ => false,
            })).unwrap_or(true);
            if late_use || rename.contains_key(v) {
                continue;
            }
            let shown = rename.get(&reg_name(r)).cloned().unwrap_or_else(|| reg_name(r));
            rename.insert(v.clone(), shown);
        }
    }
    // loops: back edges
    let mut loops: HashMap<usize, Vec<usize>> = HashMap::new();
    for b in 0..n {
        for s in &succ_idx[b] {
            if *s <= b {
                loops.entry(*s).or_default().push(b);
            }
        }
    }
    // drop unused call results
    let mut counts: HashMap<String, usize> = HashMap::new();
    for o in &outs {
        for (_, s) in &o.stmts {
            match s {
                Stmt::Assign(l, r) => {
                    if !matches!(l, Ex::Var(_)) {
                        count_vars(l, &mut counts);
                    }
                    count_vars(r, &mut counts)
                }
                Stmt::Expr(e) => count_vars(e, &mut counts),
                _ => {}
            }
        }
        for t in [&o.term] {
            match t {
                Term::Ret(Some(e)) | Term::Indirect(e) => count_vars(e, &mut counts),
                Term::Cond { cond, .. } => count_vars(cond, &mut counts),
                _ => {}
            }
        }
    }
    for m in &mat {
        for (_, e) in m {
            count_vars(e, &mut counts);
        }
    }
    for o in outs.iter_mut() {
        for (_, s) in o.stmts.iter_mut() {
            if let Stmt::Assign(Ex::Var(v), r) = s {
                if (v.starts_with('v') || v.starts_with('t')) && v[1..].chars().all(|c| c.is_ascii_digit()) && counts.get(v.as_str()).copied().unwrap_or(0) == 0 {
                    *s = if matches!(r, Ex::Call(..)) { Stmt::Expr(r.clone()) } else { Stmt::Comment(String::new()) };
                }
            }
        }
    }
    // inline single-use call results: `v1 = f(); x = v1;`-style is left alone; only drop trivial self-assignments
    for o in outs.iter_mut() {
        o.stmts.retain(|(_, s)| !matches!(s, Stmt::Assign(a, b) if a == b) && !matches!(s, Stmt::Comment(c) if c.is_empty()));
    }

    // emit (twice: the first run finds which blocks are jump targets, the second prints their labels)
    let rename_ref = rename.clone();
    let render_types = infer_render_types(&outs);
    let own_proto = crate::protos::find(&name);
    let enum_return = own_proto.as_ref().and_then(|p| p.ret.trim().strip_prefix("enum ").map(str::to_string));
    let enum_params: HashMap<String, String> = own_proto.as_ref().map(|p| p.params.iter().enumerate().filter_map(|(i, (ty, _))| ty.trim().strip_prefix("enum ").map(|name| (format!("a{}", i + 1), name.to_string()))).collect()).unwrap_or_default();
    let enum_vars = infer_enum_vars(&outs, &enum_params, &name, enum_return.as_deref());
    let make = |labels: HashSet<u64>, mat: Vec<Vec<(u8, Ex)>>| Emit {
        f,
        outs: &outs,
        mat,
        idx: idx.clone(),
        fmt: Fmt { rename: &rename_ref, types: &render_types, structs },
        lines: vec![],
        labels,
        suppress: HashSet::new(),
        open: HashSet::new(),
        loops: loops.clone(),
        done: HashSet::new(),
        switches: &an.switches,
        switch_case_indices: &an.switch_case_indices,
        enum_constants,
        enum_return: enum_return.clone(),
        enum_vars: enum_vars.clone(),
    };
    let mut first = make(HashSet::new(), mat.clone());
    first.emit(0, n, 1, None);
    let found = first.labels.clone();
    let mut em = make(found, mat);
    em.emit(0, n, 1, None);
    let body = std::mem::take(&mut em.lines);
    let labels = std::mem::take(&mut em.labels);

    // header & declarations
    let returns_value = outs.iter().any(|o| matches!(o.term, Term::Ret(Some(_))));
    let ptype = if word == 8 { "int64_t" } else { "int32_t" };
    let params: Vec<String> = (1..=total_params).map(|k| format!("{ptype} a{k}")).collect();
    let mut lines: Vec<DLine> = vec![];
    if !comp_note.is_empty() {
        lines.push(DLine { text: format!("// {comp_note}"), addr: f.start, indent: 0 });
    }
    // the function's own prototype (built in or typed by the person) gives it real types and parameter names
    let own = own_proto;
    let mut param_names: Vec<(String, String)> = vec![];
    let (ret_ty, params) = match &own {
        Some(p) => {
            let mut ps: Vec<String> = vec![];
            for (k, (t, n)) in p.params.iter().enumerate() {
                let n = if n.is_empty() { format!("a{}", k + 1) } else { n.clone() };
                param_names.push((format!("a{}", k + 1), n.clone()));
                ps.push(if t.ends_with('*') { format!("{t}{n}") } else { format!("{t} {n}") });
            }
            if p.variadic { ps.push("...".into()); }
            (p.ret.clone(), ps)
        }
        None => ((if returns_value { ptype } else { "void" }).to_string(), params),
    };
    lines.push(DLine {
        text: format!("{} {}({})", ret_ty, name, if params.is_empty() { "void".to_string() } else { params.join(", ") }),
        addr: f.start,
        indent: 0,
    });
    lines.push(DLine { text: "{".into(), addr: f.start, indent: 0 });
    for (n, sz) in &dc.locals {
        let t = match sz {
            1 => "int8_t",
            2 => "int16_t",
            4 => "int32_t",
            8 => "int64_t",
            _ => "int64_t",
        };
        lines.push(DLine { text: format!("{t} {n};"), addr: f.start, indent: 1 });
    }
    // variables that are still plain registers or temps
    let mut used: BTreeSet<String> = BTreeSet::new();
    let mut all: HashMap<String, usize> = HashMap::new();
    for o in &outs {
        for (_, s) in &o.stmts {
            match s {
                Stmt::Assign(l, r) => {
                    count_vars(l, &mut all);
                    count_vars(r, &mut all)
                }
                Stmt::Expr(e) => count_vars(e, &mut all),
                _ => {}
            }
        }
    }
    for m in &em.mat {
        for (r, e) in m {
            used.insert(reg_name(*r));
            count_vars(e, &mut all);
        }
    }
    for k in all.keys() {
        if dc.locals.contains_key(k) || k == "retaddr" {
            continue;
        }
        if k.starts_with('a') && k[1..].chars().all(|c| c.is_ascii_digit()) && !k[1..].is_empty() {
            continue;
        }
        let is_reg = reg_by_name(k).is_some() || GPR.contains(&k.as_str())
            || (k.starts_with("xmm") && k[3..].chars().all(|c| c.is_ascii_digit()))
            || (k.starts_with('v') && k[1..].chars().all(|c| c.is_ascii_digit()));
        let is_tmp = (k.starts_with('v') || k.starts_with('t')) && k.len() > 1 && k[1..].chars().all(|c| c.is_ascii_digit());
        if is_reg || is_tmp {
            used.insert(k.clone());
        }
    }
    let mut decl_regs: Vec<String> = vec![];
    for u in used {
        let disp = rename.get(&u).cloned().unwrap_or(u.clone());
        if disp.starts_with('a') && disp[1..].chars().all(|c| c.is_ascii_digit()) && !disp[1..].is_empty() {
            continue; // a parameter
        }
        if decl_regs.contains(&disp) {
            continue;
        }
        decl_regs.push(disp);
    }
    // Results of calls to functions with a known prototype get the declared return type.
    // Keep that information through copy/cast chains so a temporary introduced by the
    // lifter does not erase useful pointer or scalar type information.
    let mut assigned: HashMap<String, (usize, Option<String>)> = HashMap::new();
    let mut known_types: HashMap<String, String> = HashMap::new();
    let mut assignments = Vec::new();
    for o in &outs {
        for (_, st) in &o.stmts {
            if let Stmt::Assign(Ex::Var(t), rhs) = st {
                assignments.push((t.clone(), rhs.clone()));
                assigned.entry(t.clone()).or_insert((0, None)).0 += 1;
            }
        }
    }
    // A block can be emitted before the block containing the source assignment. A
    // small fixed-point pass handles those ordering differences without pretending
    // that arithmetic expressions have a reliable type.
    for _ in 0..assignments.len().max(1) {
        let mut changed = false;
        for (t, rhs) in &assignments {
            let ty = match rhs {
                Ex::Call(c, _) => call_return_type(c),
                Ex::Deref(inner, _) => match &**inner {
                    Ex::Call(c, _) => call_pointee_type(c),
                    Ex::Var(v) => known_types.get(v).and_then(|ty| ty.strip_suffix('*').map(|p| p.trim().to_string())),
                    Ex::Cast(ty, _) => ty.trim().strip_suffix('*').map(|p| p.trim().to_string()),
                    Ex::CastOwned(ty, _) => ty.trim().strip_suffix('*').map(|p| p.trim().to_string()),
                    Ex::Tern(_, yes, no) => {
                        let pointee = |e: &Ex| match e {
                            Ex::Call(c, _) => call_pointee_type(c),
                            Ex::Var(v) => known_types.get(v).and_then(|ty| ty.strip_suffix('*').map(|p| p.trim().to_string())),
                            Ex::Cast(t, _) => t.trim().strip_suffix('*').map(|p| p.trim().to_string()),
                            Ex::CastOwned(t, _) => t.trim().strip_suffix('*').map(|p| p.trim().to_string()),
                            _ => None,
                        };
                        let a = pointee(yes);
                        let b = pointee(no);
                        (a == b).then(|| a).flatten()
                    }
                    _ => None,
                },
                Ex::Cast(ty, _) => Some((*ty).to_string()),
                Ex::CastOwned(ty, _) => Some(ty.clone()),
                Ex::Var(v) => known_types.get(v).cloned(),
                Ex::Bin("+" | "-", left, right) if matches!(**right, Ex::Num(_)) => match &**left {
                    Ex::Var(v) => known_types.get(v).cloned(),
                    _ => None,
                },
                Ex::Tern(_, yes, no) => {
                    let branch_type = |e: &Ex| match e {
                        Ex::Var(v) => known_types.get(v).cloned(),
                        Ex::Call(c, _) => call_return_type(c),
                        Ex::Cast(t, _) => Some((*t).to_string()),
                        Ex::CastOwned(t, _) => Some(t.clone()),
                        _ => None,
                    };
                    let a = branch_type(yes);
                    let b = branch_type(no);
                    (a == b).then(|| a).flatten()
                }
                _ => None,
            };
            let old = known_types.get(t).cloned();
            if let Some(ty) = ty { known_types.insert(t.clone(), ty); }
            else { known_types.remove(t); }
            if old != known_types.get(t).cloned() { changed = true; }
        }
        if !changed { break; }
    }
    let mut type_candidates: HashMap<String, String> = HashMap::new();
    let mut type_conflicts = HashSet::new();
    for (t, rhs) in &assignments {
        let ty = match rhs {
            Ex::Call(c, _) => call_return_type(c),
            Ex::Deref(inner, _) => match &**inner {
                Ex::Call(c, _) => call_pointee_type(c),
                Ex::Var(v) => known_types.get(v).and_then(|ty| ty.strip_suffix('*').map(|p| p.trim().to_string())),
                Ex::Cast(ty, _) => ty.trim().strip_suffix('*').map(|p| p.trim().to_string()),
                Ex::CastOwned(ty, _) => ty.trim().strip_suffix('*').map(|p| p.trim().to_string()),
                Ex::Tern(_, yes, no) => {
                    let pointee = |e: &Ex| match e {
                        Ex::Call(c, _) => call_pointee_type(c),
                        Ex::Var(v) => known_types.get(v).and_then(|ty| ty.strip_suffix('*').map(|p| p.trim().to_string())),
                        Ex::Cast(t, _) => t.trim().strip_suffix('*').map(|p| p.trim().to_string()),
                        Ex::CastOwned(t, _) => t.trim().strip_suffix('*').map(|p| p.trim().to_string()),
                        _ => None,
                    };
                    let a = pointee(yes);
                    let b = pointee(no);
                    (a == b).then(|| a).flatten()
                }
                _ => None,
            },
            Ex::Cast(ty, _) => Some((*ty).to_string()),
            Ex::CastOwned(ty, _) => Some(ty.clone()),
            Ex::Var(v) => known_types.get(v).cloned(),
            Ex::Bin("+" | "-", left, right) if matches!(**right, Ex::Num(_)) => match &**left {
                Ex::Var(v) => known_types.get(v).cloned(),
                _ => None,
            },
                Ex::Tern(_, yes, no) => match (&**yes, &**no) {
                    (Ex::Var(a), Ex::Var(b)) if known_types.get(a) == known_types.get(b) => known_types.get(a).cloned(),
                    _ => {
                        let branch_type = |e: &Ex| match e {
                            Ex::Call(c, _) => call_return_type(c),
                            Ex::Cast(t, _) => Some((*t).to_string()),
                            Ex::CastOwned(t, _) => Some(t.clone()),
                            _ => None,
                        };
                        let a = branch_type(yes);
                        let b = branch_type(no);
                        (a == b).then(|| a).flatten()
                    }
                },
            _ => None,
        };
        if let Some(ty) = ty {
            if let Some(old) = type_candidates.get(t) {
                if old != &ty { type_conflicts.insert(t.clone()); }
            } else {
                type_candidates.insert(t.clone(), ty);
            }
        } else {
            type_conflicts.insert(t.clone());
        }
    }
    for (t, e) in &mut assigned {
        if !type_conflicts.contains(t) { e.1 = type_candidates.get(t).cloned(); }
    }
    let mut typed: Vec<(String, String)> = vec![];
    decl_regs.retain(|d| {
        let source = assigned.get(d).or_else(|| rename.iter().find(|(_, shown)| *shown == d).and_then(|(original, _)| assigned.get(original)));
        match source {
        Some((1, Some(ty))) => { typed.push((ty.clone(), d.clone())); false }
        _ => true,
        }
    });
    typed.sort();
    // XMM temporaries used to be emitted as integer declarations even when the
    // instruction stream clearly identified scalar float/double or vector data.
    // Recover the narrow type from the SSE mnemonic family for readable output.
    let mut sse_types: HashMap<String, String> = HashMap::new();
    for block in &f.blocks {
        for addr in &block.insns {
            let Some((ins, _)) = decode_at(bin, *addr) else { continue };
            let ty = match ins.mnemonic() {
                Mnemonic::Addss | Mnemonic::Subss | Mnemonic::Mulss | Mnemonic::Divss
                | Mnemonic::Movss | Mnemonic::Cvtsi2ss | Mnemonic::Cvtss2sd => "float",
                Mnemonic::Addsd | Mnemonic::Subsd | Mnemonic::Mulsd | Mnemonic::Divsd
                | Mnemonic::Movsd | Mnemonic::Cvtsi2sd | Mnemonic::Cvtsd2ss => "double",
                Mnemonic::Addps | Mnemonic::Subps | Mnemonic::Mulps | Mnemonic::Divps
                | Mnemonic::Movaps | Mnemonic::Movups | Mnemonic::Paddd | Mnemonic::Psubd => "__m128",
                Mnemonic::Vaddps | Mnemonic::Vsubps | Mnemonic::Vmulps | Mnemonic::Vdivps
                | Mnemonic::Vmovaps | Mnemonic::Vmovups | Mnemonic::Vmovdqa | Mnemonic::Vmovdqu => "__m256",
                Mnemonic::Addpd | Mnemonic::Subpd | Mnemonic::Mulpd | Mnemonic::Divpd
                | Mnemonic::Movapd | Mnemonic::Movupd | Mnemonic::Xorpd | Mnemonic::Andpd => "__m128d",
                Mnemonic::Vaddpd | Mnemonic::Vsubpd | Mnemonic::Vmulpd | Mnemonic::Vdivpd
                | Mnemonic::Vmovapd | Mnemonic::Vmovupd => "__m256d",
                _ => continue,
            };
            for operand in 0..ins.op_count() {
                if ins.op_kind(operand) == OpKind::Register && (ins.op_register(operand).is_xmm() || ins.op_register(operand).is_ymm() || ins.op_register(operand).is_zmm()) {
                    let r = ins.op_register(operand);
                    let actual = match (ty, r.is_xmm(), r.is_ymm(), r.is_zmm()) {
                        ("__m256", true, _, _) => "__m128",
                        ("__m256", _, _, true) => "__m512",
                        ("__m256d", true, _, _) => "__m128d",
                        ("__m256d", _, _, true) => "__m512d",
                        _ => ty,
                    };
                    sse_types.insert(reg_name(reg_index(r).unwrap()), actual.into());
                }
            }
        }
    }
    decl_regs.retain(|name| {
        if let Some(ty) = sse_types.get(name) {
            typed.push((ty.clone(), name.clone()));
            false
        } else { true }
    });
    if bin.arch == crate::loader::Arch::Arm64 {
        decl_regs.retain(|name| {
            if name.starts_with('v') && name[1..].chars().all(|c| c.is_ascii_digit()) {
                typed.push(("uint8x16_t".into(), name.clone()));
                false
            } else { true }
        });
    }
    typed.sort();
    for (ty, n) in &typed {
        lines.push(DLine { text: if ty.ends_with('*') { format!("{ty}{n};") } else { format!("{ty} {n};") }, addr: f.start, indent: 1 });
    }
    if !decl_regs.is_empty() {
        for chunk in decl_regs.chunks(8) {
            lines.push(DLine { text: format!("{ptype} {};", chunk.join(", ")), addr: f.start, indent: 1 });
        }
    }
    if !lines.is_empty() && lines.len() > 2 {
        lines.push(DLine { text: String::new(), addr: f.start, indent: 0 });
    }
    // labels that were only needed for gotos: already printed in place
    let _ = labels;
    lines.extend(body);
    lines.push(DLine { text: "}".into(), addr: f.end, indent: 0 });
    for (from, to) in &param_names {
        if from != to {
            for l in lines.iter_mut().skip(1) {
                l.text = crate::protos::replace_word(&l.text, from, to);
            }
        }
    }
    Decompiled { lines }
}

pub fn render_text(d: &Decompiled) -> String {
    let mut s = String::new();
    for l in &d.lines {
        s.push_str(&"    ".repeat(l.indent));
        s.push_str(&l.text);
        s.push('\n');
    }
    s
}

fn render_pointee_type(expression: &Ex, types: &HashMap<String, String>) -> Option<String> {
    match expression {
        Ex::Call(callee, _) => call_pointee_type(callee),
        Ex::Var(name) => types.get(name).and_then(|ty| ty.trim().strip_suffix('*').map(|pointee| pointee.trim().to_string())),
        Ex::Cast(ty, _) => ty.trim().strip_suffix('*').map(|pointee| pointee.trim().to_string()),
        Ex::CastOwned(ty, _) => ty.trim().strip_suffix('*').map(|pointee| pointee.trim().to_string()),
        Ex::Bin("+" | "-", base, offset) if render_pointee_type(offset, types).is_none() => render_pointee_type(base, types),
        Ex::Tern(_, yes, no) => {
            let yes = render_pointee_type(yes, types);
            let no = render_pointee_type(no, types);
            (yes == no).then_some(yes).flatten()
        }
        _ => None,
    }
}

fn infer_render_types(outs: &[BlockOut]) -> HashMap<String, String> {
    let mut types: HashMap<String, String> = HashMap::new();
    let mut assignments = Vec::new();
    for out in outs {
        for (_, stmt) in &out.stmts {
            if let Stmt::Assign(Ex::Var(name), rhs) = stmt {
                assignments.push((name.clone(), rhs.clone()));
            }
        }
    }
    for _ in 0..assignments.len().max(1) {
        let mut changed = false;
        for (name, rhs) in &assignments {
            let ty = match rhs {
                Ex::Call(c, _) => call_return_type(c),
                Ex::Deref(inner, _) => render_pointee_type(inner, &types),
                Ex::Cast(t, _) => Some((*t).to_string()),
                Ex::CastOwned(t, _) => Some(t.clone()),
                Ex::Var(source) => types.get(source).cloned(),
                Ex::Bin("+" | "-", left, right) if matches!(**right, Ex::Num(_)) => match &**left {
                    Ex::Var(source) => types.get(source).cloned(),
                    _ => None,
                },
                Ex::Tern(_, yes, no) => match (&**yes, &**no) {
                    (Ex::Var(a), Ex::Var(b)) if types.get(a) == types.get(b) => types.get(a).cloned(),
                    _ => {
                        let branch_type = |e: &Ex| match e {
                            Ex::Call(c, _) => call_return_type(c),
                            Ex::Cast(t, _) => Some((*t).to_string()),
                            Ex::CastOwned(t, _) => Some(t.clone()),
                            _ => None,
                        };
                        let a = branch_type(yes);
                        let b = branch_type(no);
                        (a == b).then(|| a).flatten()
                    }
                },
                _ => None,
            };
            if let Some(ty) = ty {
                if types.get(name) != Some(&ty) {
                    types.insert(name.clone(), ty);
                    changed = true;
                }
            }
        }
        if !changed { break; }
    }
    types
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{analyze, Settings};
    use crate::loader::{raw_binary, Arch, RawSpec};
    use std::sync::{atomic::AtomicU32, Arc};

    #[test]
    fn pdb_no_return_names_match_pseudocode_callees_exactly() {
        let names = vec!["fatal_error".to_string(), "panic".to_string()];
        assert!(is_debug_noreturn(&names, "fatal_error"));
        assert!(!is_debug_noreturn(&names, "fatal_error_extra"));
    }

    #[test]
    fn enum_condition_rewrites_numeric_member_through_a_cast() {
        let function = crate::analysis::Function { start: 0, end: 0, blocks: vec![], insn_count: 0, kind: crate::analysis::FuncKind::Normal, noreturn: false, calls: vec![], has_symbol: false, thunk_target: None };
        let outs = vec![];
        let empty = HashMap::new();
        let constants = HashMap::from([(String::from("Color"), HashMap::from([(1_i64, String::from("One")), (2_i64, String::from("Two"))]))]);
        let params = HashMap::from([(String::from("a1"), String::from("Color"))]);
        let switches = HashMap::new();
        let switch_case_indices = HashMap::new();
        let emit = Emit { f: &function, outs: &outs, mat: vec![], idx: HashMap::new(), fmt: Fmt { rename: &empty, types: &empty, structs: &[] }, lines: vec![], labels: HashSet::new(), suppress: HashSet::new(), open: HashSet::new(), loops: HashMap::new(), done: HashSet::new(), switches: &switches, switch_case_indices: &switch_case_indices, enum_constants: &constants, enum_return: None, enum_vars: params };
        let expression = emit.enumize(Ex::Bin("==", Box::new(Ex::Cast("int", Box::new(Ex::Var("a1".into())))), Box::new(Ex::Num(1))));
        assert_eq!(emit.fmt.show(&expression), "(int)a1 == Color::One");
        let flags = emit.enumize(Ex::Bin("==", Box::new(Ex::Var("a1".into())), Box::new(Ex::Num(3))));
        assert_eq!(emit.fmt.show(&flags), "a1 == (Color::Two | Color::One)");
        let folded = emit.enumize(Ex::Bin("==", Box::new(Ex::Var("a1".into())), Box::new(Ex::Bin("<<", Box::new(Ex::Num(1)), Box::new(Ex::Num(1))))));
        assert_eq!(emit.fmt.show(&folded), "a1 == Color::Two");
        let multiplied = emit.enumize(Ex::Bin("==", Box::new(Ex::Var("a1".into())), Box::new(Ex::Bin("*", Box::new(Ex::Num(1)), Box::new(Ex::Num(2))))));
        assert_eq!(emit.fmt.show(&multiplied), "a1 == Color::Two");
        let divided = emit.enumize(Ex::Bin("==", Box::new(Ex::Var("a1".into())), Box::new(Ex::Bin("/", Box::new(Ex::Num(4)), Box::new(Ex::Num(2))))));
        assert_eq!(emit.fmt.show(&divided), "a1 == Color::Two");
        let remainder = emit.enumize(Ex::Bin("==", Box::new(Ex::Var("a1".into())), Box::new(Ex::Bin("%", Box::new(Ex::Num(5)), Box::new(Ex::Num(3))))));
        assert_eq!(emit.fmt.show(&remainder), "a1 == Color::Two");
        let shifted_member = emit.enumize(Ex::Bin("==", Box::new(Ex::Bin("+", Box::new(Ex::Var("a1".into())), Box::new(Ex::Num(1)))), Box::new(Ex::Num(2))));
        assert_eq!(emit.fmt.show(&shifted_member), "a1 + Color::One == Color::Two");
        let flag_member = emit.enumize(Ex::Bin("==", Box::new(Ex::Bin("|", Box::new(Ex::Var("a1".into())), Box::new(Ex::Num(1)))), Box::new(Ex::Num(3))));
        assert_eq!(emit.fmt.show(&flag_member), "(a1 | Color::One) == (Color::Two | Color::One)");
        let shifted_flag = emit.enumize(Ex::Bin("==", Box::new(Ex::Bin("<<", Box::new(Ex::Var("a1".into())), Box::new(Ex::Num(1)))), Box::new(Ex::Num(2))));
        assert_eq!(emit.fmt.show(&shifted_flag), "a1 << Color::One == Color::Two");
        let conditional_member = emit.enumize(Ex::Bin("==", Box::new(Ex::Tern(Box::new(Ex::Var("cond".into())), Box::new(Ex::Var("a1".into())), Box::new(Ex::Var("a1".into())))), Box::new(Ex::Num(1))));
        assert_eq!(emit.fmt.show(&conditional_member), "(a1) == Color::One");
        let inverted_member = emit.enumize(Ex::Bin("==", Box::new(Ex::Un("~", Box::new(Ex::Var("a1".into())))), Box::new(Ex::Num(1))));
        assert_eq!(emit.fmt.show(&inverted_member), "~a1 == Color::One");
        let logical_member = emit.enumize(Ex::Bin("==", Box::new(Ex::Var("a1".into())), Box::new(Ex::Bin("&&", Box::new(Ex::Num(1)), Box::new(Ex::Num(1))))));
        assert_eq!(emit.fmt.show(&logical_member), "a1 == Color::One");
        let not_member = emit.enumize(Ex::Bin("==", Box::new(Ex::Var("a1".into())), Box::new(Ex::Un("!", Box::new(Ex::Num(0))))));
        assert_eq!(emit.fmt.show(&not_member), "a1 == Color::One");
        let ternary_member = emit.enumize(Ex::Bin("==", Box::new(Ex::Var("a1".into())), Box::new(Ex::Tern(Box::new(Ex::Num(1)), Box::new(Ex::Num(2)), Box::new(Ex::Num(1))))));
        assert_eq!(emit.fmt.show(&ternary_member), "a1 == Color::Two");
        let cast_constant = emit.enumize(Ex::Bin("==", Box::new(Ex::Var("a1".into())), Box::new(Ex::CastOwned("uint32_t".into(), Box::new(Ex::Num(2))))));
        assert_eq!(emit.fmt.show(&cast_constant), "a1 == Color::Two");
        let unary_constant = emit.enumize(Ex::Bin("==", Box::new(Ex::Un("+", Box::new(Ex::Var("a1".into())))), Box::new(Ex::Num(1))));
        assert_eq!(emit.fmt.show(&unary_constant), "+a1 == Color::One");
        let negated_value = emit.enumize(Ex::Bin("==", Box::new(Ex::Un("-", Box::new(Ex::Var("a1".into())))), Box::new(Ex::Num(1))));
        assert_eq!(emit.fmt.show(&negated_value), "-a1 == Color::One");
    }

    #[test]
    fn enum_parameter_type_propagates_through_local_copies() {
        let outs = vec![BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("v1".into()), Ex::Var("a1".into()))),
                (1, Stmt::Assign(Ex::Var("v2".into()), Ex::Var("v1".into()))),
                (2, Stmt::Assign(Ex::Var("v2".into()), Ex::Var("rax".into()))),
                (3, Stmt::Assign(Ex::Var("v3".into()), Ex::Cast("int".into(), Box::new(Ex::Var("v1".into()))))),
                (4, Stmt::Assign(Ex::Var("v4".into()), Ex::Tern(Box::new(Ex::Var("cond".into())), Box::new(Ex::Var("a1".into())), Box::new(Ex::Var("a1".into()))))),
                (5, Stmt::Assign(Ex::Var("v5".into()), Ex::Bin("+", Box::new(Ex::Var("a1".into())), Box::new(Ex::Num(1))))),
                (6, Stmt::Assign(Ex::Var("v6".into()), Ex::Call(Box::new(Ex::Var("enum_color".into())), vec![]))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 2,
        }];
        let seed = HashMap::from([(String::from("a1"), String::from("Color"))]);
        let vars = infer_enum_vars(&outs, &seed, "enum_color", Some("Color"));
        assert_eq!(vars.get("v1").map(String::as_str), Some("Color"));
        assert!(!vars.contains_key("v2"));
        assert_eq!(vars.get("v3").map(String::as_str), Some("Color"));
        assert_eq!(vars.get("v4").map(String::as_str), Some("Color"));
        assert_eq!(vars.get("v5").map(String::as_str), Some("Color"));
        assert_eq!(vars.get("v6").map(String::as_str), Some("Color"));
    }

    #[test]
    fn copy_propagation_recurses_through_owned_casts() {
        let mut out = BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("v1".into()), Ex::Var("p".into()))),
                (1, Stmt::Assign(Ex::Var("v2".into()), Ex::CastOwned("uint32_t *".into(), Box::new(Ex::Var("v1".into()))))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Ret(Some(Ex::Var("v2".into()))), term_addr: 1,
        };
        propagate_forward_copy(&mut out, false);
        assert!(matches!(out.stmts[0].1, Stmt::Assign(Ex::Var(ref name), Ex::CastOwned(_, ref inner)) if name == "v2" && **inner == Ex::Var("p".into())));
    }

    #[test]
    fn dereference_formatter_preserves_pointer_pointees() {
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &empty, structs: &[] };
        let call = Ex::Deref(Box::new(Ex::Call(Box::new(var("strdup")), vec![])), 1);
        assert_eq!(fmt.show(&call), "*(char*)strdup()");
        let cast = Ex::Deref(Box::new(Ex::CastOwned("uint32_t *".into(), Box::new(var("p")))), 4);
        assert_eq!(fmt.show(&cast), "*(uint32_t*)p");
        let types = HashMap::from([(String::from("p"), String::from("char *"))]);
        let copied = Fmt { rename: &empty, types: &types, structs: &[] };
        let read = Ex::Deref(Box::new(var("p")), 1);
        assert_eq!(copied.show(&read), "*(char*)p");
    }

    #[test]
    fn pointer_return_prototypes_wrap_call_values() {
        let proto = crate::protos::find("strdup").expect("built-in strdup prototype");
        let value = typed_call_value(Some(&proto), Ex::Call(Box::new(var("strdup")), vec![]));
        assert!(matches!(value, Ex::CastOwned(ref ty, _) if ty == "char *"));
        let plain = typed_call_value(None, Ex::Call(Box::new(var("unknown")), vec![]));
        assert!(matches!(plain, Ex::Call(_, _)));
    }

    #[test]
    fn render_type_inference_keeps_dereferenced_pointer_return_type() {
        let rhs = Ex::Deref(Box::new(Ex::Call(Box::new(var("strdup")), vec![])), 1);
        let outs = vec![BlockOut {
            stmts: vec![(0, Stmt::Assign(Ex::Var("ch".into()), rhs))],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 0,
        }];
        assert_eq!(infer_render_types(&outs).get("ch").map(String::as_str), Some("char"));
    }

    #[test]
    fn render_type_inference_keeps_pointer_type_through_constant_offset() {
        let outs = vec![BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("p".into()), Ex::Call(Box::new(var("strdup")), vec![]))),
                (1, Stmt::Assign(Ex::Var("q".into()), Ex::Bin("+", Box::new(Ex::Var("p".into())), Box::new(Ex::Num(4))))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 0,
        }];
        assert_eq!(infer_render_types(&outs).get("q").map(String::as_str), Some("char *"));
    }

    #[test]
    fn render_type_inference_keeps_common_type_through_conditional_value() {
        let call = || Ex::Call(Box::new(var("strdup")), vec![]);
        let outs = vec![BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("p".into()), call())),
                (1, Stmt::Assign(Ex::Var("q".into()), call())),
                (2, Stmt::Assign(Ex::Var("chosen".into()), Ex::Tern(Box::new(var("flag")), Box::new(var("p")), Box::new(var("q"))))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 0,
        }];
        assert_eq!(infer_render_types(&outs).get("chosen").map(String::as_str), Some("char *"));
    }

    #[test]
    fn render_type_inference_keeps_common_type_through_conditional_calls() {
        let call = |name: &str| Ex::Call(Box::new(var(name)), vec![]);
        let outs = vec![BlockOut {
            stmts: vec![(0, Stmt::Assign(
                Ex::Var("chosen".into()),
                Ex::Tern(Box::new(var("flag")), Box::new(call("strdup")), Box::new(call("strdup"))),
            ))],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 0,
        }];
        assert_eq!(infer_render_types(&outs).get("chosen").map(String::as_str), Some("char *"));
    }

    #[test]
    fn render_type_inference_keeps_pointee_through_conditional_dereference() {
        let call = || Ex::Call(Box::new(var("strdup")), vec![]);
        let rhs = Ex::Deref(Box::new(Ex::Tern(Box::new(var("flag")), Box::new(call()), Box::new(call()))), 1);
        let outs = vec![BlockOut {
            stmts: vec![(0, Stmt::Assign(Ex::Var("ch".into()), rhs))],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 0,
        }];
        assert_eq!(infer_render_types(&outs).get("ch").map(String::as_str), Some("char"));
    }

    #[test]
    fn render_type_inference_recovers_pointee_from_typed_pointer_temporary() {
        let outs = vec![BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("p".into()), Ex::Call(Box::new(var("strdup")), vec![]))),
                (1, Stmt::Assign(Ex::Var("ch".into()), Ex::Deref(Box::new(Ex::Var("p".into())), 1))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 0,
        }];
        assert_eq!(infer_render_types(&outs).get("ch").map(String::as_str), Some("char"));
    }

    #[test]
    fn render_type_inference_recovers_pointee_through_pointer_cast() {
        let outs = vec![BlockOut {
            stmts: vec![(0, Stmt::Assign(
                Ex::Var("ch".into()),
                Ex::Deref(Box::new(Ex::CastOwned("uint32_t *".into(), Box::new(var("p")))), 4),
            ))],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 0,
        }];
        assert_eq!(infer_render_types(&outs).get("ch").map(String::as_str), Some("uint32_t"));
    }

    #[test]
    fn simple_return_has_stable_pseudocode_golden() {
        let bin = raw_binary(&RawSpec {
            path: "golden".into(), name: "golden".into(), arch: Arch::X64, big: false,
            segs: vec![(0x1000, vec![0xB8, 42, 0, 0, 0, 0xC3])], entry: Some(0x1000), format: "test".into(),
        });
        let an = analyze(&bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        let f = an.functions.get(&0x1000).unwrap();
        let d = decompile(&bin, &an, &an.names, f, crate::detect::CallConv::SysV64, "");
        let text = render_text(&d);
        assert!(text.contains("return 0x2A;"), "unexpected pseudocode:\n{text}");
    }

    #[test]
    fn m68k_moveq_return_has_stable_pseudocode_golden() {
        let bin = raw_binary(&RawSpec {
            path: "m68k-golden".into(), name: "m68k-golden".into(), arch: Arch::M68k, big: true,
            segs: vec![(0x1000, vec![0x70, 0x2A, 0x4E, 0x75])], entry: Some(0x1000), format: "test".into(),
        });
        let an = analyze(&bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        let f = an.functions.get(&0x1000).unwrap();
        let raw = crate::multiarch::one(&bin, 0x1000).unwrap();
        assert_eq!((raw.mnemonic.as_str(), raw.ops.as_str()), ("moveq", "#$2a, d0"));
        let text = render_text(&decompile(&bin, &an, &an.names, f, crate::detect::CallConv::SysV64, ""));
        assert!(text.contains("return 0x2A;"), "unexpected M68k pseudocode:\n{text}");
    }

    #[test]
    fn m68k_link_frame_recovers_first_stack_argument() {
        let bin = raw_binary(&RawSpec {
            path: "m68k-stack-arg".into(), name: "m68k-stack-arg".into(), arch: Arch::M68k, big: true,
            // link.w a6, #-4; move.l 8(a6), d0; unlk a6; rts
            segs: vec![(0x1000, vec![0x4E, 0x56, 0xFF, 0xFC, 0x20, 0x2E, 0x00, 0x08, 0x4E, 0x5E, 0x4E, 0x75])],
            entry: Some(0x1000), format: "test".into(),
        });
        let an = analyze(&bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        let f = an.functions.get(&0x1000).unwrap();
        let text = render_text(&decompile(&bin, &an, &an.names, f, crate::detect::CallConv::SysV64, ""));
        assert!(text.contains("a1"), "expected first stack argument a1:\n{text}");
        assert!(!text.contains("a3"), "first stack argument was misnumbered:\n{text}");
    }

    #[test]
    fn scalar_sse_registers_get_float_declarations() {
        let bin = raw_binary(&RawSpec {
            path: "sse".into(), name: "sse".into(), arch: Arch::X64, big: false,
            segs: vec![(0x1000, vec![0xF3, 0x0F, 0x58, 0xC1, 0xF3, 0x0F, 0x11, 0x05, 0, 0, 0, 0, 0xC3])], entry: Some(0x1000), format: "test".into(),
        });
        let an = analyze(&bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        let f = an.functions.get(&0x1000).unwrap();
        let text = render_text(&decompile(&bin, &an, &an.names, f, crate::detect::CallConv::SysV64, ""));
        assert!(text.contains("float xmm0;") || text.contains("float xmm1;"), "unexpected pseudocode:\n{text}");
    }

    #[test]
    fn packed_sse_registers_get_vector_declarations() {
        let bin = raw_binary(&RawSpec {
            path: "sse2".into(), name: "sse2".into(), arch: Arch::X64, big: false,
            segs: vec![(0x1000, vec![0x0F, 0x58, 0xC1, 0x0F, 0x29, 0x05, 0, 0, 0, 0, 0xC3])], entry: Some(0x1000), format: "test".into(),
        });
        let an = analyze(&bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        let f = an.functions.get(&0x1000).unwrap();
        let text = render_text(&decompile(&bin, &an, &an.names, f, crate::detect::CallConv::SysV64, ""));
        assert!(text.contains("__m128 xmm0;") || text.contains("__m128 xmm1;"), "unexpected pseudocode:\n{text}");
    }

    #[test]
    fn integer_division_preserves_quotient_and_remainder() {
        let bin = raw_binary(&RawSpec {
            path: "div".into(), name: "div".into(), arch: Arch::X64, big: false,
            segs: vec![(0x1000, vec![0x48, 0xF7, 0xF9, 0xC3])], entry: Some(0x1000), format: "test".into(),
        });
        let an = analyze(&bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        let f = an.functions.get(&0x1000).unwrap();
        let text = render_text(&decompile(&bin, &an, &an.names, f, crate::detect::CallConv::SysV64, ""));
        assert!(text.contains("__wide_dividend") && text.contains("/"), "unexpected pseudocode:\n{text}");
    }

    #[test]
    fn enum_return_constants_render_as_named_members() {
        crate::protos::set_user("enum Color color_value(void);");
        let bin = raw_binary(&RawSpec {
            path: "enum-return".into(), name: "enum-return".into(), arch: Arch::X64, big: false,
            segs: vec![(0x1000, vec![0xB8, 1, 0, 0, 0, 0xC3])], entry: Some(0x1000), format: "test".into(),
        });
        let an = analyze(&bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        let f = an.functions.get(&0x1000).unwrap();
        let names = HashMap::from([(0x1000, ("color_value".into(), NameKind::Function))]);
        let color = crate::types::parse_c("enum Color { Zero = 0, One = 1 };", 8, &[]).unwrap();
        let text = render_text(&decompile_with_types(&bin, &an, &names, f, crate::detect::CallConv::SysV64, "", &[color]));
        assert!(text.contains("return Color::One;"), "unexpected pseudocode:\n{text}");
    }

    #[test]
    fn renders_known_struct_pointer_fields() {
        let def = crate::types::parse_c("struct Pair { int first; int second; }", 8, &[]).unwrap();
        let types = HashMap::from([(String::from("p"), String::from("struct Pair *"))]);
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &types, structs: &[def] };
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Num(4)))), 4);
        assert_eq!(fmt.show(&expression), "p->second");
    }

    #[test]
    fn folds_adjacent_temporary_copy() {
        let mut out = BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("v1".into()), Ex::Var("rax".into()))),
                (1, Stmt::Assign(Ex::Var("x".into()), Ex::Bin("+", Box::new(Ex::Var("v1".into())), Box::new(Ex::Num(1))))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 2,
        };
        propagate_adjacent_copy(&mut out, false);
        assert_eq!(out.stmts.len(), 1);
        assert!(matches!(&out.stmts[0].1, Stmt::Assign(Ex::Var(x), Ex::Bin("+", left, _)) if x == "x" && **left == Ex::Var("rax".into())));

        let mut ret = BlockOut {
            stmts: vec![(0, Stmt::Assign(Ex::Var("v2".into()), Ex::Var("rax".into())))],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Ret(Some(Ex::Var("v2".into()))), term_addr: 1,
        };
        propagate_adjacent_copy(&mut ret, false);
        assert!(ret.stmts.is_empty());
        assert!(matches!(ret.term, Term::Ret(Some(Ex::Var(ref v))) if v == "rax"));
    }

    #[test]
    fn adjacent_copy_preserves_read_modify_write_target() {
        let mut out = BlockOut {
            stmts: vec![
                (0, Stmt::Assign(var("v1"), var("rax"))),
                (1, Stmt::Assign(var("v1"), bin("+", var("v1"), Ex::Num(1)))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(),
            term: Term::Ret(Some(var("v1"))), term_addr: 2,
        };
        propagate_adjacent_copy(&mut out, false);
        assert!(matches!(out.stmts.as_slice(), [(1, Stmt::Assign(dst, rhs))]
            if *dst == var("v1") && *rhs == bin("+", var("rax"), Ex::Num(1))));
        assert!(matches!(&out.term, Term::Ret(Some(value)) if *value == var("v1")));
    }

    #[test]
    fn folds_adjacent_temporary_constant() {
        let mut out = BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("v1".into()), Ex::Num(42))),
                (1, Stmt::Assign(Ex::Var("x".into()), Ex::Bin("+", Box::new(Ex::Var("v1".into())), Box::new(Ex::Num(1))))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Ret(Some(Ex::Var("v1".into()))), term_addr: 2,
        };
        propagate_adjacent_constant(&mut out, false);
        assert_eq!(out.stmts.len(), 1);
        assert!(matches!(&out.stmts[0].1, Stmt::Assign(Ex::Var(x), Ex::Bin("+", left, _)) if x == "x" && **left == Ex::Num(42)));
        assert!(matches!(out.term, Term::Ret(Some(Ex::Num(42)))));
    }

    #[test]
    fn evaluates_compile_time_temporary_constants() {
        let mut out = BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("v1".into()), Ex::Bin("+", Box::new(Ex::Num(2)), Box::new(Ex::Num(3))))),
                (1, Stmt::Assign(Ex::Var("x".into()), Ex::Bin("*", Box::new(Ex::Var("v1".into())), Box::new(Ex::Num(4))))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Ret(Some(Ex::Var("v1".into()))), term_addr: 2,
        };
        propagate_adjacent_constant(&mut out, false);
        assert!(matches!(&out.stmts[0].1, Stmt::Assign(Ex::Var(x), Ex::Bin("*", left, _)) if x == "x" && **left == Ex::Num(5)));
        assert!(matches!(out.term, Term::Ret(Some(Ex::Num(5)))));
    }

    #[test]
    fn folds_copy_across_safe_statements_but_stops_at_source_reassignment() {
        let mut out = BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("v1".into()), Ex::Var("rax".into()))),
                (1, Stmt::Assign(Ex::Var("x".into()), Ex::Num(7))),
                (2, Stmt::Assign(Ex::Var("y".into()), Ex::Bin("+", Box::new(Ex::Var("v1".into())), Box::new(Ex::Num(1))))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 3,
        };
        propagate_forward_copy(&mut out, false);
        assert!(matches!(&out.stmts[1].1, Stmt::Assign(Ex::Var(y), Ex::Bin("+", left, _)) if y == "y" && **left == Ex::Var("rax".into())));

        let mut stopped = BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("v2".into()), Ex::Var("rax".into()))),
                (1, Stmt::Assign(Ex::Var("rax".into()), Ex::Num(9))),
                (2, Stmt::Assign(Ex::Var("z".into()), Ex::Var("v2".into()))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Stop, term_addr: 3,
        };
        propagate_forward_copy(&mut stopped, false);
        assert!(matches!(&stopped.stmts[2].1, Stmt::Assign(Ex::Var(z), Ex::Var(v)) if z == "z" && v == "v2"));
    }

    #[test]
    fn propagates_copy_into_single_predecessor_successor() {
        let f = Function {
            start: 0x1000, end: 0x1002,
            blocks: vec![
                crate::analysis::Block { start: 0x1000, end: 0x1001, insns: vec![], succs: vec![(0x1001, crate::analysis::EdgeKind::Always)] },
                crate::analysis::Block { start: 0x1001, end: 0x1002, insns: vec![], succs: vec![] },
            ],
            insn_count: 0, kind: crate::analysis::FuncKind::Normal, noreturn: false, calls: vec![], has_symbol: false, thunk_target: None,
        };
        let mut outs = vec![
            BlockOut { stmts: vec![(0, Stmt::Assign(Ex::Var("v1".into()), Ex::Var("a1".into())))], defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Jmp(0x1001), term_addr: 0 },
            BlockOut { stmts: vec![(1, Stmt::Assign(Ex::Var("v2".into()), Ex::Var("v1".into())))], defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Ret(Some(Ex::Var("v1".into()))), term_addr: 1 },
        ];
        propagate_single_predecessor_copy(&mut outs, &f);
        assert!(outs[0].stmts.is_empty());
        assert!(matches!(&outs[1].stmts[0].1, Stmt::Assign(Ex::Var(dst), Ex::Var(src)) if dst == "v2" && src == "a1"));
        assert!(matches!(&outs[1].term, Term::Ret(Some(Ex::Var(v))) if v == "a1"));
    }

    #[test]
    fn propagates_constant_into_single_predecessor_successor() {
        let f = Function {
            start: 0x1000, end: 0x1002,
            blocks: vec![
                crate::analysis::Block { start: 0x1000, end: 0x1001, insns: vec![], succs: vec![(0x1001, crate::analysis::EdgeKind::Always)] },
                crate::analysis::Block { start: 0x1001, end: 0x1002, insns: vec![], succs: vec![] },
            ],
            insn_count: 0, kind: crate::analysis::FuncKind::Normal, noreturn: false, calls: vec![], has_symbol: false, thunk_target: None,
        };
        let mut outs = vec![
            BlockOut { stmts: vec![(0, Stmt::Assign(Ex::Var("v1".into()), Ex::Num(7)))], defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Jmp(0x1001), term_addr: 0 },
            BlockOut { stmts: vec![(1, Stmt::Assign(Ex::Var("x".into()), Ex::Bin("+", Box::new(Ex::Var("v1".into())), Box::new(Ex::Num(1)))))], defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Ret(Some(Ex::Var("v1".into()))), term_addr: 1 },
        ];
        propagate_single_predecessor_constant(&mut outs, &f);
        assert!(outs[0].stmts.is_empty());
        assert!(matches!(&outs[1].stmts[0].1, Stmt::Assign(Ex::Var(x), Ex::Bin("+", left, _)) if x == "x" && **left == Ex::Num(7)));
        assert!(matches!(&outs[1].term, Term::Ret(Some(Ex::Num(7)))));
    }

    #[test]
    fn propagates_identical_copies_through_merge_block() {
        let f = Function {
            start: 0x1000, end: 0x1004,
            blocks: vec![
                crate::analysis::Block { start: 0x1000, end: 0x1001, insns: vec![], succs: vec![(0x1002, crate::analysis::EdgeKind::Taken)] },
                crate::analysis::Block { start: 0x1001, end: 0x1002, insns: vec![], succs: vec![(0x1002, crate::analysis::EdgeKind::NotTaken)] },
                crate::analysis::Block { start: 0x1002, end: 0x1004, insns: vec![], succs: vec![] },
            ],
            insn_count: 0, kind: crate::analysis::FuncKind::Normal, noreturn: false, calls: vec![], has_symbol: false, thunk_target: None,
        };
        let copy = || BlockOut { stmts: vec![(0, Stmt::Assign(Ex::Var("v1".into()), Ex::Var("a1".into())))], defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Jmp(0x1002), term_addr: 0 };
        let mut outs = vec![copy(), copy(), BlockOut { stmts: vec![(1, Stmt::Assign(Ex::Var("x".into()), Ex::Var("v1".into())))], defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Ret(Some(Ex::Var("v1".into()))), term_addr: 1 }];
        propagate_convergent_copy(&mut outs, &f);
        assert!(matches!(&outs[2].stmts[0].1, Stmt::Assign(Ex::Var(dst), Ex::Var(src)) if dst == "x" && src == "a1"));
        assert!(matches!(&outs[2].term, Term::Ret(Some(Ex::Var(v))) if v == "a1"));
    }

    #[test]
    fn propagates_identical_constants_through_merge_block() {
        let f = Function {
            start: 0x1000, end: 0x1004,
            blocks: vec![
                crate::analysis::Block { start: 0x1000, end: 0x1001, insns: vec![], succs: vec![(0x1002, crate::analysis::EdgeKind::Taken)] },
                crate::analysis::Block { start: 0x1001, end: 0x1002, insns: vec![], succs: vec![(0x1002, crate::analysis::EdgeKind::NotTaken)] },
                crate::analysis::Block { start: 0x1002, end: 0x1004, insns: vec![], succs: vec![] },
            ],
            insn_count: 0, kind: crate::analysis::FuncKind::Normal, noreturn: false, calls: vec![], has_symbol: false, thunk_target: None,
        };
        let constant = || BlockOut { stmts: vec![(0, Stmt::Assign(Ex::Var("v1".into()), Ex::Num(9)))], defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Jmp(0x1002), term_addr: 0 };
        let mut outs = vec![constant(), constant(), BlockOut { stmts: vec![(1, Stmt::Assign(Ex::Var("x".into()), Ex::Bin("+", Box::new(Ex::Var("v1".into())), Box::new(Ex::Num(1)))))], defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Ret(Some(Ex::Var("v1".into()))), term_addr: 1 }];
        propagate_convergent_constant(&mut outs, &f);
        assert!(matches!(&outs[2].stmts[0].1, Stmt::Assign(Ex::Var(x), Ex::Bin("+", left, _)) if x == "x" && **left == Ex::Num(9)));
        assert!(matches!(&outs[2].term, Term::Ret(Some(Ex::Num(9)))));
    }

    #[test]
    fn inlines_single_use_adjacent_call_temp() {
        let mut out = BlockOut {
            stmts: vec![
                (0, Stmt::Assign(Ex::Var("v1".into()), Ex::Call(Box::new(var("make")), vec![]))),
                (1, Stmt::Assign(Ex::Var("result".into()), Ex::Var("v1".into()))),
            ],
            defs: BTreeMap::new(), uses: BTreeSet::new(), term: Term::Ret(None), term_addr: 2,
        };
        inline_adjacent_call_temp(&mut out);
        assert!(matches!(&out.stmts[0].1, Stmt::Comment(c) if c.is_empty()));
        assert!(matches!(&out.stmts[1].1, Stmt::Assign(Ex::Var(name), Ex::Call(_, _)) if name == "result"));
    }

    #[test]
    fn folds_constant_division_remainder_and_comparisons() {
        assert_eq!(bin("/", Ex::Num(20), Ex::Num(4)), Ex::Num(5));
        assert_eq!(bin("%", Ex::Num(21), Ex::Num(4)), Ex::Num(1));
        assert_eq!(bin("<", Ex::Num(2), Ex::Num(3)), Ex::Num(1));
        assert_eq!(bin("==", Ex::Num(2), Ex::Num(3)), Ex::Num(0));
        assert!(matches!(bin("/", Ex::Num(1), Ex::Num(0)), Ex::Bin("/", ..)));
        assert_eq!(bin("&&", Ex::Num(1), Ex::Num(0)), Ex::Num(0));
        assert_eq!(bin("||", Ex::Num(0), Ex::Num(4)), Ex::Num(1));
        assert_eq!(un("-", Ex::Num(4)), Ex::Num(-4));
        assert_eq!(un("~", Ex::Num(0)), Ex::Num(-1));
        assert_eq!(un("!", Ex::Num(0)), Ex::Num(1));
        assert_eq!(un("!", Ex::Un("!", Box::new(var("value")))), bin("!=", var("value"), Ex::Num(0)));
    }

    #[test]
    fn folds_boolean_and_bitmask_identities() {
        let x = var("flag");
        assert_eq!(bin("&&", x.clone(), Ex::Num(0)), Ex::Num(0));
        assert_eq!(bin("||", x.clone(), Ex::Num(1)), Ex::Num(1));
        assert_eq!(bin("&&", x.clone(), Ex::Num(1)), bin("!=", x.clone(), Ex::Num(0)));
        assert_eq!(bin("||", x.clone(), Ex::Num(0)), bin("!=", x, Ex::Num(0)));
        let bits = var("bits");
        assert_eq!(bin("&", bits.clone(), Ex::Num(-1)), bits);
        assert_eq!(bin("|", var("bits"), Ex::Num(-1)), Ex::Num(-1));
        let value = var("value");
        assert_eq!(bin("==", value.clone(), value.clone()), Ex::Num(1));
        assert_eq!(bin("!=", value.clone(), value.clone()), Ex::Num(0));
        assert_eq!(bin("<=", value.clone(), value.clone()), Ex::Num(1));
        assert_eq!(bin(">", value.clone(), value), Ex::Num(0));
        let condition = var("condition");
        assert_eq!(bin("&&", condition.clone(), condition.clone()), bin("!=", var("condition"), Ex::Num(0)));
        assert_eq!(bin("||", condition.clone(), condition), bin("!=", var("condition"), Ex::Num(0)));
        let value = var("value");
        assert_eq!(bin("||", value.clone(), Ex::Un("!", Box::new(value.clone()))), Ex::Num(1));
        assert_eq!(bin("&&", value.clone(), Ex::Un("!", Box::new(value))), Ex::Num(0));
    }

    #[test]
    fn folds_nested_expression_constants() {
        let expression = Ex::Bin(
            "+",
            Box::new(Ex::Var("value".into())),
            Box::new(Ex::Bin("*", Box::new(Ex::Num(3)), Box::new(Ex::Num(4)))),
        );
        assert_eq!(fold_expression(expression), Ex::Bin("+", Box::new(Ex::Var("value".into())), Box::new(Ex::Num(12))));
    }

    #[test]
    fn folds_signed_right_shift_and_unit_remainder() {
        assert_eq!(bin(">>", Ex::Num(-8), Ex::Num(2)), Ex::Num(-2));
        assert_eq!(bin(">>", Ex::Num(8), Ex::Num(2)), Ex::Num(2));
        assert_eq!(bin(">>>", Ex::Num(-8), Ex::Num(2)), Ex::Num(0x3FFF_FFFF_FFFF_FFFE));
        assert_eq!(bin("%", var("value"), Ex::Num(1)), Ex::Num(0));
    }

    #[test]
    fn folds_constant_ternary_conditions() {
        assert_eq!(tern(Ex::Num(0), var("left"), var("right")), var("right"));
        assert_eq!(tern(Ex::Num(1), var("left"), var("right")), var("left"));
        assert_eq!(tern(var("condition"), var("same"), var("same")), var("same"));
        assert_eq!(tern(var("condition"), Ex::Num(1), Ex::Num(0)), bin("!=", var("condition"), Ex::Num(0)));
        assert_eq!(tern(var("condition"), Ex::Num(0), Ex::Num(1)), bin("==", var("condition"), Ex::Num(0)));
        assert!(matches!(tern(var("condition"), var("left"), var("right")), Ex::Tern(..)));
    }

    #[test]
    fn folds_expression_conditions_into_jumps() {
        let mut out = BlockOut {
            stmts: vec![],
            defs: BTreeMap::new(), uses: BTreeSet::new(),
            term: Term::Cond { cond: Ex::Bin("+", Box::new(Ex::Num(2)), Box::new(Ex::Num(3))), taken: 0x2000, fall: 0x3000 },
            term_addr: 0x1000,
        };
        fold_constant_term(&mut out);
        assert!(matches!(out.term, Term::Jmp(0x2000)));
    }

    #[test]
    fn renders_identical_ternary_branches_once() {
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &empty, structs: &[] };
        let expression = Ex::Tern(Box::new(var("condition")), Box::new(var("value")), Box::new(var("value")));
        assert_eq!(fmt.show(&expression), "value");
    }

    #[test]
    fn folds_constant_conditional_terminators() {
        let mut out = BlockOut {
            stmts: vec![], defs: BTreeMap::new(), uses: BTreeSet::new(),
            term: Term::Cond { cond: Ex::Num(0), taken: 0x2000, fall: 0x3000 }, term_addr: 1,
        };
        fold_constant_term(&mut out);
        assert!(matches!(out.term, Term::Jmp(0x3000)));
    }

    #[test]
    fn renders_known_scalar_pointer_index() {
        let types = HashMap::from([(String::from("p"), String::from("uint32_t *"))]);
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &types, structs: &[] };
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Num(8)))), 4);
        assert_eq!(fmt.show(&expression), "p[2]");
    }

    #[test]
    fn renders_variable_scalar_pointer_index() {
        let types = HashMap::from([(String::from("p"), String::from("uint32_t *"))]);
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &types, structs: &[] };
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Bin("*", Box::new(var("i")), Box::new(Ex::Num(4)))))), 4);
        assert_eq!(fmt.show(&expression), "p[i]");
        let reversed = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Bin("*", Box::new(Ex::Num(4)), Box::new(var("i")))))), 4);
        assert_eq!(fmt.show(&reversed), "p[i]");
        let shifted = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Bin("<<", Box::new(var("i")), Box::new(Ex::Num(2)))))), 4);
        assert_eq!(fmt.show(&shifted), "p[i]");
        let reverse = Ex::Deref(Box::new(Ex::Bin("-", Box::new(var("p")), Box::new(Ex::Bin("*", Box::new(var("i")), Box::new(Ex::Num(4)))))), 4);
        assert_eq!(fmt.show(&reverse), "p[-i]");
    }

    #[test]
    fn renders_struct_field_from_typed_call_return() {
        crate::protos::set_user("struct Pair *make_pair(void);");
        let def = crate::types::parse_c("struct Pair { uint32_t first; uint32_t second; }", 8, &[]).unwrap();
        let empty_types = HashMap::new();
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &empty_types, structs: &[def] };
        let call = Ex::Call(Box::new(var("make_pair")), vec![]);
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(call), Box::new(Ex::Num(4)))), 4);
        assert_eq!(fmt.show(&expression), "make_pair()->second");
    }

    #[test]
    fn resolves_pointee_type_through_pointer_typedef() {
        let base = crate::types::parse_c("struct Pair { uint32_t first; uint32_t second; }", 8, &[]).unwrap();
        let alias = crate::types::parse_c("typedef struct Pair *PairPtr;", 8, &[base.clone()]).unwrap();
        let empty_types = HashMap::new();
        let empty = HashMap::new();
        let defs = [base, alias];
        let fmt = Fmt { rename: &empty, types: &empty_types, structs: &defs };
        let call = Ex::CastOwned("PairPtr const".into(), Box::new(Ex::Call(Box::new(var("unknown")), vec![])));
        assert_eq!(fmt.pointee_type(&call, 4), "struct Pair");
    }

    #[test]
    fn renders_struct_field_from_cast_function_pointer_return() {
        let def = crate::types::parse_c("struct Pair { uint32_t first; uint32_t second; }", 8, &[]).unwrap();
        let empty_types = HashMap::new();
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &empty_types, structs: &[def] };
        let callee = Ex::CastOwned("struct Pair *(*)(void)".into(), Box::new(var("fp")));
        let call = Ex::Call(Box::new(callee), vec![]);
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(call), Box::new(Ex::Num(4)))), 4);
        assert_eq!(fmt.show(&expression), "(*(struct Pair *(*)(void))fp)()->second");
    }

    #[test]
    fn preserves_explicit_pointer_cast_on_call_return() {
        let def = crate::types::parse_c("struct Pair { uint32_t first; uint32_t second; }", 8, &[]).unwrap();
        let empty_types = HashMap::new();
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &empty_types, structs: &[def] };
        let call = Ex::CastOwned("struct Pair *".into(), Box::new(Ex::Call(Box::new(var("malloc")), vec![])));
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(call), Box::new(Ex::Num(4)))), 4);
        assert_eq!(fmt.show(&expression), "(struct Pair *)malloc()->second");
    }

    #[test]
    fn parses_explicit_function_pointer_call_type() {
        let proto = function_pointer_proto("int (*)(const char *, int)").unwrap();
        assert_eq!(proto.ret, "int");
        assert_eq!(proto.params.len(), 2);
        let normalized = function_pointer_proto("fn(const char *, int) -> int *").unwrap();
        assert_eq!(normalized.params.len(), 2);
        assert_eq!(normalized.ret, "int");
    }

    #[test]
    fn infers_return_type_from_cast_function_pointer_call() {
        let callee = Ex::CastOwned("struct Pair *(*)(void)".into(), Box::new(var("fp")));
        assert_eq!(call_return_type(&callee).as_deref(), Some("struct Pair *"));
    }

    #[test]
    fn infers_common_pointer_type_from_conditional_calls() {
        let expression = Ex::Tern(
            Box::new(Ex::Var("condition".into())),
            Box::new(Ex::Call(Box::new(var("malloc")), vec![])),
            Box::new(Ex::Call(Box::new(var("malloc")), vec![])),
        );
        assert_eq!(call_return_type(&expression).as_deref(), Some("void *"));
    }

    #[test]
    fn renders_struct_field_from_conditional_pointer_call() {
        crate::protos::set_user("struct Pair *make_pair(void); struct Pair *make_other(void);");
        let def = crate::types::parse_c("struct Pair { uint32_t first; uint32_t second; }", 8, &[]).unwrap();
        let empty_types = HashMap::new();
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &empty_types, structs: &[def] };
        let call = Ex::Tern(
            Box::new(Ex::Var("condition".into())),
            Box::new(Ex::Call(Box::new(var("make_pair")), vec![])),
            Box::new(Ex::Call(Box::new(var("make_other")), vec![])),
        );
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(call), Box::new(Ex::Num(4)))), 4);
        assert_eq!(fmt.show(&expression), "(condition ? make_pair() : make_other())->second");
    }

    #[test]
    fn preserves_pointer_type_through_pointer_arithmetic() {
        crate::protos::set_user("struct Pair *make_pair(void);");
        let call = Ex::Call(Box::new(var("make_pair")), vec![]);
        let adjusted = Ex::Bin("+", Box::new(call), Box::new(Ex::Num(4)));
        assert_eq!(call_return_type(&adjusted).as_deref(), Some("struct Pair *"));
    }

    #[test]
    fn preserves_nested_pointer_type_through_arithmetic() {
        crate::protos::set_user("struct Pair *make_pair(void);");
        let call = Ex::Call(Box::new(var("make_pair")), vec![]);
        let adjusted = Ex::Bin(
            "+",
            Box::new(Ex::Bin("+", Box::new(call), Box::new(Ex::Num(4)))),
            Box::new(Ex::Num(4)),
        );
        assert_eq!(call_return_type(&adjusted).as_deref(), Some("struct Pair *"));
    }

    #[test]
    fn renders_known_struct_array_field_index() {
        let def = crate::types::parse_c("struct Packet { uint32_t tag; uint16_t items[4]; }", 8, &[]).unwrap();
        let types = HashMap::from([(String::from("p"), String::from("struct Packet *"))]);
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &types, structs: &[def] };
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Num(6)))), 2);
        assert_eq!(fmt.show(&expression), "p->items[1]");
    }

    #[test]
    fn renders_first_element_of_known_struct_array() {
        let def = crate::types::parse_c("struct Packet { uint16_t items[4]; }", 8, &[]).unwrap();
        let types = HashMap::from([(String::from("p"), String::from("struct Packet *"))]);
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &types, structs: &[def] };
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Num(0)))), 2);
        assert_eq!(fmt.show(&expression), "p->items[0]");
    }

    #[test]
    fn renders_known_nested_struct_field() {
        let inner = crate::types::parse_c("struct Inner { uint32_t tag; uint32_t value; }", 8, &[]).unwrap();
        let outer = crate::types::parse_c("struct Outer { struct Inner inner; }", 8, &[inner.clone()]).unwrap();
        let types = HashMap::from([(String::from("p"), String::from("struct Outer *"))]);
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &types, structs: &[inner, outer] };
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Num(4)))), 4);
        assert_eq!(fmt.show(&expression), "p->inner.value");
    }

    #[test]
    fn renders_array_of_nested_struct_field() {
        let inner = crate::types::parse_c("struct Item { uint32_t id; uint32_t value; }", 8, &[]).unwrap();
        let outer = crate::types::parse_c("struct Batch { struct Item items[2]; }", 8, &[inner.clone()]).unwrap();
        let types = HashMap::from([(String::from("p"), String::from("struct Batch *"))]);
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &types, structs: &[inner, outer] };
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Num(12)))), 4);
        assert_eq!(fmt.show(&expression), "p->items[1].value");
    }

    #[test]
    fn renders_variable_struct_array_field_index() {
        let item = crate::types::parse_c("struct Item { uint32_t id; uint32_t value; }", 8, &[]).unwrap();
        let types = HashMap::from([(String::from("p"), String::from("struct Item *"))]);
        let empty = HashMap::new();
        let fmt = Fmt { rename: &empty, types: &types, structs: &[item] };
        let scaled = Ex::Bin("*", Box::new(var("i")), Box::new(Ex::Num(8)));
        let address = Ex::Bin("+", Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(scaled))), Box::new(Ex::Num(4)));
        let expression = Ex::Deref(Box::new(address), 4);
        assert_eq!(fmt.show(&expression), "p[i].value");
        let shifted = Ex::Bin("<<", Box::new(var("i")), Box::new(Ex::Num(3)));
        let shifted_address = Ex::Bin("+", Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(shifted))), Box::new(Ex::Num(4)));
        assert_eq!(fmt.show(&Ex::Deref(Box::new(shifted_address), 4)), "p[i].value");
        let reverse_scaled = Ex::Bin("*", Box::new(var("i")), Box::new(Ex::Num(8)));
        let reverse_base = Ex::Bin("-", Box::new(var("p")), Box::new(reverse_scaled));
        let reverse_address = Ex::Bin("+", Box::new(reverse_base), Box::new(Ex::Num(4)));
        assert_eq!(fmt.show(&Ex::Deref(Box::new(reverse_address), 4)), "p[-i].value");
    }

    #[test]
    fn resolves_struct_field_through_typedef_alias() {
        let base = crate::types::parse_c("struct Inner { uint32_t value; }", 8, &[]).unwrap();
        let alias = crate::types::parse_c("typedef struct Inner InnerAlias;", 8, &[base.clone()]).unwrap();
        let outer = crate::types::parse_c("struct Outer { InnerAlias inner; }", 8, &[base.clone(), alias.clone()]).unwrap();
        let types = HashMap::from([(String::from("p"), String::from("OuterAlias *"))]);
        let outer_alias = crate::types::parse_c("typedef struct Outer OuterAlias;", 8, &[base.clone(), alias.clone(), outer.clone()]).unwrap();
        let empty = HashMap::new();
        let defs = vec![base, alias, outer, outer_alias];
        let fmt = Fmt { rename: &empty, types: &types, structs: &defs };
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Num(0)))), 4);
        assert_eq!(fmt.show(&expression), "p->inner");
    }

    #[test]
    fn resolves_struct_field_through_pointer_typedef_alias() {
        let outer = crate::types::parse_c("struct Outer { uint32_t value; }", 8, &[]).unwrap();
        let pointer = crate::types::parse_c("typedef struct Outer *OuterPtr;", 8, &[outer.clone()]).unwrap();
        let types = HashMap::from([(String::from("p"), String::from("OuterPtr"))]);
        let empty = HashMap::new();
        let defs = vec![outer, pointer];
        let fmt = Fmt { rename: &empty, types: &types, structs: &defs };
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Num(0)))), 4);
        assert_eq!(fmt.show(&expression), "p->value");
    }

    #[test]
    fn resolves_struct_field_through_chained_pointer_typedef_alias() {
        let outer = crate::types::parse_c("struct Outer { uint32_t value; }", 8, &[]).unwrap();
        let named = crate::types::parse_c("typedef struct Outer OuterAlias;", 8, &[outer.clone()]).unwrap();
        let pointer = crate::types::parse_c("typedef OuterAlias *OuterPtr;", 8, &[outer.clone(), named.clone()]).unwrap();
        let types = HashMap::from([(String::from("p"), String::from("OuterPtr"))]);
        let empty = HashMap::new();
        let defs = vec![outer, named, pointer];
        let fmt = Fmt { rename: &empty, types: &types, structs: &defs };
        let expression = Ex::Deref(Box::new(Ex::Bin("+", Box::new(var("p")), Box::new(Ex::Num(0)))), 4);
        assert_eq!(fmt.show(&expression), "p->value");
    }

    #[test]
    fn division_pseudocode_preserves_cdq_sign_extension() {
        let bin = raw_binary(&RawSpec {
            path: "divsx".into(), name: "divsx".into(), arch: Arch::X64, big: false,
            segs: vec![(0x1000, vec![0x48, 0x99, 0x48, 0xF7, 0xF9, 0xC3])], entry: Some(0x1000), format: "test".into(),
        });
        let an = analyze(&bin, &Settings { min_string_len: 5, extra_functions: vec![], data_defs: Default::default() }, Arc::new(AtomicU32::new(0)));
        let f = an.functions.get(&0x1000).unwrap();
        let text = render_text(&decompile(&bin, &an, &an.names, f, crate::detect::CallConv::SysV64, ""));
        assert!(text.contains("__sign_extend_high"), "unexpected pseudocode:\n{text}");
    }
}
