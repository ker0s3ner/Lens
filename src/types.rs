//! User-defined structs: paste a C declaration, lay it over data, and the fields get names.

use crate::loader::Binary;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Field {
    pub off: u32,
    pub name: String,
    pub ty: String,
    pub size: u32,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<Field>,
    pub size: u32,
    /// Union members overlap at offset zero. Missing on older saved annotations.
    #[serde(default)]
    pub is_union: bool,
    /// Enum constants are stored separately because their values are not field offsets.
    #[serde(default)]
    pub is_enum: bool,
    #[serde(default)]
    pub enum_values: Vec<EnumValue>,
    /// Scalar or previously defined type used by a C typedef alias.
    #[serde(default)]
    pub alias_of: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct EnumValue {
    pub name: String,
    pub value: i64,
}

fn scalar(ty: &str, ptr: u32) -> Option<(u32, u32)> {
    let t = ty.trim();
    if t.ends_with('*') {
        return Some((ptr, ptr));
    }
    let t = t.trim_start_matches("const ").trim_start_matches("unsigned ").trim_start_matches("signed ").trim();
    Some(match t {
        "char" | "bool" | "_Bool" | "int8_t" | "uint8_t" | "u8" | "i8" | "BYTE" | "byte" | "" => (1, 1),
        "short" | "int16_t" | "uint16_t" | "u16" | "i16" | "WORD" | "wchar_t" => (2, 2),
        "int" | "int32_t" | "uint32_t" | "u32" | "i32" | "float" | "DWORD" | "long32" => (4, 4),
        "long" | "long long" | "int64_t" | "uint64_t" | "u64" | "i64" | "double" | "size_t" | "ssize_t" | "intptr_t" | "uintptr_t" | "QWORD" | "ptrdiff_t" => (8, 8),
        _ => return None,
    })
}

fn size_align(ty: &str, ptr: u32, known: &[StructDef]) -> Option<(u32, u32)> {
    size_align_inner(ty, ptr, known, 0)
}

fn size_align_inner(ty: &str, ptr: u32, known: &[StructDef], depth: usize) -> Option<(u32, u32)> {
    if depth > known.len() { return None; }
    if let Some(s) = scalar(ty, ptr) {
        return Some(s);
    }
    let n = ty.trim().trim_start_matches("struct ").trim_start_matches("union ").trim_start_matches("enum ").trim();
    let s = known.iter().find(|s| s.name == n)?;
    if let Some(alias) = &s.alias_of {
        // Aliases can point to previously defined aliases, but cannot form a cycle because
        // parse_c only accepts aliases whose target is already present in `known`.
        return size_align_inner(alias, ptr, known, depth + 1);
    }
    Some(if s.is_enum { (s.size, s.size.min(8).max(1)) }
    else { (s.size, s.fields.iter().map(|f| f.size.min(8)).max().unwrap_or(1).max(1)) })
}

/// Parse simple C-like struct, union, enum and typedef declarations.
pub fn parse_c(text: &str, ptr: u32, known: &[StructDef]) -> Result<StructDef, String> {
    let mut clean = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'/') {
            for d in chars.by_ref() { if d == '\n' { break } }
            clean.push('\n');
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut prev = ' ';
            for d in chars.by_ref() { if prev == '*' && d == '/' { break } prev = d; }
        } else {
            clean.push(c);
        }
    }
    let Some(open) = clean.find('{') else {
        let decl = clean.trim().trim_end_matches(';').trim();
        let decl = decl.strip_prefix("typedef").ok_or("Expected a struct, union, enum or typedef declaration")?.trim();
        let words: Vec<&str> = decl.split_whitespace().collect();
        if words.len() < 2 { return Err("A typedef needs a type and an alias name".into()); }
        let alias_name = words.last().unwrap().trim_matches('*');
        if !valid_ident(alias_name) { return Err(format!("Invalid typedef name `{alias_name}`")); }
        let mut target = words[..words.len() - 1].join(" ");
        let pointer_depth = decl.matches('*').count();
        target = target.replace('*', "").split_whitespace().collect::<Vec<_>>().join(" ");
        if !target.starts_with("struct ") && !target.starts_with("union ") && !target.starts_with("enum ") {
            target = target.trim_start_matches("const ").trim_start_matches("unsigned ").trim_start_matches("signed ").trim().to_string();
        }
        let (size, _) = size_align(&target, ptr, known).ok_or(format!("Unknown typedef target `{target}`"))?;
        let alias_size = if pointer_depth > 0 { ptr } else { size };
        return Ok(StructDef { name: alias_name.to_string(), fields: vec![], size: alias_size, is_union: false, is_enum: false, enum_values: vec![], alias_of: Some(if pointer_depth > 0 { "void *".into() } else { target }) });
    };
    let close = clean.rfind('}').ok_or("Missing closing brace")?;
    let head = clean[..open].replace("typedef", "");
    let is_union = head.split_whitespace().any(|w| w == "union");
    let is_enum = head.split_whitespace().any(|w| w == "enum");
    let name = head.split_whitespace().filter(|w| *w != "struct").last().ok_or("The struct needs a name")?.to_string();
    if is_enum {
        let mut values = Vec::new();
        let mut next = 0i64;
        for item in clean[open + 1..close].split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (n, value) = match item.split_once('=') {
                Some((name, value)) => {
                    let value = parse_enum_int(value.trim()).ok_or(format!("Unsupported enum value in `{item}`"))?;
                    (name.trim(), value)
                }
                None => (item, next),
            };
            if n.is_empty() || !n.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()) || n.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return Err(format!("Can't read enum member `{n}`"));
            }
            values.push(EnumValue { name: n.to_string(), value });
            next = value.saturating_add(1);
        }
        if values.is_empty() { return Err("The enum has no values".into()); }
        return Ok(StructDef { name, fields: vec![], size: 4, is_union: false, is_enum: true, enum_values: values, alias_of: None });
    }
    let mut fields = vec![];
    let mut off = 0u32;
    let mut max_align = 1u32;
    for decl in clean[open + 1..close].split(';') {
        let d = decl.trim();
        if d.is_empty() {
            continue;
        }
        let (d, count) = match (d.find('['), d.rfind(']')) {
            (Some(a), Some(b)) if b > a => (format!("{}{}", &d[..a], &d[b + 1..]), d[a + 1..b].trim().parse::<u32>().ok().or_else(|| u32::from_str_radix(d[a + 1..b].trim().trim_start_matches("0x"), 16).ok()).ok_or(format!("Unsupported array size in `{decl}`"))?),
            _ => (d.to_string(), 1),
        };
        let stars = d.matches('*').count();
        let words: Vec<&str> = d.split(|c: char| c.is_whitespace() || c == '*').filter(|w| !w.is_empty()).collect();
        if words.len() < 2 {
            return Err(format!("Can't read the field `{}`", decl.trim()));
        }
        let fname = words.last().unwrap().to_string();
        let mut ty = words[..words.len() - 1].join(" ");
        for _ in 0..stars {
            ty.push('*');
        }
        let (sz, al) = size_align(&ty, ptr, known).ok_or(format!("Unknown type `{ty}` in `{}`", decl.trim()))?;
        if !is_union {
            off = off.div_ceil(al) * al;
        }
        max_align = max_align.max(al.min(8));
        if count == 0 { return Err(format!("Array size must be greater than zero in `{decl}`")); }
        let total = sz.checked_mul(count).ok_or(format!("Field size overflows in `{decl}`"))?;
        if fields.iter().any(|field: &Field| field.name == fname) { return Err(format!("Duplicate field name `{fname}`")); }
        let shown_ty = if count > 1 { format!("{ty}[{count}]") } else { ty };
        fields.push(Field { off: if is_union { 0 } else { off }, name: fname, ty: shown_ty, size: total });
        if is_union {
            off = off.max(total);
        } else {
            off = off.checked_add(total).ok_or("Struct size overflows")?;
        }
    }
    if fields.is_empty() {
        return Err("The struct has no fields".into());
    }
    let size = off.checked_add(max_align - 1).ok_or("Struct size overflows")? / max_align * max_align;
    Ok(StructDef { name, fields, size, is_union, is_enum: false, enum_values: vec![], alias_of: None })
}

fn valid_ident(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
        && !name.chars().next().is_some_and(|c| c.is_ascii_digit())
}

fn parse_enum_int(s: &str) -> Option<i64> {
    let s = s.trim().trim_end_matches(|c: char| matches!(c, 'u' | 'U' | 'l' | 'L'));
    if let Some(hex) = s.strip_prefix("-0x") {
        i64::from_str_radix(hex, 16).ok().map(i64::wrapping_neg)
    } else if let Some(hex) = s.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Names for the fields of every applied struct.
pub fn field_names(structs: &[StructDef], applied: &[(u64, String)]) -> Vec<(u64, String)> {
    let mut out = vec![];
    for (addr, sname) in applied {
        if let Some(s) = structs.iter().find(|s| &s.name == sname) {
            if s.is_enum { continue; }
            append_field_names(structs, *addr, s, &s.name, 0, &mut vec![], &mut out);
        }
    }
    out
}

fn append_field_names(
    structs: &[StructDef], base: u64, def: &StructDef, prefix: &str, depth: usize,
    stack: &mut Vec<String>, out: &mut Vec<(u64, String)>,
) {
    if depth >= 8 || stack.contains(&def.name) { return; }
    stack.push(def.name.clone());
    for field in &def.fields {
        let Some(address) = base.checked_add(field.off as u64) else { continue };
        let path = format!("{prefix}.{}", field.name);
        out.push((address, path.clone()));
        if field.ty.contains('*') { continue; }
        let (type_name, count, is_array) = if let Some((ty, n)) = field.ty.split_once('[') {
            (ty.trim(), n.trim_end_matches(']').parse::<usize>().unwrap_or(0).min(256), true)
        } else { (field.ty.trim(), 1, false) };
        let type_name = type_name.trim_start_matches("const ").trim_start_matches("struct ").trim_start_matches("union ").trim();
        let Some(mut nested) = structs.iter().find(|s| s.name == type_name) else { continue };
        if nested.is_enum { continue; }
        for _ in 0..structs.len() {
            let Some(alias) = &nested.alias_of else { break };
            let alias_name = alias.trim().trim_start_matches("struct ").trim_start_matches("union ").trim();
            let Some(target) = structs.iter().find(|s| s.name == alias_name) else { break };
            nested = target;
        }
        if nested.alias_of.is_some() { continue; }
        let stride = if is_array { nested.size as u64 } else { 0 };
        for index in 0..count {
            let Some(element) = address.checked_add(stride.saturating_mul(index as u64)) else { continue };
            let element_path = if is_array { format!("{path}[{index}]") } else { path.clone() };
            append_field_names(structs, element, nested, &element_path, depth + 1, stack, out);
        }
    }
    stack.pop();
}

/// Read an applied enum at an address and resolve its raw integer to a named constant.
pub fn enum_value(bin: &Binary, addr: u64, def: &StructDef) -> Option<String> {
    if !def.is_enum { return None; }
    let bytes = bin.read(addr, def.size as usize);
    if bytes.len() < def.size as usize || def.size == 0 || def.size > 8 { return None; }
    let mut raw = 0u64;
    if bin.big_endian {
        for b in bytes { raw = (raw << 8) | *b as u64; }
    } else {
        for b in bytes.iter().rev() { raw = (raw << 8) | *b as u64; }
    }
    let width = def.size * 8;
    let signed = if width < 64 && raw & (1u64 << (width - 1)) != 0 { (raw | (!0u64 << width)) as i64 } else { raw as i64 };
    let name = def.enum_values.iter().find(|v| v.value == signed).map(|v| v.name.as_str()).unwrap_or("unknown");
    Some(format!("{name} ({signed})"))
}

/// A field's value as text, read from the program image.
pub fn value(bin: &Binary, addr: u64, f: &Field) -> String {
    let a = addr + f.off as u64;
    let bytes = bin.read(a, f.size as usize);
    if bytes.len() < f.size as usize {
        return "?".into();
    }
    let be = bin.big_endian;
    let int = |b: &[u8]| -> u64 {
        let mut v = 0u64;
        if be { for x in b { v = (v << 8) | *x as u64 } } else { for x in b.iter().rev() { v = (v << 8) | *x as u64 } }
        v
    };
    if f.ty.contains('[') {
        if f.ty.starts_with("char") || f.ty.starts_with("uint8_t") || f.ty.starts_with("u8") {
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            return format!("\"{}\"", crate::code::escape_str(&String::from_utf8_lossy(&bytes[..end]), 60));
        }
        return crate::code::hex_bytes(&bytes[..bytes.len().min(16)]);
    }
    match f.size {
        1 | 2 | 4 | 8 => {
            let v = int(bytes);
            if f.ty.ends_with('*') && v != 0 { format!("0x{v:X}") } else if v > 9 { format!("{v} (0x{v:X})") } else { v.to_string() }
        }
        _ => crate::code::hex_bytes(&bytes[..bytes.len().min(16)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses() {
        let s = parse_c("struct Foo { int a; char tag[6]; void *next; /* x */ short n; }", 8, &[]).unwrap();
        assert_eq!(s.fields[0].off, 0);
        assert_eq!(s.fields[1].off, 4);
        assert_eq!(s.fields[2].off, 16);
        assert_eq!(s.fields[3].off, 24);
        assert_eq!(s.size, 32);
    }
}
