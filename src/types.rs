//! User-defined structs: paste a C declaration, lay it over data, and the fields get names.

use crate::loader::Binary;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Field {
    pub off: u32,
    pub name: String,
    pub ty: String,
    pub size: u32,
    /// Bit position within the storage unit for a C bitfield (LSB-first layout).
    #[serde(default)]
    pub bit_offset: Option<u8>,
    #[serde(default)]
    pub bit_width: Option<u8>,
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

pub fn is_pointer_type(ty: &str, structs: &[StructDef]) -> bool {
    let mut current = ty.trim();
    for _ in 0..=structs.len() {
        if current.ends_with('*') { return true; }
        let name = current.trim_start_matches("struct ").trim_start_matches("union ").trim();
        let Some(def) = structs.iter().find(|d| d.name == name) else { return false };
        let Some(alias) = &def.alias_of else { return false };
        current = alias.trim();
    }
    false
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
    let pack_align = clean.split("#pragma pack(").nth(1).and_then(|s| s.split(')').next()).and_then(|s| s.split(',').next_back()).and_then(|s| s.trim().parse::<u32>().ok()).filter(|n| *n > 0 && *n <= 16);
    let packed = clean.contains("__attribute__((packed))") || clean.contains("__attribute__ ((packed))") || clean.contains(" packed ") || pack_align.is_some_and(|n| n == 1);
    if clean.contains("#pragma pack(") {
        clean = clean.lines().filter(|line| !line.trim_start().starts_with("#pragma pack(")).collect::<Vec<_>>().join("\n");
    }
    clean = clean.replace("__attribute__((packed))", "").replace("__attribute__ ((packed))", "");
    let Some(open) = clean.find('{') else {
        let decl = clean.trim().trim_end_matches(';').trim();
        let decl = decl.strip_prefix("typedef").ok_or("Expected a struct, union, enum or typedef declaration")?.trim();
        if let Some((ret, tail)) = decl.split_once("(*") {
            if let Some((alias, signature)) = tail.split_once(')') {
                let stars = 1 + alias.chars().take_while(|c| *c == '*').count();
                let alias = alias.trim_start_matches('*').trim();
                if signature.trim_start().starts_with('(') && valid_ident(alias) {
                    let params = signature.trim().trim_start_matches('(').trim_end_matches(')').trim();
                    let target = format!("fn({params}) -> {} {}", ret.trim(), "*".repeat(stars));
                    return Ok(StructDef { name: alias.to_string(), fields: vec![], size: ptr, is_union: false, is_enum: false, enum_values: vec![], alias_of: Some(target) });
                }
            }
        }
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
        if let Some(callable) = known.iter().find(|def| def.name == target).and_then(|def| def.alias_of.as_deref()).filter(|alias| alias.starts_with("fn(")) {
            return Ok(StructDef { name: alias_name.to_string(), fields: vec![], size: ptr, is_union: false, is_enum: false, enum_values: vec![], alias_of: Some(callable.to_string()) });
        }
        let (size, _) = size_align(&target, ptr, known).ok_or(format!("Unknown typedef target `{target}`"))?;
        let alias_size = if pointer_depth > 0 { ptr } else { size };
        let aliased = if pointer_depth > 0 {
            format!("{} {}", target, "*".repeat(pointer_depth))
        } else {
            target
        };
        return Ok(StructDef { name: alias_name.to_string(), fields: vec![], size: alias_size, is_union: false, is_enum: false, enum_values: vec![], alias_of: Some(aliased) });
    };
    let close = clean.rfind('}').ok_or("Missing closing brace")?;
    let head = clean[..open].replace("typedef", "");
    let is_union = head.split_whitespace().any(|w| w == "union");
    let is_enum = head.split_whitespace().any(|w| w == "enum");
    let mut name = head.split_whitespace().filter(|w| !matches!(*w, "struct" | "union" | "enum" | "typedef")).last().unwrap_or("").to_string();
    if name.is_empty() {
        let trailer = clean[close + 1..].trim().trim_end_matches(';').trim();
        if valid_ident(trailer) { name = trailer.to_string(); }
    }
    if name.is_empty() { return Err("The struct needs a name".into()); }
    if is_enum {
        let mut values = Vec::new();
        let mut names = HashMap::new();
        let mut next = 0i64;
        for item in clean[open + 1..close].split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (n, value) = match item.split_once('=') {
                Some((name, value)) => {
                    let value = parse_enum_int(value.trim(), &names).ok_or(format!("Unsupported enum value in `{item}`"))?;
                    (name.trim(), value)
                }
                None => (item, next),
            };
            if n.is_empty() || !n.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()) || n.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return Err(format!("Can't read enum member `{n}`"));
            }
            values.push(EnumValue { name: n.to_string(), value });
            names.insert(n.to_string(), value);
            next = value.saturating_add(1);
        }
        if values.is_empty() { return Err("The enum has no values".into()); }
        return Ok(StructDef { name, fields: vec![], size: 4, is_union: false, is_enum: true, enum_values: values, alias_of: None });
    }
    let mut fields = vec![];
    let mut off = 0u32;
    let mut max_align = 1u32;
    let mut bit_unit: Option<(u32, u32, u32, String)> = None; // address, bytes, used bits, type
    for decl in clean[open + 1..close].split(';') {
        let d = decl.trim();
        if d.is_empty() {
            continue;
        }
        let (d, bit_width) = match d.rsplit_once(':') {
            Some((left, right)) => {
                let width = right.trim().parse::<u8>().ok().filter(|n| *n <= 64).ok_or(format!("Unsupported bitfield width in `{decl}`"))?;
                (left.trim(), Some(width))
            }
            None => (d, None),
        };
        if bit_width.is_some() && d.contains(['[', ']']) {
            return Err(format!("Bitfield arrays are unsupported in `{decl}`"));
        }
        if bit_width == Some(0) {
            let ty = d.trim().to_string();
            let type_words = ty.split_whitespace().filter(|word| !word.is_empty()).count();
            if type_words > 2 {
                return Err(format!("Zero-width bitfield must be unnamed in `{decl}`"));
            }
            let (sz, al) = match size_align(&ty, ptr, known) {
                Some(layout) => layout,
                None if type_words > 1 => return Err(format!("Zero-width bitfield must be unnamed in `{decl}`")),
                None => return Err(format!("Unknown type `{ty}` in `{}`", decl.trim())),
            };
            let field_align = if packed { 1 } else { pack_align.unwrap_or(al).min(al) };
            if is_union || !integer_bitfield_type(&ty, known) || !matches!(sz, 1 | 2 | 4 | 8) {
                return Err(format!("Zero-width bitfield must use an integer storage type in `{decl}`"));
            }
            off = off.div_ceil(field_align) * field_align;
            bit_unit = None;
            continue;
        }
        let (d, count) = match (d.find('['), d.rfind(']')) {
            (Some(a), Some(b)) if b > a => (format!("{}{}", &d[..a], &d[b + 1..]), d[a + 1..b].trim().parse::<u32>().ok().or_else(|| u32::from_str_radix(d[a + 1..b].trim().trim_start_matches("0x"), 16).ok()).ok_or(format!("Unsupported array size in `{decl}`"))?),
            _ => (d.to_string(), 1),
        };
        let (fname, ty, stars) = if let Some((ret, tail)) = d.split_once("(*") {
            // Common C function-pointer field: `int (*callback)(int, void *)`.
            let (name, params) = tail.split_once(')').ok_or(format!("Can't read the function-pointer field `{}`", decl.trim()))?;
            let stars = 1 + name.chars().take_while(|c| *c == '*').count();
            let name = name.trim_start_matches('*').trim();
            if !params.trim_start().starts_with('(') || !valid_ident(name) {
                return Err(format!("Can't read the function-pointer field `{}`", decl.trim()));
            }
            let signature = params.trim().trim_start_matches('(').trim_end_matches(')').trim();
            (name.to_string(), format!("fn({signature}) -> {} {}", ret.trim(), "*".repeat(stars)), stars)
        } else {
            let stars = d.matches('*').count();
            let words: Vec<&str> = d.split(|c: char| c.is_whitespace() || c == '*').filter(|w| !w.is_empty()).collect();
            if words.len() < 2 {
                return Err(format!("Can't read the field `{}`", decl.trim()));
            }
            let fname = words.last().unwrap().to_string();
            let mut ty = words[..words.len() - 1].join(" ");
            for _ in 0..stars { ty.push('*'); }
            (fname, ty, stars)
        };
        let (sz, al) = size_align(&ty, ptr, known).ok_or(format!("Unknown type `{ty}` in `{}`", decl.trim()))?;
        let field_align = if packed { 1 } else { pack_align.unwrap_or(al).min(al) };
        if let Some(width) = bit_width {
            if stars != 0 || !integer_bitfield_type(&ty, known) || !matches!(sz, 1 | 2 | 4 | 8) || width as u32 > sz * 8 {
                return Err(format!("Bitfield `{}` must fit an integer storage type of at most 64 bits", fname));
            }
            let share = bit_unit.as_ref().filter(|(_, unit_size, used, unit_ty)| *unit_size == sz && compatible_bitfield_storage(unit_ty, &ty) && *used + width as u32 <= sz * 8).cloned();
            let (unit_addr, bit_off, used) = if is_union {
                (0, 0, 0)
            } else if let Some((unit_addr, _, used, _)) = share {
                (unit_addr, used, used)
            } else {
                bit_unit = None;
                off = off.div_ceil(field_align) * field_align;
                let addr = off;
                off = off.checked_add(sz).ok_or("Struct size overflows")?;
                max_align = max_align.max(field_align.min(8));
                (addr, 0, 0)
            };
            fields.push(Field { off: unit_addr, name: fname, ty, size: sz, bit_offset: Some(bit_off as u8), bit_width: Some(width) });
            if !is_union {
                let next_used = used + width as u32;
                bit_unit = if next_used < sz * 8 { Some((unit_addr, sz, next_used, fields.last().unwrap().ty.clone())) } else { None };
            }
            continue;
        }
        bit_unit = None;
        if !is_union {
            off = off.div_ceil(field_align) * field_align;
        }
        max_align = max_align.max(field_align.min(8));
        if count == 0 { return Err(format!("Array size must be greater than zero in `{decl}`")); }
        let total = sz.checked_mul(count).ok_or(format!("Field size overflows in `{decl}`"))?;
        if fields.iter().any(|field: &Field| field.name == fname) { return Err(format!("Duplicate field name `{fname}`")); }
        let shown_ty = if count > 1 { format!("{ty}[{count}]") } else { ty };
        fields.push(Field { off: if is_union { 0 } else { off }, name: fname, ty: shown_ty, size: total, bit_offset: None, bit_width: None });
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

fn integer_bitfield_type(ty: &str, known: &[StructDef]) -> bool {
    let t = ty.trim().trim_start_matches("const ").trim_start_matches("unsigned ").trim_start_matches("signed ").trim();
    matches!(t, "char" | "short" | "int" | "long" | "long long" | "_Bool" | "bool"
        | "int8_t" | "uint8_t" | "int16_t" | "uint16_t" | "int32_t" | "uint32_t" | "int64_t" | "uint64_t"
        | "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "BYTE" | "WORD" | "DWORD" | "QWORD")
        || known.iter().any(|d| d.is_enum && d.name == t)
}

fn compatible_bitfield_storage(a: &str, b: &str) -> bool {
    if a == b { return true; }
    let a = a.strip_prefix("signed ").unwrap_or(a);
    let b = b.strip_prefix("signed ").unwrap_or(b);
    a == b
}

fn parse_enum_int(s: &str, names: &HashMap<String, i64>) -> Option<i64> {
    fn atom(raw: &str, names: &HashMap<String, i64>) -> Option<i64> {
        let mut s = raw.trim();
        while s.starts_with('(') && s.ends_with(')') {
            let inner = &s[1..s.len() - 1];
            if inner.trim().is_empty() { break; }
            s = inner.trim();
        }
        let s = s.trim_end_matches(|c: char| matches!(c, 'u' | 'U' | 'l' | 'L'));
        if let Some(value) = names.get(s) { return Some(*value); }
        if let Some(ch) = s.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')).filter(|v| v.chars().count() == 1) {
            return ch.chars().next().map(|c| c as i64);
        }
        let (neg, s) = s.strip_prefix('-').map(|v| (true, v)).unwrap_or((false, s));
        let (radix, digits) = if let Some(v) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            (16, v)
        } else if let Some(v) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
            (2, v)
        } else if s.len() > 1 && s.starts_with('0') {
            (8, &s[1..])
        } else {
            (10, s)
        };
        let v = i64::from_str_radix(digits, radix).ok()?;
        Some(if neg { v.wrapping_neg() } else { v })
    }
    fn eval(s: &str, names: &HashMap<String, i64>) -> Option<i64> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix('~') {
            return Some(!eval(rest, names)?);
        }
        for op in ["|", "^", "&", "<<", ">>", "+", "-"] {
            let mut depth = 0i32;
            for (i, c) in s.char_indices().rev() {
                match c { ')' => depth += 1, '(' => depth -= 1, _ => {} }
                if depth == 0 && s[i..].starts_with(op) && (op != "-" || i > 0) {
                    let a = eval(&s[..i], names)?;
                    let b = eval(&s[i + op.len()..], names)?;
                    return Some(match op {
                        "|" => a | b, "^" => a ^ b, "&" => a & b,
                        "<<" => a.wrapping_shl(b as u32), ">>" => a.wrapping_shr(b as u32),
                        "+" => a.wrapping_add(b), "-" => a.wrapping_sub(b), _ => unreachable!(),
                    });
                }
            }
        }
        atom(s, names)
    }
    eval(s, names)
}

/// Names for the fields of every applied struct.
pub fn field_names(structs: &[StructDef], applied: &[(u64, String)]) -> Vec<(u64, String)> {
    let mut out = vec![];
    for (addr, sname) in applied {
        if let Some(s) = structs.iter().find(|s| &s.name == sname) {
            if s.is_enum { continue; }
            out.extend(flatten_fields(structs, s).into_iter().map(|f| (addr.saturating_add(f.off as u64), format!("{}.{}", s.name, f.name))));
        }
    }
    out
}

/// Flattens an applied record into displayable fields while preserving offsets from its base.
/// Embedded records and fixed arrays are expanded; scalar pointers and cyclic layouts stay opaque.
pub fn flatten_fields(structs: &[StructDef], def: &StructDef) -> Vec<Field> {
    let mut out = vec![];
    append_fields(structs, def, 0, "", 0, &mut vec![], &mut out);
    out
}

fn append_fields(
    structs: &[StructDef], def: &StructDef, base: u32, prefix: &str, depth: usize,
    stack: &mut Vec<String>, out: &mut Vec<Field>,
) {
    if depth >= 8 || stack.contains(&def.name) { return; }
    stack.push(def.name.clone());
    for field in &def.fields {
        let Some(offset) = base.checked_add(field.off) else { continue };
        let path = if prefix.is_empty() { field.name.clone() } else { format!("{prefix}.{}", field.name) };
        let mut flat = field.clone();
        flat.off = offset;
        flat.name = path.clone();
        out.push(flat);
        let (type_name, count, is_array) = if let Some((ty, n)) = field.ty.split_once('[') {
            (ty.trim(), n.trim_end_matches(']').parse::<usize>().unwrap_or(0).min(256), true)
        } else { (field.ty.trim(), 1, false) };
        let enum_type = type_name.trim_start_matches("enum ").trim();
        let primitive = scalar(type_name, 8).is_some() || is_pointer_type(type_name, structs)
            || structs.iter().any(|d| d.is_enum && d.name == enum_type);
        let primitive_array = is_array && count > 1 && type_name != "char" && primitive;
        if primitive_array {
            out.pop(); // replace the opaque aggregate row with navigable elements
            let Some((element_size, _)) = size_align(type_name, 8, structs) else { continue };
            for index in 0..count {
                let Some(delta) = element_size.checked_mul(index as u32) else { continue };
                let Some(element) = offset.checked_add(delta) else { continue };
                let mut item = field.clone();
                item.off = element;
                item.name = format!("{path}[{index}]");
                item.ty = type_name.to_string();
                item.size = element_size;
                out.push(item);
            }
            continue;
        }
        if type_name.contains('*') { continue; }
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
        let stride = if is_array { nested.size } else { 0 };
        for index in 0..count {
            let Some(element_delta) = stride.checked_mul(index as u32) else { continue };
            let Some(element) = offset.checked_add(element_delta) else { continue };
            let element_path = if is_array { format!("{path}[{index}]") } else { path.clone() };
            append_fields(structs, nested, element, &element_path, depth + 1, stack, out);
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

/// Build the enum namespace used by pseudocode constant propagation.
pub fn enum_constants(structs: &[StructDef]) -> HashMap<String, HashMap<i64, String>> {
    structs.iter().filter(|s| s.is_enum).map(|s| {
        (s.name.clone(), s.enum_values.iter().map(|v| (v.value, v.name.clone())).collect())
    }).collect()
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
    if let (Some(bit_offset), Some(bit_width)) = (f.bit_offset, f.bit_width) {
        let raw = int(bytes);
        let shift = if be { f.size.saturating_mul(8).saturating_sub(bit_offset as u32 + bit_width as u32) } else { bit_offset as u32 };
        let mask = if bit_width == 64 { u64::MAX } else { (1u64 << bit_width) - 1 };
        let extracted = (raw >> shift) & mask;
        let ty = f.ty.trim().trim_start_matches("const ");
        let unsigned = ty.starts_with("unsigned ") || ty.starts_with("uint") || ty.starts_with('u');
        let shown = if !unsigned && bit_width < 64 && extracted & (1u64 << (bit_width - 1)) != 0 {
            (extracted | (!0u64 << bit_width)) as i64
        } else {
            extracted as i64
        };
        return format!("{shown} (bits {bit_offset}..{})", bit_offset as u32 + bit_width as u32 - 1);
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

    #[test]
    fn parses_function_pointer_fields() {
        let s = parse_c("struct Callbacks { int (*on_value)(int, void *); void (*destroy)(void); }", 8, &[]).unwrap();
        assert_eq!(s.fields.len(), 2);
        assert_eq!(s.fields[0].name, "on_value");
        assert_eq!(s.fields[0].ty, "fn(int, void *) -> int *");
        assert_eq!(s.fields[0].size, 8);
        assert_eq!(s.fields[1].off, 8);
        let alias = parse_c("typedef int (*callback_t)(int, void *);", 8, &[]).unwrap();
        assert_eq!(alias.alias_of.as_deref(), Some("fn(int, void *) -> int *"));
        assert!(is_pointer_type("callback_t", &[alias.clone()]));
        let nested = parse_c("struct Nested { int (**callback)(int); }", 8, &[]).unwrap();
        assert_eq!(nested.fields[0].ty, "fn(int) -> int **");
        assert_eq!(nested.fields[0].size, 8);
        let nested_alias = parse_c("typedef int (**callback_ptr_t)(int);", 8, &[]).unwrap();
        assert_eq!(nested_alias.alias_of.as_deref(), Some("fn(int) -> int **"));
        let chained_alias = parse_c("typedef callback_t callback_alias_t;", 8, &[alias.clone()]).unwrap();
        assert_eq!(chained_alias.alias_of.as_deref(), Some("fn(int, void *) -> int *"));
    }

    #[test]
    fn preserves_struct_pointer_typedef_targets() {
        let base = parse_c("struct Item { int value; }", 8, &[]).unwrap();
        let alias = parse_c("typedef struct Item *ItemPtr;", 8, &[base]).unwrap();
        assert_eq!(alias.alias_of.as_deref(), Some("struct Item *"));
        assert!(is_pointer_type("ItemPtr", &[alias]));
    }

    #[test]
    fn exports_enum_constants_for_pseudocode() {
        let color = parse_c("enum Color { Red = 1, Blue = 4 }", 8, &[]).unwrap();
        let constants = enum_constants(&[color]);
        assert_eq!(constants["Color"][&4], "Blue");
    }

    #[test]
    fn parses_enum_constant_expressions() {
        let flags = parse_c("enum Flags { None = 0, Read = 1u << 0, Write = 01 << 1, Both = Read | Write, All = ~0u, Letter = 'A' }", 8, &[]).unwrap();
        let values = flags.enum_values.iter().map(|v| (v.name.as_str(), v.value)).collect::<Vec<_>>();
        assert_eq!(values, [("None", 0), ("Read", 1), ("Write", 2), ("Both", 3), ("All", -1), ("Letter", 65)]);
    }

    #[test]
    fn parses_anonymous_typedef_records_and_enums() {
        let record = parse_c("typedef struct { int value; } Value;", 8, &[]).unwrap();
        assert_eq!(record.name, "Value");
        assert_eq!(record.fields[0].name, "value");
        let en = parse_c("typedef enum { Zero, One = 1 } Count;", 8, &[]).unwrap();
        assert_eq!(en.name, "Count");
        assert_eq!(en.enum_values[1].name, "One");
    }

    #[test]
    fn packed_records_use_byte_alignment() {
        let packed = parse_c("struct Packet __attribute__((packed)) { char tag; int value; };", 8, &[]).unwrap();
        assert_eq!(packed.fields[1].off, 1);
        assert_eq!(packed.size, 5);
    }

    #[test]
    fn pragma_pack_one_uses_byte_alignment() {
        let packed = parse_c("#pragma pack(1)\nstruct Packet { char tag; int value; };", 8, &[]).unwrap();
        assert_eq!(packed.fields[1].off, 1);
        assert_eq!(packed.size, 5);
    }

    #[test]
    fn pragma_pack_push_one_uses_byte_alignment() {
        let packed = parse_c("#pragma pack(push, 1)\nstruct Packet { char tag; int value; };", 8, &[]).unwrap();
        assert_eq!(packed.fields[1].off, 1);
        assert_eq!(packed.size, 5);
    }

    #[test]
    fn zero_width_bitfield_starts_a_new_storage_unit() {
        let bits = parse_c("struct Bits { char first:1; int :0; int second:1; };", 8, &[]).unwrap();
        assert_eq!(bits.fields[0].off, 0);
        assert_eq!(bits.fields[1].off, 4);
    }

    #[test]
    fn rejects_named_zero_width_bitfields() {
        let err = parse_c("struct Bits { int separator:0; };", 8, &[]).unwrap_err();
        assert!(err.contains("zero-width") || err.contains("Zero-width"), "unexpected error: {err}");
    }

    #[test]
    fn signed_bitfields_are_sign_extended_in_values() {
        let bits = parse_c("struct Bits { int value:3; unsigned int raw:3; };", 8, &[]).unwrap();
        let bin = crate::loader::raw_binary(&crate::loader::RawSpec {
            path: "bits".into(), name: "bits".into(), arch: crate::loader::Arch::X64, big: false,
            segs: vec![(0x1000, vec![0x05, 0, 0, 0, 0x02, 0, 0, 0])], entry: None, format: "test".into(),
        });
        assert!(value(&bin, 0x1000, &bits.fields[0]).starts_with("-3"));
        assert!(value(&bin, 0x1000, &bits.fields[1]).starts_with("2"));
    }

    #[test]
    fn compatible_signedness_bitfields_share_storage() {
        let bits = parse_c("struct Bits { int signed_value:3; signed int raw_value:3; };", 8, &[]).unwrap();
        assert_eq!(bits.fields[0].off, 0);
        assert_eq!(bits.fields[1].off, 0);
        assert_eq!(bits.fields[1].bit_offset, Some(3));
    }
}
