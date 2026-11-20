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
    if let Some(s) = scalar(ty, ptr) {
        return Some(s);
    }
    let n = ty.trim().trim_start_matches("struct ").trim();
    known.iter().find(|s| s.name == n).map(|s| (s.size, s.fields.iter().map(|f| f.size.min(8)).max().unwrap_or(1).max(1)))
}

/// Parse `struct Name { int a; char b[8]; void *p; }` (comments and `typedef` are ignored).
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
    let open = clean.find('{').ok_or("Expected `struct Name { … }`")?;
    let close = clean.rfind('}').ok_or("Missing closing brace")?;
    let head = clean[..open].replace("typedef", "");
    let name = head.split_whitespace().filter(|w| *w != "struct").last().ok_or("The struct needs a name")?.to_string();
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
        off = off.div_ceil(al) * al;
        max_align = max_align.max(al.min(8));
        let total = sz * count;
        let shown_ty = if count > 1 { format!("{ty}[{count}]") } else { ty };
        fields.push(Field { off, name: fname, ty: shown_ty, size: total });
        off += total;
    }
    if fields.is_empty() {
        return Err("The struct has no fields".into());
    }
    let size = off.div_ceil(max_align) * max_align;
    Ok(StructDef { name, fields, size })
}

/// Names for the fields of every applied struct.
pub fn field_names(structs: &[StructDef], applied: &[(u64, String)]) -> Vec<(u64, String)> {
    let mut out = vec![];
    for (addr, sname) in applied {
        if let Some(s) = structs.iter().find(|s| &s.name == sname) {
            for f in &s.fields {
                out.push((addr + f.off as u64, format!("{}.{}", s.name, f.name)));
            }
        }
    }
    out
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
