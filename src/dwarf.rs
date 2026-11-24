//! Reads DWARF debug information (inside the program, or in an adjacent .dSYM on macOS) and turns it into
//! function names and C prototypes with real types and parameter names.

use crate::loader::Binary;
use gimli::AttributeValue;
use object::{Object, ObjectSection};
use std::borrow::Cow;
use std::collections::HashMap;

pub struct DebugInfo {
    /// (address, function name)
    pub functions: Vec<(u64, String)>,
    /// C declarations, one per line
    pub protos: String,
    /// struct / union / enum definitions found, as C text
    pub types: String,
    /// Structs, unions and enums with member offsets taken directly from DWARF.
    pub parsed_types: Vec<crate::types::StructDef>,
}

type R<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

fn section<'a>(file: &'a object::File<'a>, name: &str) -> Cow<'a, [u8]> {
    // Mach-O calls them __debug_info, ELF .debug_info; the gimli id gives the ELF name
    let alt = format!("__{}", name.trim_start_matches('.'));
    file.section_by_name(name)
        .or_else(|| file.section_by_name(&alt))
        .and_then(|s| s.uncompressed_data().ok())
        .unwrap_or(Cow::Borrowed(&[]))
}

struct Ctx<'a> {
    dwarf: &'a gimli::Dwarf<R<'a>>,
}

fn attr_string<'a>(c: &Ctx<'a>, unit: &gimli::Unit<R<'a>>, v: AttributeValue<R<'a>>) -> Option<String> {
    let s = c.dwarf.attr_string(unit, v).ok()?;
    Some(s.to_string_lossy().to_string())
}

fn array_count(unit: &gimli::Unit<R<'_>>, off: gimli::UnitOffset) -> Option<u64> {
    let mut tree = unit.entries_at_offset(off).ok()?;
    tree.next_dfs().ok()??;
    while let Some((depth, child)) = tree.next_dfs().ok()? {
        if depth < 1 { break; }
        if depth != 1 || child.tag() != gimli::DW_TAG_subrange_type { continue; }
        if let Some(count) = child.attr_value(gimli::DW_AT_count).ok().flatten().and_then(|v| v.udata_value()) {
            return Some(count);
        }
        let upper = child.attr_value(gimli::DW_AT_upper_bound).ok().flatten().and_then(|v| v.udata_value().or_else(|| v.sdata_value().and_then(|n| u64::try_from(n).ok())))?;
        let lower = child.attr_value(gimli::DW_AT_lower_bound).ok().flatten().and_then(|v| v.udata_value().or_else(|| v.sdata_value().and_then(|n| u64::try_from(n).ok()))).unwrap_or(0);
        return upper.checked_sub(lower)?.checked_add(1);
    }
    None
}

fn type_name<'a>(c: &Ctx<'a>, unit: &gimli::Unit<R<'a>>, off: Option<gimli::UnitOffset>, depth: u32) -> String {
    let Some(off) = off else { return "void".into() };
    if depth > 8 {
        return "void".into();
    }
    let Ok(e) = unit.entry(off) else { return "void".into() };
    let name = e.attr_value(gimli::DW_AT_name).ok().flatten().and_then(|v| attr_string(c, unit, v));
    let inner = || -> Option<gimli::UnitOffset> {
        match e.attr_value(gimli::DW_AT_type).ok().flatten() {
            Some(AttributeValue::UnitRef(o)) => Some(o),
            _ => None,
        }
    };
    match e.tag() {
        gimli::DW_TAG_base_type | gimli::DW_TAG_typedef => name.unwrap_or_else(|| "int".into()),
        gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type => {
            let t = type_name(c, unit, inner(), depth + 1);
            if t.ends_with('*') { format!("{t}*") } else { format!("{t} *") }
        }
        gimli::DW_TAG_const_type => format!("const {}", type_name(c, unit, inner(), depth + 1)),
        gimli::DW_TAG_volatile_type | gimli::DW_TAG_restrict_type | gimli::DW_TAG_atomic_type => type_name(c, unit, inner(), depth + 1),
        gimli::DW_TAG_structure_type => format!("struct {}", name.unwrap_or_else(|| "anon".into())),
        gimli::DW_TAG_union_type => format!("union {}", name.unwrap_or_else(|| "anon".into())),
        gimli::DW_TAG_class_type => format!("class {}", name.unwrap_or_else(|| "anon".into())),
        gimli::DW_TAG_enumeration_type => format!("enum {}", name.unwrap_or_else(|| "anon".into())),
        gimli::DW_TAG_array_type => {
            let t = type_name(c, unit, inner(), depth + 1);
            let count = array_count(unit, e.offset()).map(|n| n.to_string()).unwrap_or_default();
            format!("{t}[{count}]")
        }
        gimli::DW_TAG_subroutine_type => {
            let ret = type_name(c, unit, inner(), depth + 1);
            let mut params = Vec::new();
            if let Ok(mut tree) = unit.entries_at_offset(e.offset()) {
                let _ = tree.next_dfs();
                while let Ok(Some((level, child))) = tree.next_dfs() {
                    if level < 1 { break; }
                    if level == 1 && child.tag() == gimli::DW_TAG_formal_parameter {
                        let p = match child.attr_value(gimli::DW_AT_type).ok().flatten() {
                            Some(AttributeValue::UnitRef(o)) => type_name(c, unit, Some(o), depth + 1),
                            _ => "void".into(),
                        };
                        params.push(p);
                    }
                }
            }
            format!("fn({}) -> {ret}", params.join(", "))
        }
        _ => "void".into(),
    }
}

fn type_size<'a>(unit: &gimli::Unit<R<'a>>, off: Option<gimli::UnitOffset>, depth: u32) -> Option<u32> {
    if depth > 12 { return None; }
    let off = off?;
    let e = unit.entry(off).ok()?;
    let number = |attr| e.attr_value(attr).ok().flatten().and_then(|v| v.udata_value().or_else(|| v.sdata_value().map(|n| n as u64)));
    if let Some(n) = number(gimli::DW_AT_byte_size) { return u32::try_from(n).ok(); }
    match e.tag() {
        gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type => Some(unit.header.address_size() as u32),
        gimli::DW_TAG_typedef | gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type | gimli::DW_TAG_restrict_type | gimli::DW_TAG_atomic_type => {
            let inner = match e.attr_value(gimli::DW_AT_type).ok().flatten()? { AttributeValue::UnitRef(o) => Some(o), _ => None };
            type_size(unit, inner, depth + 1)
        }
        _ => None,
    }
}

fn tidy(t: &str) -> String {
    let mut t = t.replace("* *", "**");
    while t.contains("* *") {
        t = t.replace("* *", "**");
    }
    t
}

/// Full C text for struct / union / enum definitions.
fn type_defs<'a>(c: &Ctx<'a>, unit: &gimli::Unit<R<'a>>, out: &mut Vec<String>, parsed: &mut Vec<crate::types::StructDef>) -> gimli::Result<()> {
    let mut entries = unit.entries();
    while let Some((_, e)) = entries.next_dfs()? {
        let tag = e.tag();
        if !matches!(tag, gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_enumeration_type) {
            continue;
        }
        let Some(name) = e.attr_value(gimli::DW_AT_name)?.and_then(|v| attr_string(c, unit, v)) else { continue };
        let off = e.offset();
        let mut tree = unit.entries_at_offset(off)?;
        tree.next_dfs()?;
        let mut body = vec![];
        let mut fields = vec![];
        let mut enum_values = vec![];
        let mut layout_ok = true;
        let mut depth = 0isize;
        while let Some((d, child)) = tree.next_dfs()? {
            depth += d;
            if depth < 1 {
                break;
            }
            if depth != 1 {
                continue;
            }
            match child.tag() {
                gimli::DW_TAG_member => {
                    let n = child.attr_value(gimli::DW_AT_name)?.and_then(|v| attr_string(c, unit, v)).unwrap_or_default();
                    let type_off = match child.attr_value(gimli::DW_AT_type)? { Some(AttributeValue::UnitRef(o)) => Some(o), _ => None };
                    let t = type_name(c, unit, type_off, 0);
                    body.push(format!("  {} {};", tidy(&t), n).replace("* ", "*"));
                    let bit_width = child.attr_value(gimli::DW_AT_bit_size)?.and_then(|v| v.udata_value()).and_then(|n| u8::try_from(n).ok());
                    let bit_offset = child.attr_value(gimli::DW_AT_data_bit_offset)?.and_then(|v| v.udata_value());
                    let member_offset = if tag == gimli::DW_TAG_union_type { Some(0) } else {
                        child.attr_value(gimli::DW_AT_data_member_location)?.and_then(|v| v.udata_value().or_else(|| v.sdata_value().and_then(|n| u64::try_from(n).ok())))
                    };
                    let Some(size) = type_size(unit, type_off, 0) else { layout_ok = false; continue };
                    if n.is_empty() { layout_ok = false; continue; }
                    if let Some(width) = bit_width {
                        if width == 0 || (width as u32) > size.saturating_mul(8) { layout_ok = false; continue; }
                        let Some(bits) = bit_offset else { layout_ok = false; continue };
                        let Some(off) = u32::try_from(bits / 8).ok() else { layout_ok = false; continue };
                        let Some(bit) = u8::try_from(bits % 8).ok() else { layout_ok = false; continue };
                        fields.push(crate::types::Field { off, name: n, ty: tidy(&t), size, bit_offset: Some(bit), bit_width: Some(width) });
                    } else {
                        let Some(off) = member_offset.and_then(|n| u32::try_from(n).ok()) else { layout_ok = false; continue };
                        fields.push(crate::types::Field { off, name: n, ty: tidy(&t), size, bit_offset: None, bit_width: None });
                    }
                }
                gimli::DW_TAG_enumerator => {
                    let n = child.attr_value(gimli::DW_AT_name)?.and_then(|v| attr_string(c, unit, v)).unwrap_or_default();
                    let v = child.attr_value(gimli::DW_AT_const_value)?.and_then(|v| v.sdata_value().or_else(|| v.udata_value().map(|x| x as i64))).unwrap_or(0);
                    body.push(format!("  {n} = {v},"));
                    if !n.is_empty() { enum_values.push(crate::types::EnumValue { name: n, value: v }); }
                }
                _ => {}
            }
        }
        if body.is_empty() {
            continue;
        }
        let kw = match tag { gimli::DW_TAG_structure_type => "struct", gimli::DW_TAG_union_type => "union", _ => "enum" };
        out.push(format!("{kw} {name} {{\n{}\n}};", body.join("\n")));
        if tag == gimli::DW_TAG_enumeration_type {
            let size = e.attr_value(gimli::DW_AT_byte_size)?.and_then(|v| v.udata_value()).and_then(|n| u32::try_from(n).ok()).unwrap_or(4);
            if !enum_values.is_empty() && (1..=8).contains(&size) {
                parsed.push(crate::types::StructDef { name, fields: vec![], size, is_union: false, is_enum: true, enum_values, alias_of: None });
            }
        } else {
            let size = e.attr_value(gimli::DW_AT_byte_size)?.and_then(|v| v.udata_value()).and_then(|n| u32::try_from(n).ok());
            if layout_ok && !fields.is_empty() {
                if let Some(size) = size {
                    parsed.push(crate::types::StructDef { name, fields, size, is_union: tag == gimli::DW_TAG_union_type, is_enum: false, enum_values: vec![], alias_of: None });
                }
            }
        }
    }
    Ok(())
}

fn read_all<'a>(file: &'a object::File<'a>, data: &'a HashMap<String, Cow<'a, [u8]>>) -> Option<gimli::Dwarf<R<'a>>> {
    let endian = if file.is_little_endian() { gimli::RunTimeEndian::Little } else { gimli::RunTimeEndian::Big };
    let get = |id: gimli::SectionId| -> Result<R<'a>, gimli::Error> {
        let n = id.name();
        let d: &[u8] = data.get(n).map(|c| &**c).unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(d, endian))
    };
    gimli::Dwarf::load(get).ok()
}

pub fn extract(bytes: &[u8]) -> Option<DebugInfo> {
    let file = object::File::parse(bytes).ok()?;
    let ids = [
        gimli::SectionId::DebugAbbrev, gimli::SectionId::DebugInfo, gimli::SectionId::DebugStr, gimli::SectionId::DebugLine,
        gimli::SectionId::DebugLineStr, gimli::SectionId::DebugStrOffsets, gimli::SectionId::DebugAddr, gimli::SectionId::DebugRanges,
        gimli::SectionId::DebugRngLists, gimli::SectionId::DebugTypes, gimli::SectionId::DebugLoc, gimli::SectionId::DebugLocLists,
    ];
    let mut data: HashMap<String, Cow<[u8]>> = HashMap::new();
    for id in ids {
        data.insert(id.name().to_string(), section(&file, id.name()));
    }
    if std::env::var("LENS_TRACE3").is_ok() {
        eprintln!("dwarf sections: {:?}", data.iter().map(|(k, v)| (k.clone(), v.len())).collect::<Vec<_>>());
    }
    if data.get(".debug_info").map(|d| d.is_empty()).unwrap_or(true) {
        return None;
    }
    let dwarf = read_all(&file, &data)?;
    let c = Ctx { dwarf: &dwarf };
    let mut functions = vec![];
    let mut protos = vec![];
    let mut types = vec![];
    let mut parsed_types = vec![];
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else { continue };
        let _ = type_defs(&c, &unit, &mut types, &mut parsed_types);
        let mut entries = unit.entries();
        let mut cur: Option<(u64, String, String, Vec<(String, String)>, bool)> = None;
        let mut depth = 0isize;
        let mut fdepth = 0isize;
        while let Ok(Some((d, e))) = entries.next_dfs() {
            depth += d;
            if cur.is_some() {
                if depth <= fdepth {
                    let (a, n, r, ps, var) = cur.take().unwrap();
                    functions.push((a, n.clone()));
                    let plist: Vec<String> = ps.iter().map(|(t, nm)| if t.ends_with('*') { format!("{t}{nm}") } else { format!("{t} {nm}") }).collect();
                    let mut all = plist;
                    if var { all.push("...".into()); }
                    protos.push(format!("{} {}({});", tidy(&r), n, if all.is_empty() { "void".to_string() } else { all.join(", ") }));
                }
            }
            match e.tag() {
                gimli::DW_TAG_subprogram => {
                    if std::env::var("LENS_TRACE3").is_ok() {
                        eprintln!("subprogram attrs: {:?}", e.attr_value(gimli::DW_AT_low_pc).ok().flatten());
                    }
                    let low = match e.attr_value(gimli::DW_AT_low_pc).ok().flatten() {
                        Some(AttributeValue::Addr(a)) => Some(a),
                        Some(v @ AttributeValue::DebugAddrIndex(_)) => dwarf.attr_address(&unit, v).ok().flatten(),
                        _ => None,
                    };
                    let name = e.attr_value(gimli::DW_AT_name).ok().flatten().and_then(|v| attr_string(&c, &unit, v));
                    if let (Some(low), Some(name)) = (low, name) {
                        if low != 0 {
                            let ret = match e.attr_value(gimli::DW_AT_type).ok().flatten() {
                                Some(AttributeValue::UnitRef(o)) => type_name(&c, &unit, Some(o), 0),
                                _ => "void".into(),
                            };
                            cur = Some((low, name, ret, vec![], false));
                            fdepth = depth;
                        }
                    }
                }
                gimli::DW_TAG_formal_parameter if cur.is_some() && depth == fdepth + 1 => {
                    let n = e.attr_value(gimli::DW_AT_name).ok().flatten().and_then(|v| attr_string(&c, &unit, v)).unwrap_or_default();
                    let t = match e.attr_value(gimli::DW_AT_type).ok().flatten() {
                        Some(AttributeValue::UnitRef(o)) => type_name(&c, &unit, Some(o), 0),
                        _ => "void".into(),
                    };
                    if let Some(f) = cur.as_mut() { f.3.push((tidy(&t), n)); }
                }
                gimli::DW_TAG_unspecified_parameters if cur.is_some() && depth == fdepth + 1 => {
                    if let Some(f) = cur.as_mut() { f.4 = true; }
                }
                _ => {}
            }
        }
        if let Some((a, n, r, ps, var)) = cur.take() {
            functions.push((a, n.clone()));
            let mut all: Vec<String> = ps.iter().map(|(t, nm)| format!("{t} {nm}")).collect();
            if var { all.push("...".into()); }
            protos.push(format!("{} {}({});", tidy(&r), n, all.join(", ")));
        }
    }
    let _ = c.dwarf.units().next();
    if functions.is_empty() && types.is_empty() {
        return None;
    }
    types.sort();
    types.dedup();
    parsed_types.sort_by(|a, b| a.name.cmp(&b.name));
    parsed_types.dedup_by(|a, b| a.name == b.name);
    Some(DebugInfo { functions, protos: protos.join("\n"), types: types.join("\n"), parsed_types })
}

/// Looks for DWARF in the program itself, then in a .dSYM bundle next to it.
pub fn load(bin: &Binary) -> Option<DebugInfo> {
    let bytes = std::fs::read(&bin.path).ok()?;
    let mine = bytes.get(bin.file_base as usize..).unwrap_or(&bytes);
    if let Some(d) = extract(mine) {
        return Some(d);
    }
    let p = std::path::Path::new(&bin.path);
    let name = p.file_name()?.to_string_lossy().to_string();
    let dsym = p.parent()?.join(format!("{name}.dSYM/Contents/Resources/DWARF/{name}"));
    let db = std::fs::read(dsym).ok()?;
    // a universal dSYM holds one DWARF file per CPU; take the one that matches
    if let Ok(f) = object::read::macho::MachOFatFile64::parse(&*db).map(|_| ()).or_else(|_| Err(())) {
        let _ = f;
    }
    extract(&db).or_else(|| {
        let fat = object::read::macho::MachOFatFile32::parse(&*db).ok()?;
        use object::read::macho::FatArch;
        let want_arm = bin.arch == crate::loader::Arch::Arm64;
        for a in fat.arches() {
            let is_arm = a.cputype() == object::macho::CPU_TYPE_ARM64;
            if is_arm == want_arm {
                return extract(a.data(&*db).ok()?);
            }
        }
        None
    })
}

/// Names the functions found in the debug info and keeps their prototypes for the decompiler.
pub fn apply(bin: &mut Binary) {
    if let Some(d) = load(bin) {
        let known: std::collections::HashSet<u64> = bin.symbols.iter().map(|s| s.0).collect();
        let mut n = 0;
        for (a, name) in &d.functions {
            if !known.contains(a) && bin.is_exec(*a) {
                bin.symbols.push((*a, name.clone()));
                n += 1;
            }
        }
        bin.notes.push(format!("Debug info (DWARF): {} functions, {} recoverable type layouts ({} functions named from it).", d.functions.len(), d.parsed_types.len(), n));
        bin.debug_protos = d.protos;
        bin.debug_types = d.types;
        bin.debug_structs = d.parsed_types;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_dwarf_in_garbage() {
        assert!(extract(b"not an object file").is_none());
    }
}
