//! Minimal Microsoft PDB symbol ingestion for PE files.

use pdb::{FallibleIterator, SymbolData};
use std::collections::HashMap;
use std::path::Path;

fn pdb_enum_declarations(db: &mut pdb::PDB<std::fs::File>) -> Vec<String> {
    let Ok(info) = db.type_information() else { return Vec::new() };
    let mut iter = info.iter();
    let mut lists: HashMap<pdb::TypeIndex, (Vec<(String, i64)>, Option<pdb::TypeIndex>)> = HashMap::new();
    let mut enums = Vec::new();
    while let Ok(Some(item)) = iter.next() {
        let Ok(data) = item.parse() else { continue };
        match data {
            pdb::TypeData::FieldList(list) => {
                let values = list.fields.iter().filter_map(|field| match field {
                    pdb::TypeData::Enumerate(e) => e.value.to_string().parse().ok().map(|v| (e.name.to_string().into_owned(), v)),
                    _ => None,
                }).collect::<Vec<_>>();
                lists.insert(item.index(), (values, list.continuation));
            }
            pdb::TypeData::Enumeration(e) => enums.push((e.name.to_string().into_owned(), e.fields)),
            _ => {}
        }
    }
    enums.into_iter().filter_map(|(name, fields)| {
        let mut values = Vec::new();
        let mut current = Some(fields);
        let mut seen = std::collections::HashSet::new();
        while let Some(index) = current {
            if !seen.insert(index) { return None; }
            let (part, next) = lists.get(&index)?;
            values.extend(part.iter().cloned());
            current = *next;
        }
        if name.is_empty() || values.is_empty() { return None; }
        let body = values.iter().map(|(n, v)| format!("{n} = {v}")).collect::<Vec<_>>().join(", ");
        Some(format!("enum {name} {{ {body} }};"))
    }).collect()
}

fn pdb_structs(db: &mut pdb::PDB<std::fs::File>, types: &HashMap<pdb::TypeIndex, String>, ptr: u32) -> Vec<crate::types::StructDef> {
    let Ok(info) = db.type_information() else { return Vec::new() };
    let mut iter = info.iter();
    let mut lists: HashMap<pdb::TypeIndex, (Vec<(String, pdb::TypeIndex, u64)>, Option<pdb::TypeIndex>, bool)> = HashMap::new();
    let mut bitfields: HashMap<pdb::TypeIndex, (u8, u8)> = HashMap::new();
    let mut enum_sizes: HashMap<pdb::TypeIndex, u32> = HashMap::new();
    let mut layout_sizes: HashMap<String, u32> = HashMap::new();
    let mut records = Vec::new();
    while let Ok(Some(item)) = iter.next() {
        let Ok(data) = item.parse() else { continue };
        match data {
            pdb::TypeData::FieldList(list) => {
                let has_base = list.fields.iter().any(|field| matches!(field, pdb::TypeData::BaseClass(_) | pdb::TypeData::VirtualBaseClass(_)));
                let fields = list.fields.iter().filter_map(|field| match field {
                    pdb::TypeData::Member(member) => Some((member.name.to_string().into_owned(), member.field_type, member.offset)),
                    _ => None,
                }).collect();
                lists.insert(item.index(), (fields, list.continuation, has_base));
            }
            pdb::TypeData::Class(class) if matches!(class.kind, pdb::ClassKind::Struct | pdb::ClassKind::Class | pdb::ClassKind::Interface) => {
                if class.size <= u32::MAX as u64 { layout_sizes.insert(format!("struct {}", class.name), class.size as u32); }
                if let Some(fields) = class.fields { records.push((class.name.to_string().into_owned(), fields, class.size, false)); }
            }
            pdb::TypeData::Bitfield(bitfield) => {
                bitfields.insert(item.index(), (bitfield.position, bitfield.length));
            }
            pdb::TypeData::Enumeration(enumeration) => {
                let underlying = type_name(enumeration.underlying_type, types);
                let size = match underlying.as_str() {
                    "char" | "int8_t" | "uint8_t" | "bool" => 1,
                    "short" | "int16_t" | "uint16_t" => 2,
                    "int" | "int32_t" | "uint32_t" | "float" => 4,
                    "long" | "int64_t" | "uint64_t" | "double" => 8,
                    _ => 0,
                };
                if size != 0 { enum_sizes.insert(item.index(), size); }
            }
            pdb::TypeData::Union(union) => {
                if union.size <= u32::MAX as u64 { layout_sizes.insert(format!("union {}", union.name), union.size as u32); }
                records.push((union.name.to_string().into_owned(), union.fields, union.size, true));
            }
            _ => {}
        }
    }
    records.into_iter().filter_map(|(name, field_list, size, is_union)| {
        let mut fields = Vec::new();
        let mut current = Some(field_list);
        let mut seen = std::collections::HashSet::new();
        while let Some(index) = current {
            if !seen.insert(index) { return None; }
            let (part, next, has_base) = lists.get(&index)?;
            if *has_base { return None; }
            fields.extend(part.iter().cloned());
            current = *next;
        }
        let mut out = Vec::new();
        for (field_name, field_type, offset) in fields {
            let ty = types.get(&field_type)?.clone();
            let field_size = if let Some(size) = enum_sizes.get(&field_type) { *size } else if let Some(size) = layout_sizes.get(&ty) { *size } else if ty.ends_with('*') || ty.starts_with("fn(") { ptr } else if let Some((base, count)) = ty.strip_suffix(']').and_then(|t| t.rsplit_once('[')) {
                let element = match base { "char" | "int8_t" | "uint8_t" | "bool" => 1, "short" | "int16_t" | "uint16_t" => 2, "int" | "int32_t" | "uint32_t" | "float" => 4, "long" | "int64_t" | "uint64_t" | "double" => 8, _ if base.ends_with('*') => ptr, _ => 0 };
                if element == 0 { return None; }
                element.saturating_mul(count.parse::<u32>().ok()?)
            } else { match ty.trim_start_matches("const ").trim_start_matches("volatile ") {
                "char" | "int8_t" | "uint8_t" | "bool" => 1,
                "short" | "int16_t" | "uint16_t" => 2,
                "int" | "int32_t" | "uint32_t" | "float" => 4,
                "long" | "int64_t" | "uint64_t" | "double" => 8,
                _ => return None,
            }};
            if field_name.is_empty() || offset > u32::MAX as u64 { return None; }
            let (bit_offset, bit_width) = bitfields.get(&field_type).map(|(position, length)| (Some(*position), Some(*length))).unwrap_or((None, None));
            out.push(crate::types::Field { off: offset as u32, name: field_name, ty, size: field_size, bit_offset, bit_width });
        }
        if name.is_empty() || out.is_empty() || size > u32::MAX as u64 { return None; }
        Some(crate::types::StructDef { name, fields: out, size: size as u32, is_union, is_enum: false, enum_values: vec![], alias_of: None })
    }).collect()
}

fn type_name(index: pdb::TypeIndex, types: &HashMap<pdb::TypeIndex, String>) -> String {
    if index.0 < 0x1000 {
        let base = match index.0 & 0xff {
            0x03 => "void", 0x10 | 0x70 => "char", 0x20 => "unsigned char",
            0x68 => "int8_t", 0x69 => "uint8_t", 0x11 | 0x72 => "int16_t", 0x21 | 0x73 => "uint16_t",
            0x12 | 0x74 => "int32_t", 0x22 | 0x75 => "uint32_t", 0x13 | 0x76 => "int64_t", 0x23 | 0x77 => "uint64_t",
            0x40 | 0x45 => "float", 0x41 => "double", 0x50 => "complex64", 0x51 => "complex128",
            0x08 => "HRESULT", _ => "void",
        };
        let indirect = (index.0 & 0xf00) != 0;
        return if indirect { format!("{base} *") } else { base.into() };
    }
    types.get(&index).cloned().unwrap_or_else(|| "void".into())
}

fn primitive_name(p: pdb::PrimitiveType) -> String {
    let base = match p.kind {
        pdb::PrimitiveKind::Void => "void",
        pdb::PrimitiveKind::Char | pdb::PrimitiveKind::RChar => "char",
        pdb::PrimitiveKind::WChar | pdb::PrimitiveKind::RChar16 | pdb::PrimitiveKind::RChar32 => "wchar_t",
        pdb::PrimitiveKind::I8 => "int8_t",
        pdb::PrimitiveKind::U8 => "uint8_t",
        pdb::PrimitiveKind::Short | pdb::PrimitiveKind::I16 => "int16_t",
        pdb::PrimitiveKind::UShort | pdb::PrimitiveKind::U16 => "uint16_t",
        pdb::PrimitiveKind::Long | pdb::PrimitiveKind::I32 => "int32_t",
        pdb::PrimitiveKind::ULong | pdb::PrimitiveKind::U32 => "uint32_t",
        pdb::PrimitiveKind::Quad | pdb::PrimitiveKind::I64 => "int64_t",
        pdb::PrimitiveKind::UQuad | pdb::PrimitiveKind::U64 => "uint64_t",
        pdb::PrimitiveKind::F32 | pdb::PrimitiveKind::F32PP => "float",
        pdb::PrimitiveKind::F64 => "double",
        pdb::PrimitiveKind::Bool8 | pdb::PrimitiveKind::Bool16 | pdb::PrimitiveKind::Bool32 | pdb::PrimitiveKind::Bool64 => "bool",
        pdb::PrimitiveKind::HRESULT => "HRESULT",
        _ => "void",
    };
    match p.indirection {
        Some(_) => format!("{base} *"),
        None => base.into(),
    }
}

fn pdb_types(db: &mut pdb::PDB<std::fs::File>) -> HashMap<pdb::TypeIndex, String> {
    let Ok(info) = db.type_information() else { return HashMap::new() };
    let mut iter = info.iter();
    let mut out = HashMap::new();
    while let Ok(Some(item)) = iter.next() {
        let Ok(data) = item.parse() else { continue };
        let name = match data {
            pdb::TypeData::Primitive(p) => primitive_name(p),
            pdb::TypeData::Pointer(p) => format!("{} *", type_name(p.underlying_type, &out)),
            pdb::TypeData::Modifier(m) => {
                let mut ty = type_name(m.underlying_type, &out);
                if m.volatile { ty = format!("volatile {ty}"); }
                if m.constant { ty = format!("const {ty}"); }
                ty
            }
            pdb::TypeData::Bitfield(b) => type_name(b.underlying_type, &out),
            pdb::TypeData::Class(c) => format!("struct {}", c.name),
            pdb::TypeData::Union(u) => format!("union {}", u.name),
            pdb::TypeData::Enumeration(e) => format!("enum {}", e.name),
            pdb::TypeData::ArgumentList(a) => a.arguments.iter().map(|i| type_name(*i, &out)).collect::<Vec<_>>().join(", "),
            pdb::TypeData::Array(a) => {
                let element = type_name(a.element_type, &out);
                let element_size = match element.trim_end_matches(" *") {
                    "char" | "int8_t" | "uint8_t" | "bool" => 1,
                    "short" | "int16_t" | "uint16_t" => 2,
                    "int" | "int32_t" | "uint32_t" | "float" => 4,
                    "long" | "int64_t" | "uint64_t" | "double" => 8,
                    _ if element.ends_with('*') => 8,
                    _ => 0,
                };
                let count = a.dimensions.last().copied().unwrap_or(0).checked_div(element_size).unwrap_or(0);
                if element_size == 0 || count == 0 { continue; }
                format!("{element}[{count}]")
            }
            pdb::TypeData::Procedure(p) => {
                let ret = p.return_type.map(|i| type_name(i, &out)).unwrap_or_else(|| "void".into());
                let args = type_name(p.argument_list, &out);
                format!("fn({args}) -> {ret}")
            }
            _ => continue,
        };
        out.insert(item.index(), name);
    }
    out
}

fn collect<'a>(mut iter: pdb::SymbolIter<'a>, map: &pdb::AddressMap<'_>, types: &HashMap<pdb::TypeIndex, String>, out: &mut Vec<(u32, String)>, protos: &mut Vec<String>, noreturn: &mut Vec<String>) {
    while let Ok(Some(symbol)) = iter.next() {
        let Ok(data) = symbol.parse() else { continue };
        let (offset, name) = match data {
            SymbolData::Public(data) => (data.offset, data.name),
            SymbolData::Procedure(data) => {
                if data.flags.never { noreturn.push(data.name.to_string().into_owned()); }
                let signature = types.get(&data.type_index).cloned();
                let result = (data.offset, data.name);
                if let Some(sig) = signature {
                    if let Some((args, ret)) = sig.strip_prefix("fn(").and_then(|s| s.split_once(") -> ")) {
                        protos.push(format!("{ret} {}({args});", data.name));
                    }
                }
                result
            }
            _ => continue,
        };
        let Some(rva) = offset.to_rva(map) else { continue };
        let name = name.to_string().into_owned();
        if !name.is_empty() { out.push((rva.0, name)); }
    }
}

/// Read global procedure/public symbols and return their RVAs plus display names.
pub fn symbols(path: &Path, ptr: u32) -> Option<(Vec<(u32, String)>, String, Vec<String>, Vec<String>, Vec<crate::types::StructDef>)> {
    let file = std::fs::File::open(path).ok()?;
    let mut db = pdb::PDB::open(file).ok()?;
    let map = db.address_map().ok()?;
    let types = pdb_types(&mut db);
    let enum_decls = pdb_enum_declarations(&mut db);
    let structs = pdb_structs(&mut db, &types, ptr);
    let mut out = Vec::new();
    let mut protos = Vec::new();
    let mut noreturn = Vec::new();
    if let Ok(table) = db.global_symbols() {
        collect(table.iter(), &map, &types, &mut out, &mut protos, &mut noreturn);
    }
    if let Ok(info) = db.debug_information() {
        if let Ok(mut modules) = info.modules() {
            while let Ok(Some(module)) = modules.next() {
                if let Ok(Some(module_info)) = db.module_info(&module) {
                    if let Ok(symbols) = module_info.symbols() {
                        collect(symbols, &map, &types, &mut out, &mut protos, &mut noreturn);
                    }
                }
            }
        }
    }
    out.sort_by_key(|(rva, _)| *rva);
    out.dedup_by_key(|(rva, _)| *rva);
    protos.sort();
    protos.dedup();
    noreturn.sort();
    noreturn.dedup();
    Some((out, protos.join("\n"), noreturn, enum_decls, structs))
}

#[cfg(test)]
mod tests {
    use super::{symbols, type_name};
    use std::collections::HashMap;

    #[test]
    fn ignores_non_pdb_inputs() {
        let path = std::env::temp_dir().join("lens-not-a-pdb.bin");
        std::fs::write(&path, b"not a PDB").unwrap();
        assert!(symbols(&path, 8).is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn decodes_inline_primitive_type_indices() {
        let types = HashMap::new();
        assert_eq!(type_name(pdb::TypeIndex(0x74), &types), "int32_t");
        assert_eq!(type_name(pdb::TypeIndex(0x474), &types), "int32_t *");
    }
}
