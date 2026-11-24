//! Minimal Microsoft PDB symbol ingestion for PE files.

use pdb::{FallibleIterator, SymbolData};
use std::collections::HashMap;
use std::path::Path;

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
            pdb::TypeData::Modifier(m) => type_name(m.underlying_type, &out),
            pdb::TypeData::Class(c) => format!("struct {}", c.name),
            pdb::TypeData::Union(u) => format!("union {}", u.name),
            pdb::TypeData::Enumeration(e) => format!("enum {}", e.name),
            pdb::TypeData::ArgumentList(a) => a.arguments.iter().map(|i| type_name(*i, &out)).collect::<Vec<_>>().join(", "),
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

fn collect<'a>(mut iter: pdb::SymbolIter<'a>, map: &pdb::AddressMap<'_>, types: &HashMap<pdb::TypeIndex, String>, out: &mut Vec<(u32, String)>, protos: &mut Vec<String>) {
    while let Ok(Some(symbol)) = iter.next() {
        let Ok(data) = symbol.parse() else { continue };
        let (offset, name) = match data {
            SymbolData::Public(data) => (data.offset, data.name),
            SymbolData::Procedure(data) => {
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
pub fn symbols(path: &Path) -> Option<(Vec<(u32, String)>, String)> {
    let file = std::fs::File::open(path).ok()?;
    let mut db = pdb::PDB::open(file).ok()?;
    let map = db.address_map().ok()?;
    let types = pdb_types(&mut db);
    let mut out = Vec::new();
    let mut protos = Vec::new();
    if let Ok(table) = db.global_symbols() {
        collect(table.iter(), &map, &types, &mut out, &mut protos);
    }
    if let Ok(info) = db.debug_information() {
        if let Ok(mut modules) = info.modules() {
            while let Ok(Some(module)) = modules.next() {
                if let Ok(Some(module_info)) = db.module_info(&module) {
                    if let Ok(symbols) = module_info.symbols() {
                        collect(symbols, &map, &types, &mut out, &mut protos);
                    }
                }
            }
        }
    }
    out.sort_by_key(|(rva, _)| *rva);
    out.dedup_by_key(|(rva, _)| *rva);
    protos.sort();
    protos.dedup();
    Some((out, protos.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::symbols;

    #[test]
    fn ignores_non_pdb_inputs() {
        let path = std::env::temp_dir().join("lens-not-a-pdb.bin");
        std::fs::write(&path, b"not a PDB").unwrap();
        assert!(symbols(&path).is_none());
        let _ = std::fs::remove_file(path);
    }
}
