//! Minimal Microsoft PDB symbol ingestion for PE files.

use pdb::{FallibleIterator, SymbolData};
use std::path::Path;

fn collect<'a>(mut iter: pdb::SymbolIter<'a>, map: &pdb::AddressMap<'_>, out: &mut Vec<(u32, String)>) {
    while let Ok(Some(symbol)) = iter.next() {
        let Ok(data) = symbol.parse() else { continue };
        let (offset, name) = match data {
            SymbolData::Public(data) => (data.offset, data.name),
            SymbolData::Procedure(data) => (data.offset, data.name),
            _ => continue,
        };
        let Some(rva) = offset.to_rva(map) else { continue };
        let name = name.to_string().into_owned();
        if !name.is_empty() { out.push((rva.0, name)); }
    }
}

/// Read global procedure/public symbols and return their RVAs plus display names.
pub fn symbols(path: &Path) -> Option<Vec<(u32, String)>> {
    let file = std::fs::File::open(path).ok()?;
    let mut db = pdb::PDB::open(file).ok()?;
    let map = db.address_map().ok()?;
    let mut out = Vec::new();
    if let Ok(table) = db.global_symbols() {
        collect(table.iter(), &map, &mut out);
    }
    if let Ok(info) = db.debug_information() {
        if let Ok(mut modules) = info.modules() {
            while let Ok(Some(module)) = modules.next() {
                if let Ok(Some(module_info)) = db.module_info(&module) {
                    if let Ok(symbols) = module_info.symbols() {
                        collect(symbols, &map, &mut out);
                    }
                }
            }
        }
    }
    out.sort_by_key(|(rva, _)| *rva);
    out.dedup_by_key(|(rva, _)| *rva);
    Some(out)
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
