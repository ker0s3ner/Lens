//! Minimal Microsoft PDB symbol ingestion for PE files.

use pdb::{FallibleIterator, SymbolData};
use std::path::Path;

/// Read global procedure/public symbols and return their RVAs plus display names.
pub fn symbols(path: &Path) -> Option<Vec<(u32, String)>> {
    let file = std::fs::File::open(path).ok()?;
    let mut db = pdb::PDB::open(file).ok()?;
    let map = db.address_map().ok()?;
    let table = db.global_symbols().ok()?;
    let mut iter = table.iter();
    let mut out = Vec::new();
    while let Some(symbol) = iter.next().ok()? {
        let data = symbol.parse().ok()?;
        let (offset, name) = match data {
            SymbolData::Public(data) => (data.offset, data.name),
            SymbolData::Procedure(data) => (data.offset, data.name),
            _ => continue,
        };
        let Some(rva) = offset.to_rva(&map) else { continue };
        let name = name.to_string().into_owned();
        if !name.is_empty() { out.push((rva.0, name)); }
    }
    out.sort_by_key(|(rva, _)| *rva);
    out.dedup_by_key(|(rva, _)| *rva);
    Some(out)
}
