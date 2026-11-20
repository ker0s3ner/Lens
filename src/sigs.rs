//! Library function recognition. Signature files are learned from any program that still has its
//! function names (a library with symbols, a debug build) and are matched against functions that
//! have no name. A function is described by its first 32 instructions with addresses blanked out.

use crate::analysis::{Analysis, FuncKind};
use crate::loader::{Arch, Binary};
use crate::multiarch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

const PREFIX: usize = 32;
const MIN_INSNS: usize = 8;

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub n: u32,
    pub h: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SigFile {
    pub library: String,
    pub arch: String,
    pub entries: Vec<Entry>,
}

pub fn dir() -> PathBuf {
    let d = crate::store::config_dir().join("sigs");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// Blank out numbers that look like addresses so the same code at another address hashes the same.
fn normalise(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'0' && b.get(i + 1) == Some(&b'x') {
            let mut j = i + 2;
            while j < b.len() && b[j].is_ascii_hexdigit() {
                j += 1;
            }
            let v = u64::from_str_radix(&s[i + 2..j], 16).unwrap_or(0);
            if v > 0xFFF {
                out.push('N');
            } else {
                out.push_str(&s[i..j]);
            }
            i = j;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

fn fnv(h: &mut u64, bytes: &[u8]) {
    for b in bytes {
        *h ^= *b as u64;
        *h = h.wrapping_mul(0x100000001b3);
    }
}

/// (instructions hashed, hash) for the function starting at `start`.
pub fn signature(bin: &Binary, an: &Analysis, start: u64) -> Option<(u32, u64)> {
    let f = an.functions.get(&start)?;
    let mut addrs: Vec<u64> = f.blocks.iter().flat_map(|b| b.insns.iter().copied()).collect();
    addrs.sort_unstable();
    addrs.truncate(PREFIX);
    if addrs.len() < MIN_INSNS {
        return None;
    }
    let mut h: u64 = 0xcbf29ce484222325;
    for a in &addrs {
        let r = multiarch::one(bin, *a)?;
        fnv(&mut h, normalise(&multiarch::text(&r)).as_bytes());
        fnv(&mut h, b"\n");
    }
    Some((addrs.len() as u32, h))
}

fn arch_key(a: Arch) -> String {
    format!("{a:?}")
}

fn is_auto_name(n: &str) -> bool {
    n.starts_with("sub_") || n.starts_with("loc_") || n.starts_with("nullsub") || n.is_empty()
}

/// Learn from a program whose functions have real names.
pub fn learn(bin: &Binary, an: &Analysis) -> SigFile {
    let mut by_hash: HashMap<(u32, u64), Vec<String>> = HashMap::new();
    for (a, f) in &an.functions {
        if f.kind == FuncKind::Import {
            continue;
        }
        let Some((n, name)) = an.names.get(a).map(|(n, _)| (n.clone(), ())).map(|(n, _)| (n.clone(), n)) else { continue };
        if is_auto_name(&n) {
            continue;
        }
        if let Some((cnt, h)) = signature(bin, an, *a) {
            by_hash.entry((cnt, h)).or_default().push(name);
        }
    }
    let mut entries = vec![];
    for ((n, h), names) in by_hash {
        // identical code under several names is ambiguous, keep only unique matches
        if names.len() == 1 {
            entries.push(Entry { n, h: format!("{h:016x}"), name: names[0].clone() });
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    SigFile { library: bin.file_name.clone(), arch: arch_key(bin.arch), entries }
}

pub fn save(sf: &SigFile) -> Result<PathBuf, String> {
    let p = dir().join(format!("{}-{}.json", sf.library.replace(['/', ' '], "_"), sf.arch));
    let s = serde_json::to_string(sf).map_err(|e| e.to_string())?;
    std::fs::write(&p, s).map_err(|e| e.to_string())?;
    Ok(p)
}

pub fn load_all(arch: Arch) -> Vec<SigFile> {
    let key = arch_key(arch);
    let Ok(rd) = std::fs::read_dir(dir()) else { return vec![] };
    rd.filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|s| serde_json::from_str::<SigFile>(&s).ok())
        .filter(|s| s.arch == key)
        .collect()
}

/// Names for unnamed functions that match a known signature.
pub fn apply(bin: &Binary, an: &Analysis) -> HashMap<u64, String> {
    let files = load_all(bin.arch);
    let mut out = HashMap::new();
    if files.is_empty() {
        return out;
    }
    let mut table: HashMap<(u32, String), String> = HashMap::new();
    for f in &files {
        for e in &f.entries {
            table.entry((e.n, e.h.clone())).or_insert_with(|| e.name.clone());
        }
    }
    for (a, f) in &an.functions {
        if f.kind == FuncKind::Import {
            continue;
        }
        let unnamed = an.names.get(a).map(|(n, _)| is_auto_name(n)).unwrap_or(true);
        if !unnamed {
            continue;
        }
        if let Some((n, h)) = signature(bin, an, *a) {
            if let Some(name) = table.get(&(n, format!("{h:016x}"))) {
                out.insert(*a, name.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn blanks_addresses() {
        assert_eq!(super::normalise("bl 0x100004428"), "bl N");
        assert_eq!(super::normalise("add x0, x1, #0x20"), "add x0, x1, #0x20");
    }
}
