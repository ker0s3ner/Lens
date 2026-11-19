//! Recovering real source where the program really contains it (Electron apps keep their
//! JavaScript in app.asar), and honest notes where it doesn't.

use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct AsarInfo {
    pub path: PathBuf,
    pub files: usize,
    pub js_files: usize,
    pub bytes: u64,
}

struct Entry {
    path: String,
    offset: u64,
    size: u64,
}

pub fn find_asar(program: &str) -> Option<PathBuf> {
    let p = Path::new(program);
    for anc in p.ancestors() {
        for rel in ["Contents/Resources/app.asar", "resources/app.asar", "Resources/app.asar"] {
            let c = anc.join(rel);
            if c.is_file() {
                return Some(c);
            }
        }
    }
    None
}

fn read_header(path: &Path) -> Result<(Vec<Entry>, u64), String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut h = [0u8; 16];
    f.read_exact(&mut h).map_err(|e| e.to_string())?;
    let header_size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as u64;
    let json_len = u32::from_le_bytes([h[12], h[13], h[14], h[15]]) as usize;
    if json_len == 0 || json_len > 64 << 20 {
        return Err("This doesn't look like an asar archive.".into());
    }
    let mut js = vec![0u8; json_len];
    f.read_exact(&mut js).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&js).map_err(|e| e.to_string())?;
    let mut out = vec![];
    fn walk(v: &Value, prefix: &str, out: &mut Vec<Entry>) {
        if let Some(files) = v.get("files").and_then(|f| f.as_object()) {
            for (name, node) in files {
                let p = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
                if node.get("files").is_some() {
                    walk(node, &p, out);
                } else if node.get("unpacked").and_then(|u| u.as_bool()) != Some(true) {
                    let size = node.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                    let offset = node.get("offset").and_then(|o| o.as_str()).and_then(|o| o.parse().ok()).unwrap_or(0);
                    out.push(Entry { path: p, offset, size });
                }
            }
        }
    }
    walk(&v, "", &mut out);
    Ok((out, 8 + header_size))
}

pub fn asar_info(path: &Path) -> Option<AsarInfo> {
    let (e, _) = read_header(path).ok()?;
    Some(AsarInfo {
        path: path.to_path_buf(),
        files: e.len(),
        js_files: e.iter().filter(|x| x.path.ends_with(".js") || x.path.ends_with(".mjs") || x.path.ends_with(".ts")).count(),
        bytes: e.iter().map(|x| x.size).sum(),
    })
}

/// Writes every file of the archive under `dest`. Returns how many were written.
pub fn extract_asar(path: &Path, dest: &Path) -> Result<usize, String> {
    use std::io::{Read, Seek, SeekFrom};
    let (entries, data_start) = read_header(path)?;
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut n = 0;
    for e in entries {
        let rel = Path::new(&e.path);
        if rel.is_absolute() || rel.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            continue;
        }
        let target = dest.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        f.seek(SeekFrom::Start(data_start + e.offset)).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; e.size as usize];
        f.read_exact(&mut buf).map_err(|e| e.to_string())?;
        std::fs::write(&target, buf).map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}
