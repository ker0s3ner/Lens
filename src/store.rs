//! Remembers recent files, settings and the person's own names and comments for each program.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct Annotations {
    #[serde(default)]
    pub names: HashMap<u64, String>,
    #[serde(default)]
    pub comments: HashMap<u64, String>,
    #[serde(default)]
    pub functions: Vec<u64>,
    #[serde(default)]
    pub marks: Vec<u64>,
    #[serde(default)]
    pub patches: Vec<crate::patch::Patch>,
    #[serde(default)]
    pub structs: Vec<crate::types::StructDef>,
    /// (address, struct name) pairs: the struct is laid over the data at that address.
    #[serde(default)]
    pub applied: Vec<(u64, String)>,
    #[serde(default)]
    pub breakpoints: Vec<u64>,
    /// Names found by signature matching (not saved; recomputed on every open).
    #[serde(skip)]
    pub sig_names: HashMap<u64, String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Prefs {
    #[serde(default)]
    pub recent: Vec<String>,
    #[serde(default)]
    pub dark: bool,
    #[serde(default = "yes")]
    pub inspector: bool,
    #[serde(default = "default_min")]
    pub min_string_len: usize,
    #[serde(default = "yes")]
    pub auto_update: bool,
    #[serde(default = "one")]
    pub zoom: f32,
}

fn yes() -> bool {
    true
}
fn one() -> f32 {
    1.0
}
fn default_min() -> usize {
    5
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { recent: vec![], dark: false, inspector: true, min_string_len: 5, auto_update: true, zoom: 1.0 }
    }
}

pub fn config_dir() -> PathBuf {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    let base = if cfg!(target_os = "macos") {
        PathBuf::from(&home).join("Library/Application Support/Lens")
    } else if cfg!(target_os = "windows") {
        std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(&home)).join("Lens")
    } else {
        std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(&home).join(".config"))
            .join("lens")
    };
    let _ = std::fs::create_dir_all(&base);
    base
}

pub fn load_prefs() -> Prefs {
    std::fs::read_to_string(config_dir().join("prefs.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_prefs(p: &Prefs) {
    if let Ok(s) = serde_json::to_string_pretty(p) {
        let _ = std::fs::write(config_dir().join("prefs.json"), s);
    }
}

fn key(path: &str, size: u64) -> String {
    // FNV-1a of the path and size.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in path.bytes().chain(size.to_le_bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn ann_path(path: &str, size: u64) -> PathBuf {
    let d = config_dir().join("notes");
    let _ = std::fs::create_dir_all(&d);
    d.join(format!("{}.json", key(path, size)))
}

pub fn load_annotations(path: &str, size: u64) -> Annotations {
    std::fs::read_to_string(ann_path(path, size))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_annotations(path: &str, size: u64, a: &Annotations) {
    if let Ok(s) = serde_json::to_string_pretty(a) {
        let _ = std::fs::write(ann_path(path, size), s);
    }
}
