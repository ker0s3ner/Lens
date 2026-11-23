//! Remembers recent files, settings and the person's own names and comments for each program.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

const PROJECT_SCHEMA_VERSION: u32 = 1;

/// A user-managed workspace containing one or more binaries. Per-file annotations
/// remain in their normal keyed stores; this manifest only defines membership and
/// which file should be opened first.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProjectManifest {
    pub schema_version: u32,
    pub name: String,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub active_file: Option<String>,
}

pub fn load_project(path: &std::path::Path) -> Result<ProjectManifest, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("Couldn't read project: {e}"))?;
    let project: ProjectManifest = serde_json::from_str(&text).map_err(|e| format!("Invalid Lens project: {e}"))?;
    if project.schema_version > PROJECT_SCHEMA_VERSION { return Err("This Lens project was created by a newer version".into()); }
    if project.files.is_empty() { return Err("The Lens project has no files".into()); }
    Ok(project)
}

pub fn save_project(path: &std::path::Path, name: &str, files: &[String], active_file: Option<&str>) -> Result<(), String> {
    if files.is_empty() { return Err("A Lens project needs at least one file".into()); }
    let project = ProjectManifest {
        schema_version: PROJECT_SCHEMA_VERSION,
        name: name.trim().to_string(),
        files: files.to_vec(),
        active_file: active_file.map(str::to_string),
    };
    let text = serde_json::to_string_pretty(&project).map_err(|e| format!("Couldn't encode project: {e}"))?;
    let tmp = path.with_extension(format!("lensproj.{}.tmp", std::process::id()));
    std::fs::write(&tmp, text).map_err(|e| format!("Couldn't write project: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| { let _ = std::fs::remove_file(&tmp); format!("Couldn't save project: {e}") })
}

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
    /// Data the person defined by hand (D, A, U): address -> size code, see `analysis::DEF_*`.
    #[serde(default)]
    pub data_defs: HashMap<u64, u8>,
    #[serde(default)]
    pub patches: Vec<crate::patch::Patch>,
    #[serde(default)]
    pub structs: Vec<crate::types::StructDef>,
    /// (address, struct name) pairs: the struct is laid over the data at that address.
    #[serde(default)]
    pub applied: Vec<(u64, String)>,
    #[serde(default)]
    pub breakpoints: Vec<u64>,
    /// LLDB condition expressions keyed by static breakpoint address.
    #[serde(default)]
    pub bp_conditions: HashMap<u64, String>,
    /// The person's own function prototypes (C declarations, one per line).
    #[serde(default)]
    pub protos: String,
    /// Names the person gave to variables in pseudocode: "func_addr_hex:old" -> new.
    #[serde(default)]
    pub vars: HashMap<String, String>,
    /// Names found by signature matching (not saved; recomputed on every open).
    #[serde(skip)]
    pub sig_names: HashMap<u64, String>,
}

/// Versioned per-binary analysis database. Older releases wrote `Annotations`
/// directly; the loader below continues to accept that format and upgrades it
/// when the file is next saved.
#[derive(Serialize, Deserialize)]
struct ProjectDb {
    schema_version: u32,
    binary_path: String,
    binary_size: u64,
    annotations: Annotations,
}

const PROJECT_DB_VERSION: u32 = 1;

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
    #[serde(default = "code13")]
    pub code_size: f32,
    #[serde(default = "builtin")]
    pub ui_font: String,
    #[serde(default = "builtin")]
    pub mono_font: String,
    /// Key bindings that differ from the defaults (action id -> "Cmd+F").
    #[serde(default)]
    pub keys: HashMap<String, String>,
    #[serde(default = "crate::custom::default_integrations")]
    pub integrations: Vec<crate::custom::Integration>,
    #[serde(default = "ask_default")]
    pub ask_text: String,
}
fn code13() -> f32 {
    13.0
}
fn builtin() -> String {
    "Built-in".into()
}
fn ask_default() -> String {
    "Explain what this function does, then suggest clearer names for it and its variables.".into()
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
        Prefs {
            recent: vec![],
            dark: false,
            inspector: true,
            min_string_len: 5,
            auto_update: true,
            zoom: 1.0,
            code_size: 13.0,
            ui_font: builtin(),
            mono_font: builtin(),
            keys: HashMap::new(),
            integrations: crate::custom::default_integrations(),
            ask_text: ask_default(),
        }
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
    let Some(text) = std::fs::read_to_string(ann_path(path, size)).ok() else { return Annotations::default() };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else { return Annotations::default() };
    if value.get("schema_version").is_some() {
        return serde_json::from_value::<ProjectDb>(value).ok()
            .filter(|db| db.schema_version <= PROJECT_DB_VERSION && db.binary_path == path && db.binary_size == size)
            .map(|db| db.annotations).unwrap_or_default();
    }
    // Backward compatibility with pre-project-database annotation files.
    serde_json::from_str::<Annotations>(&text).unwrap_or_default()
}

pub fn save_annotations(path: &str, size: u64, a: &Annotations) {
    let db = ProjectDb { schema_version: PROJECT_DB_VERSION, binary_path: path.to_string(), binary_size: size, annotations: a.clone() };
    if let Ok(s) = serde_json::to_string_pretty(&db) {
        let dest = ann_path(path, size);
        let tmp = dest.with_extension(format!("json.{}.tmp", std::process::id()));
        if std::fs::write(&tmp, s).is_ok() {
            if std::fs::rename(&tmp, &dest).is_err() { let _ = std::fs::remove_file(tmp); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_manifest_round_trips_and_rejects_empty_projects() {
        let dir = std::env::temp_dir().join(format!("lens-project-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("sample.lensproj");
        let files = vec!["/tmp/one.bin".into(), "/tmp/two.bin".into()];
        save_project(&path, "Sample", &files, Some("/tmp/two.bin")).unwrap();
        let loaded = load_project(&path).unwrap();
        assert_eq!(loaded.name, "Sample");
        assert_eq!(loaded.files, files);
        assert_eq!(loaded.active_file.as_deref(), Some("/tmp/two.bin"));
        assert!(save_project(&path, "Empty", &[], None).is_err());
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(dir);
    }
}
