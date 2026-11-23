//! In-app updates: checks GitHub Releases, downloads the new Lens.app and swaps it in, then relaunches.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Instant;

/// Live progress of a download, shared with the UI thread.
#[derive(Default)]
pub struct Progress {
    pub done: AtomicU64,
    pub total: AtomicU64,
    /// 0 = downloading, 1 = unpacking and verifying
    pub phase: AtomicU64,
}

impl Progress {
    /// 0.0 to 1.0 while downloading (None if the size is unknown).
    pub fn fraction(&self) -> Option<f32> {
        let t = self.total.load(Ordering::Relaxed);
        (t > 0).then(|| (self.done.load(Ordering::Relaxed) as f32 / t as f32).clamp(0.0, 1.0))
    }
}

const REPO: &str = "ker0s3ner/Lens";
const ASSET: &str = "Lens-macos-arm64.zip";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
pub const CODENAME: &str = "Fourier";
pub const CURRENT_WHATS_NEW: &[&str] = &[
    "PowerPC mulhw, mulhwu, mulhd, and mulhdu now preserve signed and unsigned high-half products in pseudocode.",
    "PowerPC wide multiplication is represented with explicit semantic helpers instead of an opaque instruction.",
    "RISC-V mulh, mulhu, and mulhsu now preserve signed and unsigned high-half product semantics in pseudocode.",
    "High-half multiplication is represented with named semantic helpers instead of an opaque unsupported instruction.",
    "MIPS signed and unsigned division now preserve quotient in LO and remainder in HI for mflo/mfhi consumers.",
    "MIPS division and multiply share explicit HI/LO data flow in pseudocode.",
    "MIPS mult, multu, dmult, and dmultu now preserve implicit HI/LO results through mfhi and mflo.",
    "MIPS wide multiply pseudocode no longer drops the architecture's hidden result pair.",
    "ARM/Thumb long multiply and accumulate instructions now preserve both low and high result registers in pseudocode.",
    "Long arithmetic is represented with explicit wide-value helpers instead of silently dropping the upper half.",
    "Stripped functions ending in an architectural stop/trap instruction are now conservatively inferred as no-return.",
    "Trap-terminated x86-64 functions now have regression coverage.",
    "ARM64 scaled switch-table offsets and halfword entries now honor big-endian binaries.",
    "Common switch-table support now spans x86, ARM, RISC-V, MIPS, and PowerPC, with remaining compiler idioms still tracked.",
    "Thumb indexed ldr pc, [pc, index, lsl #2] jump tables now recover bounded absolute targets.",
    "Recovered targets are validated against executable mappings and decoded instructions before becoming switch cases.",
    "Mach-O LC_DATA_IN_CODE ranges are excluded from executable discovery.",
    "Analysis notes record recognized embedded-data ranges in Mach-O files.",
    "Decompiler types survive unambiguous call-result copy chains and explicit casts.",
    "Conflicting or unknown repeated assignments remain conservatively untyped.",
    "The macOS release build now uses an explicit Apple Silicon runner with verbose diagnostics.",
    "Decompiler type propagation recognizes both internal and owned cast expressions.",
    "Dereferences of known pointer-returning calls and explicit pointer casts render their pointee types.",
    "Copied pointer temporaries retain inferred pointee types in subsequent memory reads.",
    "Versioned .lensproj manifests group multiple binaries and open the selected active file.",
    "File > Save Project creates or updates a .lensproj manifest from the current session.",
    "File > Add File to Project appends binaries with duplicate detection and persistence.",
    "Opening a project member keeps the workspace active and records the active file.",
    "Relative project members resolve from the .lensproj directory for portable projects.",
    "Resolved absolute paths continue to match relative project members when switching files.",
    "Save Project serializes in-project members as relative paths for portability.",
    "Decompiler branch structuring now preserves loop headers inside forward conditional regions.",
    "The Overview displays project members and opens them directly.",
    "The active project indicator resolves relative manifest paths correctly.",
];

pub fn current_release_title() -> String {
    format!("Lens {CURRENT} — {CODENAME}")
}

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub notes: String,
    pub url: String,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    assets: Vec<GhAsset>,
}
#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

pub enum Status {
    Idle,
    Checking(Receiver<Result<Option<Release>, String>>),
    Available(Release),
    Downloading(Release, Receiver<Result<(), String>>, Arc<Progress>),
    /// The new version is in place; the app closes itself and reopens.
    Restarting(Instant),
    Failed(String, Instant),
    UpToDate(Instant),
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(180)))
        .user_agent(concat!("Lens/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn parse_ver(s: &str) -> Vec<u64> {
    s.trim_start_matches('v').split(['.', '-', '+']).map(|p| p.parse().unwrap_or(0)).collect()
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (a, b) = (parse_ver(candidate), parse_ver(current));
    for i in 0..3 {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    false
}

pub fn check_async() -> Receiver<Result<Option<Release>, String>> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(check());
    });
    rx
}

fn check() -> Result<Option<Release>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let mut resp = agent().get(&url).header("Accept", "application/vnd.github+json").call().map_err(|e| match e {
        ureq::Error::StatusCode(404) => "No releases published yet".to_string(),
        e => format!("Couldn't reach GitHub: {e}"),
    })?;
    let r: GhRelease = resp.body_mut().read_json().map_err(|e| e.to_string())?;
    if !is_newer(&r.tag_name, CURRENT) {
        return Ok(None);
    }
    let asset = r.assets.iter().find(|a| a.name == ASSET).ok_or("The new release has no Apple Silicon download")?;
    Ok(Some(Release {
        version: r.tag_name.trim_start_matches('v').to_string(),
        notes: r.body.unwrap_or_default(),
        url: asset.browser_download_url.clone(),
    }))
}

/// The .app bundle we're running from, if any (a `cargo run` build has none and can't self-update).
pub fn bundle_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let app = exe.parent()?.parent()?.parent()?;
    app.extension().map(|e| e == "app").unwrap_or(false).then(|| app.to_path_buf())
}

pub fn install_async(rel: Release) -> (Receiver<Result<(), String>>, Arc<Progress>) {
    let (tx, rx) = channel();
    let prog = Arc::new(Progress::default());
    let p2 = prog.clone();
    std::thread::spawn(move || {
        let _ = tx.send(install(&rel, &p2));
    });
    (rx, prog)
}

fn install(rel: &Release, prog: &Progress) -> Result<(), String> {
    let app = bundle_path().ok_or("Lens isn't running from an installed app, so it can't update itself. Download the new version from the GitHub releases page.")?;
    let parent = app.parent().ok_or("bad app path")?;
    // make sure we can write next to the old app before downloading anything
    let probe = parent.join(".lens-write-test");
    std::fs::write(&probe, b"").map_err(|_| format!("No permission to replace {}. Move Lens to Applications or ~/Applications.", app.display()))?;
    let _ = std::fs::remove_file(probe);
    let work = std::env::temp_dir().join(format!("lens-update-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let zip = work.join(ASSET);
    let mut resp = agent().get(&rel.url).call().map_err(|e| format!("Download failed: {e}"))?;
    let total = resp.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    prog.total.store(total, Ordering::Relaxed);
    let mut f = std::fs::File::create(&zip).map_err(|e| e.to_string())?;
    {
        use std::io::{Read, Write};
        let mut r = resp.body_mut().as_reader();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = r.read(&mut buf).map_err(|e| format!("Download failed: {e}"))?;
            if n == 0 { break; }
            f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            prog.done.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
    drop(f);
    prog.phase.store(1, Ordering::Relaxed);
    let out = work.join("new");
    run("ditto", &["-x", "-k", zip.to_str().unwrap(), out.to_str().unwrap()])?;
    let new_app = out.join("Lens.app");
    if !new_app.join("Contents/MacOS/Lens").exists() {
        return Err("The download didn't contain Lens.app".into());
    }
    run("codesign", &["--verify", "--deep", new_app.to_str().unwrap()])?;
    let script = format!(
        r#"while kill -0 {pid} 2>/dev/null; do sleep 0.2; done
OLD={old}; NEW={new}
mv "$OLD" "$OLD.old" && mv "$NEW" "$OLD" || {{ mv "$OLD.old" "$OLD" 2>/dev/null; open "$OLD"; exit 1; }}
xattr -dr com.apple.quarantine "$OLD" 2>/dev/null
rm -rf "$OLD.old" {work}
open "$OLD"
"#,
        pid = std::process::id(),
        old = sh(&app),
        new = sh(&new_app),
        work = sh(&work)
    );
    let sp = work.join("swap.sh");
    std::fs::write(&sp, script).map_err(|e| e.to_string())?;
    std::process::Command::new("/bin/sh")
        .arg(&sp)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn sh(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', r"'\''"))
}

fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let o = std::process::Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if o.status.success() { Ok(()) } else { Err(format!("{cmd} failed: {}", String::from_utf8_lossy(&o.stderr).trim())) }
}

#[cfg(test)]
mod tests {
    use super::is_newer;
    #[test]
    fn versions() {
        assert!(is_newer("v0.2.0", "0.1.9"));
        assert!(is_newer("0.1.10", "0.1.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
    }
}
