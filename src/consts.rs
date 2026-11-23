//! Turns magic numbers in call arguments into the names a programmer would have written
//! (`open(path, 0x602)` becomes `open(path, O_RDWR | O_CREAT | O_TRUNC)`), per operating system.

#[derive(Clone, Copy, PartialEq)]
pub enum Os {
    Mac,
    Linux,
    Windows,
}

pub fn os_of(format: &str) -> Os {
    if format.starts_with("Mach-O") { Os::Mac } else if format.starts_with("PE") { Os::Windows } else { Os::Linux }
}

fn flags(n: u64, table: &[(u64, &str)]) -> Option<String> {
    let mut rest = n;
    let mut parts: Vec<String> = vec![];
    for (bit, name) in table {
        if *bit != 0 && rest & bit == *bit {
            parts.push((*name).to_string());
            rest &= !bit;
        }
    }
    if parts.is_empty() {
        return None;
    }
    if rest != 0 {
        parts.push(format!("0x{rest:X}"));
    }
    Some(parts.join(" | "))
}

fn exact(n: u64, table: &[(u64, &str)]) -> Option<String> {
    table.iter().find(|(v, _)| *v == n).map(|(_, s)| s.to_string())
}

const PROT: &[(u64, &str)] = &[(1, "PROT_READ"), (2, "PROT_WRITE"), (4, "PROT_EXEC")];
const SIG_COMMON: &[(u64, &str)] = &[(1, "SIGHUP"), (2, "SIGINT"), (3, "SIGQUIT"), (4, "SIGILL"), (6, "SIGABRT"), (9, "SIGKILL"), (11, "SIGSEGV"), (13, "SIGPIPE"), (14, "SIGALRM"), (15, "SIGTERM")];

/// The symbolic text for argument `idx` (0-based) of `func`, if this is a place where we know what the number means.
pub fn symbolize(os: Os, func: &str, idx: usize, n: i64) -> Option<String> {
    let n = n as u64;
    let f = func.trim_start_matches('_');
    let f = if os == Os::Windows { f.strip_suffix('W').or_else(|| f.strip_suffix('A')).unwrap_or(f) } else { f };
    match (f, idx) {
        ("open", 1) | ("openat", 2) => {
            let mode = match n & 3 { 0 => "O_RDONLY", 1 => "O_WRONLY", _ => "O_RDWR" };
            let extra: &[(u64, &str)] = match os {
                Os::Mac => &[(0x4, "O_NONBLOCK"), (0x8, "O_APPEND"), (0x200, "O_CREAT"), (0x400, "O_TRUNC"), (0x800, "O_EXCL"), (0x100_0000, "O_CLOEXEC")],
                _ => &[(0x40, "O_CREAT"), (0x80, "O_EXCL"), (0x200, "O_TRUNC"), (0x400, "O_APPEND"), (0x800, "O_NONBLOCK"), (0x8_0000, "O_CLOEXEC")],
            };
            let rest = n & !3;
            if rest == 0 { return Some(mode.to_string()); }
            let e = flags(rest, extra)?;
            Some(format!("{mode} | {e}"))
        }
        ("mmap", 2) | ("mprotect", 2) => if n == 0 { Some("PROT_NONE".into()) } else { flags(n, PROT) },
        ("mmap", 3) => {
            let t: &[(u64, &str)] = match os {
                Os::Mac => &[(1, "MAP_SHARED"), (2, "MAP_PRIVATE"), (0x10, "MAP_FIXED"), (0x1000, "MAP_ANON")],
                _ => &[(1, "MAP_SHARED"), (2, "MAP_PRIVATE"), (0x10, "MAP_FIXED"), (0x20, "MAP_ANONYMOUS")],
            };
            flags(n, t)
        }
        ("open", 2) | ("mkdir", 1) | ("chmod", 1) | ("creat", 1) | ("fchmod", 1) if n > 0 && n <= 0o7777 => Some(format!("0{n:o}")),
        ("lseek", 2) | ("fseek", 2) => exact(n, &[(0, "SEEK_SET"), (1, "SEEK_CUR"), (2, "SEEK_END")]),
        ("socket", 0) => exact(n, &[(1, "AF_UNIX"), (2, "AF_INET"), (if os == Os::Mac { 30 } else { 10 }, "AF_INET6")]),
        ("socket", 1) => exact(n & 0xf, &[(1, "SOCK_STREAM"), (2, "SOCK_DGRAM"), (3, "SOCK_RAW")]),
        ("signal", 0) | ("kill", 1) | ("raise", 0) => exact(n, SIG_COMMON).or_else(|| {
            let t: &[(u64, &str)] = if os == Os::Mac { &[(20, "SIGCHLD"), (30, "SIGUSR1"), (31, "SIGUSR2")] } else { &[(17, "SIGCHLD"), (10, "SIGUSR1"), (12, "SIGUSR2")] };
            exact(n, t)
        }),
        ("access", 1) => if n == 0 { Some("F_OK".into()) } else { flags(n, &[(4, "R_OK"), (2, "W_OK"), (1, "X_OK")]) },
        ("VirtualAlloc", 2) | ("VirtualFree", 2) => flags(n, &[(0x1000, "MEM_COMMIT"), (0x2000, "MEM_RESERVE"), (0x8000, "MEM_RELEASE"), (0x4000, "MEM_DECOMMIT")]),
        ("VirtualAlloc", 3) | ("VirtualProtect", 2) => exact(n, &[(0x01, "PAGE_NOACCESS"), (0x02, "PAGE_READONLY"), (0x04, "PAGE_READWRITE"), (0x10, "PAGE_EXECUTE"), (0x20, "PAGE_EXECUTE_READ"), (0x40, "PAGE_EXECUTE_READWRITE")]),
        ("CreateFile", 1) => flags(n, &[(0x8000_0000, "GENERIC_READ"), (0x4000_0000, "GENERIC_WRITE"), (0x2000_0000, "GENERIC_EXECUTE")]),
        ("CreateFile", 4) => exact(n, &[(1, "CREATE_NEW"), (2, "CREATE_ALWAYS"), (3, "OPEN_EXISTING"), (4, "OPEN_ALWAYS"), (5, "TRUNCATE_EXISTING")]),
        ("Sleep", 0) if n == 0xFFFF_FFFF => Some("INFINITE".into()),
        ("WaitForSingleObject", 1) if n == 0xFFFF_FFFF => Some("INFINITE".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_open_flags_per_os() {
        assert_eq!(symbolize(Os::Mac, "_open", 1, 0x602).unwrap(), "O_RDWR | O_CREAT | O_TRUNC");
        assert_eq!(symbolize(Os::Linux, "open", 1, 0x241).unwrap(), "O_WRONLY | O_CREAT | O_TRUNC");
        assert_eq!(symbolize(Os::Linux, "open", 1, 0).unwrap(), "O_RDONLY");
    }

    #[test]
    fn names_memory_and_win32() {
        assert_eq!(symbolize(Os::Linux, "mmap", 2, 7).unwrap(), "PROT_READ | PROT_WRITE | PROT_EXEC");
        assert_eq!(symbolize(Os::Windows, "VirtualAlloc", 3, 0x40).unwrap(), "PAGE_EXECUTE_READWRITE");
        assert_eq!(symbolize(Os::Windows, "CreateFileW", 4, 3).unwrap(), "OPEN_EXISTING");
        assert!(symbolize(Os::Mac, "printf", 0, 5).is_none());
    }
}
