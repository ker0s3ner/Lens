//! Debugger front-end. Lens drives `lldb` (installed with Xcode's command line tools): it launches the
//! program, sets breakpoints at addresses from the listing, steps, and shows registers, stack and
//! backtrace next to the code. Any other lldb command can be typed into the console, including
//! `gdb-remote host:port` to debug firmware in an emulator or on a board.
//! Lens can also replay static PCs from an exported trace entirely offline.

mod replay;
use replay::{Replay, MAX_STEPS};

use crate::analysis::{Analysis, Flow, NameKind};
use crate::app::{Action, LensApp, State};
use eframe::egui::{self, FontId, RichText, ScrollArea, TextEdit};
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};

const DONE: &str = "@@LENS_PROMPT@@";
type BehaviorCallSite = (u64, String, Vec<String>);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunState {
    Starting,
    Stopped,
    Running,
    Exited,
}

#[derive(Clone, Debug)]
pub struct DynamicEvent {
    id: u64,
    pub category: String,
    pub severity: String,
    pub address: Option<u64>,
    pub message: String,
    /// Register values captured at the stop, kept so call-site evidence remains
    /// attached to its own event after the debugger advances.
    pub registers: Vec<(String, String)>,
    /// Stack words captured before a watched API call, in ascending address order.
    pub stack_words: Vec<String>,
    pub string_arguments: Vec<(String, String)>,
}

impl DynamicEvent {
    fn new(id: u64, message: String) -> Self {
        let lower = message.to_ascii_lowercase();
        let (category, severity) = if ["sigsegv", "sigbus", "sigill", "sigabrt", "sigfpe"]
            .iter().any(|signal| lower.contains(signal)) {
            ("fault", "high")
        } else if lower.contains("watchpoint") {
            ("memory-watch", "medium")
        } else if lower.contains("breakpoint") || lower.contains("sigtrap") {
            ("breakpoint", "info")
        } else if lower.contains("exited") {
            ("process-exit", "info")
        } else if lower.contains("signal") {
            ("signal", "medium")
        } else {
            ("stop", "info")
        };
        Self { id, category: category.into(), severity: severity.into(), address: None, message, registers: Vec::new(), stack_words: Vec::new(), string_arguments: Vec::new() }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Plain,
    Launch,
    Slide,
    Resume,
    TraceStep,
    Regs,
    Stack,
    Memory,
    StringArgument { event_id: u64, name: String, wide: bool },
    Bt,
    Pc,
    Bp(u64),
    Watch(String),
}

struct Req {
    kind: Kind,
    cmd: String,
}

pub struct Dbg {
    child: Child,
    stdin: File,
    rx: Receiver<String>,
    buf: Vec<String>,
    queue: VecDeque<Req>,
    inflight: Option<Kind>,
    ready: bool,
    last_cmd: String,
    pub state: RunState,
    pub slide: u64,
    pub pc: Option<u64>,
    pub regs: Vec<(String, String)>,
    pub stack: Vec<String>,
    pub memory: Vec<String>,
    pub bt: Vec<String>,
    pub watch_values: HashMap<String, String>,
    /// Program counters observed at debugger stops while stop tracing is enabled.
    pub trace: Vec<u64>,
    /// Bounded, human-readable stop/exit events captured alongside the trace.
    pub dynamic_events: Vec<DynamicEvent>,
    next_event_id: u64,
    behavior_site_apis: HashMap<u64, String>,
    argument_registers: Vec<String>,
    capture_string_arguments: bool,
    pub trace_enabled: bool,
    trace_active: bool,
    trace_remaining: usize,
    watch_exprs: Vec<String>,
    pub console: Vec<String>,
    bp_ids: HashMap<u64, u32>,
    bp_conditions: HashMap<u64, String>,
    pending_bps: Vec<u64>,
    stack_arch: crate::loader::Arch,
    hardware_breakpoints: bool,
}

#[derive(Default)]
pub struct DbgUi {
    replay: Option<Replay>,
    pub open: bool,
    pub args: String,
    pub remote: String,
    pub attach_pid: String,
    pub memory_address: String,
    pub hardware_breakpoints: bool,
    pub behavior_watch: bool,
    pub behavior_strings: bool,
    behavior_sites: Vec<BehaviorCallSite>,
    behavior_sites_key: Option<(String, u64, u64)>,
    pub trace: bool,
    pub triage_only: bool,
    pub event_category_filter: String,
    pub confirm: bool,
    pub input: String,
    pub follow: bool,
    pub watches: Vec<String>,
    pub new_watch: String,
    pub condition: String,
    pub condition_addr: Option<u64>,
}

impl Drop for Dbg {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"process kill\nquit\n");
        let _ = self.child.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::weighted_signal_counts;
    use std::collections::HashMap;

    #[test]
    fn weighted_signal_counts_use_address_hits_once() {
        let mut lookup = HashMap::new();
        lookup.insert(0x10, ("f".into(), vec!["Network communication".into()]));
        lookup.insert(0x20, ("g".into(), vec!["Network communication".into(), "Process execution".into()]));
        let counts = weighted_signal_counts(&[0x10, 0x10, 0x20], &lookup);
        assert_eq!(counts.get("Network communication"), Some(&3));
        assert_eq!(counts.get("Process execution"), Some(&1));
    }
}

fn clean(line: &str) -> String {
    line.replace("(lldb) ", "").trim_end().to_string()
}

fn parse_hex_after(s: &str, key: &str) -> Option<u64> {
    let i = s.find(key)? + key.len();
    let rest = s[i..].trim_start().strip_prefix("0x")?;
    let end = rest.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len());
    u64::from_str_radix(&rest[..end], 16).ok()
}

fn parse_register_pointer(value: &str) -> Option<u64> {
    let value = value.trim().strip_prefix("0x").or_else(|| value.trim().strip_prefix("0X"))?;
    let end = value.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(value.len());
    u64::from_str_radix(&value[..end], 16).ok()
}

fn parse_stack_words(lines: &[String]) -> Vec<String> {
    lines.iter().filter_map(|line| line.split_once(':').map(|(_, values)| values))
        .flat_map(|values| values.split_whitespace())
        .filter_map(parse_register_pointer)
        .map(|value| format!("0x{value:x}"))
        .collect()
}

fn x86_argument_width(ty: &str) -> Option<usize> {
    match ty.trim() {
        "BOOL" | "DWORD" | "LONG" | "ULONG" | "UINT" | "HRESULT" => return Some(4),
        "BYTE" => return Some(1),
        "WORD" => return Some(2),
        "ULONGLONG" | "LONGLONG" => return Some(8),
        _ => {}
    }
    let compact = ty.split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "restrict"))
        .collect::<Vec<_>>().join("").to_ascii_lowercase();
    if compact.contains('*') || compact.contains('[')
        || matches!(compact.as_str(), "handle" | "hmodule" | "hwnd" | "lpcstr" | "pcstr" | "lpstr" | "pstr" | "lpcwstr" | "pwstr" | "lpwstr" | "pcwstr" | "lpvoid" | "lpcvoid" | "lpcbyte" | "lpbyte")
    { return Some(4); }
    match compact.as_str() {
        "char" | "signedchar" | "unsignedchar" | "int8_t" | "uint8_t" | "bool" | "_bool" => Some(1),
        "short" | "shortint" | "signedshort" | "signedshortint" | "unsignedshort" | "unsignedshortint" | "int16_t" | "uint16_t" => Some(2),
        "int" | "signed" | "signedint" | "unsigned" | "unsignedint" | "long" | "longint" | "signedlong" | "signedlongint" | "unsignedlong" | "unsignedlongint"
        | "int32_t" | "uint32_t" | "size_t" | "ssize_t" | "uintptr_t" | "intptr_t" | "mode_t" | "pid_t" | "uid_t" | "gid_t"
        | "int32" | "uint32" | "bool32" | "dword" | "word32" | "uint" | "long32" | "ulong" | "hresult" | "enum" | "float" => Some(4),
        "wchar_t" => Some(2),
        "longlong" | "longlongint" | "signedlonglong" | "signedlonglongint" | "unsignedlonglong" | "unsignedlonglongint" | "int64_t" | "uint64_t" | "int64" | "uint64" | "double" | "__int64" => Some(8),
        other if other.starts_with("enum") => Some(4),
        _ => None,
    }
}

fn stack_argument_location(
    arch: crate::loader::Arch,
    register_count: usize,
    index: usize,
    parameters: &[(String, String)],
) -> Option<(usize, usize)> {
    if index < register_count { return None; }
    match (arch, register_count) {
        (crate::loader::Arch::X86, 0) => {
            let mut offset = 0usize;
            for (ty, _) in parameters.iter().take(index) {
                let width = x86_argument_width(ty)?;
                offset = offset.checked_add((width + 3) & !3)?;
            }
            Some((offset, x86_argument_width(&parameters.get(index)?.0)?))
        }
        (crate::loader::Arch::X64, 6) => Some(((index - 6) * 8, 8)), // System V caller RSP.
        (crate::loader::Arch::X64, 4) => Some((index * 8, 8)),      // Windows shadow space.
        (crate::loader::Arch::Arm64, 8) => Some(((index - 8) * 8, 8)),
        _ => None,
    }
}

fn read_stack_argument(words: &[String], offset: usize, width: usize) -> Option<u64> {
    if width == 0 || width > 8 { return None; }
    let mut value = 0u64;
    for byte in 0..width {
        let address = offset.checked_add(byte)?;
        let word = parse_register_pointer(words.get(address / 8)?)?;
        value |= ((word >> ((address % 8) * 8)) & 0xff) << (byte * 8);
    }
    Some(value)
}

fn weighted_signal_counts(trace: &[u64], lookup: &HashMap<u64, (String, Vec<String>)>) -> std::collections::BTreeMap<String, usize> {
    let mut hits = HashMap::<u64, usize>::new();
    for address in trace { *hits.entry(*address).or_default() += 1; }
    let mut counts = std::collections::BTreeMap::new();
    for (address, (_, signals)) in lookup {
        let weight = hits.get(address).copied().unwrap_or(1);
        for signal in signals { *counts.entry(signal.clone()).or_default() += weight; }
    }
    counts
}

#[derive(Clone)]
struct RuntimeEventAnnotation {
    function: String,
    api: Option<String>,
    category: String,
    api_signals: Vec<String>,
    signals: Vec<String>,
    severity: String,
}

fn behavior_api_category(api: &str) -> &'static str {
    let api = api.rsplit(|character| character == '!' || character == ':').next().unwrap_or(api).to_ascii_lowercase();
    let api = api.trim_start_matches("__imp_").trim_start_matches("imp_");
    if ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "ntsetinformationthread", "outputdebugstring", "ptrace", "sysctl"].iter().any(|name| api.contains(name)) {
        "anti-debugging"
    } else if ["regopen", "regcreate", "regset", "regquery", "regdelete", "ntopenkey", "ntsetvalue", "ntqueryvalue"].iter().any(|name| api.contains(name)) {
        "registry"
    } else if ["socket", "connect", "send", "recv", "accept", "bind", "listen", "getaddrinfo", "internet", "winhttp", "urlopen", "dnsquery", "wsastartup"].iter().any(|name| api.contains(name)) {
        "network"
    } else if ["virtualalloc", "virtualprotect", "virtualfree", "createfilemapping", "mapview", "ntmapviewofsection", "mmap", "mremap", "mprotect", "madvise", "mlock", "munlock", "mincore", "brk", "sbrk", "valloc", "pvalloc", "memfd_create", "memfd_secret", "shm_open", "shmget", "shmat", "shmdt", "shmctl", "shm_unlink", "aligned_alloc", "posix_memalign", "reallocarray", "heapalloc", "heapfree", "malloc", "calloc", "realloc", "free", "writeprocessmemory", "readprocessmemory", "ntallocvirtualmemory", "ntprotectvirtualmemory"].iter().any(|name| api.contains(name)) {
        "memory"
    } else if ["seccomp", "prctl", "landlock", "pledge", "unveil"].iter().any(|name| api.contains(name)) {
        "sandbox"
    } else if ["credread", "credwrite", "credenumerate", "lsaretrieveprivatedata", "secitemcopymatching", "seckeychainfindgenericpassword", "pam_get_authtok", "getpass"].iter().any(|name| api.contains(name)) {
        "credentials"
    } else if ["bcrypt", "ncrypt", "crypt", "evp_", "aes_", "rsa_", "sha256", "md5", "cc_sha", "cc_md5", "cccrypt", "seckey", "secrandom", "mbedtls", "sodium_", "gcry_"].iter().any(|name| api.contains(name)) {
        "cryptography"
    } else if ["createfile", "ntcreatefile", "readfile", "ntreadfile", "writefile", "ntwritefile", "deletefile", "movefile", "copyfile", "copy_file_range", "splice", "fopen", "fread", "fwrite", "shm_open", "shm_unlink", "fallocate", "ftruncate", "openat2", "openat", "open", "read", "write", "unlinkat", "unlink", "renameat2", "renameat", "rename", "remove", "chmod", "mkdir"].iter().any(|name| api == *name || api.ends_with(name)) {
        "filesystem"
    } else if ["createprocess", "shellexecute", "winexec", "createproc", "fork", "exec", "posix_spawn", "pidfd_open", "pidfd_send_signal", "close_range", "system", "popen", "createremotethread", "ntcreatethread", "openprocess", "terminateprocess", "ntterminateprocess", "waitforsingleobject"].iter().any(|name| api.contains(name)) {
        "process"
    } else {
        "behavior-callsite"
    }
}

fn runtime_event_category<'a>(event: &'a DynamicEvent, annotation: Option<&'a RuntimeEventAnnotation>) -> &'a str {
    annotation.filter(|annotation| !annotation.api_signals.is_empty())
        .map(|annotation| annotation.category.as_str()).unwrap_or(event.category.as_str())
}

#[derive(Clone)]
struct RuntimeArgument {
    name: String,
    ty: String,
    register: String,
    value: String,
    symbolic_value: Option<String>,
    string_preview: Option<String>,
}

fn abi_argument_registers(arch: crate::loader::Arch, format: &str) -> &'static [&'static str] {
    match arch {
        crate::loader::Arch::X64 if format.starts_with("PE") => &["rcx", "rdx", "r8", "r9"],
        crate::loader::Arch::X64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        crate::loader::Arch::Arm64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        _ => &[],
    }
}

fn narrow_string_pointer(ty: &str) -> bool {
    let compact = ty.split_whitespace().filter(|word| !matches!(*word, "const" | "volatile" | "restrict"))
        .collect::<Vec<_>>().join("").to_ascii_lowercase();
    matches!(compact.as_str(), "char*" | "signedchar*" | "unsignedchar*" | "lpcstr" | "pcstr" | "lpstr" | "pstr")
}

fn wide_string_pointer(ty: &str) -> bool {
    let compact = ty.split_whitespace().filter(|word| !matches!(*word, "const" | "volatile" | "restrict"))
        .collect::<Vec<_>>().join("").to_ascii_lowercase();
    matches!(compact.as_str(), "lpwstr" | "lpcwstr" | "pwstr" | "pcwstr")
}

fn parse_string_preview(lines: &[String], wide: bool) -> Option<String> {
    let mut bytes = Vec::new();
    let max_bytes = if wide { 192 } else { 96 };
    for line in lines {
        let Some((_, values)) = line.split_once(':') else { continue };
        for token in values.split_whitespace() {
            let Some(hex) = token.strip_prefix("0x") else { continue };
            if hex.is_empty() || hex.len() > 2 { continue; }
            let byte = u8::from_str_radix(hex, 16).ok()?;
            bytes.push(byte);
            if bytes.len() == max_bytes { break; }
        }
        if bytes.len() == max_bytes { break; }
    }
    if wide {
        let units = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|unit| *unit != 0).collect::<Vec<_>>();
        if units.is_empty() { return None; }
        Some(String::from_utf16_lossy(&units).chars().flat_map(char::escape_default).collect())
    } else {
        let bytes = bytes.into_iter().take_while(|byte| *byte != 0).collect::<Vec<_>>();
        if bytes.is_empty() { return None; }
        Some(String::from_utf8_lossy(&bytes).chars().flat_map(char::escape_default).collect())
    }
}

fn runtime_event_arguments(
    event: &DynamicEvent,
    annotation: Option<&RuntimeEventAnnotation>,
    arch: crate::loader::Arch,
    format: &str,
) -> Vec<RuntimeArgument> {
    let Some(annotation) = annotation.filter(|annotation| !annotation.api_signals.is_empty()) else { return Vec::new() };
    let Some(api) = annotation.api.as_deref() else { return Vec::new() };
    let registers: HashMap<String, String> = event.registers.iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone())).collect();
    let argument_registers = abi_argument_registers(arch, format);
    let prototype = crate::protos::find(api);
    let mut out = argument_registers.iter().enumerate().filter_map(|(index, register)| {
        let value = registers.get(*register)?.clone();
        let symbolic_value = symbolic_runtime_value(format, api, index, &value);
        let (ty, name) = prototype.as_ref().and_then(|prototype| prototype.params.get(index))
            .map(|(ty, name)| (ty.clone(), if name.trim().is_empty() { format!("arg{}", index + 1) } else { name.clone() }))
            .unwrap_or_else(|| ("?".into(), format!("arg{}", index + 1)));
        let string_preview = event.string_arguments.iter().find(|(param, _)| param == &name).map(|(_, text)| text.clone());
        Some(RuntimeArgument { name, ty, register: (*register).to_string(), value, symbolic_value, string_preview })
    }).collect::<Vec<_>>();
    if let Some(prototype) = &prototype {
        for index in argument_registers.len()..prototype.params.len() {
            let (ty, parameter) = &prototype.params[index];
            let Some((offset, width)) = stack_argument_location(arch, argument_registers.len(), index, &prototype.params) else { continue };
            let Some(raw) = read_stack_argument(&event.stack_words, offset, width) else { continue };
            let value = if arch == crate::loader::Arch::X86 { format!("0x{raw:08x}") } else { format!("0x{raw:x}") };
            let symbolic_value = symbolic_runtime_value(format, api, index, &value);
            let name = if parameter.trim().is_empty() { format!("arg{}", index + 1) } else { parameter.clone() };
            let string_preview = event.string_arguments.iter().find(|(param, _)| param == &name).map(|(_, text)| text.clone());
            out.push(RuntimeArgument { name, ty: ty.clone(), register: format!("stack+0x{offset:x}"), value, symbolic_value, string_preview });
        }
    }
    out
}

fn symbolic_runtime_value(format: &str, api: &str, index: usize, value: &str) -> Option<String> {
    let raw = u64::from_str_radix(value.trim().strip_prefix("0x")?, 16).ok()?;
    crate::consts::symbolize(crate::consts::os_of(format), api, index, raw as i64)
}

fn runtime_arguments_json(arguments: &[RuntimeArgument]) -> Vec<serde_json::Value> {
    arguments.iter().map(|argument| {
        serde_json::json!({"name": argument.name, "type": argument.ty, "register": argument.register, "value": argument.value, "symbolic_value": argument.symbolic_value, "string_preview": argument.string_preview})
    }).collect()
}

fn format_runtime_arguments(arguments: &[RuntimeArgument]) -> String {
    arguments.iter().map(|argument| {
        let label = if argument.ty == "?" { format!("{} [{}]={}", argument.name, argument.register, argument.value) }
            else { format!("{} {} [{}]={}", argument.ty, argument.name, argument.register, argument.value) };
        let label = argument.symbolic_value.as_ref().map(|symbol| format!("{label} ({symbol})")).unwrap_or(label);
        if let Some(preview) = &argument.string_preview { format!("{label} → \"{preview}\"") }
        else { label }
    }).collect::<Vec<_>>().join(", ")
}

fn api_target_at(
    address: u64,
    analysis: &Analysis,
    names: &HashMap<u64, (String, NameKind)>,
) -> Option<String> {
    let instruction = analysis.insns.get(&address)?;
    let target = match instruction.flow {
        Flow::Call => instruction.target,
        Flow::IndirectCall => instruction.mem,
        _ => return None,
    };
    let (name, kind) = names.get(&target)?;
    (*kind == NameKind::Import).then(|| name.clone())
}

fn behavior_api_call_sites(
    analysis: &Analysis,
    names: &HashMap<u64, (String, NameKind)>,
    signals: &[crate::detect::ThreatSignal],
) -> Vec<BehaviorCallSite> {
    let mut sites = analysis.insns.iter().filter_map(|(address, _instruction)| {
        let api = api_target_at(*address, analysis, names)?;
        let matched = signals.iter().filter(|signal| signal_matches_callee(signal, &api))
            .map(|signal| signal.name.clone()).collect::<Vec<_>>();
        if matched.is_empty() { return None; }
        let severity = signals.iter().filter(|signal| matched.contains(&signal.name)).map(|signal| signal.severity).max().unwrap_or(0);
        Some((*address, api, matched, severity))
    }).collect::<Vec<_>>();
    sites.sort_by(|a, b| b.3.cmp(&a.3).then(a.0.cmp(&b.0)));
    sites.truncate(64);
    sites.into_iter().map(|(address, api, signals, _)| (address, api, signals)).collect()
}

fn runtime_event_annotations(
    events: &[DynamicEvent],
    analysis: &Analysis,
    names: &HashMap<u64, (String, NameKind)>,
    signals: &[crate::detect::ThreatSignal],
) -> HashMap<u64, RuntimeEventAnnotation> {
    events.iter().filter_map(|event| {
        let address = event.address?;
        let function = analysis.function_containing(address)?;
        let function_name = names.get(&function.start).map(|(name, _)| name.clone())
            .unwrap_or_else(|| format!("sub_{:X}", function.start));
        let api = api_target_at(address, analysis, names);
        let mut api_signals = api.as_ref().map(|api| signals.iter().filter(|signal| signal_matches_callee(signal, api))
            .map(|signal| signal.name.clone()).collect::<Vec<_>>()).unwrap_or_default();
        api_signals.sort();
        api_signals.dedup();
        let mut matched = signals.iter().filter(|signal| signal_matches_callee(signal, &function_name))
            .map(|signal| signal.name.clone()).collect::<Vec<_>>();
        matched.extend(api_signals.iter().cloned());
        matched.sort();
        matched.dedup();
        let severity = signals.iter().filter(|signal| matched.contains(&signal.name)).map(|signal| signal.severity).max().unwrap_or(0);
        let severity = match severity { 3 => "high", 2 => "medium", 1 => "info", _ => "info" }.to_string();
        let category = api.as_deref().filter(|_| !api_signals.is_empty()).map(behavior_api_category).unwrap_or("behavior-callsite").to_string();
        Some((address, RuntimeEventAnnotation { function: function_name, api, category, api_signals, signals: matched, severity }))
    }).collect()
}

fn effective_event_severity<'a>(
    event: &'a DynamicEvent,
    annotations: &'a HashMap<u64, RuntimeEventAnnotation>,
) -> &'a str {
    event.address.and_then(|address| annotations.get(&address))
        .filter(|annotation| !annotation.signals.is_empty())
        .map(|annotation| annotation.severity.as_str())
        .unwrap_or(event.severity.as_str())
}

type RuntimeCall = (usize, u64, u64, String, String, Vec<String>);

fn signal_matches_callee(signal: &crate::detect::ThreatSignal, callee_name: &str) -> bool {
    signal.evidence.strip_prefix("imports:")
        .and_then(|evidence| evidence.split(';').next())
        .map(|apis| apis.split(',').any(|api| callee_name.contains(api.trim())))
        .unwrap_or(false)
}

fn observed_runtime_calls(
    trace: &[u64],
    analysis: &Analysis,
    names: &HashMap<u64, (String, NameKind)>,
    signals: &[crate::detect::ThreatSignal],
) -> Vec<RuntimeCall> {
    trace.windows(2).enumerate().filter_map(|(step, pair)| {
        let from = pair[0];
        let to = pair[1];
        let instruction = analysis.insns.get(&from)?;
        if !matches!(instruction.flow, Flow::Call | Flow::IndirectCall) { return None; }
        let caller = analysis.function_containing(from)?;
        let callee = analysis.function_containing(to)?;
        if instruction.flow == Flow::Call
            && (instruction.target == 0 || (instruction.target != to && instruction.target != callee.start)) { return None; }
        let name_at = |address: u64| names.get(&address).map(|(name, _)| name.clone()).unwrap_or_else(|| format!("sub_{address:X}"));
        let caller_name = name_at(caller.start);
        let callee_name = name_at(callee.start);
        let matched_signals = signals.iter().filter(|signal| signal_matches_callee(signal, &callee_name)).map(|signal| signal.name.clone()).collect();
        Some((step, from, to, caller_name, callee_name, matched_signals))
    }).collect()
}

impl Dbg {
    pub fn start(path: &str, arch_flag: Option<&str>, args: &str, remote: &str, attach_pid: &str, hardware_breakpoints: bool, bps: &[u64], conditions: &HashMap<u64, String>, behavior_sites: &[BehaviorCallSite], stack_arch: crate::loader::Arch, argument_registers: &[String], capture_string_arguments: bool) -> Result<Dbg, String> {
        let attach_pid = attach_pid.trim();
        if !attach_pid.is_empty() && !attach_pid.chars().all(|c| c.is_ascii_digit()) {
            return Err("Process ID must contain digits only.".into());
        }
        let remote = remote.trim();
        if !remote.is_empty() && !attach_pid.is_empty() {
            return Err("Choose either a remote target or a local process ID.".into());
        }
        if !remote.is_empty() && (!remote.chars().all(|c| c.is_ascii_alphanumeric() || ".:-_[]".contains(c)) || !remote.contains(':')) {
            return Err("Remote target must be a host:port address.".into());
        }
        // lldb needs a terminal: without one it buffers its output and stalls while the program runs
        let (mut master, mut slave) = (0i32, 0i32);
        if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) } != 0 {
            return Err("Couldn't open a terminal for lldb".into());
        }
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            libc::tcgetattr(slave, &mut t);
            t.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
            libc::tcsetattr(slave, libc::TCSANOW, &t);
        }
        let mut cmd = Command::new("lldb");
        cmd.arg("--no-lldbinit").env("TERM", "dumb");
        unsafe {
            cmd.stdin(Stdio::from_raw_fd(libc::dup(slave)));
            cmd.stdout(Stdio::from_raw_fd(libc::dup(slave)));
            cmd.stderr(Stdio::from_raw_fd(libc::dup(slave)));
            cmd.pre_exec(|| {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY as _, 0);
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(|e| format!("Couldn't start lldb ({e}). Install Xcode's command line tools: xcode-select --install"))?;
        unsafe { libc::close(slave) };
        let stdin = unsafe { File::from_raw_fd(master) };
        let reader = stdin.try_clone().map_err(|e| e.to_string())?;
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut reader = reader;
            let mut acc = String::new();
            let mut buf = [0u8; 4096];
            let strip = |t: &str| -> String {
                let mut out = String::new();
                let mut in_esc = false;
                for c in t.chars() {
                    if in_esc { if c.is_ascii_alphabetic() { in_esc = false } continue }
                    if c == '\x1b' { in_esc = true; continue }
                    if c != '\r' { out.push(c) }
                }
                out
            };
            loop {
                let n = match reader.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => n };
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                while let Some(pos) = acc.find('\n') {
                    let line: String = acc.drain(..=pos).collect();
                    let _ = tx.send(strip(&line));
                }
                // lldb shows "(lldb) " without a newline when it is ready for the next command
                let t = strip(&acc);
                if t.trim_end().ends_with("(lldb)") && t.ends_with(' ') {
                    let before = t.trim_end().trim_end_matches("(lldb)").to_string();
                    if !before.trim().is_empty() { let _ = tx.send(format!("{before}\n")); }
                    let _ = tx.send(format!("{DONE}\n"));
                    acc.clear();
                }
            }
        });
        let mut d = Dbg {
            child,
            stdin,
            rx,
            buf: vec![],
            queue: VecDeque::new(),
            inflight: None,
            ready: false,
            last_cmd: String::new(),
            state: RunState::Starting,
            slide: 0,
            pc: None,
            regs: vec![],
            stack: vec![],
            memory: vec![],
            bt: vec![],
            watch_values: HashMap::new(),
            trace: Vec::new(),
            dynamic_events: Vec::new(),
            next_event_id: 0,
            behavior_site_apis: behavior_sites.iter().map(|(address, api, _)| (*address, api.clone())).collect(),
            argument_registers: argument_registers.to_vec(),
            capture_string_arguments,
            trace_enabled: false,
            trace_active: false,
            trace_remaining: 0,
            watch_exprs: vec![],
            console: vec![],
            bp_ids: HashMap::new(),
            bp_conditions: conditions.clone(),
            pending_bps: bps.to_vec(),
            stack_arch,
            hardware_breakpoints,
        };
        d.push(Kind::Plain, "settings set auto-confirm true");
        d.push(Kind::Plain, "settings set stop-line-count-before 0");
        let a = arch_flag.map(|a| format!("-a {a} ")).unwrap_or_default();
        d.push(Kind::Plain, &format!("target create {a}\"{path}\""));
        if !remote.is_empty() {
            d.push(Kind::Launch, &format!("gdb-remote {remote}"));
        } else if !attach_pid.is_empty() {
            d.push(Kind::Launch, &format!("process attach --pid {attach_pid}"));
        } else {
            d.push(Kind::Launch, &format!("process launch --stop-at-entry --stdin /dev/null -- {args}"));
        }
        d.push(Kind::Slide, "target modules list -o -f");
        Ok(d)
    }

    fn push(&mut self, kind: Kind, cmd: &str) {
        self.queue.push_back(Req { kind, cmd: cmd.to_string() });
    }

    pub fn command(&mut self, cmd: &str) {
        self.push(Kind::Plain, cmd);
        self.console.push(format!("> {cmd}"));
    }

    pub fn resume(&mut self, cmd: &str) {
        if self.state != RunState::Stopped {
            return;
        }
        self.push(Kind::Resume, cmd);
    }

    pub fn queue_idle(&self) -> bool {
        self.queue.is_empty() && self.inflight.is_none()
    }

    pub fn interrupt(&mut self) {
        if self.state == RunState::Running {
            // lldb stops the program when it gets SIGINT
            let _ = self.stdin.write_all(&[3]); // ^C reaches lldb through the terminal and stops the program
        }
    }

    /// Steps one instruction at a time and records each resulting PC, up to the requested limit.
    pub fn trace_instructions(&mut self, count: usize) -> Result<(), String> {
        if self.state != RunState::Stopped || !self.queue_idle() {
            return Err("Instruction tracing starts when the target is stopped and the debugger is idle.".into());
        }
        let count = count.clamp(1, MAX_STEPS);
        let pc = self.pc.ok_or("The current instruction address is unavailable.")?;
        self.trace.push(pc);
        if self.trace.len() > MAX_STEPS { self.trace.remove(0); }
        self.trace_active = true;
        self.trace_remaining = count;
        self.push(Kind::TraceStep, "thread step-inst");
        Ok(())
    }

    pub fn stop_trace(&mut self) {
        self.trace_active = false;
        self.trace_remaining = 0;
    }

    pub fn set_bp(&mut self, addr: u64, on: bool) {
        if on {
            if self.slide == 0 && self.state == RunState::Starting {
                self.pending_bps.push(addr);
            } else {
                let hw = if self.hardware_breakpoints { " -H" } else { "" };
                self.push(Kind::Bp(addr), &format!("breakpoint set{hw} -a 0x{:x}", addr + self.slide));
            }
        } else {
            self.bp_conditions.remove(&addr);
            if let Some(id) = self.bp_ids.remove(&addr) {
                self.push(Kind::Plain, &format!("breakpoint delete {id}"));
            }
        }
        self.pending_bps.retain(|a| on || *a != addr);
    }

    pub fn set_condition(&mut self, addr: u64, condition: &str) {
        let condition = condition.trim();
        if condition.contains(['\n', '\r']) { return; }
        if condition.is_empty() {
            self.bp_conditions.remove(&addr);
        } else {
            self.bp_conditions.insert(addr, condition.to_string());
        }
        if let Some(id) = self.bp_ids.get(&addr).copied() {
            let escaped = condition.replace('\\', "\\\\").replace('"', "\\\"");
            let cmd = if condition.is_empty() {
                format!("breakpoint modify --condition '' {id}")
            } else {
                format!("breakpoint modify --condition \"{escaped}\" {id}")
            };
            self.push(Kind::Plain, &cmd);
        }
    }

    fn send_next(&mut self) {
        if self.inflight.is_some() || !self.ready {
            return;
        }
        let Some(r) = self.queue.pop_front() else { return };
        let ok = writeln!(self.stdin, "{}", r.cmd).is_ok() && self.stdin.flush().is_ok();
        if !ok {
            self.state = RunState::Exited;
            self.console.push("lldb stopped responding.".into());
            return;
        }
        if matches!(r.kind, Kind::Resume | Kind::TraceStep | Kind::Launch) {
            self.state = RunState::Running;
        }
        self.ready = false;
        self.last_cmd = r.cmd.clone();
        self.buf.clear();
        self.inflight = Some(r.kind);
    }

    fn after_stop(&mut self) {
        self.push(Kind::Pc, "register read pc");
        self.push(Kind::Regs, "register read");
        self.push(Kind::Stack, "memory read -s8 -fx -c24 $sp");
        self.push(Kind::Bt, "thread backtrace -c 16");
        for expression in self.watch_exprs.clone() {
            self.push(Kind::Watch(expression.clone()), &format!("expression -- {expression}"));
        }
    }

    fn retain_dynamic_event(&mut self, message: String) {
        let id = self.next_event_id;
        self.next_event_id = self.next_event_id.wrapping_add(1);
        self.dynamic_events.push(DynamicEvent::new(id, message));
        if self.dynamic_events.len() > 512 { self.dynamic_events.remove(0); }
    }

    pub fn set_watches(&mut self, expressions: Vec<String>) {
        let expressions: Vec<String> = expressions.into_iter().map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.contains(['\n', '\r']))
            .collect();
        if expressions == self.watch_exprs { return; }
        self.watch_exprs = expressions;
        self.watch_values.retain(|expr, _| self.watch_exprs.contains(expr));
        if self.state == RunState::Stopped {
            for expression in self.watch_exprs.clone() {
                self.push(Kind::Watch(expression.clone()), &format!("expression -- {expression}"));
            }
        }
    }

    pub fn read_memory(&mut self, address: &str) -> Result<(), String> {
        if self.state != RunState::Stopped { return Err("Pause the target before reading memory.".into()); }
        let a = address.trim().trim_start_matches("0x").trim_start_matches("0X");
        if a.is_empty() || a.len() > 16 || !a.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Enter a hexadecimal memory address.".into());
        }
        let address = u64::from_str_radix(a, 16).map_err(|_| "Invalid memory address.")?;
        self.push(Kind::Memory, &format!("memory read -f x -s 1 -c 128 0x{address:x}"));
        Ok(())
    }

    /// Reads lldb's output. Returns the new program counter (static address) when the program stopped somewhere new.
    pub fn poll(&mut self) -> Option<u64> {
        let mut new_pc = None;
        while let Ok(line) = self.rx.try_recv() {
            let l = clean(&line);
            if l.trim() == DONE {
                self.ready = true;
                let lines = std::mem::take(&mut self.buf);
                if let Some(k) = self.inflight.take() {
                    new_pc = new_pc.or(self.finish(k, lines));
                }
            } else if l.trim().is_empty() || l.trim() == self.last_cmd {
                // blank lines and the echo of the command we just sent
            } else if self.inflight.is_some() {
                self.buf.push(l);
            } else {
                self.console.push(l);
            }
        }
        if let Ok(Some(status)) = self.child.try_wait() {
            if self.state != RunState::Exited {
                self.state = RunState::Exited;
                self.ready = false;
                self.queue.clear();
                self.inflight = None;
                self.trace_active = false;
                self.trace_remaining = 0;
                self.console.push(format!("lldb exited{}.", status.code().map(|code| format!(" with status {code}")).unwrap_or_default()));
            }
        }
        self.send_next();
        new_pc
    }

    fn finish(&mut self, kind: Kind, lines: Vec<String>) -> Option<u64> {
        let joined = lines.join("\n");
        match kind {
            Kind::Slide => {
                // "[  0] 0x0000000000000000 /path/to/program"
                if let Some(l) = lines.iter().find(|l| l.trim_start().starts_with("[  0]") || l.trim_start().starts_with("[0]")) {
                    self.slide = parse_hex_after(l, "]").unwrap_or(0);
                }
                let bps: Vec<u64> = std::mem::take(&mut self.pending_bps);
                for a in bps {
                    self.set_bp(a, true);
                }
                if self.state != RunState::Exited {
                    self.state = RunState::Stopped;
                }
                self.console.extend(lines);
                self.after_stop();
            }
            Kind::Launch | Kind::Resume | Kind::TraceStep => {
                self.console.extend(lines.iter().cloned());
                if let Some(reason) = lines.iter().find(|line| line.contains("stop reason")) {
                    self.retain_dynamic_event(reason.clone());
                }
                if joined.contains("exited with status") || (joined.contains("Process") && joined.contains("exited")) {
                    self.state = RunState::Exited;
                    self.pc = None;
                    self.retain_dynamic_event(lines.iter().find(|line| line.contains("exited")).cloned().unwrap_or_else(|| "process exited".into()));
                } else if joined.contains("error:") && !joined.contains("stop reason") {
                    self.state = RunState::Exited;
                } else {
                    self.state = RunState::Stopped;
                    if kind == Kind::TraceStep && self.trace_active {
                        self.push(Kind::Pc, "register read pc");
                    } else if kind == Kind::Resume || kind == Kind::TraceStep {
                        self.after_stop();
                    }
                }
            }
            Kind::Pc => {
                if let Some(pc) = lines.iter().find_map(|l| parse_hex_after(l, "= ")) {
                    self.pc = Some(pc.wrapping_sub(self.slide));
                    if let Some(event) = self.dynamic_events.iter_mut().rev().find(|event| event.address.is_none()) {
                        event.address = self.pc;
                    }
                    if self.trace_enabled && !self.trace_active {
                        let pc = pc.wrapping_sub(self.slide);
                        if self.trace.last() != Some(&pc) { self.trace.push(pc); }
                        if self.trace.len() > MAX_STEPS { self.trace.remove(0); }
                    }
                    if self.trace_active {
                        let pc = pc.wrapping_sub(self.slide);
                        self.trace_remaining = self.trace_remaining.saturating_sub(1);
                        if self.trace_remaining > 0 {
                            self.trace.push(pc);
                            if self.trace.len() > MAX_STEPS { self.trace.remove(0); }
                            self.push(Kind::TraceStep, "thread step-inst");
                        } else {
                            self.trace_active = false;
                            self.push(Kind::Regs, "register read");
                            self.push(Kind::Stack, "memory read -s8 -fx -c24 $sp");
                            self.push(Kind::Bt, "thread backtrace -c 16");
                            for expression in self.watch_exprs.clone() {
                                self.push(Kind::Watch(expression.clone()), &format!("expression -- {expression}"));
                            }
                        }
                    }
                    return self.pc;
                }
            }
            Kind::Regs => {
                self.regs = lines
                    .iter()
                    .filter_map(|l| {
                        let (n, v) = l.split_once('=')?;
                        let n = n.trim();
                        if n.is_empty() || n.contains(' ') { return None; }
                        Some((n.to_string(), v.split_whitespace().next()?.to_string()))
                    })
                    .collect();
                let event_id = self.dynamic_events.iter_mut().rev().find(|event| event.address == self.pc && self.pc.is_some()).map(|event| {
                    event.registers = self.regs.clone();
                    event.id
                });
                if self.capture_string_arguments {
                    if let (Some(event_id), Some(address)) = (event_id, self.pc) {
                        if let Some(api) = self.behavior_site_apis.get(&address).cloned() {
                            if let Some(prototype) = crate::protos::find(&api) {
                                let mut captured = 0;
                                for (index, (ty, parameter)) in prototype.params.iter().enumerate() {
                                    if captured == 4 { break; }
                                    let wide = wide_string_pointer(ty);
                                    if !wide && !narrow_string_pointer(ty) { continue; }
                                    let Some(register) = self.argument_registers.get(index) else { continue };
                                    let Some(raw) = self.regs.iter().find(|(name, _)| name.eq_ignore_ascii_case(register)).map(|(_, value)| value) else { continue };
                                    let Some(pointer) = parse_register_pointer(raw).filter(|pointer| *pointer != 0) else { continue };
                                    let name = if parameter.trim().is_empty() { format!("arg{}", index + 1) } else { parameter.clone() };
                                    let byte_limit = if wide { 192 } else { 96 };
                                    self.push(Kind::StringArgument { event_id, name, wide }, &format!("memory read -f x -s 1 -c {byte_limit} 0x{pointer:x}"));
                                    captured += 1;
                                }
                            }
                        }
                    }
                }
            }
            Kind::StringArgument { event_id, name, wide } => {
                if let Some(preview) = parse_string_preview(&lines, wide) {
                    if let Some(event) = self.dynamic_events.iter_mut().find(|event| event.id == event_id) {
                        if let Some(existing) = event.string_arguments.iter_mut().find(|(parameter, _)| parameter == &name) {
                            existing.1 = preview;
                        } else {
                            event.string_arguments.push((name, preview));
                        }
                    }
                }
            }
            Kind::Stack => {
                self.stack = lines;
                let stack_words = parse_stack_words(&self.stack);
                let event_id = self.dynamic_events.iter_mut().rev()
                    .find(|event| event.address == self.pc && self.pc.is_some())
                    .map(|event| {
                        event.stack_words = stack_words.clone();
                        event.id
                    });
                if self.capture_string_arguments {
                    if let (Some(event_id), Some(address)) = (event_id, self.pc) {
                        if let Some(api) = self.behavior_site_apis.get(&address).cloned() {
                            if let Some(prototype) = crate::protos::find(&api) {
                                let existing = self.dynamic_events.iter().find(|event| event.id == event_id)
                                    .map(|event| event.string_arguments.len()).unwrap_or(0);
                                let queued = self.queue.iter().filter(|request| matches!(
                                    &request.kind,
                                    Kind::StringArgument { event_id: queued_id, .. } if *queued_id == event_id
                                )).count();
                                let mut captured = existing + queued;
                                for (index, (ty, parameter)) in prototype.params.iter().enumerate().skip(self.argument_registers.len()) {
                                    if captured == 4 { break; }
                                    let wide = wide_string_pointer(ty);
                                    if !wide && !narrow_string_pointer(ty) { continue; }
                                    let Some((offset, width)) = stack_argument_location(self.stack_arch, self.argument_registers.len(), index, &prototype.params) else { continue };
                                    let Some(pointer) = read_stack_argument(&stack_words, offset, width) else { continue };
                                    if pointer == 0 { continue; }
                                    let name = if parameter.trim().is_empty() { format!("arg{}", index + 1) } else { parameter.clone() };
                                    let byte_limit = if wide { 192 } else { 96 };
                                    self.push(Kind::StringArgument { event_id, name, wide }, &format!("memory read -f x -s 1 -c {byte_limit} 0x{pointer:x}"));
                                    captured += 1;
                                }
                            }
                        }
                    }
                }
            }
            Kind::Memory => self.memory = lines,
            Kind::Bt => self.bt = lines,
            Kind::Watch(expression) => {
                let value = lines.iter().filter(|line| !line.trim().is_empty()).cloned().collect::<Vec<_>>().join(" ");
                if self.watch_exprs.contains(&expression) {
                    self.watch_values.insert(expression, if value.is_empty() { "<no value>".into() } else { value });
                }
            }
            Kind::Bp(addr) => {
                // "Breakpoint 3: where = ..."
                if let Some(id) = joined.strip_prefix("Breakpoint ").and_then(|r| r.split(':').next()).and_then(|n| n.trim().parse::<u32>().ok()) {
                    self.bp_ids.insert(addr, id);
                    if let Some(condition) = self.bp_conditions.get(&addr).cloned() {
                        self.set_condition(addr, &condition);
                    }
                }
                self.console.extend(lines);
            }
            Kind::Plain => self.console.extend(lines),
        }
        if self.console.len() > 800 {
            let k = self.console.len() - 800;
            self.console.drain(..k);
        }
        None
    }
}

impl LensApp {
    pub fn dbg_sync_breakpoint(&mut self, addr: u64, on: bool) {
        if let Some(d) = &mut self.dbg {
            d.set_bp(addr, on);
        }
    }

    pub fn dbg_start(&mut self) {
        if self.tools2.dbg.replay.is_some() { return; }
        let Some(l) = self.loaded() else { return };
        let path = l.bin.path.clone();
        let arch = match l.bin.slice.as_str() {
            "x86_64" => Some("x86_64"),
            "arm64e" => Some("arm64e"),
            _ if l.bin.arch == crate::loader::Arch::X64 && cfg!(target_arch = "aarch64") => Some("x86_64"),
            _ => None,
        };
        let (args, remote, pid, hardware) = (self.tools2.dbg.args.clone(), self.tools2.dbg.remote.clone(), self.tools2.dbg.attach_pid.clone(), self.tools2.dbg.hardware_breakpoints);
        let watch_requested = self.tools2.dbg.behavior_watch;
        let local_launch = remote.trim().is_empty() && pid.trim().is_empty();
        let behavior_sites = if watch_requested && local_launch && !hardware {
            behavior_api_call_sites(&l.an, &l.names, &l.det.threat_signals)
        } else { Vec::new() };
        let mut bps = l.ann.breakpoints.clone();
        bps.extend(behavior_sites.iter().map(|(address, _, _)| *address));
        bps.sort_unstable();
        bps.dedup();
        let conditions = l.ann.bp_conditions.clone();
        let argument_registers = abi_argument_registers(l.bin.arch, &l.bin.format).iter().map(|register| (*register).to_string()).collect::<Vec<_>>();
        let capture_strings = self.tools2.dbg.behavior_watch && self.tools2.dbg.behavior_strings;
        match Dbg::start(&path, arch, &args, &remote, &pid, hardware, &bps, &conditions, &behavior_sites, l.bin.arch, &argument_registers, capture_strings) {
            Ok(d) => {
                self.dbg = Some(d);
                if watch_requested && !local_launch {
                    self.logm("Behavior API watchpoints require a local launch; no automatic breakpoints were added.");
                } else if watch_requested && hardware {
                    self.logm("Behavior API watchpoints use software breakpoints; turn off the hardware-breakpoint requirement to arm them.");
                } else if watch_requested {
                    self.logm(format!("Debugging {path} with lldb; watching {} statically flagged API call sites (execution pauses at each hit).", behavior_sites.len()));
                } else {
                    self.logm(format!("Debugging {path} with lldb"));
                }
            }
            Err(e) => self.modal_message("Couldn't start the debugger", e),
        }
    }

    pub fn poll_debugger(&mut self, ctx: &egui::Context) {
        let follow = self.tools2.dbg.follow;
        let mut goto = None;
        let mut pc = None;
        if let Some(d) = &mut self.dbg {
            if let Some(a) = d.poll() {
                goto = Some(a);
            }
            pc = d.pc.filter(|_| d.state == RunState::Stopped);
            if !matches!(d.state, RunState::Exited) {
                ctx.request_repaint_after(std::time::Duration::from_millis(120));
            }
        }
        if let State::Ready(l) = &mut self.state {
            l.dbg_pc = match &self.tools2.dbg.replay {
                Some(replay) => Some(replay.pc()).filter(|&a| l.bin.is_mapped(a)),
                None => pc,
            };
        }
        let mapped = goto.map(|a| self.loaded().map(|l| l.bin.is_mapped(a)).unwrap_or(false)).unwrap_or(false);
        if let (Some(a), true, true) = (goto, follow, mapped) {
            if self.nav.view == crate::app::View::Overview {
                self.actions.push(Action::SetView(crate::app::View::Text));
            }
            self.actions.push(Action::Goto(a));
        }
    }

    pub fn debugger_window(&mut self, ctx: &egui::Context) {
        let p = self.p;
        let mut open = true;
        let ready = self.loaded().is_some();
        let dynamic_trace: Vec<(u64, String, Vec<String>)> = match (&self.dbg, self.loaded()) {
            (Some(d), Some(l)) => d.trace.iter().rev().filter_map(|address| {
                let function = l.an.function_containing(*address)?;
                let name = l.names.get(&function.start).map(|(n, _)| n.clone()).unwrap_or_else(|| format!("sub_{:X}", function.start));
                let signals = l.det.threat_signals.iter().filter(|signal| signal_matches_callee(signal, &name)).map(|signal| signal.name.clone()).collect();
                Some((*address, name, signals))
            }).collect(),
            _ => vec![],
        };
        let runtime_calls: Vec<RuntimeCall> = match (&self.dbg, self.loaded()) {
            (Some(d), Some(l)) => observed_runtime_calls(&d.trace, &l.an, &l.names, &l.det.threat_signals),
            _ => vec![],
        };
        let dynamic_lookup: HashMap<u64, (String, Vec<String>)> = dynamic_trace.iter().cloned().fold(HashMap::new(), |mut map, (address, name, signals)| {
            map.entry(address).or_insert((name, signals));
            map
        });
        let runtime_event_lookup = match (&self.dbg, self.loaded()) {
            (Some(d), Some(l)) => runtime_event_annotations(&d.dynamic_events, &l.an, &l.names, &l.det.threat_signals),
            _ => HashMap::new(),
        };
        let (event_arch, event_format) = self.loaded()
            .map(|loaded| (loaded.bin.arch, loaded.bin.format.clone()))
            .unwrap_or((crate::loader::Arch::Other, String::new()));
        let behavior_sites_count = if self.tools2.dbg.behavior_watch && self.dbg.is_none() {
            let key = self.loaded().map(|l| (l.bin.path.clone(), l.bin.file_size, l.version));
            if self.tools2.dbg.behavior_sites_key != key {
                let sites = self.loaded().map(|l| behavior_api_call_sites(&l.an, &l.names, &l.det.threat_signals)).unwrap_or_default();
                self.tools2.dbg.behavior_sites = sites;
                self.tools2.dbg.behavior_sites_key = key;
            }
            self.tools2.dbg.behavior_sites.len()
        } else { 0 };
        let dynamic_function_count = dynamic_trace.iter().map(|(_, name, _)| name).collect::<std::collections::BTreeSet<_>>().len();
        let dynamic_signal_count = dynamic_trace.iter().filter(|(_, _, signals)| !signals.is_empty()).count();
        let dynamic_signal_addresses = dynamic_trace.iter().filter(|(_, _, signals)| !signals.is_empty()).map(|(address, _, _)| address).collect::<std::collections::BTreeSet<_>>().len();
        let dynamic_flagged_function_count = dynamic_lookup.values().filter(|(_, signals)| !signals.is_empty()).map(|(name, _)| name).collect::<std::collections::BTreeSet<_>>().len();
        let dynamic_signal_hit_count = match &self.dbg {
            Some(d) => d.trace.iter().filter(|address| dynamic_lookup.get(address).map(|(_, signals)| !signals.is_empty()).unwrap_or(false)).count(),
            None => 0,
        };
        let mut dynamic_signal_counts = std::collections::BTreeMap::<String, usize>::new();
        for signals in dynamic_lookup.values().map(|(_, signals)| signals) {
            for signal in signals { *dynamic_signal_counts.entry(signal.clone()).or_default() += 1; }
        }
        let mut dynamic_signal_hit_counts = std::collections::BTreeMap::<String, usize>::new();
        if let Some(d) = &self.dbg {
            let mut hits = std::collections::HashMap::<u64, usize>::new();
            for address in &d.trace { *hits.entry(*address).or_default() += 1; }
            for (address, (_, signals)) in &dynamic_lookup {
                let weight = hits.get(address).copied().unwrap_or(1);
                for signal in signals { *dynamic_signal_hit_counts.entry(signal.clone()).or_default() += weight; }
            }
        }
        let hot_trace: Vec<(u64, usize)> = match &self.dbg {
            Some(d) => {
                let mut counts = std::collections::HashMap::<u64, usize>::new();
                for address in &d.trace { *counts.entry(*address).or_default() += 1; }
                let mut hot: Vec<_> = counts.into_iter().collect();
                hot.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                hot.into_iter().take(5).collect()
            }
            None => vec![],
        };
        let cursor = self.nav.cursor;
        let mut start = false;
        let mut stop = false;
        let mut cmd: Option<String> = None;
        let mut resume: Option<&'static str> = None;
        let mut goto: Option<u64> = None;
        let mut bp: Option<u64> = None;
        let mut remove_watch: Option<usize> = None;
        let mut add_watch = false;
        let mut read_memory = false;
        let mut trace_instructions: Option<usize> = None;
        let mut stop_instruction_trace = false;
        let mut set_condition: Option<(u64, String)> = None;
        let bps = self.loaded().map(|l| l.ann.breakpoints.clone()).unwrap_or_default();
        let bp_conditions = self.loaded().map(|l| l.ann.bp_conditions.clone()).unwrap_or_default();
        let bin = self.loaded().map(|l| l.bin.clone());
        let mut replay_error = None;
        let mut navigate_replay = false;
        egui::Window::new("Debugger").open(&mut open).default_size([760.0, 560.0]).show(ctx, |ui| {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if self.tools2.dbg.replay.is_none() && self.native_session_ui(ui) {
                return;
            }
            let ui_state = &mut self.tools2.dbg;
            if self.dbg.is_none() {
                if ui.button("Open offline trace…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().set_title("Open Lens instruction trace")
                        .add_filter("Lens instruction trace", &["json", "txt"]).pick_file()
                    {
                        match Replay::open(&path) {
                            Ok(replay) => {
                                ui_state.replay = Some(replay);
                                navigate_replay = true;
                            }
                            Err(error) => replay_error = Some(error),
                        }
                    }
                }
                if let Some(replay) = &mut ui_state.replay {
                    ui.heading("Offline trace replay");
                    ui.horizontal(|ui| {
                        if ui.add_enabled(replay.step_index() > 0, egui::Button::new("Back")).clicked() {
                            replay.back();
                            navigate_replay = true;
                        }
                        if ui.add_enabled(replay.step_index() + 1 < replay.len(), egui::Button::new("Step")).clicked() {
                            replay.step();
                            navigate_replay = true;
                        }
                        ui.label(format!("Instruction {} of {}", replay.step_index() + 1, replay.len()));
                    });
                    let pc = replay.pc();
                    ui.monospace(format!("Static PC  0x{pc:016X}"));
                    let mapped = bin.as_ref().is_some_and(|b| b.is_mapped(pc));
                    if ui.add_enabled(mapped, egui::Button::new("Show in disassembly")).clicked() {
                        navigate_replay = true;
                    }
                    if !ready {
                        ui.label("Open the corresponding program to navigate its disassembly.");
                    } else if !mapped {
                        ui.label("This address is outside the loaded program.");
                    }
                    if ui.button("Close replay").clicked() { ui_state.replay = None; }
                    return;
                }
                ui.separator();
            }
            if !ready {
                ui.label(RichText::new("Open a program to start a live debugger.").color(p.muted));
                return;
            }
            if ui_state.condition_addr != Some(cursor) {
                ui_state.condition_addr = Some(cursor);
                ui_state.condition = bp_conditions.get(&cursor).cloned().unwrap_or_default();
            }
            if bps.contains(&cursor) {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("Condition at {cursor:X}")).small().color(p.faint));
                    ui.add(TextEdit::singleline(&mut ui_state.condition).desired_width(260.0).font(FontId::monospace(13.0)).hint_text("e.g. $rax == 0"));
                    if ui.button("Apply").clicked() { set_condition = Some((cursor, ui_state.condition.clone())); }
                });
            }
            match &mut self.dbg {
                None => {
                    ui.label(RichText::new("Start a local program, attach to its PID, or connect to a GDB remote target. Only debug targets you are authorized to inspect.").color(p.muted));
                    ui.checkbox(&mut ui_state.confirm, "I understand, run it");
                    ui.horizontal(|ui| {
                        ui.label("Arguments");
                        ui.add(TextEdit::singleline(&mut ui_state.args).desired_width(260.0).font(FontId::monospace(13.0)));
                    });
                    ui.horizontal(|ui| {
                        ui.label("or connect to");
                        ui.add(TextEdit::singleline(&mut ui_state.remote).desired_width(220.0).hint_text("localhost:1234 (gdb server)").font(FontId::monospace(13.0)));
                    });
                    ui.horizontal(|ui| {
                        ui.label("or attach PID");
                        ui.add(TextEdit::singleline(&mut ui_state.attach_pid).desired_width(140.0).hint_text("process ID").font(FontId::monospace(13.0)));
                    });
                    ui.checkbox(&mut ui_state.hardware_breakpoints, "Require hardware breakpoints").on_hover_text("Uses LLDB's hardware breakpoint request; target hardware and debugger permissions still apply.");
                    if ui.add_enabled(ui_state.confirm, egui::Button::new("Start").fill(p.accent_soft)).clicked() {
                        start = true;
                    }
                    ui.label(RichText::new("macOS only debugs programs that allow it: your own builds work; Apple's protected system programs don't.").small().color(p.faint));
                ui.checkbox(&mut ui_state.behavior_watch, "Watch behavior APIs at call sites")
                    .on_hover_text("Opt in to temporary software breakpoints at up to 64 imported API call sites linked to static behavior clues. This stops execution immediately before a watched call and can change timing. Local launch only; remote and attached targets are not instrumented.");
                if ui_state.behavior_watch {
                    let status = if ui_state.hardware_breakpoints { "candidates · turn off hardware mode to arm" } else { "behavior call sites ready · local launch only" };
                    ui.label(RichText::new(format!("{} {status}", behavior_sites_count)).small().color(p.muted));
                    ui.checkbox(&mut ui_state.behavior_strings, "Preview string arguments (UTF-8 / Windows UTF-16)")
                        .on_hover_text("When stopped before a watched API, read at most four prototype-marked character pointers: up to 96 bytes for narrow strings or 192 bytes for Windows UTF-16. Pointer contents are read only when this option is enabled.");
                }
                }
                Some(d) => {
                    ui.horizontal(|ui| {
                        let stopped = d.state == RunState::Stopped;
                        let st = match d.state { RunState::Starting => "starting", RunState::Stopped => "stopped", RunState::Running => "running", RunState::Exited => "exited" };
                        ui.label(RichText::new(st).strong().color(if stopped { p.accent } else { p.muted }));
                        if ui.add_enabled(stopped, egui::Button::new("Continue")).clicked() { resume = Some("process continue"); }
                        if ui.add_enabled(stopped, egui::Button::new("Step in")).clicked() { resume = Some("thread step-inst"); }
                        if ui.add_enabled(stopped, egui::Button::new("Step over")).clicked() { resume = Some("thread step-inst-over"); }
                        if ui.add_enabled(stopped, egui::Button::new("Step out")).clicked() { resume = Some("thread step-out"); }
                        if ui.add_enabled(d.state == RunState::Running, egui::Button::new("Pause")).clicked() { d.interrupt(); }
                        if ui.button("Stop").clicked() { stop = true; }
                        if d.state == RunState::Exited && ui.button("Reconnect / restart").clicked() { start = true; }
                        ui.checkbox(&mut ui_state.follow, "follow").on_hover_text("Move the listing to the current instruction");
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Breakpoint at cursor (F2)").clicked() { bp = Some(cursor); }
                        ui.checkbox(&mut ui_state.hardware_breakpoints, "hardware").on_hover_text("Request a processor debug-register breakpoint when adding breakpoints.");
                        if let Some(pc) = d.pc { if ui.button(format!("Go to {pc:X}")).clicked() { goto = Some(pc); } }
                        ui.label(RichText::new(format!("{} breakpoints", bps.len())).small().color(p.muted));
                    });
                    d.trace_enabled = ui_state.trace;
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut ui_state.trace, "Record stop trace").on_hover_text("Records up to 5,000 program-counter locations observed at stops.");
                        ui.checkbox(&mut ui_state.triage_only, "Triage only").on_hover_text("Show only dynamic trace entries matching static heuristic signals.");
                        if ui.add_enabled(d.state == RunState::Stopped && d.queue_idle(), egui::Button::new("Trace 100 instructions")).clicked() { trace_instructions = Some(100); }
                        if ui.add_enabled(d.state == RunState::Stopped && d.queue_idle(), egui::Button::new("Trace 1,000")).clicked() { trace_instructions = Some(1000); }
                        if ui.add_enabled(d.trace_active, egui::Button::new("Stop trace")).clicked() { stop_instruction_trace = true; }
                        if ui.small_button("Clear trace").clicked() { d.trace.clear(); }
                        if ui.add_enabled(!d.trace.is_empty(), egui::Button::new("Export trace…")).clicked() {
                            if let Some(path) = rfd::FileDialog::new().set_title("Export instruction trace").set_file_name("lens-trace.txt").save_file() {
                                let mut hits = std::collections::HashMap::<u64, usize>::new();
                                for address in &d.trace { *hits.entry(*address).or_default() += 1; }
                                let text = d.trace.iter().enumerate().map(|(i, address)| {
                                    let annotation = dynamic_lookup.get(address).map(|(name, signals)| {
                                        format!("  {name}  {}", if signals.is_empty() { "".into() } else { format!("heuristic: {}", signals.join(", ")) })
                                    }).unwrap_or_default();
                                    format!("{i:06}  {address:016X}  hits={}{}", hits.get(address).copied().unwrap_or(1), annotation)
                                }).collect::<Vec<_>>().join("\n");
                                match std::fs::write(&path, format!("# Lens instruction trace\n# columns: step address hits function signal\n{text}\n")) {
                                    Ok(_) => d.console.push(format!("trace exported to {}", path.display())),
                                    Err(error) => d.console.push(format!("trace export failed: {error}")),
                                }
                            }
                        }
                        if ui.add_enabled(!d.trace.is_empty(), egui::Button::new("Export trace JSON…")).clicked() {
                            if let Some(path) = rfd::FileDialog::new().set_title("Export JSON instruction trace").set_file_name("lens-trace.json").save_file() {
                                let mut hits = std::collections::HashMap::<u64, usize>::new();
                                for address in &d.trace { *hits.entry(*address).or_default() += 1; }
                                let records = d.trace.iter().enumerate().map(|(step, address)| {
                                    let resolved = dynamic_lookup.get(address);
                                    serde_json::json!({
                                        "step": step,
                                        "address": address,
                                        "hits": hits.get(address).copied().unwrap_or(1),
                                        "function": resolved.map(|(name, _)| name),
                                        "heuristic_signal": resolved.map(|(_, signals)| !signals.is_empty()).unwrap_or(false),
                                        "heuristic_signals": resolved.map(|(_, signals)| signals.clone()).unwrap_or_default(),
                                    })
                                }).collect::<Vec<_>>();
                                let unique_addresses = hits.len();
                                let flagged_addresses = dynamic_trace.iter().filter(|(_, _, signals)| !signals.is_empty()).map(|(address, _, _)| address).collect::<std::collections::BTreeSet<_>>().len();
                                let heuristic_matches = dynamic_trace.iter().filter(|(_, _, signals)| !signals.is_empty()).count();
                                let flagged_functions = dynamic_lookup.values().filter(|(_, signals)| !signals.is_empty()).map(|(name, _)| name).collect::<std::collections::BTreeSet<_>>().len();
                                let flagged_function_names = dynamic_lookup.values().filter(|(_, signals)| !signals.is_empty()).map(|(name, _)| name.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>();
                                let max_hits = hits.values().copied().max().unwrap_or(0);
                                let hot_addresses = hits.values().filter(|hits| **hits > 1).count();
                                let mut signal_names = dynamic_trace.iter().flat_map(|(_, _, signals)| signals.iter().cloned()).collect::<Vec<_>>();
                                signal_names.sort();
                                signal_names.dedup();
                                let mut signal_counts = std::collections::BTreeMap::<String, usize>::new();
                                for signals in dynamic_lookup.values().map(|(_, signals)| signals) {
                                    for signal in signals { *signal_counts.entry(signal.clone()).or_default() += 1; }
                                }
                                let signal_hit_counts = weighted_signal_counts(&d.trace, &dynamic_lookup);
                                let observed_calls = runtime_calls.iter().map(|(step, from, to, caller, callee, signals)| serde_json::json!({"step": step, "from": from, "to": to, "caller": caller, "callee": callee, "heuristic_signals": signals})).collect::<Vec<_>>();
                                let runtime_events = d.dynamic_events.iter().map(|event| {
                                    let annotation = event.address.and_then(|address| runtime_event_lookup.get(&address));
                                    serde_json::json!({"category": runtime_event_category(event, annotation), "api_call_state": if annotation.is_some_and(|annotation| !annotation.api_signals.is_empty()) { Some("stopped_before_api_call") } else { None::<&str> }, "severity": annotation.filter(|annotation| !annotation.signals.is_empty()).map(|annotation| annotation.severity.as_str()).unwrap_or(event.severity.as_str()), "address": event.address, "message": event.message, "function": annotation.map(|annotation| annotation.function.as_str()), "api": annotation.and_then(|annotation| annotation.api.as_deref()), "heuristic_signals": annotation.map(|annotation| annotation.signals.clone()).unwrap_or_default(), "arguments": runtime_arguments_json(&runtime_event_arguments(event, annotation, event_arch, &event_format))})
                                }).collect::<Vec<_>>();
                                let event_counts = ["high", "medium", "info"].into_iter().map(|severity| (severity, d.dynamic_events.iter().filter(|event| {
                                    effective_event_severity(event, &runtime_event_lookup) == severity
                                }).count())).collect::<std::collections::BTreeMap<_, _>>();
                                let event_category_counts = d.dynamic_events.iter().fold(std::collections::BTreeMap::<String, usize>::new(), |mut counts, event| {
                                    let annotation = event.address.and_then(|address| runtime_event_lookup.get(&address));
                                    *counts.entry(runtime_event_category(event, annotation).to_string()).or_default() += 1;
                                    counts
                                });
                                let value = serde_json::json!({"schema": "lens.dynamic-trace.v1", "entries": d.trace.len(), "unique_addresses": unique_addresses, "hot_addresses": hot_addresses, "max_hits": max_hits, "flagged_addresses": flagged_addresses, "flagged_functions": flagged_functions, "flagged_function_names": flagged_function_names, "heuristic_matches": heuristic_matches, "signal_names": signal_names, "signal_counts": signal_counts, "signal_hit_counts": signal_hit_counts, "observed_call_count": observed_calls.len(), "observed_calls": observed_calls, "event_count": d.dynamic_events.len(), "event_capacity": 512, "event_severity_counts": event_counts, "event_category_counts": event_category_counts, "events": d.dynamic_events.iter().map(|event| event.message.clone()).collect::<Vec<_>>(), "runtime_events": runtime_events, "records": records});
                                match std::fs::write(&path, serde_json::to_string_pretty(&value).unwrap_or_default()) {
                                    Ok(_) => d.console.push(format!("trace JSON exported to {}", path.display())),
                                    Err(error) => d.console.push(format!("trace JSON export failed: {error}")),
                                }
                            }
                        }
                        ui.label(RichText::new(format!("{} instructions", d.trace.len())).small().color(p.muted));
                    });
                    ScrollArea::vertical().id_salt("dbg_trace").max_height(90.0).show(ui, |ui| {
                        for address in d.trace.iter().rev().take(16) {
                            if ui.small_button(format!("{address:016X}")).clicked() { goto = Some(*address); }
                        }
                    });
                    if !dynamic_trace.is_empty() {
                        ui.label(RichText::new("DYNAMIC TRACE TRIAGE").small().color(p.faint));
                        ui.label(RichText::new(format!("{} trace entries · {} functions · {} heuristic hits ({} addresses · {} functions · {} executions)", dynamic_trace.len(), dynamic_function_count, dynamic_signal_count, dynamic_signal_addresses, dynamic_flagged_function_count, dynamic_signal_hit_count)).small().color(p.muted));
                        if !dynamic_signal_counts.is_empty() {
                            let mut ranked = dynamic_signal_counts.iter().map(|(name, count)| (name, *count)).collect::<Vec<_>>();
                            ranked.sort_by(|(a_name, a_count), (b_name, b_count)| b_count.cmp(a_count).then(a_name.cmp(b_name)));
                            let summary = ranked.iter().map(|(name, count)| format!("{name} ×{count}")).collect::<Vec<_>>().join(" · ");
                            ui.label(RichText::new(format!("Observed signal frequency: {summary}")).small().color(p.muted));
                            if ui.small_button("Copy signal frequencies").clicked() { ui.ctx().copy_text(summary); }
                            if !dynamic_signal_hit_counts.is_empty() && ui.small_button("Copy signal intensity").clicked() {
                                let mut ranked = dynamic_signal_hit_counts.iter().map(|(name, count)| (name, *count)).collect::<Vec<_>>();
                                ranked.sort_by(|(a_name, a_count), (b_name, b_count)| b_count.cmp(a_count).then(a_name.cmp(b_name)));
                                ui.ctx().copy_text(ranked.iter().map(|(name, count)| format!("{name}\t{count}")).collect::<Vec<_>>().join("\n"));
                            }
                        }
                        if dynamic_signal_count > 0 && ui.small_button("Copy observed signals").clicked() {
                            let mut names = dynamic_lookup.values().flat_map(|(_, signals)| signals.iter().cloned()).collect::<Vec<_>>();
                            names.sort();
                            names.dedup();
                            ui.ctx().copy_text(names.join("\n"));
                        }
                        if dynamic_lookup.values().any(|(_, signals)| !signals.is_empty()) && ui.small_button("Copy flagged functions").clicked() {
                            let names = dynamic_lookup.values().filter(|(_, signals)| !signals.is_empty()).map(|(name, _)| name.clone()).collect::<std::collections::BTreeSet<_>>();
                            ui.ctx().copy_text(names.into_iter().collect::<Vec<_>>().join("\n"));
                        }
                        if hot_trace.len() > 1 {
                            ui.label(RichText::new("HOT ADDRESSES").small().color(p.faint));
                            if ui.small_button("Copy hotspots").clicked() {
                                ui.ctx().copy_text(hot_trace.iter().map(|(address, hits)| {
                                    let name = dynamic_lookup.get(address).map(|(name, _)| name.as_str()).unwrap_or("unknown");
                                    format!("{name}\t{address:016X}\t{hits}")
                                }).collect::<Vec<_>>().join("\n"));
                            }
                            ui.horizontal_wrapped(|ui| {
                                for (address, hits) in &hot_trace {
                                    let label = dynamic_lookup.get(address).map(|(name, _)| name.as_str()).unwrap_or("unknown");
                                    if ui.small_button(format!("{label}  {address:016X} ×{hits}")).clicked() { goto = Some(*address); }
                                }
                            });
                        }
                        for (address, name, signals) in dynamic_trace.iter().filter(|(_, _, signals)| !ui_state.triage_only || !signals.is_empty()).take(8) {
                            let flagged = !signals.is_empty();
                            let color = if flagged { p.edge_not } else { p.muted };
                            ui.label(RichText::new(format!("{address:016X}  {name}{}", if flagged { format!("  · {}", signals.join(", ")) } else { String::new() })).monospace().small().color(color));
                        }
                    }
                    if !runtime_calls.is_empty() {
                        ui.label(RichText::new(format!("OBSERVED CALLS · {} transitions", runtime_calls.len())).small().color(p.faint));
                        if ui.small_button("Copy observed calls").clicked() {
                            ui.ctx().copy_text(runtime_calls.iter().map(|(step, from, to, caller, callee, signals)| format!("step {step}\t{caller}\t{from:016X}\t{callee}\t{to:016X}\t{}", signals.join(", "))).collect::<Vec<_>>().join("\n"));
                        }
                        for (step, from, to, caller, callee, signals) in runtime_calls.iter().rev().filter(|(_, _, _, _, _, signals)| !ui_state.triage_only || !signals.is_empty()).take(8) {
                            let label = format!("step {step} · {caller} → {callee} · {to:016X}{}", if signals.is_empty() { String::new() } else { format!(" · {}", signals.join(", ")) });
                            if ui.add(egui::Button::new(RichText::new(label).small().color(if signals.is_empty() { p.muted } else { p.edge_not }))).clicked() { goto = Some(*to); }
                            ui.label(RichText::new(format!("call at {from:016X}")).monospace().small().color(p.muted));
                        }
                    }
                    if !d.dynamic_events.is_empty() {
                        let high = d.dynamic_events.iter().filter(|event| effective_event_severity(event, &runtime_event_lookup) == "high").count();
                        let medium = d.dynamic_events.iter().filter(|event| effective_event_severity(event, &runtime_event_lookup) == "medium").count();
                        ui.label(RichText::new(format!("RUNTIME EVENTS · {}/512 retained · {high} high · {medium} medium", d.dynamic_events.len())).small().color(if high > 0 { p.edge_not } else { p.faint }));
                        egui::ComboBox::from_id_salt("runtime_event_category_filter")
                            .selected_text(if ui_state.event_category_filter.is_empty() { "All behavior categories" } else { ui_state.event_category_filter.as_str() })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut ui_state.event_category_filter, String::new(), "All behavior categories");
                                for category in ["process", "filesystem", "registry", "memory", "network", "anti-debugging", "sandbox", "credentials", "cryptography", "behavior-callsite", "fault", "signal", "breakpoint", "memory-watch", "process-exit", "stop"] {
                                    ui.selectable_value(&mut ui_state.event_category_filter, category.to_string(), category);
                                }
                            });
                        if ui.small_button("Copy debug events").clicked() { ui.ctx().copy_text(d.dynamic_events.iter().rev().map(|event| {
                            let annotation = event.address.and_then(|address| runtime_event_lookup.get(&address));
                            let arguments = format_runtime_arguments(&runtime_event_arguments(event, annotation, event_arch, &event_format));
                            format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", annotation.filter(|annotation| !annotation.signals.is_empty()).map(|annotation| annotation.severity.as_str()).unwrap_or(event.severity.as_str()), runtime_event_category(event, annotation), event.address.map(|address| format!("{address:016X}")).unwrap_or_default(), annotation.map(|annotation| annotation.function.as_str()).unwrap_or(""), annotation.and_then(|annotation| annotation.api.as_deref()).unwrap_or(""), annotation.map(|annotation| annotation.signals.join(", ")).unwrap_or_default(), arguments, event.message)
                        }).collect::<Vec<_>>().join("\n")); }
                        if ui.small_button("Copy events JSON").clicked() {
                            let value = d.dynamic_events.iter().map(|event| {
                                let annotation = event.address.and_then(|address| runtime_event_lookup.get(&address));
                                serde_json::json!({"category": runtime_event_category(event, annotation), "api_call_state": if annotation.is_some_and(|annotation| !annotation.api_signals.is_empty()) { Some("stopped_before_api_call") } else { None::<&str> }, "severity": annotation.filter(|annotation| !annotation.signals.is_empty()).map(|annotation| annotation.severity.as_str()).unwrap_or(event.severity.as_str()), "address": event.address, "message": event.message, "function": annotation.map(|annotation| annotation.function.as_str()), "api": annotation.and_then(|annotation| annotation.api.as_deref()), "heuristic_signals": annotation.map(|annotation| annotation.signals.clone()).unwrap_or_default(), "arguments": runtime_arguments_json(&runtime_event_arguments(event, annotation, event_arch, &event_format))})
                            }).collect::<Vec<_>>();
                            ui.ctx().copy_text(serde_json::to_string_pretty(&value).unwrap_or_default());
                        }
                        if ui.small_button("Clear debug events").clicked() { d.dynamic_events.clear(); }
                        for event in d.dynamic_events.iter().rev().filter(|event| {
                            let annotation = event.address.and_then(|address| runtime_event_lookup.get(&address));
                            (!ui_state.triage_only || effective_event_severity(event, &runtime_event_lookup) != "info")
                                && (ui_state.event_category_filter.is_empty() || runtime_event_category(event, annotation) == ui_state.event_category_filter.as_str())
                        }).take(8) {
                            let annotation = event.address.and_then(|address| runtime_event_lookup.get(&address));
                            let function = annotation.map(|annotation| format!(" · {}", annotation.function)).unwrap_or_default();
                            let api = annotation.and_then(|annotation| annotation.api.as_ref()).map(|api| format!(" → {api}")).unwrap_or_default();
                            let signals = annotation.filter(|annotation| !annotation.signals.is_empty()).map(|annotation| format!(" · {}", annotation.signals.join(", "))).unwrap_or_default();
                            let category = runtime_event_category(event, annotation);
                            let severity = effective_event_severity(event, &runtime_event_lookup);
                            let label = format!("{} · {}{}{}{}{} · {}", severity.to_ascii_uppercase(), category, event.address.map(|address| format!(" · {address:016X}")).unwrap_or_default(), function, api, signals, event.message);
                            let color = match severity { "high" => p.edge_not, "medium" => p.comment, _ => p.muted };
                            if let Some(address) = event.address.filter(|address| bin.as_ref().is_some_and(|binary| binary.is_mapped(*address))) {
                                if ui.add(egui::Button::new(RichText::new(label).small().color(color))).clicked() { goto = Some(address); }
                            } else {
                                ui.label(RichText::new(label).small().color(color));
                            }
                            let arguments = runtime_event_arguments(event, annotation, event_arch, &event_format);
                            if !arguments.is_empty() {
                                ui.label(RichText::new(format!("   Args: {}", format_runtime_arguments(&arguments))).small().monospace().color(p.muted));
                            }
                        }
                    }
                    ui.separator();
                    ui.columns(2, |cols| {
                        cols[0].label(RichText::new("REGISTERS").small().color(p.faint));
                        ScrollArea::vertical().id_salt("regs").max_height(170.0).show(&mut cols[0], |ui| {
                            egui::Grid::new("regsg").num_columns(2).spacing([12.0, 1.0]).show(ui, |ui| {
                                for (n, v) in &d.regs {
                                    ui.label(RichText::new(n).monospace().color(p.register));
                                    let target = u64::from_str_radix(v.trim_start_matches("0x"), 16).ok().map(|x| x.wrapping_sub(d.slide)).filter(|x| bin.as_ref().is_some_and(|b| b.is_mapped(*x)));
                                    if ui.add(egui::Label::new(RichText::new(v).monospace().color(if target.is_some() { p.func_name } else { p.text })).sense(egui::Sense::click())).clicked() {
                                        goto = target;
                                    }
                                    ui.end_row();
                                }
                            });
                        });
                        cols[1].label(RichText::new("CALL STACK").small().color(p.faint));
                        ScrollArea::vertical().id_salt("bt").max_height(170.0).show(&mut cols[1], |ui| {
                            for l in &d.bt { ui.label(RichText::new(l).monospace().small()); }
                        });
                    });
                    ui.label(RichText::new("STACK").small().color(p.faint));
                    ScrollArea::vertical().id_salt("stk").max_height(90.0).show(ui, |ui| {
                        for l in &d.stack { ui.label(RichText::new(l).monospace().small()); }
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("MEMORY").small().color(p.faint));
                        ui.add(TextEdit::singleline(&mut ui_state.memory_address).desired_width(160.0).font(FontId::monospace(13.0)).hint_text("hex address"));
                        if ui.add_enabled(d.state == RunState::Stopped, egui::Button::new("Read 128 bytes")).clicked() { read_memory = true; }
                    });
                    ScrollArea::vertical().id_salt("dbg_mem").max_height(100.0).show(ui, |ui| {
                        for line in &d.memory { ui.label(RichText::new(line).monospace().small()); }
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("WATCHES").small().color(p.faint));
                        ui.add(TextEdit::singleline(&mut ui_state.new_watch).desired_width(240.0).font(FontId::monospace(13.0)).hint_text("expression, e.g. $rax"));
                        if ui.button("Add watch").clicked() || (ui.input(|i| i.key_pressed(egui::Key::Enter)) && ui_state.new_watch.trim() != "") {
                            add_watch = true;
                        }
                    });
                    for (i, expression) in ui_state.watches.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(expression).monospace().color(p.keyword));
                            ui.label(RichText::new(d.watch_values.get(expression).map(String::as_str).unwrap_or("(waiting for stop)" )).monospace().small());
                            if ui.small_button("×").clicked() { remove_watch = Some(i); }
                        });
                    }
                    ui.separator();
                    ui.label(RichText::new("CONSOLE (any lldb command)").small().color(p.faint));
                    ScrollArea::vertical().id_salt("con").max_height(120.0).stick_to_bottom(true).show(ui, |ui| {
                        for l in &d.console { ui.label(RichText::new(l).monospace().small()); }
                    });
                    let r = ui.add(TextEdit::singleline(&mut ui_state.input).desired_width(f32::INFINITY).font(FontId::monospace(13.0)).hint_text("memory read 0x… · expr x0 · gdb-remote localhost:1234"));
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !ui_state.input.trim().is_empty() {
                        cmd = Some(std::mem::take(&mut ui_state.input));
                        r.request_focus();
                    }
                }
            }
        });
        if let Some(error) = replay_error {
            self.modal_message("Couldn't open instruction trace", error);
        }
        if navigate_replay && open {
            if let Some(pc) = self.tools2.dbg.replay.as_ref().map(Replay::pc)
                .filter(|&pc| bin.as_ref().is_some_and(|b| b.is_mapped(pc)))
            {
                self.actions.push(Action::SetView(crate::app::View::Text));
                goto = Some(pc);
            }
        }
        if start {
            self.dbg_start();
        }
        if stop {
            self.dbg = None;
            if let State::Ready(l) = &mut self.state { l.dbg_pc = None; }
            self.logm("Debugger stopped.");
        }
        if let Some(d) = &mut self.dbg {
            d.hardware_breakpoints = self.tools2.dbg.hardware_breakpoints;
            d.trace_enabled = self.tools2.dbg.trace;
            if stop_instruction_trace {
                d.stop_trace();
                if d.state == RunState::Running { d.interrupt(); }
            }
            if let Some(count) = trace_instructions {
                if let Err(error) = d.trace_instructions(count) { d.console.push(error); }
            }
            if read_memory {
                if let Err(error) = d.read_memory(&self.tools2.dbg.memory_address) {
                    d.console.push(error);
                }
            }
            if let Some(i) = remove_watch { if i < self.tools2.dbg.watches.len() { self.tools2.dbg.watches.remove(i); } }
            if add_watch {
                let expression = self.tools2.dbg.new_watch.trim().to_string();
                if !expression.is_empty() && !expression.contains(['\n', '\r']) && !self.tools2.dbg.watches.contains(&expression) {
                    self.tools2.dbg.watches.push(expression);
                }
                self.tools2.dbg.new_watch.clear();
            }
            d.set_watches(self.tools2.dbg.watches.clone());
            if let Some((addr, condition)) = &set_condition { d.set_condition(*addr, condition); }
            if let Some(c) = resume { d.resume(c); }
            if let Some(c) = cmd { d.command(&c); }
        }
        if let Some((addr, condition)) = set_condition {
            if let State::Ready(l) = &mut self.state {
                if condition.trim().is_empty() { l.ann.bp_conditions.remove(&addr); }
                else if !condition.contains(['\n', '\r']) { l.ann.bp_conditions.insert(addr, condition.trim().to_string()); }
                crate::store::save_annotations(&l.bin.path, l.bin.file_size, &l.ann);
            }
        }
        if let Some(a) = bp { self.actions.push(Action::ToggleBreakpoint(a)); }
        if let Some(a) = goto { self.actions.push(Action::Goto(a)); }
        self.tools2.dbg.open = open;
        if !open {
            self.dbg = None;
            self.tools2.dbg.replay = None;
        }
    }
}
