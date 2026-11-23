# Roadmap: getting Lens as close to IDA Pro as possible

Honest status: Lens is roughly 10-15% of IDA Pro overall. This is the ordered plan to close the gap.
Each phase should be validated against real binaries as well as targeted regression fixtures. Status below reflects the implementation in this repository; planned work is kept separate from completed work.

## Phase 1 - Reliability (first, everything else depends on it)
- Run Lens over a large corpus (system binaries, dylibs, ELF, PE, stripped, Go/Rust/Swift) and fix every crash and bad decode.
- Performance on 100 MB+ files: background analysis, incremental listing, memory limits.
- Regression test suite with golden outputs for disassembly and pseudocode.

## Phase 2 - Analysis depth
- Extend switch/jump-table recovery beyond the current x86 and ARM64 support to ARM/Thumb, RISC-V, MIPS and PowerPC.
- Vtable, RTTI and Objective-C / Swift metadata recovery.
- Extend function-boundary recovery beyond the current ELF `.eh_frame`, PE `.pdata` and Mach-O `LC_FUNCTION_STARTS` / `__unwind_info` sources; add more robust malformed-table handling.
- Constant propagation, no-return detection, tail-call detection, thunks.
- Better data-vs-code discrimination and string / array / pointer-table typing.
- Debug info: DWARF, PDB, dSYM; symbol demangling (C++, Rust, Swift).

## Phase 3 - Decompiler
- Type recovery and propagation across calls; struct and array access reconstruction.
- SSA-based data-flow, dead code and copy propagation, better loop and `switch` structuring.
- Floating point, SIMD / NEON / SSE, 64-bit arithmetic idioms, calling-convention inference.
- Thumb/Thumb-2 in the main loader, MIPS delay slots, PPC extras.
- Interactive: retype variables, rename locals, jump between pseudocode and disassembly.

## Phase 4 - Type system and libraries
- Expand the C-like type parser: unions and basic enums are supported; typedef resolution, nested declarations, function pointers and bitfields remain.
- Type libraries for libc, POSIX, Win32, macOS frameworks; apply to imports and calls.
- Signature library built from system libraries (libSystem, libc, MSVC CRT) and shipped with releases.

## Phase 5 - Debugger
- Own debug engine (ptrace / Mach / Windows debug API) instead of driving lldb.
- Registers, memory and stack views, watches, conditional breakpoints, hardware breakpoints, tracing.
- Remote debugging (gdbserver, lldb-server) and attach to process.

## Phase 6 - Scripting and plugins
- Full scripting API (read/write database, types, decompiler output, UI hooks).
- Plugin loading with a stable ABI or embedded script runtime, package/manager, example plugins.

## Phase 7 - Formats and CPUs
- Firmware, raw flash dumps, kernels, Android DEX / APK, Java class, .NET IL, WebAssembly, Mach-O fileset.
- More processors: AVR, 6502, Z80, SuperH, SPARC, s390x, TriCore, 68k, eBPF.
- Proper per-CPU semantics for each, not just text classification.

## Phase 8 - Workflow and UI
- Persistent project database, undo/redo, multiple views, bookmarks, graph overview.
- Binary diffing, cross-references everywhere, structure/enum windows, local and global search upgrades.
- Collaboration / export (IDC-like scripts, JSON, Ghidra/IDA database import).

## Done so far (toward parity)
- C-like union definitions with overlapping fields, persisted alongside existing struct definitions.
- Basic C enum definitions with implicit and explicit decimal/hex values; applying an enum to data resolves the stored integer to a named member.
- Scalar, pointer and previously defined type aliases via `typedef`; aliases are checked against known layouts, and cyclic or unknown alias targets fail clearly. Duplicate fields and zero/overflowing array layouts are rejected.
- Applied enum values are shown in data cross-reference comments as `EnumName::MemberName`.
- Debugger expression watches are evaluated by lldb and refreshed whenever the process stops.
- Breakpoint conditions can be set per address, persist with annotations and are applied by lldb both to existing breakpoints and when a debug session starts.
- Embedded struct/union member names propagate into the listing as dotted paths, including bounded fixed arrays of nested records; pointer fields are not followed.
- Known direct tail jumps now appear as call-graph edges and are counted among the destination function's callers.
- Calls and jumps through imported function slots are classified as call/jump xrefs, so import caller views and cross-reference lists include them.
- Undo / redo for names, notes, bookmarks, structs and functions (Cmd+Z, Cmd+Shift+Z).
- Lists window: functions, names, imports, exports, entry points, bookmarks, sortable and filterable.
- Binary diff: compare two versions of a program by function name and shape.
- Export: IDA script (.idc), Ghidra script (.py), JSON database, map file.
- Chat with AI inside the app (Claude Code, Codex or any command), with conversation history.
- Function map: scroll to zoom, drag to pan, zoom buttons.
- Import names and notes from Lens JSON, IDA .idc or Ghidra .py scripts.
- Lists window also covers strings (with use counts) and sections.
- Switch / jump-table recovery on x86 (position-independent and absolute tables): cases become real graph edges and a `switch` in pseudocode.
- Function starts from Mach-O LC_FUNCTION_STARTS, ELF .eh_frame and PE .pdata, so stripped programs get far fewer missed functions.
- Mach-O `__unwind_info` regular and compressed second-level pages now contribute bounded, validated function-start hints for stripped binaries.
- Crash safety: a failure while analysing or decompiling is reported instead of freezing or closing the app.
- Corpus run: 200 system programs decompiled end to end with no crashes or timeouts (found and fixed a runaway-memory bug on stack offsets).
- Export the listing as text and the call graph as Graphviz.
- Function prototypes (type library): ~190 built-in libc / POSIX / sockets / threads / Win32 / macOS signatures plus your own. Calls get the exact argument count, noreturn functions end paths, call results get real types (`char *v5`), and a function with a prototype is printed with its types and parameter names.
- ARM64 switch tables (both the 4-byte-offset and byte/halfword-scaled forms), so the Apple Silicon side of Mach-O files gets real switch edges.
- Constant names in call arguments per OS (open flags, mmap, sockets, signals, Win32 memory/file) and short string arguments recovered.
- FindCrypt-style detection of AES, SHA, MD5, CRC, Blowfish, ChaCha, Base64 and other constants (Lists > Crypto, overview).
- Rename variables in pseudocode (double-click), remembered per function and undoable.
- First unit tests (regression suite is still to be built out).
- Data definition keys like IDA: D cycles byte / word / dword / qword, A makes a C string, U undefines; saved per file and re-analysed.
- IDA-style stack slots in the listing for frame-pointer functions: `[rbp+var_8]`, `[rbp+arg_0]`; pseudocode variable renames show up in the listing too.

## Next implementation queue
1. **Type application:** add enum names to pseudocode, show nested field values in the structure view, and add bitfields with target-aware layout validation. Enum values now appear by name in the listing and cross-reference comments when applied to data.
2. **Analysis quality:** improve tail-call and thunk classification beyond known direct targets; add ARM/Thumb switch recovery; add vtable and RTTI discovery with explicit confidence and source locations.
3. **Data views:** add array and pointer-table definitions, data xrefs inside those ranges, and a synchronized structure view that follows selected fields.
4. **Decompiler:** preserve types across calls and memory accesses, improve switch/loop recovery, and add floating-point/SIMD semantics incrementally.
5. **Debugging:** add process attach and remote target management to the existing lldb-backed debugger. Conditional breakpoints and expression watches are implemented.
6. **Projects and scale:** move annotations into a versioned project database, support large binaries with incremental analysis/listing, and add repeatable corpus fixtures for supported formats/architectures.
7. **Interchange:** import IDA/Ghidra names, comments and data/type definitions more completely; add a stable documented script API and plugin examples.

## Current boundaries
- Lens is an analysis and disassembly workbench, not yet a replacement for IDA's mature debugger, decompiler, type system, processor modules or database ecosystem.
- ARM64/ARM/RISC-V/MIPS/PowerPC decoding is available, but CPU-specific analysis and pseudocode semantics still vary in depth.
- C type parsing remains deliberately small; declarations that are not understood should produce a clear error rather than silently inventing a layout.
- Existing repository edits may be in progress. Update status only after confirming the corresponding behavior in source.

## Releasing
Bump `version` in Cargo.toml, commit, push, then `git tag vX.Y.Z && git push --tags`. CI builds Apple Silicon
and publishes the release; installed apps update themselves from Settings or Tools > Check for updates.
