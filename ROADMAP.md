# Roadmap: getting Lens as close to IDA Pro as possible

Honest status: Lens is roughly 10-15% of IDA Pro overall. This is the ordered plan to close the gap.
Each phase ends with testing on real binaries, not just samples.

## Phase 1 - Reliability (first, everything else depends on it)
- Run Lens over a large corpus (system binaries, dylibs, ELF, PE, stripped, Go/Rust/Swift) and fix every crash and bad decode.
- Performance on 100 MB+ files: background analysis, incremental listing, memory limits.
- Regression test suite with golden outputs for disassembly and pseudocode.

## Phase 2 - Analysis depth
- Switch/jump-table recovery on x86, ARM64, ARM, RISC-V, MIPS.
- Vtable, RTTI and Objective-C / Swift metadata recovery.
- Exception and unwind tables (.eh_frame, __unwind_info, PE .pdata) for function boundaries.
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
- Full C type parser (typedefs, unions, enums, function pointers, bitfields).
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

## Releasing
Bump `version` in Cargo.toml, commit, push, then `git tag vX.Y.Z && git push --tags`. CI builds Apple Silicon
and publishes the release; installed apps update themselves from Settings or Tools > Check for updates.
