# Lens

Lens is a Rust and egui desktop workbench for inspecting executable files, following their control flow, and editing analysis annotations. It supports common native binary formats and several processor families. It is still an early analysis tool, not a drop-in replacement for IDA Pro.

## What it can do

### Load and identify programs

- Open ELF executables, shared libraries and relocatable ELF/Mach-O object files, PE and Mach-O files, including universal Mach-O binaries, macOS app bundles and other folders containing a program. ELF ET_REL applies common static relocations, including x86/x64 PC-relative and AArch64 call/jump forms. Mach-O MH_OBJECT applies common x86-64 unsigned/PC-relative and ARM64 unsigned/branch relocations. GOT/PLT-dependent, paired, and architecture-specific compound relocations remain unresolved.
- Open raw binaries with a selected CPU, byte order, load address and entry point.
- Translate pasted hex, C byte arrays, `\\x` escapes, Intel HEX and S-record data into disassembly.
- Inspect program metadata: operating system, CPU, likely compiler and language, packers, security flags, imports, capabilities, entropy and SHA-256.
- Detect Electron `app.asar` archives and extract their JavaScript resources as source files.
- Read function-start hints from ELF `.eh_frame`, PE `.pdata`, and Mach-O `LC_FUNCTION_STARTS` and `__unwind_info`. DWARF can supply function names and prototypes; named struct, union and enum layouts with supported member offsets can be imported into the Types tool and applied to data.

### Analyze and navigate

- Decode x86 16/32/64-bit, ARM, Thumb, ARM64, RISC-V 32/64, MIPS 32/64, PowerPC 32/64 and Motorola 68000. Decoder-backed analysis depth varies by architecture.
- Find functions, basic blocks, imports, exports, strings and code/data cross-references. Recover switch edges for supported x86, ARM32 PC-indexed/literal tables, ARM64, RISC-V, MIPS, PowerPC and bounded Thumb PC-indexed/TBB/TBH patterns; switch-case xrefs are labeled separately from direct jumps.
- Discovered pointer tables can be promoted to persistent native-pointer data from the context menu or command palette.
- Contiguous matching data elements can be promoted to a persistent inferred array from the same workflow.
- Control-flow analysis recognizes additional C++, Rust and Swift panic/trap entry points as non-returning.
- Prototype parsing preserves named function-pointer parameters and emits valid callback signatures.
- Known prototype return types now propagate through simple temporary-to-temporary assignments in pseudocode declarations.
- Identify direct and imported-slot one-instruction forwarding thunks and show their destination in function lists.
- Detect conservative vtable-like runs in read-only data by validating consecutive pointers into executable code, including Itanium C++ tables with offset-to-top and typeinfo headers; the analysis summary reports the discovered table count.
- View synchronized disassembly, control-flow graph, hex, pseudocode, call graph, function map and program overview.
- Browse discovered vtable-like and pointer tables from the Lists window and jump to their data addresses.
- Browse persisted inferred arrays from the Lists window and jump to their first element.
- Lists tabs can also be selected in automation with `LENS_TAB=arrays`, `pointer_tables`, or `vtables`.
- Search names, notes, strings, listing text, numeric values and byte patterns with wildcards such as `48 8B ?? 05`. Data rows can be explicitly marked as native-width pointers with the `O` action.
- Rename addresses and pseudocode variables, add notes, bookmarks and breakpoints; annotations are saved per input file.
- Define bytes and strings, apply C-like structs, unions, enums, scalar and function-pointer typedefs, function-pointer fields and integer bitfields, import supported DWARF layouts, inspect nested fields and indexed array values, follow typed pointer members, and get xrefs from typed pointer arrays.
- Identify common cryptographic constants and use built-in or learned function signatures to recognize library code.

### Decompile and edit

- Produce approximate C-like pseudocode and render it as C, Rust, Python, Go or JavaScript; scalar SSE and common AVX operations retain float/double or vector declarations and binary expressions.
- The x86/x64 lifter has the broadest coverage. ARM64, ARM/Thumb, RISC-V, MIPS and PowerPC use integer-focused lifters; ARM64 NEON vector registers are tracked as 128-bit values, common floating-point arithmetic, moves, comparisons and conditional selects become readable expressions, and other unsupported vector operations remain visible as intrinsic-style calls.
- Patch bytes, NOP instructions, invert supported branches, or force supported conditional branches. Save a patched copy separately from the original; Mach-O output is ad-hoc signed when possible.
- Run Rhai scripts against a read-only analysis snapshot (including types, segments, imports/exports, and incoming/outgoing xrefs), then apply queued actions such as renames, notes, bookmarks, patches, navigation, and defining/applying types. `.rhai` plugins may define an `on_open` hook.
- Rhai snapshots expose `pointer_tables()` and `vtables()` for scripted inspection, and scripts can promote entries with `define_pointer_table(addr)` or `define_array(addr)`.
- Compare two program versions by function shape and name.
- Import exported Lens JSON databases with annotations, data definitions and applied-type references restored.
- Exported/imported JSON databases also preserve user-authored prototypes used by the decompiler.
- Lens JSON exports carry schema version 2 and preserve names, types, prototypes, data definitions, tables, xrefs and annotations.

### Debug and exchange data

- Drive LLDB from the debugger window: launch or attach to a local PID, step, continue, pause, inspect registers, stack, backtrace and 128-byte memory windows, set conditional or requested hardware breakpoints, evaluate watches, and use the command console. Restart a target after exit. Trace 100 or 1,000 instructions by single-stepping and recording each executed PC; traces are capped at 5,000 addresses.
- Connect to a GDB remote server with `gdb-remote` for supported targets.
- Import names and notes from Lens JSON, IDA `.idc` or Ghidra `.py` scripts. Export IDC, Ghidra Python, JSON annotations, assembly listing, Graphviz call graph and map files.

## Keyboard shortcuts

| Key | Action |
| --- | --- |
| `G` | Go to an address or name |
| `N` | Rename |
| `;` | Add a note |
| `X` | Show cross-references |
| `Enter` | Follow a target |
| `Esc` | Go back |
| `Space` | Switch graph/code view |
| `P` | Make a function |
| `M` | Bookmark |
| `F2` | Toggle a breakpoint |
| `F5` | Show pseudocode |
| `Cmd/Ctrl+F` | Search |
| `Cmd/Ctrl+P` | Command palette |
| `Cmd/Ctrl+Z` / `Cmd/Ctrl+Shift+Z` | Undo / redo |

Bindings can be changed in Settings.

## Command line

```sh
cargo build --release
./target/release/lens [program-or-app]
```

Useful options:

```sh
lens program --report
lens program --decompile main
lens program --decompile all --lang rust
lens universal-binary --slice arm64 --report
lens raw.bin --arch arm64 --base 0x1000 --report
lens program --screenshot out.png --view graph --dark
lens program --report --extract ./asar-source
```

`--decompile` accepts `main`, `all`, a function name or an address. `--lang` accepts `c`, `rust`, `python`, `go` or `js`. Raw input also accepts `--big` for big-endian data. Other CLI tools include `--learn-sigs`, `--sigs`, `--run-script`, `--patch ADDR:HEX --save FILE`, and `--report --extract DIR` for detected Electron archives.

## Build and release

Lens uses stable Rust and Cargo. Build locally with `cargo build --release`. The checked-in release workflow currently packages **macOS Apple Silicon** builds; it does not publish Intel Mac or Windows installers.

Release versions use `x.y.z`: `x` is a themed major release, `y` is a monthly feature release, and `z` is a fixes/QoL release. Mathematical codenames are recorded in `RELEASE_NOTES.md`, shown in Lens under Help > What's New, included in GitHub releases, and archived on the [public version history](https://ker0s3ner.github.io/Lens/releases.html). The planned first full release is `1.0.0 — Stokes`.

## Current limitations

- Analysis completeness and pseudocode quality vary substantially by architecture and compiler. The pseudocode is a best-effort lift, not source recovery or a correctness proof.
- Switch recovery covers x86, ARM32, ARM64, Thumb TBB/TBH, RISC-V, MIPS and PowerPC patterns, but remains conservative. Advanced RTTI/vtable recovery, Objective-C/Swift metadata, and broad data-versus-code typing are not implemented. Relocatable ELF inputs apply common static relocations but do not synthesize linker GOT/PLT entries or resolve every architecture's compound relocations.
- The type parser is intentionally limited. It supports simple integer bitfields and function-pointer typedef aliases, but not full function-pointer declarations or compiler-specific bitfield ABI layouts. DWARF types containing bitfields or unsupported member-location expressions are skipped instead of assigned guessed offsets.
- Debugging depends on LLDB; Lens does not yet have its own native debug engine. Hardware breakpoints depend on target support. Instruction tracing uses repeated single-step operations, so it is slower than processor trace facilities and stops at the selected instruction limit. Process attach and GDB remote connection are available through LLDB.
- Files are read fully into memory, then loading and analysis run on a background thread. Incremental analysis/listing, explicit memory limits and measured performance on very large files remain future work.
- Java, .NET, DEX/APK, WebAssembly, firmware and the additional processor families listed in the roadmap are not supported as native analysis targets yet.

See [ROADMAP.md](ROADMAP.md) for planned work and [MECHANICS.md](MECHANICS.md) for naming and analysis rules.
