# Lens

Lens is a Rust and egui desktop workbench for inspecting executable files, following their control flow, and editing analysis annotations. It supports common native binary formats and several processor families. It is still an early analysis tool, not a drop-in replacement for IDA Pro.

## What it can do

### Load and identify programs

- Open ELF, PE and Mach-O files, including universal Mach-O binaries, macOS app bundles and other folders containing a program.
- Open raw binaries with a selected CPU, byte order, load address and entry point.
- Translate pasted hex, C byte arrays, `\\x` escapes, Intel HEX and S-record data into disassembly.
- Inspect program metadata: operating system, CPU, likely compiler and language, packers, security flags, imports, capabilities, entropy and SHA-256.
- Detect Electron `app.asar` archives and extract their JavaScript resources as source files.
- Read function-start hints from ELF `.eh_frame`, PE `.pdata`, and Mach-O `LC_FUNCTION_STARTS` and `__unwind_info`. DWARF information can supply function names and prototypes when present.

### Analyze and navigate

- Decode x86, x86-64, ARM, Thumb, ARM64, RISC-V 32/64, MIPS 32/64 and PowerPC 32/64.
- Find functions, basic blocks, imports, exports, strings and code/data cross-references. Recover switch edges for supported x86 and ARM64 patterns.
- View synchronized disassembly, control-flow graph, hex, pseudocode, call graph, function map and program overview.
- Search names, notes, strings, listing text, numeric values and byte patterns with wildcards such as `48 8B ?? 05`.
- Rename addresses and pseudocode variables, add notes, bookmarks and breakpoints; annotations are saved per input file.
- Define bytes and strings, apply simple C-like structs, unions, enums and typedefs, and see embedded nested field names in the listing.
- Identify common cryptographic constants and use built-in or learned function signatures to recognize library code.

### Decompile and edit

- Produce approximate C-like pseudocode and render it as C, Rust, Python, Go or JavaScript.
- The x86/x64 lifter has the broadest coverage. ARM64, ARM/Thumb, RISC-V, MIPS and PowerPC use an integer-focused lifter; unsupported operations remain visible as intrinsic-style calls.
- Patch bytes, NOP instructions, invert supported branches, or force supported conditional branches. Save a patched copy separately from the original; Mach-O output is ad-hoc signed when possible.
- Run Rhai scripts against a read-only analysis snapshot, then apply queued actions such as renames, notes, bookmarks, patches and navigation. `.rhai` plugins may define an `on_open` hook.
- Compare two program versions by function shape and name.

### Debug and exchange data

- Drive LLDB from the debugger window: launch a program, step, continue, pause, inspect registers, stack and backtrace, set conditional breakpoints, evaluate watches, and use the command console.
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

## Current limitations

- Analysis completeness and pseudocode quality vary substantially by architecture and compiler. The pseudocode is a best-effort lift, not source recovery or a correctness proof.
- Switch recovery is currently focused on x86 and ARM64. Advanced RTTI/vtable recovery, Objective-C/Swift metadata, and broad data-versus-code typing are not implemented.
- The type parser is intentionally limited. It does not yet provide full C declarations, bitfields, function-pointer layouts or a complete type-library workflow.
- Debugging depends on LLDB. Lens does not have its own native debug engine, process attach, hardware breakpoints or trace system.
- Files are read fully into memory, then loading and analysis run on a background thread. Incremental analysis/listing, explicit memory limits and measured performance on very large files remain future work.
- Java, .NET, DEX/APK, WebAssembly, firmware and the additional processor families listed in the roadmap are not supported as native analysis targets yet.

See [ROADMAP.md](ROADMAP.md) for planned work and [MECHANICS.md](MECHANICS.md) for naming and analysis rules.
