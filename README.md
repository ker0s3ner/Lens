# Lens

A clean, friendly disassembler for x86 and x64 programs, written in Rust with egui.

- Opens Windows (PE), Linux (ELF) and macOS (Mach-O, including universal binaries and `.app` bundles)
- Finds functions, labels, strings, imports, exports and cross-references
- Code listing, flow graph (with overview map) and hex view, kept in sync
- Function outline: callers, callees, text and data each function uses
- Rename (N), notes (;), cross-references (X), go to (G), back (Esc), follow (Enter), graph (Space), command palette (Cmd/Ctrl+P)
- Your names and notes are saved per file
- Light and dark themes

### New: it works out what a program is by itself
- Drop in an `.exe`, `.dll`, ELF file or `.app`: Lens detects the file kind, OS, CPU, **compiler / toolchain** (MSVC with Visual Studio version from the Rich header, GCC, Clang, MinGW, rustc, Go, Swift, Delphi, .NET…), language, packers (UPX, Themida, VMProtect…), protections (ASLR, DEP, PIE, RELRO, canaries, signing) and what the imports can do
- Picks the **calling convention** from that (Microsoft x64, System V, cdecl, fastcall, Delphi, Go ABI) and finds the program's own `main`, skipping the C runtime start-up
- **Overview** page shows all of it, with a section map, an entropy chart, imports by library and the biggest functions
- **Pseudocode** (F5): a built-in lifter turns each function into C-like code (variables, locals, if / else / while / do-while, calls with arguments); *Export all as .c* writes every function to one file
- **Call graph**: callers on the left, callees on the right, 1–3 levels deep
- **Map**: every function as a treemap, coloured by how often it is called, how branchy it is, or whether it has a real name
- Names and Marks lists, bookmarks (M), byte-pattern search (type `48 8B ?? 05` in Find)

`lens <file> --report` prints the detection result, `lens <file> --decompile main|all|<name>|<address>` prints pseudocode.

### Multi-CPU, raw code, search
- Disassembly, graph, xrefs, strings and imports for **x86, x64, ARM64, ARM, Thumb, RISC-V, MIPS and PowerPC** (Capstone). Pseudocode is x86/x64 only so far.
- Universal Mach-O: pick a part with `--slice arm64`. Chained-fixup imports on arm64 are resolved.
- **Tools > Hex to Code**: paste hex / C arrays / `\x` escapes, or load `.bin`, Intel HEX, S-record; choose CPU, endianness and base address; copy the listing or open it as a program.
- **Cmd+F** search: code and notes, strings, names, byte patterns with `??`, numbers. **Cmd+,** settings.
- **Pseudocode on ARM64, ARM, RISC-V, MIPS and PowerPC** (integer core; anything else shows as a visible `__mnemonic(...)` call).
- **Patching** (Tools > Patch bytes): NOP, invert branch, always-jump or raw bytes; patches are a revertible list; *Save patched copy* writes the file and re-signs Mach-O ad hoc.
- **Signatures** (Tools > Learn signatures from a file): learn from any program with function names, then unnamed library functions are recognised in other programs.
- **Structs** (Tools > Structs): paste a C struct, lay it over data; fields become names in the listing and pseudocode.
- **Scripts and plugins** (Tools > Script): Rhai scripts over the analysis; `.rhai` files in the plugins folder appear under Tools > Plugins and may define `fn on_open()`.
- **Debugger** (Tools > Debugger, F2 for breakpoints): drives lldb; registers, stack, call stack, console, `gdb-remote` for emulators and boards.
- Releases: push a `vX.Y.Z` tag and CI publishes `Lens-macos-arm64.zip`; the app updates itself from it.

## Build and run

```sh
cargo build --release
./target/release/lens [program-or-app]
```

`--screenshot out.png` draws about 120 frames, saves a picture of the window and exits.
`--view graph|hex` and `--dark` / `--light` choose the starting view and theme.

See `MECHANICS.md` for the analysis and naming rules.

## Roadmap
See [ROADMAP.md](ROADMAP.md) for the plan to bring Lens as close to IDA Pro as possible.
