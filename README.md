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

## Build and run

```sh
cargo build --release
./target/release/lens [program-or-app]
```

`--screenshot out.png` draws about 120 frames, saves a picture of the window and exits.
`--view graph|hex` and `--dark` / `--light` choose the starting view and theme.

See `MECHANICS.md` for the analysis and naming rules.
