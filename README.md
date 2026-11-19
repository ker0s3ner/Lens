# Lens

A clean, friendly disassembler for x86 and x64 programs, written in Rust with egui.

- Opens Windows (PE), Linux (ELF) and macOS (Mach-O, including universal binaries and `.app` bundles)
- Finds functions, labels, strings, imports, exports and cross-references
- Code listing, flow graph (with overview map) and hex view, kept in sync
- Function outline: callers, callees, text and data each function uses
- Rename (N), notes (;), cross-references (X), go to (G), back (Esc), follow (Enter), graph (Space), command palette (Cmd/Ctrl+P)
- Your names and notes are saved per file
- Light and dark themes

## Build and run

```sh
cargo build --release
./target/release/lens [program-or-app]
```

`--screenshot out.png` draws about 120 frames, saves a picture of the window and exits.
`--view graph|hex` and `--dark` / `--light` choose the starting view and theme.

See `MECHANICS.md` for the analysis and naming rules.
