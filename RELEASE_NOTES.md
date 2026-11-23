# Lens 0.6.28 — Fourier

## What's new

- MIPS signed and unsigned division now preserve quotient in LO and remainder in HI for `mflo`/`mfhi` consumers.
- MIPS division and multiply share explicit HI/LO data flow in pseudocode.

- MIPS `mult`, `multu`, `dmult`, and `dmultu` now preserve implicit HI/LO results through `mfhi` and `mflo`.
- MIPS wide multiply pseudocode no longer drops the architecture's hidden result pair.

- ARM/Thumb long multiply and accumulate instructions now preserve both low and high result registers in pseudocode.
- Long arithmetic is represented with explicit wide-value helpers instead of silently dropping the upper half.

- Stripped functions ending in an architectural stop/trap instruction are now conservatively inferred as no-return.
- Added regression coverage for trap-terminated x86-64 functions.

- ARM64 scaled switch-table offsets and halfword entries now honor big-endian binaries.
- The roadmap now records completed common switch-table support across x86, ARM, RISC-V, MIPS, and PowerPC while identifying remaining idioms for validation.

- Thumb indexed `ldr pc, [pc, index, lsl #2]` jump tables now recover bounded absolute targets.
- Recovered targets are validated against executable mappings and decoded instructions before becoming switch cases.

- Mach-O `LC_DATA_IN_CODE` ranges are excluded from executable discovery.
- Analysis notes record the number of embedded-data ranges recognized in Mach-O files.
- Decompiler types now survive call-result copy chains and explicit casts when the source type is unambiguous.
- Repeated assignments with conflicting or unknown types remain conservatively untyped.
- Release notes remain synchronized across Lens, GitHub Releases, and the public version history.
- The macOS release job now uses an explicit Apple Silicon runner and verbose bundle-build diagnostics.
- Decompiler type propagation now recognizes both internal and owned cast expressions.
- Dereferences of known pointer-returning calls and explicit pointer casts now render their pointee types.
- Copied pointer temporaries retain inferred pointee types in subsequent memory reads.
- Versioned `.lensproj` manifests can group multiple binaries and open the selected active file while keeping per-file annotations separate.
- File > Save Project creates or updates a `.lensproj` manifest from the current analysis session.
- File > Add File to Project appends another binary with duplicate detection and manifest persistence.
- Opening a project member keeps the workspace active and records that binary as the manifest’s active file.
- Relative project members now resolve from the `.lensproj` directory, making project files portable.
- Resolved absolute paths continue to match relative project members when switching files.
- Save Project now serializes members inside the project directory as relative paths while preserving external paths.
- Decompiler branch structuring now detects loop headers inside forward conditional regions instead of flattening them into simple `if` blocks.
- The Overview displays project members and opens them directly, including relative-path resolution.
- The active project indicator now resolves relative manifest paths correctly.

## Release cadence

Lens versions use `x.y.z`: major theme releases, monthly minor feature releases, and patch releases for fixes and quality-of-life improvements. The first full release, `1.0.0`, will be codenamed **Stokes**.
