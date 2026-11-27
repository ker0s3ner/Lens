# Lens

Lens is a Rust and egui desktop workbench for inspecting executable files, following their control flow, and editing analysis annotations. It supports common native binary formats and several processor families. It is still an early analysis tool, not a drop-in replacement for IDA Pro.

Latest shipped build: **0.6.482 — Fourier**. Added defensive dynamic-trace handoff metrics, synchronized in-app release notes, and smoother dense call-graph rendering. Read the [in-app-style What's New archive](docs/whats-new.html), the [0.6.482 release page](docs/release-0.6.482.html), or the [complete GitHub Pages release archive](docs/releases.html).

## IDA Pro parity status

The current engineering estimate is **about 40–45% of IDA Pro in practical workflow capability**; the weighted roadmap model measures **38.7% of IDA Pro's breadth**. Lens is below the 50% target mainly because its decompiler and type recovery are shallower, processor-specific analysis is narrower, debugging still depends on LLDB, and large-file/performance validation is limited. The roadmap tracks the remaining work and its evidence.

## What it can do

### Load and identify programs

- Open ELF executables, shared libraries and relocatable ELF/Mach-O object files, PE and Mach-O files, including universal Mach-O binaries, Mach-O filesets, macOS app bundles and other folders containing a program. `--slice <entry-name>` can select an embedded fileset image. ELF function discovery includes ordinary and GNU IFUNC symbols. PE Imports includes ordinary and delay-loaded APIs. ELF ET_REL applies common static relocations, including x86/x64 PC-relative and AArch64 call/jump forms. Mach-O MH_OBJECT applies common x86-64 unsigned/PC-relative and ARM64 unsigned/branch relocations. GOT/PLT-dependent, paired, and architecture-specific compound relocations remain unresolved.
- Open raw binaries with a selected CPU, byte order, load address and entry point; the CLI accepts `--arch` (including `x64`/`amd64` aliases), `--big`, `--base`, and `--entry` for explicit firmware analysis.
- Translate pasted hex, C byte arrays, `\\x` escapes, Intel HEX and S-record data into disassembly.
- Inspect program metadata: operating system, CPU, likely compiler and language, packers, security flags, imports, capabilities, entropy and SHA-256.
- Detect Electron `app.asar` archives and extract their JavaScript resources as source files.
- Read function-start hints from ELF `.eh_frame`, dynamic `DT_INIT`/`DT_FINI` plus preinit/init/fini arrays, PE `.pdata` and TLS callbacks, and Mach-O `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`, and `__unwind_info`. Mach-O embedded data ranges are excluded from code discovery. DWARF can supply function names and prototypes; PE files can import global procedure/public symbols from an adjacent CodeView PDB. Named struct, union and enum layouts with supported member offsets can be imported into the Types tool and applied to data.

### Analyze and navigate

- Decode x86 16/32/64-bit, ARM, Thumb, ARM64, RISC-V 32/64, MIPS 32/64, PowerPC 32/64 and Motorola 68000. Decoder-backed analysis depth varies by architecture.
- Find functions, basic blocks, imports, exports, strings and code/data cross-references. Recover switch edges for supported x86, ARM32 PC-indexed/literal tables and register-based tables (including signed/add-or-sub PC-relative bases), ARM64 signed address adjustments, RISC-V signed address adjustments, MIPS, PowerPC and bounded Thumb PC-indexed/register-based/TBB/TBH patterns; switch-case xrefs are labeled separately from direct jumps.
- Discovered pointer tables can be promoted to persistent native-pointer data from the context menu or command palette.
- Contiguous matching data elements can be promoted to a persistent inferred array from the same workflow.
- Control-flow analysis recognizes additional C++, Rust and Swift panic/trap entry points as non-returning.
- Prototype parsing preserves named function-pointer parameters and emits valid callback signatures.
- Known prototype return types now propagate through simple temporary-to-temporary assignments in pseudocode declarations.
- Identify direct and imported-slot forwarding thunks, including common `nop`/`endbr`-decorated stubs, and show their destination in function lists.
- Detect conservative vtable-like runs in read-only data by validating consecutive pointers into executable code, including Itanium C++ tables with offset-to-top and typeinfo headers; available RTTI symbols are converted to readable C++ names in Lists and JSON. Objective-C method/property-name sections in Mach-O files receive selector-aware `sel_` names, Swift `$s` symbols get readable component names, and Swift reflection/type-reference strings receive `swift_` names.
- View synchronized disassembly, control-flow graph, hex, pseudocode, call graph, function map and program overview; recovered switch-case destinations also appear as graph edges.
- Call-graph neighborhoods deduplicate caller functions before applying responsiveness caps, so repeated call sites do not hide distinct callers.
- Dense call-graph rendering skips off-screen relationships and uses lighter curve sampling, reducing paint work while panning and zooming.
- Browse discovered vtable-like and pointer tables from the Lists window and jump to their data addresses.
- Browse persisted inferred arrays from the Lists window and jump to their first element.
- Browse manual and inferred scalar, pointer, string, and array-backed definitions from the synchronized Data tab in Lists, including applied types and analyst comments. Double-click a row to open Types focused on its applied type and address, or copy its selected address for scripts and notes.
- Lists tabs can also be selected in automation with `LENS_TAB=arrays`, `pointer_tables`, or `vtables`.
- Search names, notes, strings, listing text, numeric values and byte patterns with wildcards such as `48 8B ?? 05`; scope searches to the current function or full program, and copy results as an address-and-text report for external triage. Function-scoped searches scan the full function before capping displayed results and clear when navigation moves to another function. Data rows can be explicitly marked as native-width pointers with the `O` action.
- Rename addresses and pseudocode variables, add notes, bookmarks and breakpoints; annotations are saved per input file.
- Define bytes and strings, apply C-like structs, unions, enums (including common binary/octal and bitwise/shift constant expressions), scalar and function-pointer typedefs, function-pointer fields, packed layouts (`__attribute__((packed))` and `#pragma pack(1)`), integer bitfields with signed-value display, and zero-width bitfield storage separators, import supported DWARF layouts, inspect nested fields and indexed array values, follow typed pointer members, and get xrefs from typed pointer arrays.
- Identify common cryptographic constants and use built-in or learned function signatures to recognize library code.

### Decompile and edit

- Produce approximate C-like pseudocode and render it as C, Rust, Python, Go or JavaScript; scalar SSE and common AVX operations retain float/double or vector declarations and binary expressions.
- Known typed struct-pointer offsets now render named fields and bounded fixed-array indices in pseudocode; known pointer prototypes also propagate through inferred call arguments and preserve pointer types for inferred variables, including explicit function-pointer return casts and typed field access through those returns. Decompiler copy propagation crosses safe intervening statements but stops at source or temporary reassignment. Objective-C `objc_msgSend` and `objc_getClass` literals render as `@selector(...)` and `@class(...)`; uncertain types and offsets remain explicit dereferences.
- Known pointer-typed prototypes cast constant call arguments in pseudocode, while leaving inferred variables untouched when their type is uncertain.
- Applied user-defined enum types now name matching integer constants in typed pseudocode call arguments, such as `Color::Blue`.
- Bitfield storage compatibility now ignores redundant `const`, `volatile`, and `restrict` qualifiers when matching equivalent signed integer declarations.
- Enum-aware constant propagation also folds multiplication, division, and remainder in typed comparisons, preserving named members when arithmetic computes an enum value.
- Enum identity now survives safe `+`/`-` arithmetic with integer constants in typed comparisons.
- Enum identity also survives safe constant bitwise `|`, `&`, and `^` transformations used by flag-style code.
- Enum identity also survives constant `<<` and `>>` transformations used by flag and bitfield code.
- Enum identity now propagates through conditional expressions whose branches retain the same enum type.
- Enum identity now propagates through bitwise-not expressions used by flag masks.
- No-return analysis now recognizes compiler unreachable helpers and panic-family symbols, improving caller control-flow termination.
- Enum constant propagation now folds C-style logical `&&` and `||` expressions in typed comparisons.
- C enum declarations now accept logical `&&`, `||`, and unary `!` constant expressions, including parenthesized forms.
- Enum constant propagation now folds constant ternary expressions in typed comparisons.
- Enum local type recovery now survives conditional branch merges.
- Enum local type recovery now survives safe constant arithmetic and bitwise transformations.
- Enum local type recovery now recognizes typed prototype call returns and recursive enum-return calls.
- Typed pointer dereferences now reconstruct variable-index scalar accesses such as `p[i]` when the element stride is known.
- Variable-index reconstruction also accepts compiler-generated `stride * index` address expressions.
- Known struct-pointer arrays now render variable-index field accesses such as `p[i].field`.
- Variable-index reconstruction also recognizes power-of-two shifts such as `i << 2` for element strides.
- Shift-scaled variable-index struct arrays now preserve nested field paths such as `p[i].value`.
- Copy propagation now traverses owned casts used by typed pointer and function-pointer values.
- Dereference/liveness analysis now traverses owned casts consistently.
- Typed pointer and struct-array reconstruction now handles reverse-index forms such as `p[-i]`.
- Enum constant recovery now folds transparent borrowed and owned casts before naming typed members.
- Enum constant folding now handles transparent unary-plus wrappers.
- Enum type propagation now retains identity through unary-plus expressions.
- Enum type propagation now retains identity through unary-minus expressions.
- C enum parsing now accepts unary-plus constant expressions consistently with pseudocode folding.
- Enum constant parsing now preserves equality and relational comparisons as 0/1 values.
- Decompiler enum folding now evaluates equality and relational operators consistently with C declarations.
- C enum parsing now supports checked multiplication, division, and remainder expressions.
- Enum declarations and pseudocode now share arithmetic coverage for scalar constant folding.
- Debugger shutdown now clears stale commands and trace state when LLDB exits unexpectedly.
- Debugger exit status is surfaced in the console and reconnects start from a clean session.
- C enum parsing now decodes common escaped, hexadecimal, and octal character constants.
- Character-valued enum members now match C literal semantics in the type database.
- Project members can now be removed directly from the workspace inspector.
- Active and last project files are protected so removal cannot strand the session or empty the manifest.
- Open raw binary is now available directly from the command palette.
- Raw-file commands preload the existing architecture, endian, base, and Intel HEX/S-record loader controls.
- Decompiler copy propagation now crosses an unambiguous single-predecessor basic-block edge.
- Cross-block propagation preserves source and destination reassignment barriers with regression coverage.
- Decompiler copy propagation now folds identical temporary copies through converging control-flow edges.
- Merge-block propagation remains conservative and requires matching incoming assignments before rewriting uses.
- Reference tracking and expression sizing now traverse owned casts consistently.
- Enum identity also survives constant `<<` and `>>` transformations used by flag and bitfield code.
- The x86/x64 lifter has the broadest coverage, including immediate and register-count rotate expressions, BMI2 `mulx`, flag-independent `rorx`, AVX/FMA3 fused arithmetic, double-precision shifts, integer division with implicit wide dividends and `cdq`/`cqo` sign extension, named bit-count operations, BMI2 bit manipulation, and byte swaps useful for hash, crypto, endian, and wide-integer code. ARM64, ARM/Thumb, RISC-V, MIPS and PowerPC use integer-focused lifters; ARM/Thumb long multiply preserves both halves of 64-bit results, RISC-V and PowerPC high-half multiplication preserve signedness, MIPS HI/LO multiply and division results flow through `mfhi`/`mflo`, ARM64 NEON vector registers are tracked and declared as 128-bit values, common floating-point arithmetic, pairwise/reduction operations, saturating arithmetic, vector comparisons, widening/narrowing and high-half operations, variable and rounded shifts, reciprocal/complex/dot-product operations, bit-select masks, bitfield extraction/insertion, rotate/extract idioms, conditional integer selects, moves and comparisons become readable expressions, typed enum parameters and return values render named members even through transparent casts and enum switch cases, and other unsupported vector operations remain visible as intrinsic-style calls.
- x86 switch normalization preserves case bases for both subtract-before-index and add-before-index idioms.
- Patch bytes, NOP instructions, invert supported branches, or force supported conditional branches. Save a patched copy separately from the original; Mach-O output is ad-hoc signed when possible.
- Run Rhai scripts against a read-only analysis snapshot (including types, segments, imports/exports, incoming/outgoing xrefs, normalized call-only `callers(addr)`/`callees(addr)` queries, and bounded two-sided structured `call_graph(addr, depth)` edges with caller/callee direction; outgoing queries aggregate instruction-level call sites across each function), then apply queued actions such as renames, notes, bookmarks, patches, navigation, and defining/applying types. `.rhai` plugins may define an `on_open` hook.
- Rhai snapshots expose `pointer_tables()` and `vtables()` for scripted inspection; vtable records include an optional recovered RTTI `type`, and scripts can promote entries with `define_pointer_table(addr)` or `define_array(addr)`.
- `xrefs_to_details(addr)` exposes incoming xrefs as `{from, kind}` records, preserving distinctions such as `call`, `switch case`, `read`, `write`, and `pointer`.
- `xrefs_from_details(addr)` exposes outgoing xrefs as `{to, kind}` records with the same relationship labels.
- JSON vtable records include their owning segment and file offset when the recovered table maps to file-backed data.
- Desktop JSON database exports preserve the same vtable source context for round-tripping.
- Rhai `vtables()` records expose the same optional `segment` and `file_offset` fields.
- The Lists vtables view also shows the owning segment beside entry and xref counts.
- `decompile(addr)` returns the typed C-like pseudocode for a recovered function, using the same decompiler path as the UI.
- `script_api_version()` returns the current compatible Rhai API version (`1`); plugins can check it before using newer functions or record fields.
- `comment_at(addr)` reads an analyst note and `bookmarks()` returns saved bookmark addresses.
- `data_at(addr)` reads a persisted data-definition code, and `data_definitions()` returns sorted `{addr, code}` records.
- `threat_signals()` returns explainable static analyst-triage clues with severity, name and evidence fields for defensive automation; these are heuristics, not malware verdicts.
- `--report` prints the same triage clues for terminal workflows, while `--json` includes them in the `threat_signals` array.
- Smoke and golden-analysis checks assert that triage data remains present in machine-readable reports.
- Database JSON exports also preserve `threat_signals`, keeping defensive review context attached to shared analysis.
- Exported dynamic traces include per-address hit counts, making repeated loop or hot-path behavior visible during review.
- The Overview triage panel can copy a compact, explicitly heuristic summary for case notes and handoff.
- Triage adds an explainable multi-capability signal when several behavior categories co-occur.
- Runtime code-loading behavior is now surfaced as a separate triage clue for unpacking and late-bound execution review.
- Filesystem activity is surfaced as its own low-severity behavior clue, separate from persistence detection.
- System-information discovery is surfaced as a separate reconnaissance clue.
- Threading/timing and cryptographic imports are surfaced as additional low-severity behavior clues.
- Desktop and UI interaction imports are surfaced as a separate low-severity clue.
- Binaries with six or more capability categories receive an explainable broad-profile prioritization clue.
- The triage panel summarizes high, medium, and note-level signal counts before listing evidence.
- Protection context now distinguishes ASLR disabled from ASLR enabled, with conservative explanatory evidence.
- DEP/NX-disabled posture is also surfaced as a separate executable-memory hardening clue.
- Disabled stack protection is surfaced as a separate hardening-posture clue.
- Control-flow-guard-disabled posture is surfaced as a separate indirect-control-flow hardening clue.
- Unavailable code-signature validation is surfaced as a conservative provenance clue when reported by the loader.
- RELRO-disabled and unavailable runtime-fortification posture are also surfaced as conservative hardening clues.
- PIE-disabled posture is surfaced as a separate position-independent executable hardening clue.
- Analysts can copy only high-severity signals for focused defensive handoff.
- Analysts can also copy the combined medium-and-high signal set for escalation notes.
- Dynamic traces can be exported as structured `lens.dynamic-trace.v1` JSON with addresses, hit counts, function names, and heuristic flags.
- Dynamic trace annotations are indexed once per debugger frame, keeping full-trace review responsive at the 5,000-entry cap.
- The debugger includes a Triage only filter for quickly reviewing trace entries that match static heuristic signals.
- Structured dynamic-trace records now include the matching heuristic signal names, not only a boolean flag.
- Dynamic-trace JSON includes top-level entry and unique-address counts for downstream behavior metrics.
- Dynamic-trace JSON also reports the number of distinct heuristic-flagged addresses.
- Dynamic-trace JSON reports total heuristic matches separately from distinct flagged addresses.
- Dynamic-trace JSON includes a deduplicated top-level list of observed heuristic signal names.
- Dynamic-trace JSON also reports hot-address count and maximum address hit count for loop intensity analysis.
- The debugger can copy the deduplicated set of observed heuristic signal names for quick handoff.
- Dynamic summaries separate repeated heuristic hits from the number of distinct flagged addresses.
- Hot-address controls include resolved function names as well as addresses and hit counts.
- Hotspot lists can be copied as tab-separated function, address, and hit-count records.
- `search(query)` returns case-insensitive `{addr, kind, text}` matches across names, strings, comments, and generated pseudocode.
- `function_at(addr)` resolves an address to its containing recovered function record.
- Compare two program versions by function shape and name.
- Import exported Lens JSON databases with annotations, data definitions and applied-type references restored.
- Exported/imported JSON databases also preserve user-authored prototypes used by the decompiler.
- Lens JSON exports carry schema version 2 and preserve names, types, prototypes, data definitions, tables, xrefs and annotations.

### Debug and exchange data

- Drive LLDB from the debugger window: launch or attach to a local PID, step, continue, pause, inspect registers, stack, backtrace and 128-byte memory windows, set conditional or requested hardware breakpoints, evaluate watches, and use the command console. Restart a target after exit. Trace 100 or 1,000 instructions by single-stepping and recording each executed PC; traces are capped at 5,000 addresses. The trace view now resolves recent PCs to static function names and marks entries that match known analyst-triage signals.
- Dynamic and malware analysis are an explicit roadmap area: Lens is adding behavior-oriented trace triage, static capability clues, and explainable analyst signals. These signals are heuristics for review, not an automated malware verdict.
- Connect to a GDB remote server with `gdb-remote` for supported targets.
- Import names and notes from Lens JSON, IDA `.idc` or Ghidra `.py` scripts; Lens JSON restores import-slot and recovered-vtable names as well as functions, exports, analysis name/symbol records, recovered debug types/prototypes, scalar/pointer/string data records, pointer tables/vtables and RTTI-derived names, function records and entry hints, discovered strings, legacy import/export records, comments, types, patches, applied types, breakpoints, breakpoint conditions, variable renames, and prototypes. Analysis JSON exports round-trip the same analyst-state records, apply imported patches to the in-memory binary, reanalyze patched bytes, and report restored patch counts. Call graph layout is cached between frames, invalidated after analysis changes, and built with memoized caller and callee scans to keep large graphs responsive. Export IDC, Ghidra Python, JSON annotations, assembly listing, Graphviz call graph and map files.

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

`--decompile` accepts `main`, `all`, a function name or an address. `--lang` accepts `c`, `rust`, `python`, `go` or `js`. Raw input also accepts `--big` for big-endian data. Other CLI tools include `--learn-sigs`, `--sigs`, `--run-script`, `--patch ADDR:HEX --save FILE`, and `--report --extract DIR` for detected Electron archives. Use `--json` with a file to emit a stable `lens.analysis.v1` machine-readable analysis summary containing format, architecture, entry point, image slice/base, aggregate counts, per-function boundaries/calls/normalized callers/callees/no-return/thunk records with names, kinds, mapped segments, symbol provenance, incoming references, conservative tail-call edges and tail-call no-return propagation with regression coverage, shared-decompiler pseudocode records with matching metadata and line counts, compact per-instruction flow and operand-reference records, classified listing-line records, basic-block boundaries and typed successor edges, explicit function-level call edges and exact direct/indirect call-site records, entry-point records including sorted/deduplicated loader hints, a unified name stream, recovered switch-table records with references and aligned `case_indices`, typed xref records, discovered string records with incoming references, mapped segment records, import/export records with incoming references, imported-library records with symbol lists, inferred data records with incoming references, top-level non-pointer array records that round-trip through database import, recovered pointer-table/vtable records with incoming references, recovered debug type layouts and prototypes, named internal symbol records, hashes, and loader notes. CLI function records now include stable normalized caller/callee arrays; desktop JSON database exports carry the same identifier in `schema_id` while retaining their legacy numeric `schema` field.

## Build and release

Lens uses stable Rust and Cargo. Build locally with `cargo build --release`. The checked-in release workflow currently packages **macOS Apple Silicon** builds; it does not publish Intel Mac or Windows installers.

Release versions use `x.y.z`: `x` is a themed major release, `y` is a monthly feature release, and `z` is a fixes/QoL release. Mathematical codenames are recorded in `RELEASE_NOTES.md`, shown in Lens under Help > What's New, included in GitHub releases, and archived on the [public version history](https://ker0s3ner.github.io/Lens/releases.html). The planned first full release is `1.0.0 — Stokes`.

## Current limitations

- Analysis completeness and pseudocode quality vary substantially by architecture and compiler. The pseudocode is a best-effort lift, not source recovery or a correctness proof.
- Switch recovery covers x86, ARM32, ARM64, Thumb TBB/TBH, RISC-V, MIPS and PowerPC patterns, including validated absolute and relative-offset tables where recognized, but remains conservative. Forwarding thunks and indirect calls through import slots contribute call-graph edges. Vtable/RTTI, Objective-C selector, and Swift symbol/reflection metadata recovery are implemented heuristically; broad data-versus-code typing is not. Relocatable ELF inputs apply common x86/x64, AArch64, ARM, RISC-V, 68k, MIPS, and PowerPC static relocations but do not synthesize linker GOT/PLT entries or resolve every architecture's compound relocations.
- The type parser is intentionally limited. It supports anonymous typedef records/enums, simple integer bitfields, callback fields, nested function-pointer declarations and function-pointer typedef aliases, but not compiler-specific bitfield ABI layouts. Supported DWARF bitfields and callback signatures are imported; unsupported member-location expressions are skipped instead of assigned guessed offsets.
- Debugging depends on LLDB; Lens does not yet have its own native debug engine. Hardware breakpoints depend on target support. Instruction tracing uses repeated single-step operations, so it is slower than processor trace facilities and stops at the selected instruction limit; captured traces can be exported with step indexes and addresses. Process attach and GDB remote connection are available through LLDB. Multi-file projects expose their binaries as switchable inspector entries and preserve relative paths when moved.
- Files are read fully into memory, then loading and analysis run on a background thread. Incremental analysis/listing, explicit memory limits and measured performance on very large files remain future work.
- `scripts/smoke-corpus.sh` runs the headless `--report` path against representative executable files found on the host, providing a repeatable loader/analysis smoke check without committing platform binaries.
- `scripts/golden-analysis.sh` runs deterministic raw x64, ARM32, Thumb, ARM64, RISC-V 64, PowerPC 64, and MIPS32 JSON fixtures with exact schema, entry metadata, and record-shape assertions; the smoke script runs it after the host corpus.
- The GitHub Pages release archive is at `docs/releases.html`; the current build's readable What's New page is `docs/whats-new.html`.
- GitHub release automation runs both `cargo test --locked` and the smoke corpus before packaging or publishing a release.
- Enum-aware decompiler behavior has direct regression coverage for call arguments, returns, conditions, switch cases, and transparent casts.
- PDB type recovery is intentionally conservative: primitive, pointer, modifier, procedure and argument-list records can contribute prototypes; CodeView enum, struct/union, and simple C++ class/interface records import named members/layouts, including split field-list continuations, supported callback fields, nested record sizes, enum storage widths, bitfield positions/widths, fixed arrays, and const/volatile qualifiers; inheritance, virtual layouts, and other unsupported records are skipped without exposing partial class types. CodeView procedures marked never-returning terminate both PE control-flow analysis and pseudocode call lifting, with exact-name regression coverage.
- Java, .NET, DEX/APK, WebAssembly, firmware and the additional processor families listed in the roadmap are not supported as native analysis targets yet.

See [ROADMAP.md](ROADMAP.md) for planned work and [MECHANICS.md](MECHANICS.md) for naming and analysis rules.
