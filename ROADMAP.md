# Roadmap: getting Lens as close to IDA Pro as possible

Authoritative current build: **Lens 0.6.452 — Fourier**. The release archive and in-app What's New history are synchronized through this build; the 50% target remains unmet.

Release update: **Lens 0.6.452 — Fourier** adds readable RISC-V and MIPS atomic load/store lifting with explicit success status, building on the ARM synchronization semantics from 0.6.451. The 50% target remains unmet.

Release update: **Lens 0.6.451 — Fourier** adds ARM/Thumb `rbit` and exclusive load/store lifting for synchronization-heavy code, including byte, halfword, and doubleword forms. The 50% target remains unmet.

Release update: **Lens 0.6.450 — Fourier** broadens no-return recognition across Rust, Go, Swift, Objective-C, C++, and Windows/Apple runtime symbols, including hashed Rust panic names. The 50% target remains unmet.

Release update: **Lens 0.6.449 — Fourier** hardens switch-table recovery with checked bounds and entry addressing across ARM64, Thumb, RISC-V, MIPS, PowerPC, and x86-style tables. The 50% target remains unmet.

Release update: **Lens 0.6.448 — Fourier** corrects unsigned RISC-V/MIPS comparison lifting and makes scripted function, search, bookmark, and call-graph results deterministic while reusing one indexed graph. The 50% target remains unmet.

Release update: **Lens 0.6.447 — Fourier** hardens call-graph rendering with bounded pan/zoom input, safe cache fallback, deterministic adjacency ordering, malformed-edge guards, and lower-cost curve painting. The 50% target remains unmet. Current audit marker remains **38.7% weighted capability / about 40–45% practical workflow**.

Release update: **Lens 0.6.446 — Fourier** adds deterministic ARM64 NEON `bsl` decode coverage for the new mask-combine semantics. The 50% target remains unmet.

Release update: **Lens 0.6.445 — Fourier** lifts ARM64 NEON `bsl`, `bit`, and `bif` mask-combine operations into readable expressions. The 50% target remains unmet.

Release update: **Lens 0.6.444 — Fourier** adds GCC 128-bit integer aliases across layout, prototypes, and typed element recovery. The 50% target remains unmet.

Release update: **Lens 0.6.443 — Fourier** carries 128-bit integer widths through typed pointer and array recovery. The 50% target remains unmet.

Release update: **Lens 0.6.442 — Fourier** adds aligned compiler 128-bit integer sizing and prototype recognition. The 50% target remains unmet.

Release update: **Lens 0.6.441 — Fourier** bounds desktop caller xref mapping before function lookup to reduce worst-case high-fan-in graph startup work. The 50% target remains unmet.

Release update: **Lens 0.6.440 — Fourier** caps scripted call-graph edges and documents the complete graph-query API in the script panel. The 50% target remains unmet.

Release update: **Lens 0.6.439 — Fourier** replaces repeated full xref scans in scripted call-graph expansion with pre-indexed function-level adjacency. The 50% target remains unmet.

Release update: **Lens 0.6.438 — Fourier** adds source–destination-correct M68k move lifting, `$`-prefixed hexadecimal immediate parsing, and deterministic M68k return-value pseudocode coverage. The 50% target remains unmet.

Earlier baseline build: **Lens 0.6.437 — Fourier**. The golden corpus now checks ARM64 pseudocode for a recovered constant return. The CLI now maps m68k/68k/m68000 aliases to Motorola 68000 raw analysis. C++ vector-construction/destruction runtime prototypes are now built in. C++ thread-safe static-initialization guard prototypes are now built in. C++ exception begin/end/rethrow and pure-virtual runtime prototypes are now built in. C++ operator new[] and operator delete[] prototypes now resolve by their full names. Built-in C++ operator new/delete prototypes now parse and resolve by their full names. ARM64 min/max helper selection now has direct regression coverage. ARM64 scalar and vector fmin/fmax instructions now lift to explicit helpers. x86 scalar and packed SSE/AVX min/max instructions now lift to explicit fmin/fmax calls. Pseudocode now collapses identical conditional branches instead of printing redundant ternaries. Call-graph startup now renders a bounded one-hop neighborhood before optional deeper expansion. Call graph now opens at one hop for a responsive first frame, while deeper expansion remains available on demand. M68k size-suffixed arithmetic and compare mnemonics now dispatch through the generic semantic lifter, with suffix normalization regression coverage. Golden analysis now covers x64, ARM32, Thumb, ARM64, RISC-V, PowerPC, and MIPS metadata; M68k now has a dedicated generic-decompiler register and ABI family with common arithmetic, memory-form move, frame, address, teardown, register-transform, and stack-state lifting; call graphs now reuse indexed call analysis, identify named forwarding thunks, and deduplicate caller functions before responsiveness caps; vtable JSON, desktop database exports, Rhai snapshots, and the Lists view retain or show owning segment and file-offset source context; bitfield matching now normalizes const, volatile, and restrict qualifiers across equivalent signed storage types; enum identity now survives safe constant `+`/`-` arithmetic in typed comparisons; x86 switch case-index recovery now handles both add and subtract normalization idioms; enum types also propagate through locals, casts, reassignment, typed call results, flag decomposition, and constant expressions; ARM32 and Thumb register-based switch recovery now handles signed PC-relative and backward `sub reg, pc, #imm` table bases; RISC-V and ARM64 switch reconstruction now accept signed address adjustments; the parallel regression gate is deterministic; the 50% target remains unmet.

Current audit marker: **0.6.446 — Fourier**. The weighted estimate remains the prior **38.7%** engineering estimate; the practical workflow estimate remains **about 40–45%**. The 50% target is still unmet.

Status checked against the repository on 2026-11-27, at **Lens 0.6.446 — Fourier**. The weighted estimate below is carried forward from the previous audit; the current practical workflow estimate is **about 40–45% of IDA Pro**; the weighted capability model below gives **38.7% of IDA Pro's breadth** (plausible range: **31–40%**). The 50% target is not yet reached. These estimates measure feature coverage, not analysis accuracy, reliability, performance, polish, or production readiness; those remain substantially behind IDA. Each phase should be validated against real binaries as well as targeted regression fixtures. Planned work is kept separate from completed work.

| Capability area | Weight | Lens coverage estimate | Weighted contribution |
| --- | ---: | ---: | ---: |
| File formats and processor breadth | 20% | 27% | 5.4% |
| Static analysis and navigation | 20% | 58% | 11.6% |
| Decompiler and type recovery | 20% | 28% | 5.6% |
| Type system and debug information | 10% | 40% | 4.0% |
| Debugging and tracing | 10% | 35% | 3.5% |
| Workflow, scripting and interchange | 10% | 55% | 5.5% |
| Reliability, performance and scale | 10% | 31% | 3.1% |
| **Total** | **100%** |  | **38.7%** |

These are engineering estimates, not a feature-count comparison. Lens already has a broad usable workflow across loading, navigation, graphing, search, annotations, signatures, scripting, debugging, export, and multi-file project manifests. The score remains limited by the much shallower decompiler, partial architecture-specific analysis, narrower format/CPU coverage, small type system, LLDB dependency, and limited large-file validation.

## Phase 1 - Reliability (first, everything else depends on it)
- Expand the existing 200-program system-binary run into a repeatable corpus covering ELF, PE, Mach-O, stripped files, dylibs, and Go/Rust/Swift; fix crashes and incorrect results found by it.
- Performance on 100 MB+ files: background analysis, incremental listing, memory limits. Call-graph expansion now bounds high-fanout neighborhoods, uses indexed switch edges, and surfaces truncation instead of allowing oversized graphs to stall rendering.
- Add a repeatable regression suite with golden outputs for disassembly and pseudocode; the repository has targeted unit tests, but not this corpus-level suite.

## Phase 2 - Analysis depth
- Extend switch/jump-table recovery beyond x86, ARM64 and basic Thumb TBB/TBH tables to additional ARM/Thumb patterns, RISC-V, MIPS and PowerPC; common absolute-table forms and Thumb register-based PC tables are implemented, while more compiler idioms and corpus validation remain.
- Vtable, RTTI and Objective-C / Swift metadata recovery.
- Extend function-boundary recovery beyond ELF `.eh_frame`, PE `.pdata` and Mach-O `LC_FUNCTION_STARTS` / `__unwind_info`; add more robust malformed-table handling and additional format-specific tables.
- Improve constant propagation and broaden no-return, tail-call and thunk detection beyond the current known names/prototypes and direct-target cases.
- Better data-vs-code discrimination and string / array / pointer-table typing.
- Debug info: DWARF names, prototypes and supported type layouts are available, with adjacent dSYM lookup; PDB and broader C++/Rust/Swift debug-type support remain.

## Phase 3 - Decompiler
- Type recovery and propagation across calls is expanding; typed prototype returns, recursive enum returns, struct-field access, fixed-array indexing, nested records, and pointer typedefs are implemented with regression coverage. Broader SSA-based propagation and more complex array/pointer reconstruction remain.
- SSA-based data-flow, dead code and copy propagation, better loop and `switch` structuring.
- Floating point, SIMD / NEON / SSE, 64-bit arithmetic idioms, and broader calling-convention inference. M68k LINK/A6 frames now recover stack parameters from the correct first-argument offset; call-site stack-argument collection and other conventions remain planned.
- Thumb/Thumb-2 in the main loader and additional PPC extras.
- Interactive: retype variables and improve navigation/synchronization between pseudocode and disassembly; pseudocode local renaming is already implemented.

## Phase 4 - Type system and libraries
- Expand the C-like type parser: structs, unions, basic enums, scalar/pointer aliases, function-pointer typedef aliases, nested records, bounded arrays, packed layouts and simple packed integer bitfields are supported; compiler-specific bitfield ABI/layout rules remain.
- Extend the built-in/user prototype library (about 190 signatures) and improve type propagation from prototypes into variables, memory accesses, and pseudocode.
- Generate and ship broader versioned signature/type libraries from system libraries (libSystem, libc, MSVC CRT and platform frameworks); the current built-in prototype set is not a complete type library.

## Phase 5 - Debugger
- Replace the LLDB-driven backend with native platform backends (ptrace / Mach / Windows debug API), or document a deliberate LLDB dependency.
- Improve target/session management, platform coverage, reconnect/error recovery, and debugger UI synchronization.
- Decode hardware processor trace streams (such as Intel PT) and connect them to static analysis; the current instruction trace is bounded LLDB single-stepping, not hardware trace decoding.

## Phase 6 - Scripting and plugins
- Expand and document the existing Rhai script API to cover annotations, types, xrefs, decompiler output, and safe UI actions.
- Improve the existing `.rhai` plugin workflow with examples, discovery/management, error reporting, and a compatibility/versioning story. A basic embedded runtime and load/on-open hooks already exist; there is no stable native plugin ABI or package manager.

## Phase 7 - Formats and CPUs
- Firmware, raw flash dumps, kernels, Android DEX / APK, Java class, .NET IL, WebAssembly, Mach-O fileset.
- More processors: AVR, 6502, Z80, SuperH, SPARC, s390x, TriCore, eBPF. Basic Motorola 68000 decode and core arithmetic semantics are implemented via Capstone; more instruction families and corpus validation remain.
- Proper per-CPU semantics for each, not just text classification.

## Phase 8 - Workflow and UI
- Promote the new versioned per-file annotation container into a user-managed project database with project naming, migration, and multi-file sessions. Per-file annotations, undo/redo for supported edits, bookmarks, multiple views, and a function graph already exist.
- Extend xrefs consistently across pseudocode, graph and all data references; xref lists, listing comments, segment pointer scans, and pointer members in applied types already produce xrefs.
- Add a dedicated synchronized structure/data pane; top-level inferred arrays and pointer-table definitions can now be persisted and browsed from Lists, while fixed arrays inside applied types already expand into individually navigable elements and pointer-array entries produce xrefs. Improve local/global search.
- Improve collaboration and interchange; IDC/Ghidra script and JSON/map exports and partial IDC/Ghidra import already exist, but richer database import remains.

## Done so far (toward parity)
- M68k LINK frames now account for the saved frame pointer and map the first stack parameter at the correct A6-relative offset, with a pseudocode fixture guarding the result.
- Motorola 68000 arithmetic now follows source,destination operand order, writes effective-address destinations, and carries result/compare state into condition-code reconstruction.
- Generic RISC-V, MIPS, and PowerPC decompilation now uses the selected 32-bit or 64-bit architecture width for native registers.
- JSON analysis reports now declare the `lens.analysis.v1` schema, and the smoke corpus validates human-readable plus JSON output for every discovered executable.
- Call graph expansion now bounds high-fanout neighborhoods and visibly reports when a graph is truncated for responsiveness.
- Imported indirect calls now contribute explicit call-graph edges, with regression coverage separate from forwarding-thunk analysis.
- ELF dynamic `DT_INIT` and `DT_FINI` entries now seed executable-range-validated function discovery.
- ELF dynamic init/fini arrays now seed bounded executable-range-validated constructor and destructor roots when section names are unavailable.
- ELF `DT_PREINIT_ARRAY` entries now seed the same bounded executable-range-validated function discovery path.
- Mach-O filesets now open the first parseable embedded image through the normal Mach-O loader and fail closed when none is parseable.
- Mach-O fileset entries can be selected by name with `--slice`, with a recorded fallback when the requested entry is unavailable.
- The runtime smoke corpus now includes discovered shared-library/dylib candidates alongside executable programs.
- CLI reports expose selected image slices and embedded file bases for universal binaries and filesets.
- RISC-V switch recovery now accepts validated signed relative-offset tables as well as absolute pointer tables.
- MIPS switch recovery now accepts validated signed relative-offset tables as well as absolute pointer tables.
- PowerPC switch recovery now accepts validated signed relative-offset tables as well as absolute pointer tables.
- ARM32 switch recovery now accepts validated signed relative-offset tables as well as absolute pointer tables.
- Thumb PC-indexed switch recovery now accepts validated signed relative-offset tables as well as absolute pointer tables.
- Data-reference recovery now validates native pointers at unaligned offsets in packed data.
- Packed pointer-table discovery now recognizes complete native-stride runs at unaligned starts.
- Typed struct-pointer arithmetic now renders known field names in pseudocode when the type and offset are unambiguous.
- Known fixed-array members now render bounded indexed accesses in typed pseudocode.
- Known nested struct members now render chained field access in typed pseudocode.
- Known scalar pointer arithmetic now renders bounded indexed accesses in typed pseudocode.
- Typed pointer-returning calls now participate in known struct-field resolution.
- Explicit function-pointer casts now contribute conservative prototypes to indirect calls.
- Function-pointer typedef aliases now resolve to full callable parameter and return prototypes.
- Function-pointer typedef aliases resolve through bounded alias chains without unbounded parser recursion.
- Applied C type layouts now retain chained function-pointer typedef aliases.
- Prototype parsing recognizes common GCC/Clang `__attribute__((noreturn))` and C++ `[[noreturn]]` declarations.
- No-return status now propagates through known wrapper and thunk call chains to a fixed point.
- Prototype parsing also accepts GNU and compiler-qualified no-return attribute spellings.
- Imported indirect calls to known no-return symbols now mark the containing function as no-return.
- CLI JSON analysis reports now expose no-return, forwarding-thunk, and recovered switch-table counts.
- CLI JSON analysis reports now expose per-function boundaries, calls, no-return status, and thunk targets.
- Decompiler output folds safe adjacent temporary-to-register copies within a basic block.
- Decompiler expression folding now simplifies boolean truthiness identities and full-width bitmask identities.
- Decompiler constant folding now preserves signed right-shift semantics and recognizes unit remainders.
- Decompiler now inlines safe single-use call temporaries while retaining separate values when later uses exist.
- JSON function records now expose normalized caller and callee function addresses for graph consumers.
- JSON callee records are deterministic and deduplicated while raw call-site records remain available.
- The runtime smoke corpus now gates releases on the presence of normalized JSON callers/callees.
- Decompiler folds constant ternary conditions while preserving non-constant branch structure.
- Decompiler folds constant conditional terminators into direct jumps, removing impossible branches.
- Decompiler type inference now propagates return and pointee types through cast function-pointer calls.
- Typed field rendering now follows those indirect pointer-returning calls into known struct members.
- Roadmap status is maintained against the latest shipped Fourier patch and its verified regression suite.
- Script call-graph expansion is bounded and deterministic for large-binary automation.
- Decompiler lifting now distinguishes logical and arithmetic right shifts, including rotate expressions.
- Return expressions now also fold safe adjacent temporary-to-register copies.
- CLI JSON analysis reports now expose recovered switch-table locations and targets.
- Decompiler expression folding now simplifies deterministic constant division, remainder, and comparisons.
- Decompiler expression folding now simplifies constant boolean conjunctions and disjunctions.
- Decompiler expression folding now simplifies constant unary negation, bitwise-not, and logical-not.
- CLI JSON analysis reports now expose typed source/target cross-reference records.
- Raw-binary CLI analysis now supports an explicit entry address separate from the load base.
- Raw-binary JSON entry-point reporting is regression-tested end-to-end by the smoke corpus.
- Raw-binary architecture selection accepts common x64/amd64 and i386/i686 aliases.
- JSON analysis reports expose address, length, encoding, and text records for discovered strings.
- JSON analysis reports expose mapped segment ranges, permissions, file sizes, and offsets.
- JSON analysis reports expose detailed import slots and export symbol records.
- JSON analysis reports expose named internal function and data symbol records.
- JSON function records expose matched symbol names and recovered function kinds.
- JSON function records identify the mapped segment containing each function.
- JSON analysis reports expose structured imported-library records.
- JSON analysis reports expose conservative inferred scalar, pointer, and string data records.
- JSON analysis reports expose recovered pointer-table and vtable records with their targets.
- JSON analysis reports expose compact per-instruction flow, operand-reference, and memory-access records.
- JSON analysis reports expose basic-block boundaries, instruction membership, and typed successor edges.
- JSON analysis reports expose explicit call-edge and entry-point records for graph consumers.
- JSON analysis reports expose a unified name stream for function, data, and export symbols.
- JSON analysis reports expose pseudocode records generated by the shared decompiler.
- JSON pseudocode records retain each function's matched name, kind, and mapped segment.
- JSON pseudocode records include their structured decompiler line count.
- JSON string records include their incoming reference addresses.
- JSON data records include their incoming reference addresses.
- JSON function records include their incoming reference addresses.
- JSON pointer-table and vtable records include their incoming references.
- JSON vtable records now retain owning segment and file-offset source context.
- Desktop JSON database exports preserve the same vtable source context as analysis reports.
- Rhai vtable snapshots expose the same optional source-location fields.
- The Lists vtables view shows the owning segment alongside entry and xref counts.
- JSON analysis reports expose compact classified listing-line records.
- JSON analysis reports expose recovered debug struct, union, enum, and alias layouts.
- JSON analysis reports expose recovered debug prototypes from DWARF and CodeView data.
- JSON switch-table records include references to their indirect-branch instructions.
- JSON function records distinguish symbol-backed functions from inferred boundaries.
- JSON import records include incoming references to each imported API slot.
- JSON export records include incoming references to each exported symbol.
- JSON call records retain the analyzer's call-edge classification.
- JSON library records include the imported symbol names associated with each dependency.
- JSON entry records include loader-provided function-start hints.
- JSON entry records are deterministically sorted and deduplicated.
- Thumb indexed absolute jump tables (`ldr pc, [pc, index, lsl #2]`) recover bounded, validated switch targets.
- ARM64 scaled switch-table offsets and halfword entries honor the binary's declared endianness.
- Stripped functions ending in an architectural stop/trap instruction are conservatively inferred as no-return.
- ARM/Thumb long multiply and accumulate instructions preserve both halves of their wide result in pseudocode.
- MIPS HI/LO multiply results flow through `mult*` and `mfhi`/`mflo` in the generic decompiler.
- MIPS signed and unsigned division preserve quotient/remainder through the same HI/LO flow.
- RISC-V signed and unsigned high-half multiply instructions preserve their semantic result.
- PowerPC signed and unsigned high-half multiply instructions preserve their semantic result.
- ARM/Thumb multiply-accumulate and multiply-subtract instructions lift to readable arithmetic.
- MIPS conditional moves preserve register-dependent selections in pseudocode.
- MIPS branch, jump, call, and return delay slots now remain in the current basic block during control-flow analysis.
- ARM/Thumb count-leading-zero and byte-reversal idioms decompile to named operations.
- PowerPC conditional selection preserves both candidate values and the condition operand.
- x86/x64 BMI2 `mulx` and flag-independent `rorx` preserve their wide arithmetic semantics.
- ARM/Thumb saturating arithmetic preserves `usat`/`ssat` value and limit semantics.
- RISC-V signed and unsigned min/max instructions preserve conditional value semantics.
- RISC-V count-leading-zero, count-trailing-zero, and population-count instructions preserve named semantics.
- RISC-V complementing bitwise operations preserve `andn`, `orn`, and `xnor` semantics.
- PowerPC 32-bit and 64-bit count-leading-zero instructions preserve named semantics.
- x86/x64 `adcx` and `adox` preserve multi-precision carry-chain operations.
- RISC-V rotate and byte-reverse instructions preserve named bitmanip semantics.
- RISC-V bit extract/deposit instructions preserve named `bext`/`bdep` family semantics.
- x86/x64 BMI2 variable shifts preserve `shlx`, `shrx`, and `sarx` semantics.
- AArch64 count, bit-reverse, and byte-reversal idioms preserve named semantics.
- AArch64 CRC32 and CRC32C instructions preserve named checksum semantics.
- AArch64 AES and PMULL instructions preserve named cryptographic semantics.
- AArch64 signed and unsigned min/max instructions preserve conditional value semantics.
- AArch64 SHA-1 and SHA-256 instructions preserve named cryptographic semantics.
- AArch64 NEON table lookup, zip/unzip, and transpose instructions remain visible as named intrinsics.
- AArch64 NEON pairwise/reduction and saturating add/subtract instructions remain visible as named intrinsics.
- AArch64 NEON integer and floating-point comparison families remain visible as named intrinsics.
- AArch64 NEON widening, narrowing, and high-half vector operations remain visible as named intrinsics.
- AArch64 NEON variable, rounded, and narrowing shift operations remain visible as named intrinsics.
- AArch64 NEON floating/integer conversion and rounding families remain visible as named intrinsics.
- AArch64 NEON reciprocal and reciprocal-square-root estimate/refinement families remain visible as named intrinsics.
- AArch64 NEON complex add/multiply families remain visible as named intrinsics.
- AArch64 NEON `bsl`, `bit`, and `bif` bit-select/mask-combine operations now lift to explicit expressions; broader lane families remain planned.
- AArch64 SHA-512 round and schedule instructions remain visible as named intrinsics.
- AArch64 SHA-3/SM3-style Boolean and rotate-combine families remain visible as named intrinsics.
- AArch64 SM4 round and key-schedule instructions remain visible as named intrinsics.
- RISC-V, MIPS and PowerPC jump-table recognizers are now connected to live indirect-branch traversal.
- Lens JSON import now restores exported pointer-table entries as persistent native pointer definitions.
- AArch64 direct 32/64-bit pointer switch tables now recover bounded targets alongside offset tables.
- ARM32 register-relative jump tables now recover bounded targets alongside PC-relative tables.
- ARM32 register-relative switch recovery is covered by a deterministic raw-binary regression fixture.
- Go runtime panic/throw and additional Rust bounds-panic symbols are recognized as no-return functions.
- Version-specific Go runtime panic helpers now match by family, including `runtime.panicIndex` and `runtime.panicSlice*`.
- No-return regression coverage now includes Go bounds/slice panic and goroutine-exit helpers.
- DWARF structs with supported `DW_AT_data_bit_offset` bitfields now import into the native type database.
- DWARF callback types now retain return and formal-parameter types when imported into function-pointer fields.
- Named DWARF callback parameters are retained in imported function-pointer signatures when available.
- DWARF variadic callback signatures now retain their `...` parameter marker.
- PE files now import global procedure/public symbols from an adjacent CodeView PDB.
- PDB discovery now honors a valid embedded absolute path before local executable-directory fallbacks.
- PE analysis also imports procedure/public symbols from PDB module streams, not only the global symbol table.
- PDB procedure records now contribute conservative primitive/pointer prototypes to the decompiler.
- PDB prototypes are retained even when their symbol names were already known from PE exports.
- Inline CodeView primitive PDB type indices now resolve to concrete prototype types.
- Inline primitive and pointer-indirected PDB type decoding is covered by deterministic tests.
- PDB `LF_BITFIELD` records preserve their underlying scalar type when used by recovered prototypes.
- CodeView/PDB procedure flags now preserve explicit never-returning functions for PE analysis.
- PDB no-return metadata now terminates both analysis traversal and pseudocode call lifting.
- PDB no-return matching in pseudocode has exact-name regression coverage.
- CodeView/PDB enum records now import named members into the existing Types and pseudocode enum pipeline.
- CodeView/PDB struct records now import conservative scalar/pointer member layouts with compiler offsets.
- CodeView/PDB union records now import supported overlapping scalar/pointer members.
- CodeView field-list continuation records are reconstructed for large PDB structs, unions, and enums.
- CodeView procedure-type members in PDB layouts now survive as pointer-sized callback fields.
- CodeView LF_BITFIELD members now preserve bit positions and widths in imported PDB layouts.
- CodeView fixed-array members now retain supported element counts and storage sizes in PDB layouts.
- CodeView const/volatile modifiers now survive PDB prototype and layout recovery.
- Enum-typed CodeView members now retain their underlying storage widths in imported PDB layouts.
- CodeView C++ class/interface records now contribute supported explicit data members to imported layouts.
- PDB class layouts with base-class records now retain validated direct members while intentionally omitting unsupported inherited/virtual-base fields.
- Direct nested struct/union members now use recovered PDB record sizes during layout import.
- Typed enum return values now propagate into named constants in pseudocode.
- Import-slot forwarding thunks now contribute caller edges to the call graph.
- Typed enum parameters now propagate named constants into decompiler conditional expressions.
- Enum propagation now survives transparent scalar casts around typed parameters.
- Enum-typed switch expressions now render named members for recovered jump-table cases.
- Enum-aware constant propagation now folds multiplication, division, and remainder in typed comparisons.
- Thumb indexed `ldr pc` tables can now recover a table base prepared by `add reg, pc, #imm`.
- Thumb register-based switch tables accept signed PC-relative base immediates.
- ARM32 register-based switch tables accept signed PC-relative base immediates.
- ARM32 and Thumb register-based switch tables also recognize `sub reg, pc, #imm` backward-base idioms.
- RISC-V switch-table address reconstruction accepts signed `auipc` and load offsets.
- ARM64 switch-table address reconstruction accepts signed `adrp`/`adr` and immediate `add` adjustments.
- Bitfield layout validation now normalizes redundant cv-qualified qualifiers before matching signed storage types.
- Enum propagation now retains type identity through safe constant `+`/`-` arithmetic.
- x86 switch case-index recovery now handles both add and subtract normalization idioms.
- Enum propagation now retains type identity through safe constant bitwise transformations.
- Enum propagation now retains type identity through safe constant shift transformations.
- Enum propagation now retains type identity through matching enum branches in conditional expressions.
- Enum propagation now retains type identity through bitwise-not flag-mask expressions.
- No-return analysis now recognizes compiler unreachable helpers and panic-family symbols.
- Enum constant propagation now folds C-style logical `&&` and `||` expressions.
- C enum parsing now accepts logical `&&`, `||`, and unary `!` constant expressions, including parenthesized forms.
- Enum constant propagation now folds constant ternary expressions in typed comparisons.
- Enum local type recovery now survives conditional branch merges and safe constant transformations.
- Enum local type recovery now recognizes typed prototype call returns and recursive enum-return calls.
- Typed pointer reconstruction now renders variable-index scalar accesses when the element stride is explicit.
- Variable-index pointer reconstruction accepts either multiplication operand order.
- Known struct-pointer arrays now reconstruct variable-index nested field paths.
- Variable-index pointer reconstruction recognizes power-of-two shift scaling.
- Shift-scaled struct-pointer arrays now preserve variable-index nested field paths.
- SSA-style copy propagation and dereference analysis now handle owned cast expressions.
- Decompiler reference tracking, expression sizing, and variable-use counting now handle owned casts.
- Variable-index pointer and struct-array reconstruction now handles reverse-index forms.
- Enum constant propagation now handles transparent borrowed and owned casts.
- Enum constant folding and type propagation now handle transparent unary-plus wrappers.
- Enum type propagation now handles unary-minus wrappers as well as unary-plus.
- C enum parsing now accepts unary-plus constants consistently with decompiler folding.
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
- Call-graph caller neighborhoods now deduplicate functions before applying the large-graph cap.
- Added a repeatable runtime-discovered smoke corpus for headless loader/analysis validation.
- GitHub release workflow now gates packaging on locked tests and the analysis smoke corpus.
- Enum comparison rendering through transparent casts now has direct expression-level regression coverage.
- AArch64 NEON dot-product and widening multiply-accumulate families remain visible as named intrinsics.
- AArch64 NEON fixed-point saturating and rounded multiply families remain visible as named intrinsics.
- AArch64 NEON saturating rounded multiply-accumulate/subtract families remain visible as named intrinsics.
- AArch64 NEON numeric min/max and horizontal reduction families remain visible as named intrinsics.
- AArch64 NEON pairwise-long and absolute-difference accumulation families remain visible as named intrinsics.
- x86/x64 VNNI and 4-way fused multiply-add dot-product families remain visible as named intrinsics.
- x86/x64 AVX-512 ternary-logic instructions remain visible as named intrinsics.
- README decompiler coverage now reflects the latest AArch64 NEON semantic families.
- x86/x64 AVX2 packed logical, arithmetic, and variable shift families remain visible as named intrinsics.
- x86/x64 AVX2 packed absolute-value and signed/unsigned min/max families remain visible as named intrinsics.
- x86/x64 AVX2 high-half, multiply-add, and saturating multiply families remain visible as named intrinsics.
- x86/x64 AVX-512 mask-register logical, move, shift, and inversion families remain visible as named intrinsics.
- x86/x64 AVX2 packed widening, narrowing, saturation, and mask-extraction moves remain visible as named intrinsics.
- AArch64 NEON floating/integer conversion and rounding families remain visible as named intrinsics.
- x86/x64 AVX/FMA3 packed and scalar fused multiply-add/subtract instructions remain visible as named intrinsics.
- x86/x64 AVX/FMA3 negated fused multiply-add/subtract instructions remain visible as named intrinsics.
- x86/x64 AVX/SSE blend, shuffle, permute, and lane-reordering instructions remain visible as named intrinsics.
- x86/x64 packed integer AVX2 add/subtract, bitwise, and multiply families remain visible as named intrinsics.
- x86/x64 packed integer and floating-point comparison families remain visible as named intrinsics.
- x86/x64 AVX2 integer permute and gather families remain visible as named intrinsics.
- AArch64 NEON floating/integer conversion and rounding families remain visible as named intrinsics.
- AArch64 absolute and absolute-difference operations preserve signedness.
- RISC-V carry-less multiply instructions preserve named cryptographic semantics.
- MIPS immediate and register-count rotate-right instructions preserve named semantics.
- x86/x64 BMI1 low-bit isolation and mask operations preserve named semantics.
- x86/x64 BMI1 bit-field extraction preserves `bextr` control semantics.
- MIPS count-leading-zero and count-leading-one instructions preserve named semantics.
- MIPS sign-extension and byte-shuffle instructions preserve named semantics.
- MIPS `ext`/`ins` bitfield extraction and insertion preserve explicit operand semantics.
- PowerPC population-count instructions preserve named semantics.
- C-like union definitions with overlapping fields, persisted alongside existing struct definitions.
- Basic C enum definitions with implicit and explicit decimal/hex values; applying an enum to data resolves the stored integer to a named member.
- Scalar, pointer and previously defined type aliases via `typedef`; aliases are checked against known layouts, and cyclic or unknown alias targets fail clearly. Duplicate fields and zero/overflowing array layouts are rejected.
- Applied enum values are shown in data cross-reference comments as `EnumName::MemberName`.
- Debugger expression watches are evaluated by lldb and refreshed whenever the process stops.
- Breakpoint conditions can be set per address, persist with annotations and are applied by lldb both to existing breakpoints and when a debug session starts.
- Debugger can attach to a local PID, connect to a GDB remote host:port, request hardware breakpoints, inspect 128-byte memory windows, and record instruction PCs in capped 100- or 1,000-step traces.
- ELF relocatable object files load alloc sections and defined function/data symbols at synthetic addresses; common x86/x64, AArch64 absolute and call/jump, ARM/RISC-V absolute data, 68k absolute/PC-relative, MIPS absolute/PC-relative, and PowerPC absolute/PC-relative relocations are applied. GOT/PLT and paired instruction relocations remain.
- Mach-O relocatable object files map sections and defined symbols at synthetic addresses and apply common x86-64 unsigned/PC-relative and ARM64 unsigned/branch relocations. GOT, paired, and other architecture-specific relocation forms remain.
- Mach-O loader recognizes Motorola 68000 and PowerPC 32/64 CPU types, in addition to the existing x86 and ARM families.
- Raw binaries can use an x86 16-bit decoder mode in addition to x86 32/64-bit.
- Motorola 68000 instructions decode through Capstone, with basic call, branch and return flow classification.
- Data pointers from non-executable segments now produce cross-references to any mapped address and use binary endianness when read.
- Applied pointer fields in the Types window can be followed directly to their mapped targets; xref deduplication now preserves different relationship kinds from the same instruction.
- Simple integer bitfields (1–64 bits) are parsed into shared storage units and displayed/extracted with target byte order; compiler-specific bitfield ABI variants still need validation.
- The Types window supports user-defined struct/union/enum/alias declarations, application to addresses, nested field values, enum resolution, and import of supported DWARF layouts with compiler-provided offsets. Nested member names propagate into the listing; bitfields and full C declaration coverage are not supported.
- Embedded struct/union member names propagate into the listing as dotted paths; bounded fixed arrays of nested records, primitive values and pointer slots expand into indexed fields.
- Known direct tail jumps now appear as call-graph edges and are counted among the destination function's callers.
- Calls and jumps through imported function slots are classified as call/jump xrefs, so import caller views and cross-reference lists include them.
- Undo / redo for names, notes, bookmarks, structs and functions (Cmd+Z, Cmd+Shift+Z).
- Lists window: functions, names, imports, exports, entry points, bookmarks, sortable and filterable.
- Binary diff: compare two versions of a program by function name and shape.
- Export: IDA script (.idc), Ghidra script (.py), JSON database (including function metadata and discovered pointer tables), and map file.
- Chat with AI inside the app (Claude Code, Codex or any command), with conversation history.
- Function map: scroll to zoom, drag to pan, zoom buttons.
- Import names and notes from Lens JSON, IDA .idc or Ghidra .py scripts.
- Lens JSON import restores exported import-slot and recovered-vtable names alongside functions, exports, comments, types, and prototypes.
- Lists window also covers strings (with use counts) and sections.
- Switch / jump-table recovery on x86 (position-independent and absolute tables): cases become real graph edges and a `switch` in pseudocode.
- Function starts from Mach-O LC_FUNCTION_STARTS, ELF .eh_frame and PE .pdata, so stripped programs get far fewer missed functions.
- Mach-O `__unwind_info` regular and compressed second-level pages now contribute bounded, validated function-start hints for stripped binaries.
- Crash safety: a failure while analysing or decompiling is reported instead of freezing or closing the app.
- Corpus run: 200 system programs decompiled end to end with no crashes or timeouts (found and fixed a runaway-memory bug on stack offsets).
- Export the listing as text and the call graph as Graphviz.
- Function prototypes (type library): ~190 built-in libc / POSIX / sockets / threads / Win32 / macOS signatures plus your own. Calls get the exact argument count, noreturn functions end paths, call results get real types (`char *v5`), and a function with a prototype is printed with its types and parameter names.
- Known prototype return types now survive unambiguous temporary copy chains and explicit casts in pseudocode; conflicting or unknown repeated assignments stay conservative.
- Rhai scripts can read a snapshot of functions, names, strings, segments, imports/exports, types, xrefs, pointer tables, vtables, bytes and disassembly, and queue changes such as renames, comments, marks, patches, navigation, function creation, and type definitions/application. `.rhai` plugins can run manually or on file open.
- Scripts can query outgoing as well as incoming xrefs; command-line and GUI script snapshots expose the same additions.
- Thumb TBB/TBH indirect branches recover bounded case targets when a nearby compare supplies a usable bound.
- Per-file annotation storage now wraps data in a versioned project-database envelope, writes via a temporary file, and still reads legacy annotation JSON.
- Versioned `.lensproj` manifests can group multiple binaries, choose an active file, and open it through the normal analysis pipeline while retaining per-file annotation stores.
- File > Save Project creates or updates a `.lensproj` manifest from the current analysis session.
- File > Add File to Project appends another binary with duplicate detection and manifest persistence.
- Opening a project member keeps the workspace active and records that binary as the manifest’s active file.
- Relative project members resolve from the `.lensproj` directory for portable projects.
- Resolved absolute paths continue to match relative project members when switching files.
- Save Project serializes in-project members as relative paths for portability.
- Decompiler branch structuring now detects loop headers inside forward conditional regions.
- The Overview displays project members and opens them directly, including relative-path resolution.
- The active project indicator resolves relative manifest paths correctly.
- The debugger can restart the current launch/attach/remote configuration after the target exits.
- ARM64 switch tables (both the 4-byte-offset and byte/halfword-scaled forms), so the Apple Silicon side of Mach-O files gets real switch edges.
- Constant names in call arguments per OS (open flags, mmap, sockets, signals, Win32 memory/file) and short string arguments recovered.
- FindCrypt-style detection of AES, SHA, MD5, CRC, Blowfish, ChaCha, Base64 and other constants (Lists > Crypto, overview).
- Conservative vtable-like table discovery: validated runs of consecutive executable pointers in non-executable data are retained in the analysis result and reported in the analysis summary.
- Vtable-like tables are available in the Lists window with entry counts and code-xref counts, and can be opened at their data address.
- Validated mapped-pointer runs are also retained as generic pointer tables and exposed in Lists, covering global/data pointer arrays as well as vtables.
- Direct one-instruction jumps to known functions are classified as forwarding thunks and shown with their destination.
- ARM32 absolute `ldr pc, [pc, index, lsl #2]` switch tables are recovered with bounded compare-derived case counts.
- Common RISC-V `auipc` + `lw/ld` + `jr/jalr` absolute switch tables are recovered with bounded case counts.
- Common MIPS `lui`/address-build + `lw` + `jr` absolute switch tables are recovered with bounded case counts.
- Common PowerPC `lis`/`addi` + `lwz` + `mtctr`/`bctr` absolute switch tables are recovered with bounded case counts.
- Discovered pointer tables can be promoted into persistent native-pointer definitions in one action.
- JSON export now preserves no-return/thunk function metadata and discovered vtable/pointer-table entries.
- JSON export now includes explicit source/target/kind cross-reference records.
- JSON export preserves persisted data definitions and applied types.
- JSON import restores exported annotations, data definitions, applied-type references and function starts.
- JSON import also restores names embedded in exported function records.
- JSON import restores exported symbol names as well.
- JSON export/import preserves user-defined struct, union, enum and alias definitions.
- JSON export/import preserves user-authored function prototypes and reinstalls them for decompilation.
- JSON export/import preserves user-authored names without persisting generated analysis labels.
- Exported analysis JSON is distinguished from legacy annotation JSON before import, preserving the richer database fields.
- Exported JSON carries schema version 2 for explicit database-format evolution.
- Contiguous matching data elements can be promoted to persistent inferred arrays in one action.
- Lists includes an Arrays tab for persisted inferred data runs.
- Rhai snapshots expose discovered pointer tables and vtables through `pointer_tables()` and `vtables()`.
- Rhai scripts can promote discovered pointer tables and inferred arrays with `define_pointer_table` and `define_array`.
- Prototype parsing preserves named function-pointer parameters and emits valid callback signatures.
- Known prototype return types now propagate through simple temporary-to-temporary assignments in pseudocode declarations.
- No-return recognition covers additional C++, Rust and Swift panic/trap entry points.
- Common C function-pointer field declarations such as `int (*callback)(int)` now parse as pointer-sized typed fields.
- Data definitions now include an IDA-style `O` action for explicitly marking a native-width pointer, with persistence and re-analysis.
- Added a deterministic pseudocode golden regression fixture for a simple x86-64 function; corpus-scale golden coverage remains planned.
- Added a deterministic JSON interchange regression covering function, export, import-slot, vtable, and explicit name records.
- JSON name restoration now uses one shared importer path for all exported name collections.
- Scalar SSE/XMM temporaries now get float/double declarations, and packed single/double move/arithmetic families get vector declarations and binary expressions in pseudocode.
- Common VEX `vadd*`, `vsub*`, `vmul*`, `vdiv*` and vector-move forms now share the SIMD lifting path with XMM/YMM/ZMM declarations.
- ARM64 generic lifting now tracks `v0`-`v31` NEON operands as 128-bit registers, preserving unsupported vector instructions as visible intrinsic assignments instead of dropping them.
- Recovered indirect switch targets now produce explicit `switch case` xrefs in the listing, xref views and JSON export, distinct from direct jump edges.
- Common ARM64 scalar/NEON `fadd`, `fsub`, `fmul`, `fdiv`, `fmla`, `fmls`, `fneg`, `fabs` and `fsqrt` instructions now lift to visible arithmetic expressions or calls.
- Itanium C++ vtable discovery now recognizes the two-word offset-to-top/typeinfo header before validating the executable method-pointer run.
- ARM and Thumb switch recovery now also recognizes bounded PC-indexed inline jump tables formed by `add pc, pc, rN, lsl #2`.
- One-instruction jumps through imported function slots are now classified as forwarding thunks alongside direct known-target jumps.
- ARM64 `fmov`, `fcmp`/`fcmpe` and `fcsel` now preserve floating-point values and comparison conditions in generic pseudocode.
- ARM64 `ubfm`/`sbfm`/`bfm` and common `ubfx`/`sbfx`/`bfi`/`bfxil` aliases now render ordinary bitfield extraction and insertion as readable mask/shift expressions.
- ARM64 `extr` and immediate `ror` idioms now render as composed shifts and ors for common 32/64-bit forms.
- ARM64 integer `csel`, `cset`, `csetm`, `csinc`, `csinv` and `csneg` now preserve conditional value semantics in pseudocode.
- x86/x64 immediate `rol` and `ror` instructions now render as composed shifts and ors instead of opaque intrinsics.
- x86/x64 register-count `rol` and `ror` instructions now preserve variable rotate semantics in pseudocode.
- x86/x64 `shld` and `shrd` now render common immediate and register-count double-precision shifts as composed expressions.
- x86/x64 `popcnt`, `tzcnt`, `lzcnt`, `bsf` and `bsr` now render as named bit-count/index operations.
- x86/x64 BMI2 `pext`, `pdep` and `bzhi` now render as named bit-manipulation calls with preserved operands.
- x86/x64 `bswap` now renders as a named byte-swap operation.
- ARM64 NEON registers in pseudocode declarations now use the 128-bit `uint8x16_t` type instead of falling back to the architecture-wide integer type.
- Known pointer-typed prototypes now preserve casts for constant call arguments in pseudocode without forcing casts onto uncertain inferred variables.
- C-like type parsing now preserves nested function-pointer depth, including pointer-to-callback fields and typedef aliases.
- Itanium vtables now retain an associated typeinfo symbol when the binary exposes one, and Lists/JSON surface that RTTI-derived name.
- Mach-O Objective-C method/property-name sections now receive selector-aware `sel_` names during string analysis.
- Mach-O Objective-C class-name sections now receive stable `objc_class_` names during string analysis.
- Mach-O Swift reflection and type-reference string sections now receive `swift_` names during string analysis.
- Common Swift `$s` symbols now retain readable module and declaration components through basic demangling.
- ELF GNU IFUNC symbols now seed function discovery and navigation alongside ordinary function symbols.
- PE TLS callbacks now seed function discovery before the entry point, with a loader note recording the callback count.
- Zero-width C bitfields now force a fresh ABI storage unit using the declared integer alignment.
- Signed C bitfields now sign-extend when their applied values are displayed in the Types view.
- x86 `cdq`, `cqo` and `cwd` now preserve sign-extension into the high half of integer division in pseudocode.
- PE delay-import descriptors now populate delayed API names and IAT slots alongside ordinary imports.
- Mach-O `LC_DATA_IN_CODE` ranges now exclude marked embedded data from executable discovery and record the range count in analysis notes.
- C enum parsing now accepts common binary/octal literals and constant bitwise, shift, addition and subtraction expressions.
- User-defined enum definitions now propagate into typed pseudocode call arguments as scoped constants when the integer value matches.
- Simple Itanium RTTI names such as `_ZTI3Foo` and `_ZTIN3Foo3BarE` are rendered as `Foo` and `Foo::Bar` for discovered vtables.
- Rhai `vtables()` results now include the optional recovered RTTI name under `type`.
- Rhai scripts can query typed incoming xrefs with `xrefs_to_details(addr)` without losing the relationship kind.
- Rhai scripts can query typed outgoing xrefs with `xrefs_from_details(addr)` for symmetric call, jump, switch-case, data, and pointer analysis.
- Rhai scripts can query normalized function-level callers and callees with `callers(addr)` and `callees(addr)`.
- Script call queries normalize interior addresses and filter to call/jump relationships rather than data-only xrefs.
- Rhai scripts can retrieve bounded structured call-graph edges with normalized function addresses and relationship kinds.
- Script call-graph neighborhoods now expand symmetrically through callers and callees with explicit direction labels.
- Script outgoing-call queries now aggregate instruction-level xrefs across each containing function.
- Recovered switch-case xrefs now feed the call graph as outgoing control-flow edges, keeping graph navigation aligned with the listing.
- Rhai scripts can retrieve typed C-like pseudocode with `decompile(addr)` for automated audits and reports.
- The Rhai API exposes a compatibility version through `script_api_version()`, allowing plugins to guard newer capabilities.
- Rhai scripts can read saved analyst notes with `comment_at(addr)` and bookmark addresses with `bookmarks()`.
- Rhai scripts can inspect persisted byte/word/dword/qword, pointer, string and undefinition choices through `data_at(addr)` and `data_definitions()`.
- Rhai scripts can search names, strings, comments, and generated pseudocode through a single case-insensitive `search(query)` API.
- Rhai scripts can resolve arbitrary addresses to containing functions through `function_at(addr)`.
- Common packed C declarations using `__attribute__((packed))` now use byte alignment when computing applied field offsets.
- Common `#pragma pack(1)` declarations now use byte alignment when computing applied field offsets.
- Anonymous C typedef forms such as `typedef struct { ... } Name;` and `typedef enum { ... } Name;` now preserve the alias name and layout.
- Thunk classification now tolerates straight-line `nop`/`endbr32`/`endbr64` prefixes before a known direct or imported-slot jump.
- Release notes now have a shared source: the current codename and What's New list are shown in-app, attached to GitHub releases, and archived on the GitHub Pages version-history page.
- Release builds now allow up to 30 minutes for the Apple Silicon cross-target build, avoiding premature cancellation on cold runners.
- SIMD declaration width is inferred from the actual XMM/YMM/ZMM operand, avoiding blanket `__m256` labels for 128-bit VEX instructions.
- Rename variables in pseudocode (double-click), remembered per function and undoable.
- First unit tests (regression suite is still to be built out).
- Data definition keys like IDA: D cycles byte / word / dword / qword, A makes a C string, U undefines; saved per file and re-analysed.
- IDA-style stack slots in the listing for frame-pointer functions: `[rbp+var_8]`, `[rbp+arg_0]`; pseudocode variable renames show up in the listing too.

## Next implementation queue
1. **Reliability and scale:** expand the corpus beyond the current smoke targets, validate 100 MB+ binaries, and move expensive analysis/listing work toward incremental or background execution.
2. **Analysis quality:** validate tail-call/thunk classification across optimized compilers; add more ARM/Thumb switch idioms; improve data-vs-code discrimination and malformed-table handling.
3. **Decompiler depth:** broaden SSA-style propagation, loop/switch structuring, floating-point/SIMD semantics, calling-convention inference, and complex pointer/array reconstruction.
4. **Type system:** validate bitfield layouts across compiler ABIs, expand compiler-specific packed layouts, and grow the versioned prototype/signature libraries.
5. **Debugger:** deepen LLDB synchronization and reconnect behavior, add broader platform coverage, and investigate hardware trace integration.
6. **Formats and CPUs:** add firmware/raw-dump workflows and additional processors (AVR, 6502, Z80, SuperH, SPARC, s390x, TriCore, eBPF) with real semantic lifting.
7. **Projects and interchange:** promote per-file annotations into user-managed multi-file project databases; document Rhai/plugin compatibility; improve IDC/Ghidra database import beyond the current JSON interchange.

## Current boundaries
- Lens is an analysis and disassembly workbench, not yet a replacement for IDA's mature debugger, decompiler, type system, processor modules or database ecosystem.
- ARM64/ARM/RISC-V/MIPS/PowerPC decoding is available, but CPU-specific analysis and pseudocode semantics still vary in depth.
- C type parsing remains deliberately small; declarations that are not understood should produce a clear error rather than silently inventing a layout.
- Existing repository edits may be in progress. Update status only after confirming the corresponding behavior in source.

## Releasing
Bump `version` in Cargo.toml, commit, push, then `git tag vX.Y.Z && git push --tags`. CI builds Apple Silicon
and publishes the release; installed apps update themselves from Settings or Tools > Check for updates.
