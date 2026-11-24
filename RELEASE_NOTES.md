# Lens 0.6.181 — Fourier

## What's new

- No-return status now propagates through known wrapper and thunk call chains.
- Function graphs and decompiler control flow now retain termination metadata across bounded call chains.

## Verification

- `cargo test --locked --quiet` — 78 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.180 — Fourier

## What's new

- Prototype parsing now recognizes GCC/Clang and C++ no-return attributes.

## Verification

- `cargo test --locked --quiet` — 77 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.179 — Fourier

## What's new

- Applied type parsing now preserves chained function-pointer typedef aliases.

## Verification

- `cargo test --locked --quiet` — 76 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.178 — Fourier

## What's new

- Function-pointer typedef aliases now resolve through bounded alias chains.

## Verification

- `cargo test --locked --quiet` — 76 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.177 — Fourier

## What's new

- Function-pointer typedefs now resolve into callable parameter and return prototypes.
- User-defined callback aliases retain their full C-style signature in decompiler call metadata.

## Verification

- `cargo test --locked --quiet` — 76 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.176 — Fourier

## What's new

- Relocatable ELF analysis now applies common MIPS 32/64-bit and PC-relative relocations.
- Relocatable ELF analysis now applies common PowerPC 32/64-bit absolute and PC-relative relocations.

## Verification

- `cargo test --locked --quiet` — 75 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.175 — Fourier

## What's new

- Explicit C-style and normalized function-pointer casts now supply parameter and return prototypes to indirect calls.
- Indirect-call prototype parsing preserves conservative behavior for unsupported signatures.

## Verification

- `cargo test --locked --quiet` — 75 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.174 — Fourier

## What's new

- Known struct layouts now propagate through typed pointer-returning calls when rendering field accesses.
- Prototype return types participate in conservative nested field and array resolution.

## Verification

- `cargo test --locked --quiet` — 75 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.173 — Fourier

## What's new

- Known scalar pointer arithmetic now renders indexed accesses such as `p[2]` in pseudocode.
- Pointer indices are emitted only for known scalar element sizes and aligned offsets.

## Verification

- `cargo test --locked --quiet` — 74 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.172 — Fourier

## What's new

- Arrays of known nested records now render chained accesses such as `p->items[1].value`.
- Nested array indexing remains bounded by the recovered element size and record layout.

## Verification

- `cargo test --locked --quiet` — 73 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.171 — Fourier

## What's new

- Typed field resolution now walks nested records and fixed arrays recursively when layouts are known.
- Conservative fallback behavior remains unchanged for ambiguous or unsupported nested layouts.

## Verification

- `cargo test --locked --quiet` — 72 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.170 — Fourier

## What's new

- Known nested struct members now render chained field access such as `p->inner.value` in pseudocode.
- Nested field rendering remains conservative and requires an unambiguous known layout.

## Verification

- `cargo test --locked --quiet` — 71 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.169 — Fourier

## What's new

- Known fixed-array members in typed structs now render indexed accesses such as `p->items[1]` in pseudocode.
- Array indices are emitted only when the member bounds and element size are unambiguous.

## Verification

- `cargo test --locked --quiet` — 71 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.168 — Fourier

## What's new

- Typed struct-pointer arithmetic now renders known fields such as `p->second` in pseudocode.
- Unknown types and offsets retain the existing conservative dereference rendering.

## Verification

- `cargo test --locked --quiet` — 70 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.167 — Fourier

## What's new

- Packed pointer tables can now be discovered and promoted even when their first entry is unaligned.
- Unaligned table detection requires a complete native-stride run, keeping isolated packed pointers out of Lists.

## Verification

- `cargo test --locked --quiet` — 69 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.166 — Fourier

## What's new

- Data-reference recovery now detects validated native pointers at unaligned offsets in packed data.
- Added regression coverage for unaligned pointer xrefs without broadening pointer-table classification.

## Verification

- `cargo test --locked --quiet` — 68 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.165 — Fourier

## What's new

- Added deterministic ARM32 relative-offset switch regression coverage to protect cross-architecture control-flow recovery.

## Verification

- `cargo test --locked --quiet` — 67 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.164 — Fourier

## What's new

- Thumb PC-indexed switch recovery now accepts validated signed relative-offset tables in addition to absolute pointer tables.
- Relative Thumb cases are checked against both table-relative and function-relative bases before becoming control-flow edges.

## Verification

- `cargo test --locked --quiet` — 66 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.162 — Fourier

## What's new

- ARM32 switch recovery now accepts validated signed relative-offset tables in addition to absolute pointer tables.
- Relative ARM32 cases are checked against both table-relative and function-relative bases before becoming control-flow edges.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.161 — Fourier

## What's new

- PowerPC switch recovery now accepts validated signed relative-offset tables in addition to absolute pointer tables.
- Relative PowerPC cases are checked against both table-relative and function-relative bases before becoming control-flow edges.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.160 — Fourier

## What's new

- MIPS switch recovery now accepts validated signed relative-offset tables in addition to absolute pointer tables.
- Relative MIPS cases are checked against both table-relative and function-relative bases before becoming control-flow edges.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.159 — Fourier

## What's new

- RISC-V switch recovery now accepts validated signed 32-bit relative-offset tables in addition to absolute pointer tables.
- Relative cases are checked against both table-relative and function-relative bases before becoming control-flow edges.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.158 — Fourier

## What's new

- JSON and human-readable reports now expose the selected image slice and embedded file base offset.
- Fileset and universal-binary automation can distinguish the analyzed child image from its outer container.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.157 — Fourier

## What's new

- The analysis smoke corpus now discovers representative shared libraries and dylibs in addition to executable programs.
- Runtime corpus validation now covers both program and library loading paths without committing platform-specific binaries.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.156 — Fourier

## What's new

- Selected Mach-O fileset images now retain their embedded file base offset for patching and exported metadata.
- Fileset diagnostics preserve both the entry name and original file location.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.155 — Fourier

## What's new

- Mach-O fileset loading now honors `--slice <entry-name>` for embedded images.
- When a requested fileset entry is unavailable, Lens records the miss and opens the first parseable fallback image.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.154 — Fourier

## What's new

- Mach-O filesets now open the first parseable embedded image through the normal Mach-O loader.
- Fileset analysis records the embedded file offset and fails closed when no child image is parseable.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.153 — Fourier

## What's new

- ELF analysis notes now report how many dynamic init/fini array roots were accepted.
- Root-count diagnostics make stripped-binary constructor discovery and malformed-table handling visible in reports.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.152 — Fourier

## What's new

- ELF `DT_PREINIT_ARRAY` entries now seed bounded, executable-range-validated preinitialization function roots.
- The loader now covers preinit, init, and fini dynamic function arrays when section metadata is unavailable.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.151 — Fourier

## What's new

- ELF dynamic `DT_INIT_ARRAY` and `DT_FINI_ARRAY` tables now seed bounded, executable-range-validated function roots.
- Constructor and destructor discovery now works when section names are stripped but dynamic metadata remains.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.150 — Fourier

## What's new

- ELF dynamic `DT_INIT` and `DT_FINI` entry points now seed validated function discovery.
- The loader accepts these roots only when they fall inside executable mappings, preserving conservative analysis on malformed files.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.149 — Fourier

## What's new

- Pointer arithmetic propagation now remains available in the decompiler's earlier fixed-point type pass.
- Later assignments can retain pointer types after constant offsets instead of losing them before rendering.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.148 — Fourier

## What's new

- The decompiler's earlier type-analysis pass now preserves pointee types through dereferences, casts, and pointer temporaries before rendering.
- Pointer type information remains available to later assignments and call-result propagation instead of only affecting final display formatting.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.147 — Fourier

## What's new

- Decompiler pointee inference now survives explicit pointer casts before dereference.
- Added regression coverage for owned pointer casts such as `uint32_t *` memory reads.

## Verification

- `cargo test --locked --quiet` — 65 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.146 — Fourier

## What's new

- Decompiler type propagation now recovers pointee types when dereferencing typed pointer temporaries.
- Added regression coverage for both direct pointer-return dereferences and dereferences after temporary assignment.

## Verification

- `cargo test --locked --quiet` — 64 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.145 — Fourier

## What's new

- Decompiler type propagation now carries known pointer types through constant byte-offset expressions.
- Added regression coverage for `pointer + constant` assignments derived from known pointer-returning calls.

## Verification

- `cargo test --locked --quiet` — 63 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.144 — Fourier

## What's new

- Added a direct decompiler regression test for pointee-type inference through dereferenced `strdup` calls.
- The Fourier patch line now verifies this pointer-return propagation at the render-type boundary.

## Verification

- `cargo test --locked --quiet` — 62 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.143 — Fourier

## What's new

- Decompiler type propagation now preserves pointee types when assigning from dereferenced known pointer-returning calls.
- Known prototypes such as `strdup` retain useful scalar pointee information through direct dereference expressions.

## Verification

- `cargo test --locked --quiet` — 61 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.142 — Fourier

## What's new

- Desktop JSON database exports now include the shared `lens.analysis.v1` schema identifier.
- The legacy numeric JSON schema field remains intact for backward compatibility.

## Verification

- `cargo test --locked --quiet` — 61 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.141 — Fourier

## What's new

- Indirect calls through imported slots now contribute explicit call-graph edges.
- Added regression coverage for imported call instructions, alongside existing forwarding-thunk edges.

## Verification

- `cargo test --locked --quiet` — 61 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.140 — Fourier

## What's new

- JSON analysis reports now declare the stable `lens.analysis.v1` schema.
- The release smoke corpus validates both human-readable and JSON analysis output for every discovered binary.

## Verification

- `cargo test --locked --quiet` — 60 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed in both report modes

---

# Lens 0.6.139 — Fourier

## What's new

- Added `--json` CLI reports with stable machine-readable format, architecture, entry point, analysis counts, and notes.
- JSON reports expose function, instruction, basic-block, string, import, export, call-edge, and xref totals for automation.

## Verification

- `cargo test --locked --quiet` — 60 passed
- `./scripts/smoke-corpus.sh` — 6 host binaries passed

---

# Lens 0.6.138 — Fourier

## What's new

- Added direct regression coverage for enum comparison rendering through transparent casts.
- The decompiler suite now verifies named enum constants at the expression-emission boundary.

- GitHub release builds now run the locked unit-test suite and analysis smoke corpus before packaging.
- Release automation fails before publication if representative host binaries cannot be loaded and analyzed.

- Added `scripts/smoke-corpus.sh` for repeatable headless loader and analysis checks on host binaries.
- The smoke corpus discovers available executables at runtime and fails on missing analysis reports.

- Enum-typed switch expressions now render recovered case labels as named Enum::Member values.
- Unknown and non-enum jump-table cases retain their numeric labels.

- Enum constant propagation now recognizes transparent casts around typed parameters.
- Compiler-generated enum comparisons remain readable after explicit scalar conversions.

- Typed enum parameters now render named Enum::Member constants in decompiler comparisons.
- Enum propagation now covers call arguments, return values, and conditional control flow.

- Import-slot tail jumps now contribute explicit call-graph edges to their imported targets.
- Forwarding-thunk regression coverage now verifies both thunk classification and caller relationships.

- Typed enum return values now render as named Enum::Member constants in pseudocode.
- A decompiler golden test covers enum-return propagation from prototype through return lifting.

- PDB layouts now retain direct nested struct and union members using recovered record sizes.
- Nested data members are no longer discarded solely because their enclosing record is another CodeView type.

- PDB class layouts containing unsupported base-class records are now skipped instead of partially imported.
- Direct-member-only C++ class and interface layouts remain available through the Types database.

- PDB C++ class and interface records now import supported explicit data members through the Types database.
- Unsupported C++ inheritance, methods, and virtual-layout records remain conservative skips.

- PDB struct and union layouts now retain named enum members with their CodeView underlying widths.
- Enum-typed fields are no longer dropped during conservative PDB layout recovery.

- PDB CodeView modifier records now preserve const and volatile qualifiers in recovered types.
- Qualified scalar fields continue to receive correct storage sizing during layout import.

- PDB fixed-array members now import supported element counts and storage sizes from CodeView dimensions.
- Unknown array element layouts remain skipped instead of being assigned guessed sizes.

- PDB LF_BITFIELD members now retain CodeView bit positions and widths in imported layouts.
- Supported PDB bitfields no longer collapse into ordinary scalar fields during type recovery.

- PDB struct and union recovery now retains supported CodeView callback members as pointer-sized fields.
- Procedure-type members are routed through Lens callback declarations instead of being discarded.

- Split CodeView field lists are now reconstructed across continuation records.
- Large PDB structs, unions, and enums no longer lose members at field-list boundaries.

- PE/PDB union records now import supported overlapping members through the Types database.
- Union layouts reuse CodeView member offsets and declared sizes without guessing unsupported fields.

- PE/PDB struct records now import supported scalar and pointer members with their CodeView offsets.
- Incomplete or unsupported PDB layouts are skipped instead of producing partial types.

- PE/PDB enum records now import named CodeView members into the Types database.
- Recovered PDB enum values are available to pseudocode constant propagation.

- PDB no-return name matching in pseudocode is now exact and regression-tested.
- Decompiler tests cover the boundary between CodeView metadata and terminating callees.

- PDB-marked never-returning procedures now also terminate pseudocode call lifting.
- Decompiler control flow now agrees with PE analysis for CodeView no-return metadata.

- CodeView never-returning procedure flags now terminate PE control-flow analysis conservatively.
- PDB no-return metadata is preserved alongside imported symbols and prototypes.

- CodeView LF_BITFIELD records now retain their underlying scalar type in recovered PDB prototypes.
- Bitfield width and layout remain conservative until full PDB field-layout import is implemented.

- PDB primitive and pointer-indirected type decoding now has direct regression coverage.
- The deterministic suite now covers 57 cases across analysis, interchange, DWARF, and PDB paths.

- PDB prototype recovery now decodes inline CodeView primitive type indices for concrete parameter and return types.
- Primitive PDB signatures no longer fall back to `void` merely because their types are encoded below the TPI stream.

- PDB prototypes are now retained even when their symbol names were already known from PE exports.
- Debug type recovery is no longer coupled to whether PDB names add new function entries.

- PE/PDB procedure records now contribute conservative primitive/pointer prototypes to decompilation.
- Unsupported PDB type records remain skipped instead of generating guessed signatures.

- PDB ingestion now has a malformed-input regression guard before type-stream expansion.
- The deterministic test suite now covers 56 cases, including PE debug-symbol safety.

- PE analysis now imports procedure/public symbols from PDB module streams in addition to global symbols.
- Static and compiler-generated module procedures are available to function discovery when PDB data is present.

- PDB discovery now honors a valid embedded CodeView path before local executable-directory fallbacks.
- Malformed individual PDB symbol records no longer discard the rest of the symbol import.

- PE analysis now imports global procedure/public symbols from an adjacent CodeView PDB when available.
- PDB-backed function names are mapped through the executable image base before analysis begins.

- DWARF variadic callback signatures now retain their `...` parameter marker.
- Imported callback types preserve fixed parameters and variadic ABI shape together.

- Named DWARF callback parameters are retained in imported function-pointer signatures when available.
- Type recovery now preserves both callback shapes and analyst-useful parameter names.

- DWARF callback types now retain return and formal-parameter types in imported function-pointer fields.
- Typed callbacks no longer collapse to opaque `void *` declarations in the Types tool.

- Supported DWARF bitfields now import with their native storage offsets and widths.
- The Types tool can preserve compiler-emitted bitfield layouts instead of skipping those structs.

- Go runtime panic symbol matching now covers versioned panic and throw families without exact-name tables.
- No-return regression coverage includes bounds, slice, and goroutine-exit helpers.

- Go runtime.panic* and runtime.goexit symbol families are recognized as no-return functions.
- Version-specific compiler panic helpers now terminate analysis consistently.

- Go runtime panic/throw and additional Rust bounds-panic symbols are recognized as no-return functions.
- Call graphs and decompilation now terminate more accurately across Go and Rust binaries.

- ARM32 register-relative switch recovery now has a raw-binary regression fixture.
- The analyzer test suite now covers 55 deterministic cases across architecture and interchange paths.

- ARM32 table-base switch idioms now recover bounded targets from `add pc, #imm` plus indexed loads.
- Compiler-generated indirect branches through register-relative tables become real graph edges.

- AArch64 direct 32/64-bit pointer switch tables now recover bounded targets alongside offset tables.
- Common compiler-generated br-through-table cases become real graph edges and pseudocode cases.

- Lens JSON import now restores exported pointer-table entries as persistent native pointer definitions.
- Interchange preserves analyst-promoted pointer data across files and sessions.

- RISC-V, MIPS and PowerPC jump-table recognizers now participate in live indirect-branch analysis.
- Switch cases on these architectures can now become real graph edges and pseudocode cases.

- AArch64 SM4 round and key-schedule instructions now remain visible as named pseudocode intrinsics.
- Modern block-cipher operand groups are preserved alongside existing AES and SHA coverage.

- AArch64 SHA-3/SM3-style Boolean and rotate-combine instructions now remain visible as named pseudocode intrinsics.
- Modern cryptographic mix operations preserve their operand groups.

- AArch64 SHA-512 round and schedule instructions now remain visible as named pseudocode intrinsics.
- SHA-512 cryptographic operand groups are preserved alongside existing SHA-1/SHA-256 coverage.

- AVX-512 ternary-logic instructions now remain visible as named pseudocode intrinsics.
- Three-input Boolean operand groups are preserved for crypto and bit-manipulation code.

- x86/x64 VNNI and 4-way fused multiply-add dot-product families now remain visible as named pseudocode intrinsics.
- ML-oriented packed dot-product operand groups are preserved in decompiler output.

- AArch64 NEON pairwise-long and absolute-difference accumulation families now remain visible as named pseudocode intrinsics.
- Image/audio reduction kernels preserve their widening accumulation operands.

- AArch64 NEON numeric min/max and horizontal reduction families now remain visible as named pseudocode intrinsics.
- Vector aggregation operations preserve their operands instead of falling through to opaque generic handling.

- AArch64 NEON saturating rounded multiply-accumulate/subtract families now remain visible as named pseudocode intrinsics.
- Modern fixed-point codec and DSP operations preserve their operand groups.

- AArch64 NEON fixed-point saturating, rounded, and high-half multiply families now remain visible as named pseudocode intrinsics.
- Codec and DSP-oriented widening multiply-accumulate operations preserve their operand groups.

- README decompiler capability documentation now includes the latest AArch64 NEON reciprocal, complex, dot-product, and mask semantics.
- User-facing architecture coverage is synchronized with the shipped implementation.

- AArch64 NEON dot-product and widening multiply-accumulate families now remain visible as named pseudocode intrinsics.
- Common ML, image, and DSP vector accumulation operations no longer fall through to opaque generic handling.

- AArch64 NEON bit-select and mask-combine families now remain visible as named pseudocode intrinsics.
- Branchless vector mask operations no longer fall through to opaque generic handling.

- AArch64 NEON complex add and multiply families now remain visible as named pseudocode intrinsics.
- DSP-oriented complex vector operations no longer fall through to opaque generic handling.

- AArch64 NEON reciprocal and reciprocal-square-root estimate/refinement instructions now remain visible as named pseudocode intrinsics.
- Common vector math approximation steps no longer fall through to opaque generic handling.

- JSON name restoration now uses one shared importer path for functions, exports, import slots, vtables, and explicit names.
- Interchange parsing is covered by a deterministic regression test and avoids duplicated collection-specific logic.

- AVX-512 mask-register logical, move, shift, and inversion families now remain visible as named pseudocode intrinsics.
- Mask operand groups are preserved instead of disappearing into generic handling.

- Added a deterministic JSON interchange regression covering function, export, import-slot, vtable, and explicit name records.
- The repeatable test suite now has 54 passing tests.

- Common AVX2 high-half, multiply-add, and saturating multiply families now remain visible as named pseudocode intrinsics.
- Fixed-point and crypto-oriented packed multiply operand groups are preserved in decompiler output.

- Common AVX2 packed absolute-value and signed/unsigned min/max families now remain visible as named pseudocode intrinsics.
- Vector bounds and absolute-value operations preserve their operand groups in decompiler output.

- Common AVX2 packed logical, arithmetic, and variable shift families now remain visible as named pseudocode intrinsics.
- Vector lane shifts preserve their operand groups instead of falling through to opaque generic handling.

- AArch64 NEON floating/integer conversion and rounding families now remain visible as named pseudocode intrinsics.
- Common lane-width conversion and rounding operations no longer fall through to opaque generic handling.

- AVX2 packed widening, narrowing, saturation, and mask-extraction move families now remain visible as named pseudocode intrinsics.
- Sign/zero-extension lane conversions preserve their operand groups in decompiler output.

- AArch64 NEON floating/integer conversion and rounding families now remain visible as named pseudocode intrinsics.
- Common lane-width conversion and rounding operations no longer fall through to opaque generic handling.

- AVX2 integer permute and gather families now remain visible as named pseudocode intrinsics.
- Vector lane-index and memory-gather operand groups are preserved in decompiler output.

- Common x86/x64 packed integer and floating-point comparison families now remain visible as named pseudocode intrinsics.
- AVX comparison masks preserve their operand groups instead of falling through to opaque generic handling.

- Common x86/x64 packed integer add/subtract, bitwise, and multiply families now remain visible as named pseudocode intrinsics.
- AVX2 integer vector operations preserve their operand groups instead of falling through to opaque generic handling.

- Common AVX/SSE blend, shuffle, permute, and lane-reordering instructions now remain visible as named pseudocode intrinsics.
- Vector layout operations no longer fall through to opaque generic handling.

- Lens JSON import now restores exported import-slot and recovered-vtable names.
- Richer database round-trips preserve more of the analysis names shown by Lists and JSON export.

- AVX/FMA3 negated fused multiply-add/subtract families now remain visible as named pseudocode intrinsics.
- `vfnmadd*` and `vfnmsub*` operand groups are preserved in decompiler output.

- Common AVX/FMA3 packed and scalar fused multiply-add/subtract instructions now remain visible as named pseudocode intrinsics.
- FMA operand groups are preserved instead of falling through to opaque generic handling.

- Documentation now reports the current 32% weighted breadth estimate and the implemented heuristic metadata coverage accurately.
- README and roadmap limitations are synchronized with the current vtable/RTTI, Objective-C, and Swift analysis behavior.

- AArch64 NEON variable, rounded, and narrowing shift operations now remain visible as named pseudocode intrinsics.
- Common vector shift and rescale operations no longer disappear in generic lifting.

- AArch64 NEON widening, narrowing, and high-half vector operations now remain visible as named pseudocode intrinsics.
- Common lane-width conversion and rounded narrowing operations no longer disappear in generic lifting.

- AArch64 NEON integer and floating-point comparison families now remain visible as named pseudocode intrinsics.
- Vector comparison operations no longer disappear in generic lifting.

- AArch64 NEON pairwise/reduction instructions now remain visible as named pseudocode intrinsics.
- Saturating and halving vector add/subtract operations no longer disappear in generic lifting.

- AArch64 NEON table, zip, unzip, and transpose instructions now remain visible as named pseudocode intrinsics.
- Vector lane rearrangement operations no longer disappear when the generic lifter encounters them.

- AArch64 SHA-1 and SHA-256 round/schedule instructions now preserve named cryptographic semantics and operands.
- Common AArch64 hashing instructions remain visible in pseudocode.

- x86/x64 BMI1 `bextr` now preserves named bit-field extraction semantics and control operands.
- Common x86/x64 bit-field operations remain readable in pseudocode.

- x86/x64 BMI1 `blsi`, `blsr`, and `blsmsk` now preserve named low-bit isolation and mask semantics.
- Common x86/x64 bit-manipulation idioms remain readable in pseudocode.

- MIPS `rotr` and `rotrv` now preserve rotate-right semantics and operands.
- MIPS rotate idioms remain readable in pseudocode.

- RISC-V `clmul`, `clmulh`, and `clmulr` now preserve carry-less multiplication semantics.
- RISC-V cryptographic bitmanip operations remain named and readable in pseudocode.

- AArch64 `abs`, `sabd`, and `uabd` now preserve absolute and signed/unsigned absolute-difference semantics.
- AArch64 DSP-style difference operations remain readable in pseudocode.

- AArch64 signed and unsigned min/max operations now decompile as readable conditional selections.
- AArch64 bounds and comparison idioms preserve signedness in pseudocode.

- AArch64 AES round, inverse/mix, and PMULL operations now preserve named crypto semantics and operands.
- Common AArch64 cryptographic instructions remain visible in pseudocode.

- PowerPC `popcntw` and `popcntd` now decompile as named population-count operations.
- PowerPC bit-count semantics remain readable across 32-bit and 64-bit forms.

- MIPS `ext` and `ins` now preserve explicit bitfield extraction and insertion operands.
- MIPS bitfield operations remain readable in pseudocode instead of opaque intrinsics.

- MIPS `seb`, `seh`, and `wsbh` now preserve sign-extension and byte-shuffle semantics.
- Common MIPS endian and narrow-integer idioms remain readable in pseudocode.

- MIPS `clz` and `clo` now decompile as named count-leading-zero and count-leading-one operations.
- MIPS bit-count idioms remain readable in pseudocode.

- AArch64 CRC32 and CRC32C instructions now preserve named checksum semantics and operands.
- Common AArch64 checksum idioms remain readable in pseudocode.

- AArch64 `clz`, `cls`, `rbit`, and byte-reversal instructions now decompile as named operations.
- AArch64 bit and endian idioms remain readable instead of opaque generic calls.

- x86/x64 BMI2 `shlx`, `shrx`, and `sarx` now preserve variable-shift semantics in pseudocode.
- Signed and unsigned variable right shifts remain distinguishable in decompilation.

- RISC-V `bext`, `bdep`, `bcompress`, and `bdecompress` now preserve named bit extract/deposit semantics.
- RISC-V bitmanip data flow remains visible in pseudocode.

- RISC-V `rol`, `ror`, word rotate forms, and `rev8` now decompile as named rotate and byte-reverse operations.
- RISC-V bitmanip rotate semantics remain visible in pseudocode.

- x86/x64 `adcx` and `adox` now preserve named carry-chain arithmetic for multi-precision code.
- Carry-domain arithmetic remains visible instead of falling through to an opaque intrinsic.

- PowerPC `cntlzw` and `cntlzd` now decompile as named count-leading-zero operations.
- PowerPC bit-count semantics remain readable across 32-bit and 64-bit forms.

- RISC-V `andn`, `orn`, and `xnor` now decompile as explicit complement-and-combine expressions.
- RISC-V bit-manipulation extension semantics remain visible in pseudocode.

- RISC-V `clz`, `ctz`, and `cpop` now decompile as named bit-count operations, including word forms.
- RISC-V bit-manipulation idioms remain readable instead of falling through to opaque instructions.

- RISC-V `min`, `max`, `minu`, and `maxu` now decompile as signed or unsigned conditional selections.
- Common RISC-V bounds and comparison idioms remain readable in pseudocode.

- ARM/Thumb `usat` and `ssat` now preserve saturating arithmetic semantics with explicit value and limit operands.
- ARM/Thumb DSP-style saturation instructions no longer become opaque intrinsic calls.

- x86/x64 BMI2 `mulx` now preserves both low and high products from implicit RDX input.
- x86/x64 `rorx` now decompiles as a flag-independent rotate operation.

- PowerPC `isel` now preserves conditional selection operands in pseudocode.
- PowerPC conditional data flow remains visible through an explicit semantic helper.

- ARM/Thumb `clz`, `rev`, `rev16`, and `revsh` now decompile as named count-leading-zero and byte-reversal operations.
- Common ARM bit/byte idioms remain visible and readable instead of opaque intrinsic calls.

- MIPS `movz` and `movn` now decompile as conditional selections instead of opaque operations.
- MIPS register-dependent value flow is preserved in readable ternary expressions.

- ARM/Thumb `mla` and `mls` now lift to readable multiply-accumulate and multiply-subtract expressions.
- Common ARM arithmetic idioms no longer fall through to opaque intrinsic calls.

- PowerPC `mulhw`, `mulhwu`, `mulhd`, and `mulhdu` now preserve signed and unsigned high-half products in pseudocode.
- PowerPC wide multiplication is represented with explicit semantic helpers instead of an opaque instruction.

- RISC-V `mulh`, `mulhu`, and `mulhsu` now preserve signed and unsigned high-half product semantics in pseudocode.
- High-half multiplication is represented with named semantic helpers instead of an opaque unsupported instruction.

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
