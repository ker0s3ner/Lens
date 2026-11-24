# Lens 0.6.76 — Fourier

## What's new

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
