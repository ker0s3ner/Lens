# Lens 0.6.327 — Fourier

- AArch64 `eon` now decompiles as explicit XOR-with-inverted-operand logic.
- ARM complementing bitwise lowering now covers AND, OR, and XOR inverted-operand forms consistently.

# Lens 0.6.326 — Fourier

- ARM32, Thumb, and ARM64 `bic` now decompile as explicit AND-with-inverted-operand expressions.
- ARM/ARM64 `orn` now decompiles as explicit OR-with-inverted-operand logic instead of an opaque intrinsic.

# Lens 0.6.325 — Fourier

- MIPS `nor` now decompiles as an explicit inverted OR expression.
- MIPS boolean-mask idioms now share readable bitwise lowering with the PowerPC path instead of opaque intrinsics.

# Lens 0.6.324 — Fourier

- PowerPC `andc` now decompiles as an AND with an inverted operand.
- PowerPC `orc` now decompiles as an OR with an inverted operand, completing the common complementing boolean forms.

# Lens 0.6.323 — Fourier

- PowerPC `nor` and `nand` now decompile as explicit inverted OR/AND expressions.
- PowerPC `eqv` now decompiles as an inverted XOR expression, keeping boolean-mask idioms readable.

# Lens 0.6.322 — Fourier

- PowerPC `addic`/`addic.` now preserve immediate-add value semantics in pseudocode.
- PowerPC `subfic` now renders the correct immediate-minus-register operand order; XER carry state remains intentionally conservative.

# Lens 0.6.321 — Fourier

- PowerPC `rlwnm` now preserves register-count rotate-left-and-mask semantics in pseudocode.
- The PowerPC rotate/mask family now covers immediate, register-count, and mask-insert forms with shared bit-range handling.

# Lens 0.6.320 — Fourier

- PowerPC `rlwimi` now preserves rotate-left-and-mask-insert semantics in pseudocode.
- Shared PowerPC MB/ME mask generation is now unit-tested for both contiguous and wrapping bit ranges.

# Lens 0.6.319 — Fourier

- PowerPC `rlwinm` now decompiles as an explicit rotate-left-and-mask expression instead of an opaque intrinsic.
- PowerPC mask-bit numbering is converted correctly for both non-wrapping and wrapping MB/ME ranges.

# Lens 0.6.318 — Fourier

- MIPS control-flow analysis now keeps the architectural delay-slot instruction in the current basic block before following branch, jump, call, and return edges.
- Golden analysis now verifies a big-endian MIPS conditional branch with its delay slot and return instruction.

# Lens 0.6.317 — Fourier

- Thumb function-boundary scanning now recognizes common `push {…, lr}` prologues when discovering unreachable functions.
- Added regression coverage for narrow and wide Thumb register-save prologues, preventing missed function starts in stripped code.

# Lens 0.6.316 — Fourier

- Call-graph edge rendering now handles coincident control points without producing invalid geometry.
- Call-graph layer ordering now uses a total floating-point comparison, preventing malformed layout values from panicking the UI.

# Lens 0.6.315 — Fourier

- Raw Thumb entry points now normalize the low mode bit before analysis, so odd function pointers decode at the correct byte address.
- The deterministic Thumb golden fixture now verifies odd-entry normalization and the resulting function discovery.

# Lens 0.6.314 — Fourier

- Raw-binary CLI loading now accepts explicit `thumb`, `thumb2`, and `armthumb` architecture selectors.
- Deterministic golden analysis now exercises a Thumb return instruction alongside the existing x64, ARM, RISC-V, PowerPC, and MIPS fixtures.

# Lens 0.6.313 — Fourier

- The deterministic golden gate now includes a big-endian MIPS32 return fixture.
- Six representative CPU-family paths now have pinned raw decoding metadata and function counts.

# Lens 0.6.312 — Fourier

- The deterministic golden gate now includes a big-endian PowerPC 64 return fixture.
- Five representative CPU-family paths now have pinned raw decoding metadata and function counts.

# Lens 0.6.311 — Fourier

- The deterministic golden gate now includes an ARM32 return fixture alongside x64, ARM64, and RISC-V 64.
- Four representative CPU-family paths now have pinned raw decoding metadata and function counts.

# Lens 0.6.310 — Fourier

- The x64 golden fixture now verifies decompiler text as well as loader, instruction, and basic-block metadata.
- Golden regression coverage now detects pseudocode changes to a deterministic return-value function.

# Lens 0.6.309 — Fourier

- The deterministic golden gate now covers x64, ARM64, and RISC-V 64 raw instruction fixtures.
- Cross-architecture metadata and one-function decoding counts are now checked on three representative CPU families.

# Lens 0.6.308 — Fourier

- The deterministic golden gate now covers both a real x64 function and a one-instruction ARM64 return fixture.
- Cross-architecture golden checks now pin ARM64 decoding metadata and function/instruction counts.

# Lens 0.6.307 — Fourier

- The golden raw x64 fixture now contains a real five-instruction function rather than an empty one-byte input.
- Golden assertions now pin function, instruction, and basic-block counts in addition to JSON schema and metadata.

# Lens 0.6.306 — Fourier

- Added a deterministic golden-analysis gate for raw x64 JSON output, covering schema, entry metadata, and graph record shape.
- The smoke workflow now runs both the host-discovered corpus and the committed golden fixture for repeatable regression coverage.

# Lens 0.6.305 — Fourier

- ARM32 and Thumb SXTAB/SXTAH now render signed byte and halfword extension before accumulation.
- ARM extend-and-accumulate lifting now covers both signed and unsigned variants.

# Lens 0.6.304 — Fourier

- ARM32 and Thumb UXTAB/UXTAH now render as explicit zero-extend-and-add expressions.
- ARM byte and halfword accumulation idioms now remain readable in the shared non-x86 decompiler.

# Lens 0.6.303 — Fourier

- ARM32/Thumb BFC now uses its distinct three-operand form, correctly clearing the requested field in place.
- ARM bitfield insertion and clearing paths now separate source-bearing BFI operands from BFC operands.

# Lens 0.6.302 — Fourier

- ARM32 and Thumb BFI/BFC now render as explicit bitfield insertion and clearing expressions.
- ARM-family bitfield support now covers extraction plus the corresponding update-in-place operations.

# Lens 0.6.301 — Fourier

- ARM32 and Thumb UBFX/SBFX now render as explicit field-extraction expressions, matching the AArch64 path.
- ARM-family bitfield recovery now preserves unsigned and signed extraction intent instead of opaque mnemonics.

# Lens 0.6.300 — Fourier

- RISC-V SH1ADD.UW, SH2ADD.UW, and SH3ADD.UW now preserve low-word zero-extension in scaled-index expressions.
- The roadmap now tracks the current 0.6.300 Fourier build and its expanded RISC-V address-generation coverage.

# Lens 0.6.299 — Fourier

- RISC-V ADD.UW and SUB.UW now preserve their low-word zero-extension semantics in pseudocode.
- RISC-V word-width add/subtract idioms now remain distinguishable from ordinary 64-bit arithmetic.

# Lens 0.6.298 — Fourier

- RISC-V SLLI.UW now renders its 32-bit zero-extension before shifting, preserving the instruction's exact data flow.
- RISC-V word-width arithmetic is now clearer in pseudocode for this common address and integer idiom.

# Lens 0.6.297 — Fourier

- RISC-V SH1ADD, SH2ADD, and SH3ADD now render as explicit scaled-index address expressions.
- RISC-V address-generation idioms now preserve their add-and-shift data flow in pseudocode.

# Lens 0.6.296 — Fourier

- RISC-V ORC.B and REV8 now render as named byte-oriented operations instead of opaque instruction fallbacks.
- Roadmap and release documentation now track the shipped 0.6.296 Fourier build consistently.

# Lens 0.6.295 — Fourier

- RISC-V BEXTI immediate bit extraction now renders through the same visible shift-and-mask expression as BEXT.
- RISC-V indexed and immediate bit extraction paths now produce consistent pseudocode for bit-level data flow.

# Lens 0.6.294 — Fourier

- RISC-V BSETI, BCLRI, and BINVI immediate aliases now share the exact visible bit-mask lowering.
- RISC-V BEXT now renders as a shift-and-mask expression, making extracted bit flow visible in pseudocode.

# Lens 0.6.293 — Fourier

- RISC-V BSET, BCLR, and BINV bit-manipulation instructions now render as exact shift/mask expressions.
- RISC-V bit operations now preserve the modified source value visibly instead of falling back to opaque intrinsics.

# Lens 0.6.292 — Fourier

- PowerPC ROTRW/ROTRD and immediate rotate-right forms now render as explicit rotate expressions.
- PowerPC rotate lifting now covers both directions across the common 32-bit and 64-bit forms.

# Lens 0.6.291 — Fourier

- PowerPC ROTLW/ROTLD and immediate rotate-left forms now render as explicit rotate expressions.
- Bit-manipulation-heavy PowerPC code no longer falls back to opaque rotate mnemonics for these common instructions.

# Lens 0.6.290 — Fourier

- PowerPC unsigned 64-bit DIVDU instructions now lift to readable division expressions alongside DIVD.
- PowerPC division coverage now includes the common 32-bit and 64-bit signed/unsigned forms used by compiled code.

# Lens 0.6.289 — Fourier

- PowerPC integer remainder instructions (MODSW/MODUW/MODSD/MODUD) now render as readable remainder expressions.
- The non-x86 lifter now covers both PowerPC division and remainder families instead of leaving remainder operations opaque.

# Lens 0.6.288 — Fourier

- AArch64 pseudocode now models long multiply-accumulate/subtract instructions (SMADDL/UMADDL/SMSUBL/UMSUBL) instead of dropping them to opaque intrinsics.
- AArch64 MNEG now renders as an explicit negated product, improving arithmetic readability in non-x86 decompilation.

# Lens 0.6.287 — Fourier

- Roadmap status now tracks the shipped 0.6.286 Fourier indirect-type build.
- README now documents typed field access through explicit function-pointer returns.

Verification: `cargo test --locked --quiet` — 96 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.286 — Fourier

- Roadmap status now tracks the shipped 0.6.285 Fourier type-recovery build.
- README documentation now calls out typed fields through explicit indirect-call returns.

Verification: `cargo test --locked --quiet` — 96 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.285 — Fourier

- Typed struct-field rendering now follows cast function-pointer returns.
- Indirect pointer-returning calls now keep field names through dereference formatting.

Verification: `cargo test --locked --quiet` — 96 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.284 — Fourier

- Decompiler type inference now recognizes return types from cast function-pointer calls.
- Pointer-returning indirect calls now preserve pointee types through dereference rendering.

Verification: `cargo test --locked --quiet` — 95 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.283 — Fourier

- Decompiler now turns constant conditional terminators into direct jumps.
- Impossible constant branches are removed while non-constant control flow remains unchanged.

Verification: `cargo test --locked --quiet` — 94 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.282 — Fourier

- Roadmap and README now identify the shipped 0.6.281 Fourier graph-report build.
- Public CLI documentation now calls out stable normalized caller/callee arrays explicitly.

Verification: `cargo test --locked --quiet` — 93 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.281 — Fourier

- The smoke corpus now verifies callers and callees in every JSON function record.
- JSON graph regressions now fail the release gate when normalized edge fields disappear.

Verification: `cargo test --locked --quiet` — 93 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.280 — Fourier

- Roadmap and README status now track the current Fourier build and JSON graph fields.
- Release documentation now records the 50% target status and current 38.3% weighted estimate consistently.

Verification: `cargo test --locked --quiet` — 93 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.279 — Fourier

- Script `call_graph` now caps expansion at 256 functions to protect large-binary automation.
- Structured script graph edges are now sorted deterministically for repeatable reports.

Verification: `cargo test --locked --quiet` — 93 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.278 — Fourier

- Decompiler now folds constant ternary conditions after flag propagation.
- Non-constant ternary expressions remain structured, preserving branch semantics.

Verification: `cargo test --locked --quiet` — 93 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.277 — Fourier

- JSON callee records are now normalized, sorted, and deduplicated for stable graph diffs.
- Function graph exports now avoid duplicate outgoing edges while retaining raw call-site records.

Verification: `cargo test --locked --quiet` — 92 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.276 — Fourier

- JSON function records now include normalized callers and callees alongside call sites.
- Machine-readable graph consumers can now reconstruct function neighborhoods without rescanning xrefs.

Verification: `cargo test --locked --quiet` — 92 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.275 — Fourier

- Decompiler now inlines safe single-use call temporaries into their consuming assignment.
- Call results remain separate when a temporary is used later, preserving evaluation and value flow.

Verification: `cargo test --locked --quiet` — 92 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.274 — Fourier

- Script callee queries now aggregate call sites across the whole containing function.
- Two-sided script call graphs now discover outgoing edges from instruction-level xrefs correctly.

Verification: `cargo test --locked --quiet` — 91 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.273 — Fourier

- Script `call_graph` neighborhoods now include both callers and callees.
- Structured call-graph edges now label whether they came from caller or callee expansion.

Verification: `cargo test --locked --quiet` — 91 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.272 — Fourier

- Rhai scripts can now retrieve bounded structured call-graph edges with `call_graph(addr, depth)`.
- Call-graph script results include normalized from/to function addresses and relationship kinds.

Verification: `cargo test --locked --quiet` — 91 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.271 — Fourier

- Script caller/callee queries now accept any address inside a function.
- Script caller/callee results now exclude data and switch-only xrefs, keeping call relationships precise.

Verification: `cargo test --locked --quiet` — 91 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.270 — Fourier

- Rhai scripts can now query normalized function callers and callees directly.
- Caller/callee script results collapse instruction-level xrefs to containing functions when available.

Verification: `cargo test --locked --quiet` — 91 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.269 — Fourier

- Decompiler now distinguishes logical `SHR` from arithmetic `SAR` shifts.
- Rotate and unsigned-byte extraction expressions now preserve logical right-shift semantics.

Verification: `cargo test --locked --quiet` — 91 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.268 — Fourier

- Constant signed right shifts now preserve arithmetic sign extension in pseudocode.
- Decompiler remainder folding now recognizes `x % 1` as zero.

Verification: `cargo test --locked --quiet` — 91 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.267 — Fourier

- Decompiler boolean identities now simplify constant truthiness around `&&` and `||`.
- Decompiler bitmask identities now simplify `x & -1` and `x | -1` without changing semantics.

Verification: `cargo test --locked --quiet` — 90 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.266 — Fourier

- Call graph expansion now caps high-fanout neighborhoods to keep rendering responsive.
- Large call graphs now show an explicit truncation notice instead of silently overwhelming the UI.

Verification: `cargo test --locked --quiet` — 89 tests passed; `./scripts/smoke-corpus.sh` — 7 targets passed.

# Lens 0.6.197 — Fourier
# Lens 0.6.198 — Fourier
# Lens 0.6.199 — Fourier
# Lens 0.6.200 — Fourier
# Lens 0.6.201 — Fourier
# Lens 0.6.202 — Fourier
# Lens 0.6.203 — Fourier
# Lens 0.6.204 — Fourier
# Lens 0.6.205 — Fourier
# Lens 0.6.206 — Fourier
# Lens 0.6.207 — Fourier
# Lens 0.6.208 — Fourier
# Lens 0.6.209 — Fourier
# Lens 0.6.210 — Fourier
# Lens 0.6.211 — Fourier
# Lens 0.6.212 — Fourier
# Lens 0.6.213 — Fourier
# Lens 0.6.214 — Fourier
# Lens 0.6.215 — Fourier
# Lens 0.6.216 — Fourier
# Lens 0.6.217 — Fourier
# Lens 0.6.218 — Fourier
# Lens 0.6.219 — Fourier
# Lens 0.6.220 — Fourier
# Lens 0.6.221 — Fourier
# Lens 0.6.222 — Fourier
# Lens 0.6.223 — Fourier
# Lens 0.6.224 — Fourier
# Lens 0.6.225 — Fourier
# Lens 0.6.226 — Fourier
# Lens 0.6.227 — Fourier
# Lens 0.6.228 — Fourier
# Lens 0.6.229 — Fourier
# Lens 0.6.265 — Fourier

## What's new

- Call graph caller expansion now memoizes xref scans within each build.
- Multi-level call graph construction now avoids duplicate caller traversal work.

## Verification

- `cargo test --locked --quiet` — 89 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.264 — Fourier

## What's new

- Decompiler copy propagation now crosses safe intervening statements.
- Copy propagation now stops when the source or temporary is reassigned, with regression coverage.

## Verification

- `cargo test --locked --quiet` — 89 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.263 — Fourier

## What's new

- Objective-C `objc_msgSend` selector arguments now render as `@selector(...)` in pseudocode.
- Objective-C `objc_getClass` arguments now render as `@class(...)` in pseudocode.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.262 — Fourier

## What's new

- Data double-click now selects the applied type for that address in Types.
- Data double-click now pre-fills the Types apply address.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.261 — Fourier

## What's new

- Double-clicking a Data row now opens the synchronized Types pane.
- Selected Data rows now expose a one-click address copy action.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.260 — Fourier

## What's new

- Data rows now show applied struct/type annotations.
- Data rows now include analyst comments in their detail text.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.259 — Fourier

## What's new

- Lists now includes a synchronized Data tab for scalar, pointer, string, and array-backed definitions.
- The Data tab also surfaces inferred scalar data that has not been manually overridden.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.258 — Fourier

## What's new

- Call graph caches now invalidate when analysis data changes.
- Call graph construction now memoizes callee scans within each build.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.257 — Fourier

## What's new

- Imported patches now trigger reanalysis of the patched in-memory binary.
- The import log now reports how many patch records were restored.
- Call graph layout is now cached between frames to prevent repeated rescans and UI stalls.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.256 — Fourier

## What's new

- Analysis JSON now round-trips patches, breakpoints, conditions, and variable renames.
- Imported patch records are now applied immediately to the in-memory binary.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.255 — Fourier

## What's new

- Full Lens annotation JSON import now restores data, patches, types, breakpoints, prototypes, and variable renames.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.254 — Fourier

## What's new

- Decompiler call arguments now retain known pointer types for inferred variables.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.253 — Fourier

## What's new

- Known pointer prototypes now propagate through inferred call arguments in pseudocode.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.252 — Fourier

## What's new

- Function-scoped search results now clear when navigation moves to another function.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.251 — Fourier

## What's new

- Function-scoped searches now scan the full function before applying the result cap.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.250 — Fourier

## What's new

- Search can now be scoped to the current function or the full program.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.249 — Fourier

## What's new

- Search results can now be copied as an address-and-text report.

## Verification

- `cargo test --locked --quiet` — 88 tests passed.
- `./scripts/smoke-corpus.sh` — 7 host targets passed.

---

# Lens 0.6.248 — Fourier

## What's new

- JSON database import now restores legacy import and export record collections.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.247 — Fourier

## What's new

- JSON database import now restores discovered string records as persistent string definitions.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.246 — Fourier

## What's new

- JSON database import now restores analysis function records and mapped entry hints.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.245 — Fourier

## What's new

- JSON database import now restores RTTI-derived names from vtable records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.244 — Fourier

## What's new

- JSON database import now restores vtable entries as persistent native pointers.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.243 — Fourier

## What's new

- JSON database import now restores pointer-table records from both analysis and annotation schemas.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.242 — Fourier

## What's new

- JSON database import now restores conservative scalar, pointer, and string data records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.241 — Fourier

## What's new

- JSON database import now restores recovered debug type and prototype records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.240 — Fourier

## What's new

- JSON analysis name and symbol records can now be restored by database import.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.239 — Fourier

## What's new

- Portable project paths now keep the active-file highlight correct after moving a project.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.238 — Fourier

## What's new

- Multi-file projects now expose their binaries as switchable inspector entries.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.237 — Fourier

## What's new

- Debugger instruction traces can now be exported with step indexes and addresses.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.236 — Fourier

## What's new

- Decompiler struct-array access now preserves the first element index.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.235 — Fourier

## What's new

- Structure fields now show clickable incoming-xref counts in the Types view.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.234 — Fourier

## What's new

- Flow-graph rows now show clickable incoming-xref markers.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.233 — Fourier

## What's new

- Pseudocode lines now show clickable incoming-xref markers.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.232 — Fourier

## What's new

- JSON array records now round-trip through database import as persistent data definitions.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.231 — Fourier

## What's new

- JSON analysis reports now expose top-level non-pointer array records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.230 — Fourier

## What's new

- Tail-call no-return propagation now has a dedicated regression fixture.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.229 — Fourier

## What's new

- JSON analysis reports now include exact direct and indirect call-site records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.228 — Fourier

## What's new

- No-return propagation now follows conservative multi-instruction tail-call edges.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.227 — Fourier

## What's new

- Static analysis now records conservative multi-instruction tail calls in the call graph.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.226 — Fourier

## What's new

- JSON entry records are now deterministically sorted and deduplicated.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.225 — Fourier

## What's new

- JSON entry records now include loader-provided function-start hints.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.224 — Fourier

## What's new

- JSON library records now include the imported symbol names associated with each dependency.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.223 — Fourier

## What's new

- JSON call records now retain the analyzer's call-edge classification.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.222 — Fourier

## What's new

- JSON export records now include incoming references to each exported symbol.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.221 — Fourier

## What's new

- JSON import records now include incoming references to each imported API slot.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.220 — Fourier

## What's new

- JSON function records now distinguish symbol-backed functions from inferred boundaries.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.219 — Fourier

## What's new

- JSON switch-table records now include references to their indirect-branch instructions.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.218 — Fourier

## What's new

- JSON analysis reports now include recovered debug prototypes from DWARF and CodeView data.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.217 — Fourier

## What's new

- JSON analysis reports now include recovered debug struct, union, enum, and alias layouts.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.216 — Fourier

## What's new

- JSON analysis reports now include compact classified listing-line records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.215 — Fourier

## What's new

- JSON pointer-table and vtable records now include their incoming references.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.214 — Fourier

## What's new

- JSON function records now include their incoming reference addresses.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.213 — Fourier

## What's new

- JSON data records now include their incoming reference addresses.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.212 — Fourier

## What's new

- JSON string records now include their incoming reference addresses.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.211 — Fourier

## What's new

- JSON pseudocode records now include their structured decompiler line count.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.210 — Fourier

## What's new

- JSON pseudocode records now retain each function's matched name, kind, and mapped segment.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.209 — Fourier

## What's new

- JSON analysis reports now include pseudocode records generated by the shared decompiler.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.208 — Fourier

## What's new

- JSON analysis reports now include a unified name stream for function, data, and export symbols.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.207 — Fourier

## What's new

- JSON analysis reports now include explicit call-edge and entry-point records for graph consumers.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.206 — Fourier

## What's new

- JSON analysis reports now include basic-block boundaries, instruction membership, and typed successor edges.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.205 — Fourier

## What's new

- JSON analysis reports now include compact per-instruction flow, operand-reference, and memory-access records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.204 — Fourier

## What's new

- JSON analysis reports now include recovered pointer-table and vtable records with their targets.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.203 — Fourier

## What's new

- JSON analysis reports now include conservative inferred scalar, pointer, and string data records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.202 — Fourier

## What's new

- JSON analysis reports now include structured imported-library records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.201 — Fourier

## What's new

- JSON function records now identify the mapped segment containing each function.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.200 — Fourier

## What's new

- JSON function records now include matched symbol names and recovered function kinds.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.199 — Fourier

## What's new

- JSON analysis reports now include named internal function and data symbol records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.198 — Fourier

## What's new

- JSON analysis reports now include detailed import slots and export symbol records.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.197 — Fourier

## What's new

- JSON analysis reports now include mapped segment ranges, permissions, file sizes, and offsets.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.196 — Fourier

## What's new

- JSON analysis reports now include address, length, encoding, and text records for every discovered string.

## Verification

- `cargo test --locked --quiet`
- `./scripts/smoke-corpus.sh`

---

# Lens 0.6.195 — Fourier

## What's new

- Raw-binary architecture selection now accepts common x64, amd64, i386, and i686 aliases.

## Verification

- `cargo test --locked --quiet` — 81 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries plus raw-entry regression passed

---
# Lens 0.6.194 — Fourier

## What's new

- Raw-binary JSON reports now preserve explicit entry addresses, with smoke coverage for `--entry`.
- The smoke corpus now exercises raw loading separately from host executable discovery.

## Verification

- `cargo test --locked --quiet` — 81 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries plus raw-entry regression passed

---

# Lens 0.6.193 — Fourier

## What's new

- Raw-binary CLI analysis now accepts an explicit `--entry` address for firmware workflows.

## Verification

- `cargo test --locked --quiet` — 81 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.192 — Fourier

## What's new

- CLI JSON reports now include typed source/target cross-reference records.

## Verification

- `cargo test --locked --quiet` — 81 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.191 — Fourier

## What's new

- Decompiler constant folding now simplifies unary negation, bitwise-not, and logical-not.

## Verification

- `cargo test --locked --quiet` — 81 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.190 — Fourier

## What's new

- Decompiler constant folding now simplifies boolean conjunctions and disjunctions.

## Verification

- `cargo test --locked --quiet` — 81 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.189 — Fourier

## What's new

- Decompiler constant folding now simplifies deterministic division, remainder, and comparisons.

## Verification

- `cargo test --locked --quiet` — 81 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.188 — Fourier

## What's new

- CLI JSON reports now include recovered switch-table locations and targets.

## Verification

- `cargo test --locked --quiet` — 80 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.187 — Fourier

## What's new

- Decompiler copy propagation now folds temporary register copies into return expressions.

## Verification

- `cargo test --locked --quiet` — 81 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.186 — Fourier

## What's new

- Decompiler output now folds safe adjacent temporary-to-register copies.

## Verification

- `cargo test --locked --quiet` — 80 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.185 — Fourier

## What's new

- CLI JSON reports now include per-function boundaries, calls, no-return status, and thunk targets.

## Verification

- `cargo test --locked --quiet` — 79 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.184 — Fourier

## What's new

- CLI JSON reports now expose no-return, forwarding-thunk, and switch-table counts.

## Verification

- `cargo test --locked --quiet` — 79 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.183 — Fourier

## What's new

- Functions calling imported no-return slots now retain their termination metadata.

## Verification

- `cargo test --locked --quiet` — 79 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

# Lens 0.6.182 — Fourier

## What's new

- Prototype parsing now accepts GNU and compiler-qualified no-return attribute spellings.

## Verification

- `cargo test --locked --quiet` — 78 passed
- `./scripts/smoke-corpus.sh` — 7 host binaries/libraries passed in both report modes

---

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
