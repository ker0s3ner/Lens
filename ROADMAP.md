# Roadmap: getting Lens as close to IDA Pro as possible

Authoritative current GitHub build: **Lens 0.6.515 — Fourier**. This GitHub-only release improves decompiler loop recovery, conditional pointer types, ABI-aware debugger call arguments, and readable dynamic malware-triage evidence. Its Apple Silicon artifact was built and published after GitHub unit, smoke-corpus, golden-analysis, and tag/version checks passed. SHA-256: `d3646add3ccc88354461c0e7e025a244a126d51c10f625d837b1f21683d5cb97`. The last full weighted audit remains 41.8% (0.6.514); 0.6.515 is not yet re-audited, so the 50% target remains unverified and unmet.

Release update: **Lens 0.6.514 — Fourier** resolves x86/x64 thunks that materialize known targets in registers, use RIP-relative `lea`, load import slots, or use `push`/`ret`; these targets now appear in function calls and xrefs. Cross-capability evidence is linked to participating API imports and matching runtime call events. Twenty-one Linux/OpenBSD APIs now have built-in prototypes spanning directory-relative file access, process controls, secure random data, seccomp/prctl, pidfds, Landlock, pledge/unveil, and zero-copy transfers. Sandbox policy receives its own static capability and low-severity evidence signal plus a debugger event filter. Pseudocode symbolizes common Linux `openat`, rename, access, descriptor, random, seccomp, and prctl constants while leaving `openat2`'s options structure opaque. The weighted score is carried forward at 41.8% until the next full category re-audit.

Release update: **Lens 0.6.513 — Fourier** bounds direct and jump-table target collection before graph construction and warns when target, instruction, caller, or node limits may hide graph relationships; edge truncation is reported only after a distinct edge exceeds the cap. The built-in library now covers aligned allocation, memory mapping/locking, shared-memory, memfd, descriptor execution, and file-allocation APIs. Static analysis correlates shared/anonymous-memory imports with runtime code-loading capability as a heuristic, while dynamic behavior events classify these APIs. The new large-file gate passed on GitHub: a 12,288-byte ELF with 128 MiB of virtual-only zero-fill analyzed in 0.008 seconds at 13.82 MiB peak RSS. This is one synthetic measurement, not a real-binary benchmark. Weighted parity remains **41.8%** pending a full category re-audit.

Release update: **Lens 0.6.515 — Fourier** improves decompiler loops with dominance-checked natural-loop recovery, bounded CFG analysis, and conservative fallback for irregular regions. Debugger behavior-call events now decode prototype stack arguments for x86 cdecl/stdcall, System V x64, Windows x64, and AArch64; opt-in string previews cover stack-passed pointers, and known OS-specific flags/modes appear beside raw runtime values in the UI and JSON export. Conditional null branches preserve known pointer types in argument formatting and inferred declarations. GitHub unit tests, the smoke corpus, golden analysis, tag/version validation, Apple Silicon packaging, and release upload all passed. The earlier large-file gate passed on `fdccbc6`; later changes do not affect large-file analysis. The 0.6.514 weighted score remains 41.8% until 0.6.515 receives a full category re-audit.

Release update: **Lens 0.6.512 — Fourier** inlines single-block switch cases that return or exit to one shared continuation, groups labels that share a body, and skips duplicate case-block emission. Multi-block, conditional, indirect, externally entered, or otherwise complex case flow keeps the label/goto representation. Weighted parity remains **41.8%** pending a full category re-audit.


Release update: **Lens 0.6.511 — Fourier** repeats safe single-predecessor and convergent copy/constant passes until no further definitions move, updating block definitions and terminators before liveness. Backward merge edges and side-effecting or oversized expressions remain excluded. Weighted parity remains **41.8%** pending a full category re-audit.

Release update: **Lens 0.6.510 — Fourier** clips `LC_DATA_IN_CODE` records to their source segments, rejects overflowing addresses, normalizes overlapping/adjacent intervals, and uses binary search for repeated code/data membership checks. Weighted parity remains **41.8%** pending a full category re-audit.

Release update: **Lens 0.6.509 — Fourier** shares segment storage across debugger, database, script, and report snapshots; patch writes use copy-on-write, preserving older snapshots, and oversized zero-fill writes are rejected before allocation. No RSS reduction is claimed until the large-file gate measures snapshot workloads. Weighted parity remains **41.8%** pending a full category re-audit.

Release update: **Lens 0.6.508 — Fourier** adds DWARF 2–4 bitfield layout recovery, validates bitfield and ordinary member extents against record bounds, preserves valid unnamed zero-width separators, and skips unsigned enum values that cannot fit the signed internal representation. Weighted parity remains **41.8%** pending a full category re-audit.

Release update: **Lens 0.6.507 — Fourier** recovers declarations from repeated same-type assignments across blocks, including pointer, struct-pointer, and function-pointer values. A constant-zero arm can merge as a null pointer only when the other assignments agree on one pointer type; unknown nonzero and conflicting assignments remain unresolved. Weighted parity remains **41.8%** pending a full category re-audit.

Release update: **Lens 0.6.506 — Fourier** completes virtual zero-fill handling across owned reads, pointer and type inspection, Rhai accessors, in-memory patches, and ELF relocations. Large field previews are bounded, writes materialize only on edit, and the 64 MiB materialization limit is retained. Weighted parity remains **41.8%** pending a full category re-audit.

Release update: **Lens 0.6.505 — Fourier** represents ELF BSS and virtual section tails in ELF, PE, and Mach-O without allocating padded buffers, supports lazy reads across virtual zero-fill beyond the former 64 MiB cap, and displays those bytes as `00` in Hex. File-backed bytes remain the source for byte searches. Weighted parity remains **41.8%** pending a full category re-audit.

Release update: **Lens 0.6.504 — Fourier** normalizes nested and reordered pointer arithmetic before recovering indexed struct-array fields, nested array members, signed/bias-adjusted indices, and type-guided pointer call arguments. Ambiguous layouts and out-of-range offsets remain conservative. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.503 — Fourier** classifies statically flagged API call-site events into process, filesystem, registry, memory, network, and anti-debugging families; adds category filtering and export totals; and previews prototype-marked Windows UTF-16 strings alongside bounded narrow-string previews. Categories are name-based triage, not proof that an operation completed. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.502 — Fourier** adds an opt-in string preview for prototype-marked character pointers at behavior API call sites, capped at four reads of 96 bytes each; raw register values remain attached, unreadable pointers are preserved without previews, and wide strings are left uninterpreted. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.501 — Fourier** captures stop-time x64 System V/Windows and AArch64 argument registers for statically flagged API call sites, labels values with known prototype types/names, and carries them into event UI and exports. Pointer values remain raw and the event is still explicitly before the API executes. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.500 — Fourier** recounts generated temporary uses until cleanup reaches a fixed point, removing dead literal, alias, arithmetic, unary, cast, and conditional chains. Calls remain as expression statements; memory reads, division/remainder, and opaque fallback expressions are retained conservatively. The weighted parity estimate remains **41.8%**; the decompiler category estimate is unchanged pending corpus re-audit.

Release update: **Lens 0.6.499 — Fourier** handles `#pragma pack(n)`, default resets, unnamed and named push/pop stacks, nested frames, alignment changes after push/pop, and Microsoft-supported alignment caps from 1 to 16. The active cap is captured at the record declaration; malformed values and unmatched pops are reported, and packing directives inside a record body are rejected rather than silently producing a guessed layout. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.498 — Fourier** finds up to 64 statically flagged direct and import-slot call sites, ranks them by heuristic severity, and adds temporary software breakpoints for local launches. Runtime stops at watched call sites are clearly marked as occurring before the API executes, linked to caller and API names, severity-highlighted, filterable, navigable, and exportable. Hardware-breakpoint mode is detected and does not arm incompatible watchpoints. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.497 — Fourier** classifies debugger stop and exit events with severity, connects them to code addresses and recovered functions, correlates matching heuristic behavior signals, adds event-focused navigation/filtering/copy actions, and exports structured events with severity totals while keeping the prior event-string field. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.496 — Fourier** checks scaled pointer indexes against recovered pointee sizes, uses shared sizes for fixed and variable offsets, recognizes more C/Windows/POSIX scalar aliases, follows typed calls and qualified aliases, and avoids arbitrary field guesses for overlapping unions and bitfields. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.495 — Fourier** prevents Thumb switch-table arithmetic from wrapping, uses width- and endian-aware decoding for init/fini arrays, and makes block/function bounds, string addresses, and listing traversal safe near the address-space limit. The 0.6.494 large-file gate measured 4.324 seconds at 267.91 MiB peak RSS on a 134,225,920-byte synthetic ELF; this was one run, and the 50% target remains unmet.

Release update: **Lens 0.6.494 — Fourier** decodes 16-bit pointers, scans pointer references and tables directly from loaded segment bytes, checks segment-relative pointer addresses, rejects overflowing ARM switch targets and bounds, and parses signed minimum values safely. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.493 — Fourier** propagates identical pure expressions through CFG merges, requires unanimous enum assignments, finds tail calls from terminal CFG blocks, checks switch/typeinfo/instruction addresses, names more native stop signals, records debugger ownership loss, and keeps 32-byte rows visible with an explicit output-truncation marker. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.492 — Fourier** adds ten explainable import-evidence combinations spanning downloads, runtime loading, credentials, network access, capture, persistence, settings, injection, process control, and process launches. Unexplored raw-byte listing rows now cover aligned 32-byte windows, halving row count in those regions. Combined behavior clues are static import heuristics, not runtime proof. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.491 — Fourier** propagates copies and constants through forward block chains, pairs process-memory and execution-control imports across Linux/Windows/Mach triage, expands Nt/Zw and process-memory prototypes, hardens high-address scan/hex operations, and bounds high-fan-in call-graph lookup work. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Release update: **Lens 0.6.490 — Fourier** indexes sorted segment addresses, hardens malformed ranges and large-offset reads, avoids duplicating raw file buffers, releases parsed-file buffers before DWARF recovery, keeps native stepping nonblocking, forwards Linux target signals correctly, and adds paired process-injection triage with Win32/Nt/Zw prototypes. Weighted parity remains **41.8%**; no score change is claimed without a full category re-audit.

Post-release scale measurement: the 134,225,920-byte synthetic ELF passed the GitHub Actions gate in **5.278 seconds at 267.73 MiB peak RSS**, versus 393.89 MiB on the preceding run of the same fixture (about **32% less peak memory**). Runtime stayed close to the prior 5.229-second result. This is one controlled synthetic input; real-binary coverage and incremental loading remain open.

Release update: **Lens 0.6.489 — Fourier** adds validated per-variable C types in pseudocode, persists them through undo and database interchange, applies them consistently to GUI/CLI/script exports, propagates pointer aliases and nested expressions more accurately, and avoids type guesses when branches disagree. The weighted estimate is **41.8%**; the 50% target remains unmet.

Release update: **Lens 0.6.488 — Fourier** adds configurable native child sessions, entry-stop and single-step controls, bounded output and process-event capture, restart and PID handoff, four new explainable behavior-triage categories, unary enum propagation, and corrected M68k `TAS` flags. The weighted estimate is **41.0%**; the 50% target remains unmet.

Release update: **Lens 0.6.487 — Fourier** propagates parameter and return types through local callback typedefs, renders null callback arguments with C-compatible types, distinguishes persistence mechanisms from general settings access, and highlights credential-store imports in static and observed-call triage. The weighted parity estimate remains 39.5%; the 50% target remains unmet.

Release update: **Lens 0.6.486 — Fourier** adds common constant-plus DWARF member expressions, propagates prototype parameter types through pointer arithmetic and dereferences, and correlates observed debugger call transitions with explainable static behavior signals. Trace export now includes ordered caller/callee records and matched signals. The weighted estimate is **39.5%**; the 50% target remains unmet.

Release update: **Lens 0.6.485 — Fourier** adds bounded offline trace replay, consent-gated native local-child debugging, DWARF fixed-offset member recovery, corrected M68k sign extension, safer decompiler copy propagation, smoother dense call graphs, and the measured large-file performance gate. A 134,225,920-byte synthetic ELF completed static analysis in 5.427 seconds at 393.36 MiB peak RSS on GitHub Actions. The 50% target remains unmet.

Release update: **Lens 0.6.484 — Fourier** adds structured LLDB stop/exit events, event handoff and clearing, bounded-history metadata, and corrected hit-weighted dynamic triage. The 50% target remains unmet.

Release update: **Lens 0.6.483 — Fourier** adds ranked signal-frequency summaries, copyable triage handoff, distinct flagged-function breadth, and hit-weighted dynamic signal counts. The 50% target remains unmet.

Release update: **Lens 0.6.482 — Fourier** consolidates the defensive dynamic-trace metrics, in-app release-note synchronization, and dense call-graph rendering improvements shipped since 0.6.481. The 50% target remains unmet.

Release update: **Lens 0.6.481 — Fourier** adds protection-posture triage for common mitigation gaps and regression coverage for the complete signal family. The 50% target remains unmet.

Performance follow-up: dense call-graph rendering now skips off-screen edges and uses lighter curve sampling, reducing UI work during pan and zoom. The 50% target remains unmet.

Performance follow-up: dynamic trace annotation lookups now use one indexed address map per debugger frame instead of repeated full-trace scans. The 50% target remains unmet.

Dynamic-analysis follow-up: trace JSON now separates distinct flagged functions from flagged instruction addresses for clearer defensive triage. The 50% target remains unmet.

Dynamic-analysis follow-up: trace JSON now carries deduplicated flagged function names for downstream defensive review. The 50% target remains unmet.

Dynamic-analysis follow-up: trace JSON now includes per-signal observation counts for prioritizing repeated behavior categories. The 50% target remains unmet.

Dynamic-analysis follow-up: trace JSON now includes hit-weighted signal counts, separating behavior breadth from repeated execution intensity. The 50% target remains unmet.

Dynamic-analysis follow-up: structured traces now carry bounded LLDB stop/exit events alongside instruction records. The 50% target remains unmet.

Dynamic-analysis follow-up: trace JSON exposes event count and capacity so consumers can detect bounded-history truncation. The 50% target remains unmet.

Dynamic-analysis follow-up: the debugger displays the four most recent captured stop/exit events below trace triage. The 50% target remains unmet.

Dynamic-analysis follow-up: recent debug events can now be copied as a compact runtime handoff. The 50% target remains unmet.

Dynamic-analysis follow-up: debug-event history can be cleared independently from the instruction trace. The 50% target remains unmet.

Dynamic-analysis follow-up: the event panel shows retained count against its bounded 512-event capacity. The 50% target remains unmet.

Correctness follow-up: hit-weighted signal counts now apply each address hit count once, avoiding repeated-entry overcounting. The 50% target remains unmet.

Correctness follow-up: a focused regression test now protects the hit-weighted counting contract. The 50% target remains unmet.

Dynamic-analysis follow-up: the debugger triage panel now summarizes observed signal frequency before detailed trace review. The 50% target remains unmet.

Dynamic-analysis follow-up: signal-frequency summaries can now be copied directly for case notes and handoff. The 50% target remains unmet.

Dynamic-analysis follow-up: signal-frequency summaries are ranked by count with deterministic tie-breaking for repeatable review. The 50% target remains unmet.

Dynamic-analysis follow-up: a separate signal-intensity handoff copies hit-weighted counts for repeated behavior review. The 50% target remains unmet.

Dynamic-analysis follow-up: trace summaries now show distinct flagged-function breadth separately from flagged addresses. The 50% target remains unmet.

Dynamic-analysis follow-up: trace summaries now show execution intensity separately from flagged-address breadth. The 50% target remains unmet.

Dynamic-analysis follow-up: the debugger can copy deduplicated flagged function names directly for focused defensive handoff. The 50% target remains unmet.

Release update: **Lens 0.6.480 — Fourier** expands defensive behavior taxonomy and adds focused high/medium triage handoff controls. The 50% target remains unmet.

Release update: **Lens 0.6.479 — Fourier** adds structured dynamic-trace export, hotspot navigation and clipboard handoff, triage filtering, distinct-address summaries, and a stronger multi-capability heuristic. The 50% target remains unmet.

Release update: **Lens 0.6.478 — Fourier** adds explainable static malware-triage signals and dynamic trace correlation across the debugger, exports, scripts, CLI reports, database JSON, and regression gates. The 50% target remains unmet.

Release update: **Lens 0.6.477 — Fourier** adds boolean and ternary decompiler normalization plus bounded call-graph frontier, cache, and address allocation. The 50% target remains unmet.

Current follow-up: the debugger now resolves recent LLDB trace PCs to analyzed function names and highlights entries that match static analyst-triage clues. Dynamic behavior correlation and malware-analysis heuristics are now a first-class roadmap track; the 50% target remains unmet.

Release update: **Lens 0.6.476 — Fourier** adds recursive decompiler constant folding and expands native prototypes across POSIX, C++, Win32, sockets, threads, processes, filesystems, signals, randomness, clocks, and stdio. The 50% target remains unmet.

Release update: **Lens 0.6.475 — Fourier** expands built-in native prototypes across POSIX, C++, Win32, sockets, threads, processes, filesystems, signals, randomness, and stdio. The 50% target remains unmet.

Release update: **Lens 0.6.474 — Fourier** adds compile-time constant propagation through expressions, successor blocks, merge blocks, branch terms, and call-graph reliability safeguards. The 50% target remains unmet.

Release update: **Lens 0.6.473 — Fourier** adds portable character, null-pointer, POSIX, and Windows ABI typedef sizing for more accurate data layouts and prototype-driven recovery. The 50% target remains unmet.

Release update: **Lens 0.6.472 — Fourier** extends qualified pointer-typedef and alias-aware field recovery across calls, locals, casts, arithmetic, indexed access, and nested structs. The 50% target remains unmet.

Release update: **Lens 0.6.471 — Fourier** extends prototype-aware call-site typing across pointers, computed expressions, callbacks, function-pointer parameters, and array-to-pointer decay. The 50% target remains unmet.

Release update: **Lens 0.6.470 — Fourier** adds cross-call pointer type propagation through explicit casts, conditional results, pointer arithmetic, nested arithmetic, and typed struct-field rendering. The 50% target remains unmet.

Audit note: the x86 lifter already covers BMI bit extraction/deposit, byte swaps, population/zero counts, rotates, double-width shifts, and variable shifts; the next decompiler gains should target deeper type recovery and cross-call SSA rather than duplicate those semantics.

Release update: **Lens 0.6.469 — Fourier** adds PowerPC rotate-and-mask idioms and MIPS doubleword extraction/rotation lifting for compiler-generated bitfield and address code. The 50% target remains unmet.

Release update: **Lens 0.6.468 — Fourier** adds PowerPC count-trailing-zero, bit-permute, and rotate/insert idioms plus M68k swap/extend/test-and-set lifting. The 50% target remains unmet.

Release update: **Lens 0.6.467 — Fourier** adds RISC-V conditional-move and bit-permutation semantics plus MIPS floating-point conditional moves, improving optimized branchless code readability. The 50% target remains unmet.

Release update: **Lens 0.6.466 — Fourier** adds RISC-V Zbs bit operations, shifted-add address idioms, `adduw`, and MIPS bit insertion lifting for packed flags and pointer arithmetic. The 50% target remains unmet.

Release update: **Lens 0.6.465 — Fourier** adds MIPS floating-point min/max and conversion lifting plus generic RISC-V conversion lifting, keeping common numeric routines readable across both families. The 50% target remains unmet.

Release update: **Lens 0.6.464 — Fourier** adds RISC-V floating-point min/max and sign-injection semantics for numeric and bit-level idioms. The 50% target remains unmet.

Release update: **Lens 0.6.463 — Fourier** adds MIPS and RISC-V floating-point comparison semantics for explicit conditions and boolean results. The 50% target remains unmet.

Release update: **Lens 0.6.462 — Fourier** adds MIPS and RISC-V scalar floating-point arithmetic and value-flow lifting with `.s`/`.d` normalization. The 50% target remains unmet.

Release update: **Lens 0.6.461 — Fourier** adds PowerPC floating-point conversion, move, and absolute-value lifting for clearer value flow. The 50% target remains unmet.

Release update: **Lens 0.6.460 — Fourier** adds ARM/Thumb VFP and PowerPC fused multiply-add/subtract lifting with explicit operand order. The 50% target remains unmet.

Release update: **Lens 0.6.459 — Fourier** adds ARM/Thumb VFP memory and conversion lifting for clearer floating-point pseudocode. The 50% target remains unmet.

Release update: **Lens 0.6.458 — Fourier** adds ARM/Thumb and PowerPC floating-point comparisons plus VFP unary operations, feeding existing control-flow structuring. The 50% target remains unmet.

Release update: **Lens 0.6.457 — Fourier** adds ARM/Thumb VFP and PowerPC floating-point arithmetic lifting with precision-suffix normalization. The 50% target remains unmet.

Release update: **Lens 0.6.456 — Fourier** adds AArch64 compare-and-swap, swap, and atomic read-modify-write families as named operations. The 50% target remains unmet.

Release update: **Lens 0.6.455 — Fourier** adds AArch64 exclusive load/store lifting across acquire/release and byte/halfword/word/doubleword forms. The 50% target remains unmet.

Release update: **Lens 0.6.454 — Fourier** adds readable PowerPC reservation and RISC-V AMO lifting for lock-free synchronization code, extending the ARM, MIPS, and RISC-V atomic workflow. The 50% target remains unmet.

Release update: **Lens 0.6.453 — Fourier** adds explicit Motorola 68000 bit-test/set/clear/change and rotate semantics for packed flags and dispatch code. The 50% target remains unmet.

Release update: **Lens 0.6.452 — Fourier** adds readable RISC-V and MIPS atomic load/store lifting with explicit success status, building on the ARM synchronization semantics from 0.6.451. The 50% target remains unmet.

Release update: **Lens 0.6.451 — Fourier** adds ARM/Thumb `rbit` and exclusive load/store lifting for synchronization-heavy code, including byte, halfword, and doubleword forms. The 50% target remains unmet.

Release update: **Lens 0.6.450 — Fourier** broadens no-return recognition across Rust, Go, Swift, Objective-C, C++, and Windows/Apple runtime symbols, including hashed Rust panic names. The 50% target remains unmet.

Release update: **Lens 0.6.449 — Fourier** hardens switch-table recovery with checked bounds and entry addressing across ARM64, Thumb, RISC-V, MIPS, PowerPC, and x86-style tables. The 50% target remains unmet.

Release update: **Lens 0.6.448 — Fourier** corrects unsigned RISC-V/MIPS comparison lifting and makes scripted function, search, bookmark, and call-graph results deterministic while reusing one indexed graph. The 50% target remains unmet.

Release update: **Lens 0.6.447 — Fourier** hardens call-graph rendering with bounded pan/zoom input, safe cache fallback, deterministic adjacency ordering, malformed-edge guards, and lower-cost curve painting. At that build, the estimate was **38.7% weighted capability / about 40–45% practical workflow**.

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

Current build marker: **0.6.514 — Fourier**. The last full score audit at 0.6.513 measured **41.8% weighted capability** and **about 42–47% practical workflow**. These figures are carried forward, not re-estimated for the new API and triage work; the next category audit must measure any score change. The 50% target is still unmet.

Status checked against the repository on 2026-11-28, at **Lens 0.6.514 — Fourier**. Until the next category re-audit, the carried-forward weighted model is **41.8% of IDA Pro's breadth** (prior plausible range: **34–43%**) and the prior practical workflow estimate is **about 42–47%**. New 0.6.514 work is not yet reflected in the score. These estimates measure feature coverage, not analysis accuracy, reliability, performance, polish, or production readiness. The prior 0.6.505 GitHub Actions run analyzed a 134,225,920-byte synthetic ELF in 2.520 seconds at 267.77 MiB peak RSS. The 0.6.513 workflow measured 128 MiB of virtual-only zero-fill at 0.008 seconds and 13.82 MiB peak RSS on a 12,288-byte fixture. Both are individual synthetic measurements, not a broad real-binary benchmark. Each phase still needs validation against real binaries as well as targeted regression fixtures. Planned work is kept separate from completed work.

| Capability area | Weight | Lens coverage estimate | Weighted contribution |
| --- | ---: | ---: | ---: |
| File formats and processor breadth | 20% | 27% | 5.4% |
| Static analysis and navigation | 20% | 60% | 12.0% |
| Decompiler and type recovery | 20% | 32% | 6.4% |
| Type system and debug information | 10% | 44% | 4.4% |
| Debugging and tracing | 10% | 46% | 4.6% |
| Workflow, scripting and interchange | 10% | 59% | 5.9% |
| Reliability, performance and scale | 10% | 31% | 3.1% |
| **Total** | **100%** |  | **41.8%** |

These are engineering estimates, not a feature-count comparison. Lens already has a broad usable workflow across loading, navigation, graphing, search, annotations, signatures, scripting, debugging, export, and multi-file project manifests. The score remains limited by the much shallower decompiler, partial architecture-specific analysis, narrower format/CPU coverage, small type system, LLDB dependency, and limited large-file validation.

## Phase 1 - Reliability (first, everything else depends on it)
- Expand the existing 200-program system-binary run into a repeatable corpus covering ELF, PE, Mach-O, stripped files, dylibs, and Go/Rust/Swift; fix crashes and incorrect results found by it.
- Performance on 100 MB+ files: a 134,225,920-byte synthetic ELF passes a repeatable GitHub Actions metadata/performance gate (latest recorded run on 0.6.494: 4.324 s, 267.91 MiB peak RSS; prior run: 5.278 s, 267.73 MiB). Version 0.6.505 now avoids per-segment zero-fill allocations and lazily reads virtual zeros; the current fixture does not measure this behavior. Broader real-binary measurements remain open. Background analysis and incremental listing remain open. Call-graph expansion bounds high-fanout neighborhoods, indexes visible neighbors, preserves crossing edges, and surfaces truncation.
- Add a repeatable regression suite with golden outputs for disassembly and pseudocode; the repository has targeted unit tests, but not this corpus-level suite.

## Phase 2 - Analysis depth
- Extend switch/jump-table recovery beyond x86, ARM64 and basic Thumb TBB/TBH tables to additional ARM/Thumb patterns, RISC-V, MIPS and PowerPC; common absolute-table forms and Thumb register-based PC tables are implemented, while more compiler idioms and corpus validation remain.
- Vtable, RTTI and Objective-C / Swift metadata recovery.
- Extend function-boundary recovery beyond ELF `.eh_frame`, PE `.pdata` and Mach-O `LC_FUNCTION_STARTS` / `__unwind_info`; add more robust malformed-table handling and additional format-specific tables.
- Improve constant propagation and broaden no-return, tail-call and thunk detection beyond the current known names/prototypes and direct-target cases.
- Better data-vs-code discrimination and string / array / pointer-table typing.
- Debug info: DWARF names, prototypes and supported type layouts are available, with adjacent dSYM lookup; PDB and broader C++/Rust/Swift debug-type support remain.
- DWARF fixed member offsets accept both `DW_OP_plus_uconst` and equivalent nonnegative constant-plus expressions; dynamic or unsupported expressions remain excluded from recovered layouts.

## Phase 3 - Decompiler
- Type recovery and propagation across calls is expanding; consistent repeated assignments and conservative null-pointer branch merges now keep local declarations typed. Typed prototype returns, recursive enum returns, struct-field access, fixed-array indexing, nested records, pointer typedefs, normalized indexed struct-array paths, nested array members, and prototype casts for unknown call arguments are implemented. Broader SSA-based propagation, variable-length arrays, and more complex loop/switch reconstruction remain.
- Pointee types now survive dereferences through integer pointer offsets, including offsets propagated through prototype-typed parameters, local pointer variables, and conditional pointer expressions; known pointer-valued offsets are rejected.
- Conservative temporary-copy and constant propagation now flow through forward single-predecessor blocks in one address-ordered pass, while skipping backward edges and stopping at reassignment barriers. Pseudocode now removes dead generated temporary chains to a fixed point within a function; full CFG-aware SSA, broader dead-code elimination, and better loop/`switch` structuring remain planned.
- Floating point, SIMD / NEON / SSE, 64-bit arithmetic idioms, and broader calling-convention inference. M68k LINK/A6 frames now recover stack parameters from the correct first-argument offset. Call-site stack-argument collection now covers x86 cdecl/stdcall, System V x64, Windows x64, and AArch64; other conventions remain planned.
- Thumb/Thumb-2 in the main loader and additional PPC extras.
- Interactive pseudocode variable renaming and validated local retyping are available and persist per function; navigation and synchronization with disassembly still need improvement.

## Phase 4 - Type system and libraries
- Expand the C-like type parser: structs, unions, basic enums, scalar/pointer aliases, function-pointer typedef aliases, nested records, bounded arrays, scoped `#pragma pack` and simple packed integer bitfields are supported; compiler-specific bitfield ABI/layout rules remain.
- Extend the built-in/user prototype library (about 190 signatures) and improve type propagation from prototypes into variables, memory accesses, and pseudocode.
- Generate and ship broader versioned signature/type libraries from system libraries (libSystem, libc, MSVC CRT and platform frameworks); the current built-in prototype set is not a complete type library.

## Phase 5 - Debugger
- A native local-child tracer now handles launch configuration, entry stops, single stepping, signal forwarding, output capture, and bounded process events on macOS/Linux; replace LLDB for attach/remote sessions and add Windows debug API support.
- Improve target/session management, platform coverage, reconnect/error recovery, and debugger UI synchronization.
- Correlate runtime traces with static capabilities, imports, protections, packing/entropy clues, and suspicious behavior categories; keep every signal explainable and clearly labeled as heuristic triage rather than a malware verdict.
- Dynamic trace review now correlates adjacent PCs at call instructions to known callees, matches those callees to explainable static behavior signals, and highlights observed caller-to-callee transitions in order for defensive review.
- The LLDB debugger can opt in to temporary breakpoints at up to 64 direct or import-slot API call sites linked to static behavior clues; live hits show the caller, imported API, matching heuristics, and effective severity. These watchpoints are limited to local launches and may change execution timing.
- Extend structured runtime events beyond debugger stops and statically flagged API call sites to capture completed process, filesystem, registry, memory, anti-debugging, and network activity alongside the instruction trace. Current API-family categories are name-based labels for watched calls, not operating-system event telemetry. Behavior call-site events retain ABI register arguments for x64 System V/Windows and AArch64, plus prototype-labeled stack arguments for x86 cdecl/stdcall and stack-passed arguments for the other supported ABIs. Known API flags/modes are symbolized with OS-specific tables next to their raw values. Explicit opt-in previews are bounded for narrow C strings and common Windows UTF-16 aliases; generic platform-specific wide-string encodings remain open.
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
- Prototype-seeded local types now carry pointer parameters through callback typedefs into call arguments and pointer-return inference; callback null constants render with C-compatible function-pointer casts.
- Malware triage now distinguishes explicit persistence mechanisms from ordinary registry/preferences access and flags credential-store imports with explainable evidence; runtime call matching parses the API evidence list independently of explanatory text.
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
- CodeView PDB fixed-array layout sizing now uses the PE target pointer width and recognizes `wchar_t`, `char16_t`, `char32_t`, and `HRESULT` element sizes.
- PDB member extents are checked against their owning record size before a recovered layout is accepted.
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
- Decompiler copy and constant propagation now flow through forward chains of unambiguous single-predecessor basic blocks in one address-ordered pass and still stop at backward edges or reassignment barriers.
- Cross-block propagation preserves source and destination reassignment barriers with regression coverage.
- Decompiler copy propagation now folds identical temporary copies through converging control-flow edges.
- Merge-block propagation remains conservative and requires matching incoming assignments before rewriting uses.
- Decompiler dead-temporary cleanup now uses bounded CFG liveness to remove values overwritten on every path before their remaining uses, while preserving observable calls and memory reads; functions above 512 blocks retain the conservative function-wide cleanup.
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
- Rhai scripts can now read the explainable static malware-triage signals, including severity, category and evidence, for defensive review workflows.
- CLI reports and JSON analysis exports now expose the same triage signals for repeatable defensive review and CI pipelines.
- Smoke and golden-analysis gates now protect the triage export contract across supported fixture architectures.
- Lens database JSON exports now preserve triage evidence alongside analyst annotations and function data.
- Dynamic trace exports now include per-address hit counts for basic hot-path and loop triage.
- Analysts can copy a compact triage summary from the Overview for defensive case handoff.
- Static triage now highlights co-occurring behavior categories as a prioritization clue with explicit evidence text.
- Static triage now calls out runtime code loading as an explainable unpacking and late-bound-execution clue.
- Static triage now distinguishes general filesystem activity from persistence behavior.
- Static triage now distinguishes system-information discovery as a reconnaissance behavior.
- Static triage now includes threading/timing and cryptographic activity as separate evidence-backed clues.
- Static triage now distinguishes desktop and UI interaction imports as a separate behavior category.
- Static triage now highlights unusually broad capability profiles for cross-category review.
- The Overview triage card now summarizes signal severity counts for faster analyst scanning.
- Protection triage now distinguishes ASLR-disabled posture from ASLR-enabled hardening context.
- Protection triage now distinguishes DEP/NX-disabled posture as an executable-memory hardening clue.
- Protection triage now distinguishes disabled stack protection as another conservative hardening clue.
- Protection triage now distinguishes control-flow-guard-disabled posture as an indirect-control-flow hardening clue.
- Protection triage now surfaces unavailable code-signature validation as a separate provenance clue.
- Protection triage now surfaces RELRO-disabled and unavailable runtime-fortification posture.
- Protection triage now surfaces PIE-disabled posture as a separate hardening clue.
- The Overview supports focused clipboard handoff of high-severity heuristic signals.
- The Overview supports a combined medium-and-high escalation handoff.
- Structured dynamic-trace JSON export now supports downstream defensive tooling without text parsing.
- The debugger can filter its visible trace list to heuristic-matched entries for faster behavior triage.
- Dynamic-trace JSON now preserves the names of matching heuristic signals for explainable downstream review.
- Dynamic-trace JSON now includes entry-volume and unique-address metrics for downstream behavior analysis.
- Dynamic-trace JSON now includes distinct flagged-address metrics for triage breadth analysis.
- Dynamic-trace JSON now separates total heuristic matches from distinct flagged-address breadth.
- Dynamic-trace JSON now exposes deduplicated observed signal names for compact reporting.
- Dynamic-trace JSON now reports hot-address count and maximum hit count for loop-intensity analysis.
- The debugger supports clipboard handoff of deduplicated observed signal names.
- Dynamic summaries distinguish repeated flagged executions from distinct flagged addresses.
- Runtime hotspot navigation now shows the resolved function name beside each address and hit count.
- Runtime hotspot lists support clipboard handoff as tab-separated analyst records.
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
5. **Debugger:** deepen LLDB synchronization and reconnect behavior, add broader platform coverage, and investigate hardware trace integration. The 0.6.498 build adds opt-in, static-evidence-ranked behavior API call-site watchpoints for local launches.
6. **Formats and CPUs:** add firmware/raw-dump workflows and additional processors (AVR, 6502, Z80, SuperH, SPARC, s390x, TriCore, eBPF) with real semantic lifting.
7. **Projects and interchange:** promote per-file annotations into user-managed multi-file project databases; document Rhai/plugin compatibility; improve IDC/Ghidra database import beyond the current JSON interchange.

## Current boundaries
- Lens is an analysis and disassembly workbench, not yet a replacement for IDA's mature debugger, decompiler, type system, processor modules or database ecosystem.
- ARM64/ARM/RISC-V/MIPS/PowerPC decoding is available, but CPU-specific analysis and pseudocode semantics still vary in depth.
- C type parsing remains deliberately small; declarations that are not understood should produce a clear error rather than silently inventing a layout.
- Existing repository edits may be in progress. Update status only after confirming the corresponding behavior in source.

## Releasing
Bump `version` in Cargo.toml and Cargo.lock, commit, push, then `git tag vX.Y.Z && git push --tags`. CI checks the version, builds Apple Silicon, and publishes release notes plus the app asset. The release workflow can also be manually dispatched from `main` with the existing `release_tag` input to attach a GitHub-built asset to its tag. Installed apps update themselves from Settings or Tools > Check for updates.
