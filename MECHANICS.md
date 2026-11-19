# Lens — rules taken from IDA Free 9.4

Sources are files in `/Applications/IDA Free 9.4.app/Contents/MacOS` and functions in its
`libida.dylib` / `ida` programs (addresses are arm64 slice addresses). Ghidra could not open the
program on this Mac (its decompiler natives are missing), so pseudocode came from the built-in
lifter.

## What it reads
| Rule | Value | Source |
|---|---|---|
| File formats | ELF, PE, Mach-O (+ universal), dyld cache (not rebuilt) | `loaders/` folder: elf, pe, macho, dsc |
| Processor | x86 / x64 only | `procs/` folder holds only `pc.dylib` |
| Universal Mach-O | x86-64 slice is chosen (then x86) | follows from the processor rule |

## Names (auto-analysis)
| Rule | Value | Source |
|---|---|---|
| Function without a symbol | `sub_<ADDR>` (upper-case hex) | prefix table at libida 0x1b635a9 ("sub") |
| Jump target | `loc_<ADDR>`; `locret_<ADDR>` when the target is a return | libida `sub_145e50` decodes the insn and picks "locret" |
| Empty function (just `ret`) | `nullsub_<n>` | libida string "nullsub_%zu" used by `sub_220028` |
| Unknown data | `unk_`, `byte_`, `word_`, `dword_`, `qword_`, `xmmword_`… by access size; `off_` for pointers | prefix table at libida 0x1b635a9 |
| String name | `a` + capitalised words (e.g. `aBinLs`) | cfg/ida.cfg `STRLIT_PREFIX = "a"` |
| String name length | 24 characters after `a` | estimated |
| Entry function | `start` | estimated (IDA convention) |

## Analysis
| Rule | Value | Source |
|---|---|---|
| Functions found by | entry, symbols, exports, call targets, init arrays, prologue scan | estimated — IDA's own heuristics not decompiled (unknown recorded) |
| Calls that never return | exit, abort, err/errx, __stack_chk_fail, longjmp, ExitProcess, _Unwind_Resume … | cfg/noret.cfg |
| Minimal string length | 5 (user may change; values ≤ 0 become 1) | `ida` `sub_10026ab40` clamps to 1; default 5 estimated |
| String kinds | C 8-bit and UTF-16 zero-terminated | cfg/ida.cfg STRTYPE_C / STRTYPE_C_16 |

## Listing
| Rule | Value | Source |
|---|---|---|
| Cross-references shown next to an item | 2, the rest via X | cfg/ida.cfg `SHOW_XREFS = 2` |
| Xref marks | p = call, j = jump, r = read, w = write, o = offset; ↑/↓ for direction | cfg/ida.cfg `SHOW_XREF_TYPES = YES` |
| Auto comment for string references | yes | cfg/ida.cfg `STRLIT_COMMENT = YES` |
| Empty line after a jump/return | yes | cfg/ida.cfg `SHOW_EMPTYLINES = YES` |
| Opcode bytes shown | 0 | cfg/ida.cfg `OPCODE_BYTES = 0` |
| Number style | upper-case hex with `h` suffix | IDA's Intel syntax (pc.dylib) |

## Window
| Rule | Value | Source |
|---|---|---|
| Layout | functions list left (20%), views in tabs (Code / Hex …), messages at the bottom; code and hex stay in sync | default layout JSON in `ida` at 0x10044eb80 |
| Graph colours | green = branch taken, red = not taken, blue = always | themes/default/theme.css (graph section), IDA convention |
| Graph overview | small map in the corner | "Graph overview" in the default layout |
| Code colours | instructions navy, names blue, imports fuchsia, numbers green, comments blue/gray; dark theme from `os-dark-theme` | themes/default/theme.css |

## Keys
| Key | Action | Source |
|---|---|---|
| G | Jump to address | cfg/idagui.cfg `JumpAsk` |
| N | Rename | `MakeName` |
| ; or : | Comment / note | `MakeRptCmt`, `MakeComment` |
| X / Ctrl+X | Cross-references | `JumpOpXref`, `JumpXref` |
| Enter | Follow operand | `JumpEnter` |
| Esc | Back | `Return` |
| P | Make function | `MakeFunction` |
| Space | Graph / text | IDA default |
| Shift+F3 / F12 / F7 | Functions / Strings / Segments | `OpenFunctions`, `OpenStrings`, `OpenSegments` |
| Alt+T, Ctrl+T | Find text, find next | `AskNextText`, `JumpText` |
| Cmd/Ctrl+P, Ctrl+Shift+P | Command palette | `CommandPalette` |

## Not rebuilt
- Hex-Rays cloud decompiler (`plugins/hexcx64`) and the debugger (`plugins/dbg`): replaced by a
  function outline panel (calls, callers, text and data it uses).
- FLIRT signatures, type libraries, switch-table recovery.
