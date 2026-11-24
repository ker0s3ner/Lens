#!/usr/bin/env bash
set -euo pipefail

# Deterministic analysis regression: unlike the host-discovered smoke corpus,
# this fixture and its expected JSON fields are stable across machines.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -t lens-golden.XXXXXX)"
fixture_arm="$(mktemp -t lens-golden-arm.XXXXXX)"
fixture_rv="$(mktemp -t lens-golden-rv.XXXXXX)"
fixture_arm32="$(mktemp -t lens-golden-arm32.XXXXXX)"
fixture_ppc="$(mktemp -t lens-golden-ppc.XXXXXX)"
fixture_mips="$(mktemp -t lens-golden-mips.XXXXXX)"
fixture_mips_branch="$(mktemp -t lens-golden-mips-branch.XXXXXX)"
fixture_thumb="$(mktemp -t lens-golden-thumb.XXXXXX)"
fixture_m68k="$(mktemp -t lens-golden-m68k.XXXXXX)"
trap 'rm -f "$fixture" "$fixture_arm" "$fixture_rv" "$fixture_arm32" "$fixture_ppc" "$fixture_mips" "$fixture_mips_branch" "$fixture_thumb" "$fixture_m68k"' EXIT
printf '\x55\x48\x89\xE5\xB8\x2A\x00\x00\x00\x5D\xC3' > "$fixture"
printf '\xC0\x03\x5F\xD6' > "$fixture_arm"
printf '\x67\x80\x00\x00' > "$fixture_rv"
printf '\x1E\xFF\x2F\xE1' > "$fixture_arm32"
printf '\x4E\x80\x00\x20' > "$fixture_ppc"
printf '\x03\xE0\x00\x08' > "$fixture_mips"
printf '\x10\x00\x00\x01\x00\x00\x00\x00\x03\xE0\x00\x08' > "$fixture_mips_branch"
printf '\x70\x47' > "$fixture_thumb"
printf '\x4E\x75' > "$fixture_m68k"

json="$(cd "$root" && cargo run --quiet -- "$fixture" --arch x64 --base 0x1000 --entry 0x1234 --json 2>/dev/null)"

grep -q '"schema": "lens.analysis.v1"' <<<"$json" || { echo "golden: schema mismatch" >&2; exit 1; }
grep -q '"architecture": "x86-64"' <<<"$json" || { echo "golden: architecture mismatch" >&2; exit 1; }
grep -q '"entry_point": 4660' <<<"$json" || { echo "golden: entry point mismatch" >&2; exit 1; }
grep -q '"format": "Raw binary"' <<<"$json" || { echo "golden: format mismatch" >&2; exit 1; }
grep -q '"functions": 1' <<<"$json" || { echo "golden: function count mismatch" >&2; exit 1; }
grep -q '"instructions": 5' <<<"$json" || { echo "golden: instruction count mismatch" >&2; exit 1; }
grep -q '"blocks": 1' <<<"$json" || { echo "golden: block count mismatch" >&2; exit 1; }
grep -q 'return 0x2A;' <<<"$json" || { echo "golden: pseudocode return mismatch" >&2; exit 1; }
for field in function_records pseudocode_records instruction_records block_records call_records; do
  grep -q "\"$field\":" <<<"$json" || { echo "golden: missing $field" >&2; exit 1; }
done

arm_json="$(cd "$root" && cargo run --quiet -- "$fixture_arm" --arch arm64 --base 0x1000 --entry 0x1000 --json 2>/dev/null)"
grep -q '"architecture": "ARM64"' <<<"$arm_json" || { echo "golden: ARM64 architecture mismatch" >&2; exit 1; }
grep -q '"entry_point": 4096' <<<"$arm_json" || { echo "golden: ARM64 entry point mismatch" >&2; exit 1; }
grep -q '"functions": 1' <<<"$arm_json" || { echo "golden: ARM64 function count mismatch" >&2; exit 1; }
grep -q '"instructions": 1' <<<"$arm_json" || { echo "golden: ARM64 instruction count mismatch" >&2; exit 1; }

rv_json="$(cd "$root" && cargo run --quiet -- "$fixture_rv" --arch riscv64 --base 0x1000 --entry 0x1000 --json 2>/dev/null)"
grep -q '"architecture": "RISC-V 64"' <<<"$rv_json" || { echo "golden: RISC-V architecture mismatch" >&2; exit 1; }
grep -q '"entry_point": 4096' <<<"$rv_json" || { echo "golden: RISC-V entry point mismatch" >&2; exit 1; }
grep -q '"functions": 1' <<<"$rv_json" || { echo "golden: RISC-V function count mismatch" >&2; exit 1; }
grep -q '"instructions": 1' <<<"$rv_json" || { echo "golden: RISC-V instruction count mismatch" >&2; exit 1; }

arm32_json="$(cd "$root" && cargo run --quiet -- "$fixture_arm32" --arch arm --base 0x1000 --entry 0x1000 --json 2>/dev/null)"
grep -q '"architecture": "ARM (32-bit)"' <<<"$arm32_json" || { echo "golden: ARM32 architecture mismatch" >&2; exit 1; }
grep -q '"entry_point": 4096' <<<"$arm32_json" || { echo "golden: ARM32 entry point mismatch" >&2; exit 1; }
grep -q '"functions": 1' <<<"$arm32_json" || { echo "golden: ARM32 function count mismatch" >&2; exit 1; }
grep -q '"instructions": 1' <<<"$arm32_json" || { echo "golden: ARM32 instruction count mismatch" >&2; exit 1; }

ppc_json="$(cd "$root" && cargo run --quiet -- "$fixture_ppc" --arch ppc64 --big --base 0x1000 --entry 0x1000 --json 2>/dev/null)"
grep -q '"architecture": "PowerPC 64"' <<<"$ppc_json" || { echo "golden: PowerPC architecture mismatch" >&2; exit 1; }
grep -q '"entry_point": 4096' <<<"$ppc_json" || { echo "golden: PowerPC entry point mismatch" >&2; exit 1; }
grep -q '"functions": 1' <<<"$ppc_json" || { echo "golden: PowerPC function count mismatch" >&2; exit 1; }
grep -q '"instructions": 1' <<<"$ppc_json" || { echo "golden: PowerPC instruction count mismatch" >&2; exit 1; }

mips_json="$(cd "$root" && cargo run --quiet -- "$fixture_mips" --arch mips32 --big --base 0x1000 --entry 0x1000 --json 2>/dev/null)"
grep -q '"architecture": "MIPS32"' <<<"$mips_json" || { echo "golden: MIPS architecture mismatch" >&2; exit 1; }
grep -q '"entry_point": 4096' <<<"$mips_json" || { echo "golden: MIPS entry point mismatch" >&2; exit 1; }
grep -q '"functions": 1' <<<"$mips_json" || { echo "golden: MIPS function count mismatch" >&2; exit 1; }
grep -q '"instructions": 1' <<<"$mips_json" || { echo "golden: MIPS instruction count mismatch" >&2; exit 1; }

mips_branch_json="$(cd "$root" && cargo run --quiet -- "$fixture_mips_branch" --arch mips32 --big --base 0x1000 --entry 0x1000 --json 2>/dev/null)"
grep -q '"architecture": "MIPS32"' <<<"$mips_branch_json" || { echo "golden: MIPS branch architecture mismatch" >&2; exit 1; }
grep -q '"functions": 1' <<<"$mips_branch_json" || { echo "golden: MIPS branch function count mismatch" >&2; exit 1; }
grep -q '"instructions": 3' <<<"$mips_branch_json" || { echo "golden: MIPS delay-slot instruction count mismatch" >&2; exit 1; }

thumb_json="$(cd "$root" && cargo run --quiet -- "$fixture_thumb" --arch thumb --base 0x1000 --entry 0x1001 --json 2>/dev/null)"
grep -q '"architecture": "ARM Thumb"' <<<"$thumb_json" || { echo "golden: Thumb architecture mismatch" >&2; exit 1; }
grep -q '"entry_point": 4096' <<<"$thumb_json" || { echo "golden: Thumb mode-bit normalization mismatch" >&2; exit 1; }
grep -q '"functions": 1' <<<"$thumb_json" || { echo "golden: Thumb function count mismatch" >&2; exit 1; }
grep -q '"instructions": 1' <<<"$thumb_json" || { echo "golden: Thumb instruction count mismatch" >&2; exit 1; }

m68k_json="$(cd "$root" && cargo run --quiet -- "$fixture_m68k" --arch m68k --big --base 0x1000 --entry 0x1000 --json 2>/dev/null)"
grep -q '"architecture": "Motorola 68000"' <<<"$m68k_json" || { echo "golden: M68k architecture mismatch" >&2; exit 1; }
grep -q '"entry_point": 4096' <<<"$m68k_json" || { echo "golden: M68k entry point mismatch" >&2; exit 1; }
grep -q '"functions": 1' <<<"$m68k_json" || { echo "golden: M68k function count mismatch" >&2; exit 1; }
grep -q '"instructions": 1' <<<"$m68k_json" || { echo "golden: M68k instruction count mismatch" >&2; exit 1; }

echo "golden analysis: deterministic raw x64 fixture passed"
