#!/usr/bin/env bash
set -euo pipefail

# Deterministic analysis regression: unlike the host-discovered smoke corpus,
# this fixture and its expected JSON fields are stable across machines.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -t lens-golden.XXXXXX)"
fixture_arm="$(mktemp -t lens-golden-arm.XXXXXX)"
fixture_rv="$(mktemp -t lens-golden-rv.XXXXXX)"
trap 'rm -f "$fixture" "$fixture_arm" "$fixture_rv"' EXIT
printf '\x55\x48\x89\xE5\xB8\x2A\x00\x00\x00\x5D\xC3' > "$fixture"
printf '\xC0\x03\x5F\xD6' > "$fixture_arm"
printf '\x67\x80\x00\x00' > "$fixture_rv"

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

echo "golden analysis: deterministic raw x64 fixture passed"
