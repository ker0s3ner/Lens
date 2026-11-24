#!/usr/bin/env bash
set -euo pipefail

# Deterministic analysis regression: unlike the host-discovered smoke corpus,
# this fixture and its expected JSON fields are stable across machines.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -t lens-golden.XXXXXX)"
trap 'rm -f "$fixture"' EXIT
printf '\xC3' > "$fixture"

json="$(cd "$root" && cargo run --quiet -- "$fixture" --arch x64 --base 0x1000 --entry 0x1234 --json 2>/dev/null)"

grep -q '"schema": "lens.analysis.v1"' <<<"$json" || { echo "golden: schema mismatch" >&2; exit 1; }
grep -q '"architecture": "x86-64"' <<<"$json" || { echo "golden: architecture mismatch" >&2; exit 1; }
grep -q '"entry_point": 4660' <<<"$json" || { echo "golden: entry point mismatch" >&2; exit 1; }
grep -q '"format": "Raw binary"' <<<"$json" || { echo "golden: format mismatch" >&2; exit 1; }
for field in function_records pseudocode_records instruction_records block_records call_records; do
  grep -q "\"$field\":" <<<"$json" || { echo "golden: missing $field" >&2; exit 1; }
done

echo "golden analysis: deterministic raw x64 fixture passed"
