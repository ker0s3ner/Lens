#!/usr/bin/env bash
set -euo pipefail

# Run the headless loader/analyzer against representative binaries available on
# the host. The corpus is discovered at runtime so no platform binaries or generated artifacts need to be committed.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
targets=()
for candidate in \
  /bin/ls /usr/bin/true /usr/bin/grep /usr/bin/clang \
  /bin/echo /usr/bin/ld \
  /usr/lib/libSystem.B.dylib /usr/lib/system/libdyld.dylib /usr/lib/system/libsystem_kernel.dylib \
  /lib/x86_64-linux-gnu/libc.so.6 /usr/lib/x86_64-linux-gnu/libc.so.6; do
  if [[ -f "$candidate" && -x "$candidate" ]]; then
    targets+=("$candidate")
  fi
done

if ((${#targets[@]} == 0)); then
  echo "smoke corpus: no executable targets found" >&2
  exit 1
fi

for target in "${targets[@]}"; do
  echo "smoke corpus: $target"
  output="$(cd "$root" && cargo run --quiet -- "$target" --report 2>&1)"
  grep -Eq 'functions|instructions' <<<"$output" || {
    echo "smoke corpus: missing analysis report for $target" >&2
    printf '%s\n' "$output" >&2
    exit 1
  }
  json="$(cd "$root" && cargo run --quiet -- "$target" --json 2>/dev/null)"
  grep -q '"schema": "lens.analysis.v1"' <<<"$json" || {
    echo "smoke corpus: missing JSON schema for $target" >&2
    printf '%s\n' "$json" >&2
    exit 1
  }
  for field in noreturn_functions forwarding_thunks switch_tables function_records switch_records xref_records; do
    grep -q "\"$field\":" <<<"$json" || {
      echo "missing JSON field $field for $target" >&2
      exit 1
    }
  done
done

raw_fixture="$(mktemp -t lens-raw-entry.XXXXXX)"
trap 'rm -f "$raw_fixture"' EXIT
printf '\xC3' > "$raw_fixture"
raw_json="$(cd "$root" && cargo run --quiet -- "$raw_fixture" --arch x64 --base 0x1000 --entry 0x1234 --json 2>/dev/null)"
grep -q '"entry_point": 4660' <<<"$raw_json" || {
  echo "smoke corpus: raw --entry was not reflected in JSON" >&2
  printf '%s\n' "$raw_json" >&2
  exit 1
}

echo "smoke corpus: ${#targets[@]} targets passed"
