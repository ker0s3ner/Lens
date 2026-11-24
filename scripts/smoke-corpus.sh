#!/usr/bin/env bash
set -euo pipefail

# Run the headless loader/analyzer against representative binaries available on
# the host. The corpus is discovered at runtime so no platform binaries or generated artifacts need to be committed.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
targets=()
for candidate in \
  /bin/ls /usr/bin/true /usr/bin/grep /usr/bin/clang \
  /bin/echo /usr/bin/ld; do
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
done

echo "smoke corpus: ${#targets[@]} targets passed"
