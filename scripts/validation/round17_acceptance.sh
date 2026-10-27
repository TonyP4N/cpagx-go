#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="${1:?new acceptance directory required}"
python_bin="${CPAG_PYTHON:-python3}"
cd "$repo"
mkdir -p "$work"
docker build -t cpag-isolated:round5 -f deployments/isolated-executor/Dockerfile . > "$work/image.log" 2>&1
"$python_bin" scripts/validation/round17_acceptance.py --output "$work/environment" --serve > "$work/startup.log" 2>&1 &
validation_pid=$!
cleanup() { kill -TERM "$validation_pid" 2>/dev/null || true; wait "$validation_pid" || true; }
trap cleanup EXIT
for attempt in $(seq 1 600); do
  if test -f "$work/environment/state.json"; then break; fi
  if ! kill -0 "$validation_pid" 2>/dev/null; then echo "R17 failed; inspect private startup.log"; exit 1; fi
  sleep 1
done
test -f "$work/environment/state.json"
node scripts/validation/round17_browser.cjs "$work/environment/state.json" "$work/public/browser"
