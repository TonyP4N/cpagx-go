#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="${1:?new R18 acceptance directory required}"
python_bin="${CPAG_PYTHON:-python3}"
cd "$repo"
mkdir -p "$work"
image="${CPAG_R18_WORKER_IMAGE:-cpag-isolated:r18-acceptance}"
docker build -t "$image" -f deployments/isolated-executor/Dockerfile . > "$work/image.log" 2>&1
"$python_bin" scripts/validation/round18_acceptance.py --output "$work/environment" --serve > "$work/startup.log" 2>&1 &
validation_pid=$!
cleanup() { kill -TERM "$validation_pid" 2>/dev/null || true; wait "$validation_pid" || true; }
trap cleanup EXIT
for attempt in $(seq 1 900); do
  if test -f "$work/environment/state.json"; then break; fi
  if ! kill -0 "$validation_pid" 2>/dev/null; then echo "R18 failed; inspect private startup.log"; exit 1; fi
  sleep 1
done
test -f "$work/environment/state.json"
node scripts/validation/round18_browser.cjs "$work/environment/state.json" "$work/public/browser"
