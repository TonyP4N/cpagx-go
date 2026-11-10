#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="${1:?new acceptance directory required}"
python_bin="${CPAG_PYTHON:-python3}"
cd "$repo"
mkdir -p "$work"
if [[ "${CPAG_SKIP_IMAGE_BUILD:-0}" == "1" ]]; then
  # Local reuse is only for an unchanged core/image; CI always rebuilds.
  docker image inspect cpag-isolated:round5 --format '{{.Id}}' > "$work/image.log"
else
  docker build -t cpag-isolated:round5 -f deployments/isolated-executor/Dockerfile . > "$work/image.log" 2>&1
fi
"$python_bin" scripts/validation/round16_acceptance.py --output "$work/environment" --skip-image-build --serve > "$work/startup.log" 2>&1 &
validation_pid=$!
cleanup() { kill -TERM "$validation_pid" 2>/dev/null || true; wait "$validation_pid" || true; }
trap cleanup EXIT
for attempt in $(seq 1 360); do
  if test -f "$work/environment/state.json"; then break; fi
  if ! kill -0 "$validation_pid" 2>/dev/null; then echo "Environment failed; inspect private startup.log"; exit 1; fi
  sleep 1
done
test -f "$work/environment/state.json"
node scripts/validation/round16_browser.cjs "$work/environment/state.json" "$work/public/browser"
"$python_bin" scripts/validation/round16_boundaries.py --state "$work/environment/state.json" --output "$work/public/boundaries.json"
cleanup
"$python_bin" scripts/validation/round16_supplement.py --output "$work/supplement" --serve > "$work/supplement.log" 2>&1 &
validation_pid=$!
for attempt in $(seq 1 360); do
  if test -f "$work/supplement/state.json"; then break; fi
  if ! kill -0 "$validation_pid" 2>/dev/null; then echo "Supplement failed; inspect private supplement.log"; exit 1; fi
  sleep 1
done
test -f "$work/supplement/state.json"
node scripts/validation/round16_supplement_browser.cjs "$work/supplement/state.json" "$work/public/supplement-browser"
node scripts/validation/round16_browser.cjs "$work/supplement/state.json" "$work/public/supplement-restored-browser"
