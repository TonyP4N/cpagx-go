#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="${1:?new acceptance work directory required}"
mkdir -p "$work"
python_bin="${CPAG_PYTHON:-python3}"
backup_pid='' ui_pid='' celery_pid=''
cleanup() {
 for task_pid in "$ui_pid" "$celery_pid" "$backup_pid"; do
  if [[ -n "$task_pid" ]]; then kill "$task_pid" 2>/dev/null || true; wait "$task_pid" 2>/dev/null || true; fi
 done
}
trap cleanup EXIT
cd "$repo"
docker build -t cpag-isolated:round5 -f deployments/isolated-executor/Dockerfile . > "$work/image-build.log" 2>&1
"$python_bin" scripts/backup/validate_dual.py --isolated --serve --work-dir "$work/backup" > "$work/backup.log" 2>&1 &
backup_pid=$!
"$python_bin" scripts/validation/round13_celery.py --serve --output "$work/celery" --ui-port 18313 > "$work/celery-startup.log" 2>&1 &
celery_pid=$!
wait_file() {
 for _ in $(seq 1 360); do
  if [[ -f "$1" ]]; then return; fi
  if ! kill -0 "$2" 2>/dev/null; then echo "Acceptance service exited; inspect $work logs"; return 1; fi
  sleep 1
 done
 echo "Acceptance readiness timeout: $1"; return 1
}
wait_file "$work/backup/state.json" "$backup_pid"
"$python_bin" scripts/validation/round14_ui.py "$work/backup/state.json" --output "$work/ui" --ui-port 18314 > "$work/ui.log" 2>&1 &
ui_pid=$!
wait_file "$work/ui/ready.json" "$ui_pid"
wait_file "$work/celery/results.json" "$celery_pid"
"$python_bin" scripts/validation/round14_parity.py "$work/celery" "$work/ui" --output "$work/parity.json"
node scripts/validation/round14_browser.cjs "$work/ui" "$work/browser"
# Public reports deliberately exclude private credentials, DB dump, execution tokens.
mkdir "$work/public"
cp "$work/parity.json" "$work/public/"
cp -R "$work/browser" "$work/public/"
"$python_bin" - "$work" <<'PY'
import json,sys
from pathlib import Path
root=Path(sys.argv[1]);state=json.loads((root/'backup/state.json').read_text())
state={key:value for key,value in state.items() if 'token' not in key}
(root/'public/restore.json').write_text(json.dumps(state,indent=2)+'\n')
PY
