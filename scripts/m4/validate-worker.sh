#!/usr/bin/env bash
# Isolated, disposable integration environment; default application is not touched.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
python="${CPAG_PYTHON:-python3}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cpag-m4-worker.XXXXXX")"
compose_file="$repo_root/deployments/compose.m4-worker-validation.yml"
export CPAG_M4_PG_PORT="${CPAG_M4_PG_PORT:-55440}"
api_port="${CPAG_M4_API_PORT:-18095}"
api_pid=''
recovery_pid=''
cleanup() {
  if [[ -n "$api_pid" ]]; then kill "$api_pid" 2>/dev/null || true; wait "$api_pid" 2>/dev/null || true; fi
  if [[ -n "$recovery_pid" ]]; then kill "$recovery_pid" 2>/dev/null || true; wait "$recovery_pid" 2>/dev/null || true; fi
  docker compose -p cpag-m4-worker-validation -f "$compose_file" down --volumes
  rm -rf "$work_dir"
}
trap cleanup EXIT
export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/cpag-go-build}"
export GOMODCACHE="${GOMODCACHE:-${TMPDIR:-/tmp}/cpag-go-mod}"
docker compose -p cpag-m4-worker-validation -f "$compose_file" up -d --wait
export M4_TEST_DATABASE_URL="postgres://postgres:m4-disposable-only@127.0.0.1:$CPAG_M4_PG_PORT/m4_validation?sslmode=disable"
go -C "$repo_root/internal/jobs/integration" test -race -count=1 -v ./...
docker compose -p cpag-m4-worker-validation -f "$compose_file" exec -T postgres psql -U postgres -d m4_validation -c 'TRUNCATE m4_jobs CASCADE'
go -C "$repo_root/internal/jobs/integration" build -o "$work_dir/api" ./cmd/m4-job-api
go -C "$repo_root/internal/jobs/integration" build -o "$work_dir/recovery" ./cmd/m4-recovery
mkdir "$work_dir/shared"
export CPAG_SHARED_ROOT="$work_dir/shared"
database_url="$M4_TEST_DATABASE_URL"
unset M4_TEST_DATABASE_URL
export CPAG_WORKER_TOKEN
CPAG_WORKER_TOKEN="$("$python" -c 'import secrets;print(secrets.token_urlsafe(32))')"
export CPAG_JOB_API_ADDR="127.0.0.1:$api_port" CPAG_API_URL="http://127.0.0.1:$api_port"
CPAG_ENABLE_M4=1 M4_DATABASE_URL="$database_url" "$work_dir/api" > "$work_dir/api.log" 2>&1 &
api_pid=$!
"$python" - <<'PY'
import os,time,urllib.request,urllib.error
for attempt in range(100):
    try:
        urllib.request.urlopen(os.environ['CPAG_API_URL']+'/ready',timeout=.2)
    except urllib.error.HTTPError as exc:
        if exc.code==401: break
    except OSError: pass
    time.sleep(.1)
else: raise SystemExit('isolated API did not start')
PY
"$python" "$repo_root/scripts/m4/worker_http_faults.py"
# Restart the database container using its dedicated volume; not a power-loss test.
docker compose -p cpag-m4-worker-validation -f "$compose_file" restart postgres
docker compose -p cpag-m4-worker-validation -f "$compose_file" up -d --wait
"$python" - <<'PY'
import os,json,urllib.request,time
from pathlib import Path
root=Path(os.environ['CPAG_SHARED_ROOT'])
for directory in (root/'jobs').iterdir():
    request=urllib.request.Request(os.environ['CPAG_API_URL']+'/v1/jobs/'+directory.name,headers={'Authorization':'Bearer '+os.environ['CPAG_WORKER_TOKEN']})
    for attempt in range(20):
        try:
            with urllib.request.urlopen(request,timeout=5) as response: record=json.load(response)
            break
        except OSError:
            if attempt==19: raise
            time.sleep(.2)
    if record['state']=='succeeded':
        assert record['artifact_sha256'] and (root/record['artifact_path']).is_file()
print('PASS database container restart: API reconnects and reads persisted terminal metadata and published manifests')
PY

CPAG_ENABLE_M4=1 M4_DATABASE_URL="$database_url" "$work_dir/recovery" > "$work_dir/recovery.log" 2>&1 &
recovery_pid=$!
export CPAG_TEST_API_PID="$api_pid"
"$python" "$repo_root/scripts/m4/recovery_http_outage.py"
wait "$api_pid" 2>/dev/null || true
api_pid=''
