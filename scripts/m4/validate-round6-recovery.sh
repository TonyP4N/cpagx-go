#!/usr/bin/env bash
# Disposable PostgreSQL outage and independent recovery service restart check.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
compose_file="$repo_root/deployments/compose.m4-worker-validation.yml"
export CPAG_M4_PG_PORT="${CPAG_ROUND6_PG_PORT:-55447}"
project='cpag-round6-go-recovery'
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cpag-round6-go.XXXXXX")"
recovery_pid=''
cleanup() {
  if [[ -n "$recovery_pid" ]]; then kill "$recovery_pid" 2>/dev/null || true; wait "$recovery_pid" 2>/dev/null || true; fi
  docker compose -p "$project" -f "$compose_file" down --volumes
  rm -rf "$work_dir"
}
trap cleanup EXIT
export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/cpag-go-build}" GOMODCACHE="${GOMODCACHE:-${TMPDIR:-/tmp}/cpag-go-mod}"
docker compose -p "$project" -f "$compose_file" up -d --wait
export M4_TEST_DATABASE_URL="postgres://postgres:m4-disposable-only@127.0.0.1:$CPAG_M4_PG_PORT/m4_validation?sslmode=disable"
go -C "$repo_root/internal/jobs/integration" test -race -count=1 -v ./...
go -C "$repo_root/internal/jobs/integration" build -o "$work_dir/recovery" ./cmd/m4-recovery
mkdir "$work_dir/control"
docker compose -p "$project" -f "$compose_file" exec -T postgres psql -U postgres -d m4_validation -v ON_ERROR_STOP=1 -c "INSERT INTO m4_jobs(id,state,attempt,max_attempts,worker,attempt_token,lease_until) VALUES('outage-final','running',1,1,'gone','outage-token',clock_timestamp()-interval '1 second')"
# No API is running. Start the independent service while PostgreSQL is actually down.
docker compose -p "$project" -f "$compose_file" stop postgres
CPAG_ENABLE_M4=1 M4_DATABASE_URL="$M4_TEST_DATABASE_URL" CPAG_CONTROL_ROOT="$work_dir/control" "$work_dir/recovery" > "$work_dir/recovery.log" 2>&1 &
recovery_pid=$!
python3 - "$work_dir/recovery.log" <<'PY'
import pathlib,sys,time
p=pathlib.Path(sys.argv[1])
for _ in range(100):
    if p.exists() and 'recovery pass failed' in p.read_text():break
    time.sleep(.1)
else:raise SystemExit('database outage was not reported')
print('PASS actual PostgreSQL outage: independent daemon reports dependency failure, no API running')
PY
docker compose -p "$project" -f "$compose_file" up -d --wait
for attempt in {1..50}; do
  observed="$(docker compose -p "$project" -f "$compose_file" exec -T postgres psql -U postgres -d m4_validation -At -c "SELECT state||':'||(recovery_checked_at IS NOT NULL)::text FROM m4_jobs WHERE id='outage-final'")"
  if [[ "$observed" == 'failed:true' ]]; then break; fi
  sleep 0.2
done
[[ "$observed" == 'failed:true' ]]
cat "$work_dir/recovery.log"
printf '%s\n' 'PASS actual database return: same recovery process fenced expired final attempt without API/new claims'
# Restart the OS process and verify persisted history/state survives.
kill "$recovery_pid"; wait "$recovery_pid" || true
docker compose -p "$project" -f "$compose_file" exec -T postgres psql -U postgres -d m4_validation -v ON_ERROR_STOP=1 -c "INSERT INTO m4_jobs(id,state,attempt,max_attempts,worker,attempt_token,lease_until) VALUES('restart-final','running',1,1,'gone','restart-token',clock_timestamp()-interval '1 second')"
CPAG_ENABLE_M4=1 M4_DATABASE_URL="$M4_TEST_DATABASE_URL" CPAG_CONTROL_ROOT="$work_dir/control" "$work_dir/recovery" >> "$work_dir/recovery.log" 2>&1 &
recovery_pid=$!
for attempt in {1..50}; do
  restarted="$(docker compose -p "$project" -f "$compose_file" exec -T postgres psql -U postgres -d m4_validation -At -c "SELECT count(*) FROM m4_jobs WHERE id IN ('outage-final','restart-final') AND state='failed' AND recovery_checked_at IS NOT NULL")"
  if [[ "$restarted" == '2' ]]; then break; fi
  sleep 0.2
done
[[ "$restarted" == '2' ]]
kill -0 "$recovery_pid"
docker compose -p "$project" -f "$compose_file" exec -T postgres psql -U postgres -d m4_validation -At -c "SELECT j.state,a.attempt,a.publication_state FROM m4_jobs j JOIN m4_job_attempts a ON a.job_id=j.id WHERE j.id='outage-final'"
printf '%s\n' 'PASS restarted recovery OS process fenced a new expired attempt and preserved previous fenced history'
