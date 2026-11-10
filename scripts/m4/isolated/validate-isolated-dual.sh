#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cpag-isolated-dual.XXXXXX")"
project="cpag-r14-dual"
api_pid=''
cleanup() {
  if [[ -n "$api_pid" ]]; then kill "$api_pid" 2>/dev/null || true; wait "$api_pid" 2>/dev/null || true; fi
  docker compose -p "$project" -f "$repo_root/deployments/compose.m4-worker-validation.yml" down --volumes
}
trap cleanup EXIT
export CPAG_M4_PG_PORT=55471
export GOCACHE="${TMPDIR:-/tmp}/cpag-r14-go-build" GOMODCACHE="${TMPDIR:-/tmp}/cpag-r14-go-mod"
docker compose -p "$project" -f "$repo_root/deployments/compose.m4-worker-validation.yml" up -d --wait
for migration in "$repo_root"/internal/jobs/migrations/*.sql; do
  docker compose -p "$project" -f "$repo_root/deployments/compose.m4-worker-validation.yml" exec -T postgres psql -U postgres -d m4_validation < "$migration"
done
go -C "$repo_root/internal/jobs/integration" build -o "$work_dir/api" ./cmd/m4-job-api
docker build -t cpag-isolated:round5 -f "$repo_root/deployments/isolated-executor/Dockerfile" "$repo_root"
mkdir "$work_dir/shared" "$work_dir/control"
export CPAG_SHARED_ROOT="$work_dir/shared" CPAG_CONTROL_ROOT="$work_dir/control"
export CPAG_WORKER_TOKEN="r14-dual-worker-$(python3 -c 'import secrets;print(secrets.token_hex(16))')"
export CPAG_COORDINATOR_TOKEN="r14-dual-control-$(python3 -c 'import secrets;print(secrets.token_hex(16))')"
export CPAG_API_URL=http://127.0.0.1:18171 CPAG_JOB_API_ADDR=127.0.0.1:18171
export CPAG_ENABLE_M4=1 M4_DATABASE_URL="postgres://postgres:m4-disposable-only@127.0.0.1:55471/m4_validation?sslmode=disable"
"$work_dir/api" > "$work_dir/api.log" 2>&1 &
api_pid=$!
export CPAG_API_BINARY="$work_dir/api" CPAG_API_PID="$api_pid"
export PYTHONPATH="$repo_root/services/worker:$repo_root/services/analysis/src:$repo_root/scripts/validation"
export CPAG_R14_EVIDENCE_DIR="$work_dir"
"${CPAG_PYTHON:-python3}" "$repo_root/scripts/m4/isolated/isolated_dual_http.py" | tee "$work_dir/dual-validation.log"
printf 'Evidence workspace: %s\n' "$work_dir"
