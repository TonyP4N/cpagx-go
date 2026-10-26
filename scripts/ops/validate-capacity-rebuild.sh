#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cpag-capacity.XXXXXX")"
compose_file="$repo_root/deployments/compose.m4-worker-validation.yml"
project='cpag-round7-capacity';api_pid=''
export CPAG_M4_PG_PORT="${CPAG_CAPACITY_PG_PORT:-55461}"
cleanup(){
 if [[ -n "$api_pid" ]]; then kill "$api_pid" 2>/dev/null || true;wait "$api_pid" 2>/dev/null || true; fi
 docker compose -p "$project" -f "$compose_file" down --volumes
}
trap cleanup EXIT
export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/cpag-go-build}" GOMODCACHE="${GOMODCACHE:-${TMPDIR:-/tmp}/cpag-go-mod}"
docker compose -p "$project" -f "$compose_file" up -d --wait
for migration in "$repo_root"/internal/jobs/migrations/*.sql; do
 docker compose -p "$project" -f "$compose_file" exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d m4_validation < "$migration"
done
go -C "$repo_root/internal/jobs/integration" build -o "$work_dir/api" ./cmd/m4-job-api
export CPAG_CAPACITY_IMAGE="${CPAG_CAPACITY_IMAGE:-cpag-capacity:round7}"
if [[ "${CPAG_CAPACITY_SKIP_BUILD:-0}" != '1' ]]; then
 docker build -t "$CPAG_CAPACITY_IMAGE" -f "$repo_root/deployments/isolated-executor/Dockerfile" "$repo_root"
fi
docker image inspect "$CPAG_CAPACITY_IMAGE" --format 'Capacity validation compute image: {{.Id}}'
mkdir "$work_dir/shared" "$work_dir/control"
export CPAG_SHARED_ROOT="$work_dir/shared" CPAG_CONTROL_ROOT="$work_dir/control"
export CPAG_WORKER_TOKEN="capacity-worker-$(python3 -c 'import secrets;print(secrets.token_hex(16))')"
export CPAG_COORDINATOR_TOKEN="capacity-coordinator-$(python3 -c 'import secrets;print(secrets.token_hex(16))')"
export CPAG_JOB_API_ADDR="127.0.0.1:${CPAG_CAPACITY_API_PORT:-18161}" CPAG_API_URL="http://127.0.0.1:${CPAG_CAPACITY_API_PORT:-18161}"
export CPAG_ENABLE_M4=1 M4_DATABASE_URL="postgres://postgres:m4-disposable-only@127.0.0.1:$CPAG_M4_PG_PORT/m4_validation?sslmode=disable"
export CPAG_VALIDATION_DIR="${CPAG_VALIDATION_DIR:-$repo_root/docs/refactor/validation-round7}"
export PYTHONPATH="$repo_root/services/worker:$repo_root/services/analysis/src"
"$work_dir/api" > "$work_dir/api.log" 2>&1 &
api_pid=$!
python3 "$repo_root/scripts/ops/capacity_http.py"
printf 'Retained capacity repair evidence workspace: %s\n' "$work_dir"
