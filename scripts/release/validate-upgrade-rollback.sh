#!/bin/sh
# Run INSIDE the disposable, offline Docker host after loading the offline pack.
set -eu
test "${CPAG_ENGINEERING_DISPOSABLE:-}" = 1 || { echo 'Disposable engineering host opt-in required' >&2; exit 2; }
PACKAGE=${1:?offline package directory required}
PARENT=/round7-drill
test ! -e "$PARENT" || { echo 'Fresh drill directory required; existing data retained' >&2; exit 2; }
mkdir -p "$PARENT" "$PARENT/snapshots"
export CPAG_DATA_ROOT="$PARENT/data"
export CPAG_PROJECT=cpag-round7-old
export CPAG_APP_IMAGE=cpag-engineering:baseline-1386a4f
export CPAG_COMPUTE_IMAGE=cpag-isolated:baseline-1386a4f
tool() {
 docker run --rm --pull=never --network host -v /var/run/docker.sock:/var/run/docker.sock \
  --mount "type=bind,src=$PARENT,dst=$PARENT" cpag-engineering:rc1 "$@"
}
snapshot() {
 "$PACKAGE/cpag.sh" maintenance
 tool python /app/scripts/backup/engineering.py backup --project "$CPAG_PROJECT" \
  --root "$CPAG_DATA_ROOT" --bundle "$PARENT/snapshots/$1" --version "$2"
}
fresh_restore() {
 # No existing database or directory is destroyed. Every previous generation is
 # retained; rollback selects a checkpoint rather than merging incompatible data.
 "$PACKAGE/cpag.sh" stop
 mv "$CPAG_DATA_ROOT" "$PARENT/preserved-$1"
 export CPAG_PROJECT="$2"
 password=$(tool python -c 'import json,sys; print(json.load(open(sys.argv[1]))["database_password"])' "$PARENT/snapshots/$3/host/config.json")
 docker volume create --label "cpag.engineering.project=$CPAG_PROJECT" "$CPAG_PROJECT-pg" >/dev/null
 # Public isolation is enforced at the outer offline host. Inner bridge must
 # allow the loopback-only published API/evidence ports on Docker 29.
 docker network create --label "cpag.engineering.project=$CPAG_PROJECT" "$CPAG_PROJECT-internal" >/dev/null
 docker run -d --pull=never --name "$CPAG_PROJECT-postgres" --network "$CPAG_PROJECT-internal" \
  -e "POSTGRES_PASSWORD=$password" -e POSTGRES_DB=m4_validation \
  -v "$CPAG_PROJECT-pg:/var/lib/postgresql/data" mirror.gcr.io/library/postgres:17.6-alpine >/dev/null
 unset password
 count=0
 until docker exec "$CPAG_PROJECT-postgres" pg_isready -h 127.0.0.1 -U postgres -d m4_validation >/dev/null 2>&1; do
  count=$((count+1)); test "$count" -lt 60; sleep 1
 done
 hash=$(sha256sum "$PARENT/snapshots/$3/snapshot.json" | cut -d' ' -f1)
 tool python /app/scripts/backup/engineering.py restore --project "$CPAG_PROJECT" \
  --root "$CPAG_DATA_ROOT" --bundle "$PARENT/snapshots/$3" --confirm "$hash"
 cp "$PARENT/data-restore-report.json" "$PARENT/$1-restore-report.json"
 # This is only a report reservation for the next independent generation.
 mv "$PARENT/data-restore-report.json" "$PARENT/$1-reserved-report.json"
}

mkdir "$CPAG_DATA_ROOT"
"$PACKAGE/cpag.sh" install
"$PACKAGE/cpag.sh" start
"$PACKAGE/cpag.sh" demo
"$PACKAGE/cpag.sh" check
snapshot baseline 1386a4f68afbe00d83bb355632e9ff7637a227c2
"$PACKAGE/cpag.sh" stop
export CPAG_APP_IMAGE=cpag-engineering:rc1 CPAG_COMPUTE_IMAGE=cpag-isolated:round7
"$PACKAGE/cpag.sh" start
# Existing old task/evidence/download must work before any new job is submitted.
"$PACKAGE/cpag.sh" check
"$PACKAGE/cpag.sh" demo
"$PACKAGE/cpag.sh" check
snapshot candidate cpag-engineering-synthetic-rc1
tool python /app/scripts/backup/validate_engineering_snapshot.py "$PARENT/snapshots/candidate" > "$PARENT/snapshot-negatives.json"

fresh_restore upgrade cpag-round7-restored candidate
"$PACKAGE/cpag.sh" start
"$PACKAGE/cpag.sh" check
"$PACKAGE/cpag.sh" maintenance
tool python /app/scripts/backup/engineering.py verify --bundle "$PARENT/snapshots/candidate"

fresh_restore rollback cpag-round7-rollback baseline
export CPAG_APP_IMAGE=cpag-engineering:baseline-1386a4f CPAG_COMPUTE_IMAGE=cpag-isolated:baseline-1386a4f
"$PACKAGE/cpag.sh" start
"$PACKAGE/cpag.sh" check
# Actual old worker/core execute fresh tasks after restoring the old checkpoint.
"$PACKAGE/cpag.sh" demo
"$PACKAGE/cpag.sh" check
snapshot rollback-executed baseline-1386a4f-after-rollback
tool python -c 'import json,pathlib; p=pathlib.Path("/round7-drill"); print(json.dumps({"valid":True,"synthetic_only":True,"baseline":"1386a4f68afbe00d83bb355632e9ff7637a227c2","upgrade_existing_evidence":True,"candidate_independent_restore":json.load(open(p/"upgrade-restore-report.json")),"baseline_rollback":json.load(open(p/"rollback-restore-report.json")),"snapshot_negatives":json.load(open(p/"snapshot-negatives.json")),"old_executor_fresh_tasks_after_rollback":True,"newer_data_retained":True},indent=2))' > "$PARENT/upgrade-rollback-result.json"
"$PACKAGE/cpag.sh" stop
cat "$PARENT/upgrade-rollback-result.json"
