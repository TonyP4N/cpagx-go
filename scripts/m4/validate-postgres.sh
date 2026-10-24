#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
compose_file="$repo_root/deployments/compose.m4-validation.yml"
# Dedicated project, ephemeral database, fixed localhost-only port; no external DSN.
cleanup() { docker compose -f "$compose_file" down --volumes; }
trap cleanup EXIT
docker compose -f "$compose_file" up -d --wait
export M4_TEST_DATABASE_URL='postgres://postgres:m4-disposable-only@127.0.0.1:55439/m4_validation?sslmode=disable'
export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/cpag-go-build}"
export GOMODCACHE="${GOMODCACHE:-${TMPDIR:-/tmp}/cpag-go-mod}"
go -C "$repo_root/internal/jobs/integration" test -race -count=1 -v ./...
