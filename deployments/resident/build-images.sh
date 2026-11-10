#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
ARCH=${ARCH:-amd64}
case "$ARCH" in amd64|arm64) ;; *) exit 2;; esac
mkdir -p "deployments/resident/build/$ARCH"
(cd internal/jobs/integration && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "../../../deployments/resident/build/$ARCH/cpagx-v3" ./cmd/cpagx-v3)
# The static workbench export must already exist (npm ci && npm run build:static in webui).
test -f webui/out/workbench/index.html
docker build --platform "linux/$ARCH" --provenance=false -f deployments/resident/Dockerfile.api -t "cpag-resident-api:review-$ARCH" .
docker build --platform "linux/$ARCH" --provenance=false -f deployments/resident/Dockerfile.worker -t "cpag-resident-worker:review-$ARCH" .
docker save -o "deployments/resident/build/cpag-resident-$ARCH.tar" "cpag-resident-api:review-$ARCH" "cpag-resident-worker:review-$ARCH"
