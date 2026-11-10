#!/bin/sh
set -eu
PACKAGE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CPAG_DATA_ROOT=${CPAG_DATA_ROOT:-/cpag-root/data}
CPAG_PROJECT=${CPAG_PROJECT:-cpag-engineering}
CPAG_APP_IMAGE=${CPAG_APP_IMAGE:-cpag-engineering:rc1}
CPAG_COMPUTE_IMAGE=${CPAG_COMPUTE_IMAGE:-cpag-isolated:round7}
command=${1:-}
mkdir -p "$CPAG_DATA_ROOT"
case "$command" in
 install)
  (cd "$PACKAGE" && sha256sum -c SHA256SUMS)
  docker load -i "$PACKAGE/images.tar"
  ;;
 start|stop|maintenance|restart|demo|check) ;;
 *) echo 'Usage: cpag.sh install|start|stop|maintenance|restart|demo|check' >&2; exit 2;;
esac
docker run --pull=never --rm --network host -e CPAG_DATA_ROOT="$CPAG_DATA_ROOT" -e CPAG_PROJECT="$CPAG_PROJECT" -e CPAG_APP_IMAGE="$CPAG_APP_IMAGE" -e CPAG_COMPUTE_IMAGE="$CPAG_COMPUTE_IMAGE" --mount "type=bind,src=$CPAG_DATA_ROOT,dst=$CPAG_DATA_ROOT" -v /var/run/docker.sock:/var/run/docker.sock "$CPAG_APP_IMAGE" python /app/engineering/ops.py "$command"
