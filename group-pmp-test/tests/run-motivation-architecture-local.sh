#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export MOT_LOCAL_ARCHITECTURE=1
exec sh tests/run-motivation-local-performance.sh "${1:-500000000}" "${2:-3}" "${3:-cold}" \
  "${4:-/var/tmp/motivation-architecture-native-$(date +%Y%m%d-%H%M%S)-$$}"
