#!/bin/sh
set -e
cd "$(dirname "$0")"

if [ "${GROUP_PMP_ALLOW_LEGACY_PURE_AES:-0}" != 1 ]; then
  echo "[P10][RETIRED] pure-AES performance mode is disabled; use the mixed performance baseline" >&2
  exit 2
fi

if [ "${GROUP_PMP_LEASE_TEST_FALLBACK:-0}" != 1 ]; then
  ./prepare-3w1hm-isolation.sh apply
fi

: "${GROUP_PMP_TEST_MODE:=perf}"
: "${GROUP_PMP_GROUP_RUN_TIMEOUT_SEC:=600}"
: "${GROUP_PMP_CYCLE_HZ:=1000000000}"
: "${GROUP_PMP_PERF_ITERS:=8}"
export GROUP_PMP_TEST_MODE
export GROUP_PMP_GROUP_RUN_TIMEOUT_SEC
export GROUP_PMP_CYCLE_HZ
export GROUP_PMP_PERF_ITERS

exec ./group-pmp-test-runner "$@"
