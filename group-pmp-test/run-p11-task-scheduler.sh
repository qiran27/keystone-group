#!/bin/sh
set -e
cd "$(dirname "$0")"

if [ "${GROUP_PMP_ENABLE_SPARK_SCHEDULER:-0}" != 1 ]; then
  echo "[p11] Spark-style scheduler experiment is disabled by default."
  echo "[p11] Rebuild with GROUP_PMP_ENABLE_SPARK_SCHEDULER=ON and run with GROUP_PMP_ENABLE_SPARK_SCHEDULER=1."
  exit 2
fi

if [ "${GROUP_PMP_LEASE_TEST_FALLBACK:-0}" != 1 ]; then
  ./prepare-3w1hm-isolation.sh apply
fi

: "${GROUP_PMP_TEST_MODE:=task}"
: "${GROUP_PMP_GROUP_RUN_TIMEOUT_SEC:=600}"
export GROUP_PMP_TEST_MODE
export GROUP_PMP_GROUP_RUN_TIMEOUT_SEC

exec ./group-pmp-test-runner "$@"
