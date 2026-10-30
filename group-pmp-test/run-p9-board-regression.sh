#!/bin/sh
set -eu

cd "$(dirname "$0")"
if [ "${GROUP_PMP_LEASE_TEST_FALLBACK:-0}" != 1 ]; then
  ./prepare-3w1hm-isolation.sh apply
fi
RUNNER=${GROUP_PMP_RUNNER:-./run-group-pmp-test.sh}
TIMEOUT=${GROUP_PMP_TEST_TIMEOUT:-7200}

run_mode() {
  mode=$1
  echo "[p9] board mode=$mode"
  GROUP_PMP_TEST_MODE=$mode timeout "$TIMEOUT" "$RUNNER"
}

run_mode smoke
run_mode stress
run_mode fault

echo "[p9] VisionFive2 hardware regression PASS"
