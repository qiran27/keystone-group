#!/bin/sh
set -eu

cd "$(dirname "$0")"

fail()
{
  echo "[AES-FAIR][ERROR] $*" >&2
  exit 1
}

[ -x ./group-pmp-test-runner ] ||
  fail "missing group-pmp-test-runner; run ./rebuild-and-test.sh first"
[ -f ./group-pmp-aes-enclave-baseline.eapp_riscv ] ||
  fail "missing group-pmp-aes-enclave-baseline.eapp_riscv"

freq_state="${TMPDIR:-/tmp}/group-pmp-aes-fair-cpufreq.$$"
GROUP_PMP_CPU_FREQ_STATE=$freq_state
export GROUP_PMP_CPU_FREQ_STATE
freq_locked=0

if ! grep -q 'keystone-worker-cpufreq-v2' \
    ./prepare-aes-benchmark-env.sh; then
  fail "stale prepare-aes-benchmark-env.sh; rebuild and redeploy"
fi

restore_frequency()
{
  if [ "$freq_locked" = 1 ]; then
    freq_locked=0
    if [ -r "$freq_state" ]; then
      sh ./prepare-aes-benchmark-env.sh restore ||
        echo "[AES-FAIR][ERROR] failed to restore worker CPU frequency" >&2
    fi
  fi
  rm -f "$freq_state"
}

trap 'restore_frequency' EXIT HUP INT TERM
freq_locked=1
set +e
sh ./prepare-aes-benchmark-env.sh apply
freq_status=$?
set -e
if [ "$freq_status" -ne 0 ]; then
  fail "worker CPU frequency apply failed: status=$freq_status"
fi
if [ "${GROUP_PMP_LEASE_TEST_FALLBACK:-0}" != 1 ]; then
  ./prepare-3w1hm-isolation.sh apply
fi

GROUP_PMP_TEST_MODE=aes-diagnostic
export GROUP_PMP_TEST_MODE

echo "[AES-FAIR] CPU1 native/EPM/YXSTM software AES-128-ECB diagnostics"
set +e
./group-pmp-test-runner
status=$?
set -e
restore_frequency
trap - EXIT HUP INT TERM
exit "$status"
