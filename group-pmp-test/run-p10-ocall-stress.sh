#!/bin/sh
set -eu

usage() {
  echo "usage: $0 [max-workers]" >&2
  echo "  runs high-frequency OCALL stress experiments 1..max-workers (valid range: 1..64)" >&2
}

if [ "$#" -gt 1 ]; then
  usage
  exit 2
fi

if [ "$#" -eq 1 ]; then
  max_workers=$1
else
  max_workers=${GROUP_PMP_MIXED_MAX_WORKERS:-12}
fi

case "$max_workers" in
  ''|*[!0-9]*)
    usage
    exit 2
    ;;
esac
if [ "$max_workers" -lt 1 ] || [ "$max_workers" -gt 64 ]; then
  usage
  exit 2
fi

if [ "${GROUP_PMP_SKIP_3W1HM_PREPARE:-0}" != "1" ]; then
  ./prepare-3w1hm-isolation.sh apply
fi

GROUP_PMP_TEST_MODE=mixed-ocall-stress
GROUP_PMP_MIXED_MAX_WORKERS=$max_workers
: "${GROUP_PMP_MIXED_TIMEOUT_SEC:=300}"
: "${GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS:=30000}"
export GROUP_PMP_TEST_MODE
export GROUP_PMP_MIXED_MAX_WORKERS
export GROUP_PMP_MIXED_TIMEOUT_SEC
export GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS

if [ -n "${GROUP_PMP_MIXED_CSV:-}" ]; then
  export GROUP_PMP_MIXED_CSV
  csv_status=$GROUP_PMP_MIXED_CSV
else
  unset GROUP_PMP_MIXED_CSV
  csv_status=disabled
fi

echo "[p10][ocall-stress] experiments=1..${GROUP_PMP_MIXED_MAX_WORKERS} ocalls_per_worker=8 csv=${csv_status}"
exec ./group-pmp-test-runner
