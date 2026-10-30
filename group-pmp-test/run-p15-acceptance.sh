#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

RUNNER=${GROUP_PMP_RUNNER:-./group-pmp-test-runner}
DURATION=${GROUP_PMP_ACCEPTANCE_DURATION_SEC:-3600}
NETWORK_TARGET=${GROUP_PMP_NETWORK_TARGET:-127.0.0.1}
DISK_PATH=${GROUP_PMP_DISK_PATH:-/tmp/group-pmp-p15-$$.bin}
P10_AFTER=${GROUP_PMP_P10_AFTER_ACCEPTANCE:-0}
DMESG_START=$(dmesg 2>/dev/null | wc -l || printf '0')
PIDS=""

for required in taskset dd ping awk dmesg; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "[P15] required command is missing: $required" >&2
    exit 2
  fi
done
if ! dmesg >/dev/null 2>&1; then
  echo "[P15] dmesg access is required for stall/latency acceptance" >&2
  exit 2
fi

if [ "${GROUP_PMP_LEASE_TEST_FALLBACK:-0}" != 1 ]; then
  ./prepare-3w1hm-isolation.sh apply
fi

pin_cpu0() {
  taskset -c 0 "$@"
}

run_checked() {
  "$@" 2>&1 | awk '
    { print; fflush(); }
    /Invalid error 100108|[Rr][Cc][Uu].*stall|workqueue lockup|Unexpected interrupt latency/ {
      forbidden = 1;
    }
    END { if (forbidden) exit 97; }
  '
}

start_background() {
  pin_cpu0 sh -c '
    while :; do
      dd if=/dev/zero of="$1" bs=1M count=16 conv=fsync 2>/dev/null || exit 1
      dd if="$1" of=/dev/null bs=1M 2>/dev/null || exit 1
      rm -f "$1"
    done
  ' sh "$DISK_PATH" &
  PIDS="$PIDS $!"

  pin_cpu0 sh -c '
    while :; do
      ping -c 1 -W 1 "$1" >/dev/null 2>&1 || true
      sleep 1
    done
  ' sh "$NETWORK_TARGET" &
  PIDS="$PIDS $!"

  pin_cpu0 sh -c '
    while :; do
      printf "[P15][tty] cpu0 housekeeping heartbeat\n"
      sleep 10
    done
  ' &
  PIDS="$PIDS $!"

  # Short-lived task churn exercises scheduler/RCU callback progress on CPU0.
  pin_cpu0 sh -c '
    while :; do
      sh -c :
      cat /proc/self/stat >/dev/null 2>&1 || true
    done
  ' &
  PIDS="$PIDS $!"
}

stop_background() {
  for pid in $PIDS; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in $PIDS; do
    wait "$pid" 2>/dev/null || true
  done
  rm -f "$DISK_PATH"
}

trap 'stop_background' EXIT INT TERM

case "$DURATION" in
  ''|*[!0-9]*)
    echo "[P15] invalid GROUP_PMP_ACCEPTANCE_DURATION_SEC=$DURATION" >&2
    exit 2
    ;;
esac
if [ "$DURATION" -lt 1 ]; then
  echo "[P15] acceptance duration must be positive" >&2
  exit 2
fi

echo "[P15] starting 3W+1HM acceptance duration=${DURATION}s"
start_background
START=$(date +%s)
DEADLINE=$((START + DURATION))
ROUND=0
while :; do
  ROUND=$((ROUND + 1))
  echo "[P15] acceptance round=$ROUND"
  FAULTS=0
  if [ "$ROUND" -eq 1 ]; then
    FAULTS=1
  fi
  run_checked env \
    GROUP_PMP_TEST_MODE=acceptance \
    GROUP_PMP_ACCEPTANCE_FAULTS=$FAULTS \
    GROUP_PMP_GROUP_RUN_TIMEOUT_SEC=${GROUP_PMP_GROUP_RUN_TIMEOUT_SEC:-600} \
    GROUP_PMP_MASTER_WAIT_TIMEOUT_MS=${GROUP_PMP_MASTER_WAIT_TIMEOUT_MS:-600000} \
    "$RUNNER"
  for pid in $PIDS; do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "[P15] CPU0 housekeeping workload exited unexpectedly: pid=$pid" >&2
      exit 1
    fi
  done
  NOW=$(date +%s)
  if [ "$NOW" -ge "$DEADLINE" ]; then
    break
  fi
done

if [ "$P10_AFTER" = 1 ]; then
  if [ "${GROUP_PMP_ALLOW_LEGACY_PURE_AES:-0}" != 1 ]; then
    echo "[P15] legacy pure-AES tail run requested without GROUP_PMP_ALLOW_LEGACY_PURE_AES=1" >&2
    exit 2
  fi
  echo "[P15] running retired P10 1/2/3-worker diagnostic"
  run_checked env \
    GROUP_PMP_TEST_MODE=perf \
    GROUP_PMP_GROUP_RUN_TIMEOUT_SEC=${GROUP_PMP_GROUP_RUN_TIMEOUT_SEC:-600} \
    GROUP_PMP_MASTER_WAIT_TIMEOUT_MS=${GROUP_PMP_MASTER_WAIT_TIMEOUT_MS:-600000} \
    GROUP_PMP_CYCLE_HZ=${GROUP_PMP_CYCLE_HZ:-1000000000} \
    GROUP_PMP_PERF_ITERS=${GROUP_PMP_PERF_ITERS:-8} \
    "$RUNNER"
fi
for pid in $PIDS; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "[P15] CPU0 housekeeping workload exited during P10: pid=$pid" >&2
    exit 1
  fi
done
stop_background
PIDS=""

DMESG_NEW=$(dmesg 2>/dev/null | tail -n "+$((DMESG_START + 1))" || true)
if printf '%s\n' "$DMESG_NEW" | grep -Eiq \
    'Invalid error 100108|rcu[^:]*:.*stall|rcu_sched detected stalls|workqueue lockup|Unexpected interrupt latency'; then
  echo "[P15] forbidden kernel/firmware diagnostic detected:" >&2
  printf '%s\n' "$DMESG_NEW" | grep -Ei \
    'Invalid error 100108|rcu[^:]*:.*stall|rcu_sched detected stalls|workqueue lockup|Unexpected interrupt latency' >&2 || true
  exit 1
fi

echo "[P15] PASS rounds=$ROUND elapsed=$(( $(date +%s) - START ))s"
