#!/bin/sh
set -eu

LEASE_RECOVERY_MARKER=keystone-hsm-lease-recovery-v1

MODE=${1:-apply}
WORKER_CPUS=1-3
MODULE_READY=/sys/module/keystone_driver/parameters/worker_isolation_ready
MODULE_VERSION=/sys/module/keystone_driver/version
REQUIRED_DRIVER_VERSION=1.0.0-group-pmp-v6
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

fail() {
  echo "[3w1hm][ERROR] $*" >&2
  exit 1
}

cmdline_has() {
  key=$1
  case " $(cat /proc/cmdline) " in
    *" $key"*) return 0 ;;
    *) return 1 ;;
  esac
}

[ "$MODE" = apply ] || [ "$MODE" = check ] ||
  fail "usage: $0 [apply|check]"
[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ -r "$MODULE_VERSION" ] ||
  fail "Keystone driver version is unavailable: $MODULE_VERSION"
[ "$(cat "$MODULE_VERSION")" = "$REQUIRED_DRIVER_VERSION" ] ||
  fail "stale Keystone driver: loaded=$(cat "$MODULE_VERSION") required=$REQUIRED_DRIVER_VERSION"

cmdline_has "isolcpus=domain,managed_irq,$WORKER_CPUS" ||
  fail "missing boot arg: isolcpus=domain,managed_irq,$WORKER_CPUS"
cmdline_has "nohz_full=$WORKER_CPUS" ||
  fail "missing boot arg: nohz_full=$WORKER_CPUS"
cmdline_has "rcu_nocbs=$WORKER_CPUS" ||
  fail "missing boot arg: rcu_nocbs=$WORKER_CPUS"
cmdline_has "irqaffinity=0" ||
  fail "missing boot arg: irqaffinity=0"

offline_workers=
for cpu in 0 1 2 3; do
  [ -d "/sys/devices/system/cpu/cpu$cpu" ] ||
    fail "CPU$cpu is not present"
  if [ -f "/sys/devices/system/cpu/cpu$cpu/online" ]; then
    if [ "$(cat "/sys/devices/system/cpu/cpu$cpu/online")" != 1 ]; then
      [ "$cpu" -ne 0 ] || fail "housekeeping CPU0 is offline"
      offline_workers="$offline_workers $cpu"
    fi
  fi
done

if [ -n "$offline_workers" ]; then
  [ "$MODE" = apply ] ||
    fail "worker CPUs are offline:$offline_workers"
  [ -x "$SCRIPT_DIR/group-pmp-test-runner" ] ||
    fail "worker CPUs are offline and lease recovery runner is missing"
  echo "[3w1hm] recovering stale HSM worker lease for CPUs:$offline_workers"
  GROUP_PMP_TEST_MODE=lease-recover \
    "$SCRIPT_DIR/group-pmp-test-runner" ||
    fail "HSM worker lease recovery failed; reboot before retrying"
  online_deadline=50
  while [ "$online_deadline" -gt 0 ]; do
    all_online=1
    for cpu in $offline_workers; do
      if [ "$(cat "/sys/devices/system/cpu/cpu$cpu/online")" != 1 ]; then
        all_online=0
        break
      fi
    done
    [ "$all_online" = 1 ] && break
    online_deadline=$((online_deadline - 1))
    sleep 0.1
  done
  [ "$online_deadline" -gt 0 ] ||
    fail "worker CPUs did not return online after HSM lease recovery"
fi

if [ "$MODE" = apply ]; then
  irq_failures=0
  for affinity in /proc/irq/[0-9]*/smp_affinity_list; do
    [ -e "$affinity" ] || continue
    if [ -w "$affinity" ] && ! printf '0\n' > "$affinity" 2>/dev/null; then
      irq_failures=$((irq_failures + 1))
    fi
  done
  if [ "$irq_failures" -ne 0 ]; then
    echo "[3w1hm] $irq_failures managed/per-CPU IRQ affinity files refused migration"
  fi

  if [ -w /sys/devices/virtual/workqueue/cpumask ]; then
    printf '1\n' > /sys/devices/virtual/workqueue/cpumask
  else
    fail "unbound workqueue cpumask is not writable"
  fi
fi

rcu_threads=0
rcu_failures=0
for comm_file in /proc/[0-9]*/comm; do
  [ -r "$comm_file" ] || continue
  comm=$(cat "$comm_file" 2>/dev/null || true)
  case "$comm" in
    rcuo*)
      rcu_threads=$((rcu_threads + 1))
      pid=${comm_file#/proc/}
      pid=${pid%/comm}
      if [ "$MODE" = apply ]; then
        command -v taskset >/dev/null 2>&1 ||
          fail "taskset is required to pin RCU nocb threads"
        if ! taskset -p 1 "$pid" >/dev/null 2>&1; then
          rcu_failures=$((rcu_failures + 1))
          continue
        fi
      fi
      allowed=$(awk '/^Cpus_allowed_list:/ { print $2 }' "/proc/$pid/status" \
        2>/dev/null || true)
      [ "$allowed" = 0 ] || rcu_failures=$((rcu_failures + 1))
      ;;
  esac
done
[ "$rcu_failures" -eq 0 ] ||
  fail "$rcu_failures RCU nocb threads are not pinned to CPU0"

workqueue_mask=$(cat /sys/devices/virtual/workqueue/cpumask 2>/dev/null || true)
case "$workqueue_mask" in
  *1) ;;
  *) fail "unbound workqueues are not restricted to CPU0: $workqueue_mask" ;;
esac

[ -e "$MODULE_READY" ] ||
  fail "Keystone driver parameter is missing: $MODULE_READY"
if [ "$MODE" = apply ]; then
  printf 'Y\n' > "$MODULE_READY"
fi
ready=$(cat "$MODULE_READY")
case "$ready" in
  Y|1) ;;
  *) fail "driver did not accept worker isolation readiness: $ready" ;;
esac

echo "[3w1hm] ready: CPU0=housekeeping/master, CPU1-3=leased workers"
echo "[3w1hm] mapping: Linux CPU0..3 -> SM hart1..4"
echo "[3w1hm] RCU nocb threads pinned to CPU0: $rcu_threads"
