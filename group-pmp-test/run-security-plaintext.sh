#!/bin/sh
set -eu
export GROUP_PMP_BENCH_CIPHER=aes-ecb-128
cd "$(dirname "$0")"
[ "$#" -le 2 ] || { echo 'usage: run-security-plaintext.sh [new-evidence-directory] [1|3 repetitions]' >&2; exit 2; }
output=${1:-/myusb/security-plaintext-1MB}
repetitions=${2:-1}
case "$repetitions" in 1|3) ;; *) echo 'Plaintext repetitions must be 1 or 3' >&2; exit 2 ;; esac
storage=${SECURITY_SCAN_STORAGE_DIR:-/tmp}
unset GROUP_PMP_SECURITY_NONCE GROUP_PMP_SECURITY_REGIONS GROUP_PMP_SECURITY_CAPTURE_DIR GROUP_PMP_SECURITY_CAPTURE_POSITIVE
case "$output:$storage" in /*:/*) ;; *) echo 'absolute paths required' >&2; exit 2 ;; esac
[ ! -e "$output" ] || { echo 'Choose a new evidence directory; old evidence is immutable' >&2; exit 2; }
mkdir -p "$output" "$storage"
output=$(CDPATH= cd "$output" && pwd -P)
storage=$(CDPATH= cd "$storage" && pwd -P)
printf 'run_id,workload,mode,algorithm,total_bytes,workers,repetition,status\n' > "$output/planned-combinations.csv"
for plan_wl in readrandom fillrandom; do for plan_n in 1 4; do
  for plan_mode in sync-no-extent async-no-extent adaptive-extent; do
    for plan_rep in $(seq 1 "$repetitions"); do for plan_algorithm in aes-128-ecb aes-128-gcm chacha20-poly1305; do
      printf '%s-N%s-%s-%s-r%s,%s,%s,%s,1000000,%s,%s,not-executed\n' \
        "$plan_wl" "$plan_n" "$plan_mode" "$plan_algorithm" "$plan_rep" "$plan_wl" "$plan_mode" "$plan_algorithm" "$plan_n" "$plan_rep" >> "$output/planned-combinations.csv"
    done; done
  done
done; done
lock=${GROUP_PMP_RUN_LOCK_DIR:-/tmp/keystone-group-pmp-p10.lock}
mkdir "$lock" || { echo 'Another benchmark owns the worker lanes' >&2; exit 2; }
printf '%s\n' "$$" > "$lock/pid"
work=
cleanup() {
  GROUP_PMP_TEST_MODE=lease-recover timeout 30 ./group-pmp-test-runner > "$output/lease-cleanup.log" 2>&1 || true
  if [ "${loaded_observer:-0}" = 1 ]; then rmmod keystone_evidence || true; fi
  case "$work" in "$storage"/.keystone-security-*) rm -rf "$work" ;; esac
  rm -f "$lock/pid"; rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
./group-pmp-test-runner --artifact-info > "$output/artifact.log"
./group-pmp-test-runner --security-crypto-info > "$output/crypto.log"
./group-pmp-security-capture --capture-info > "$output/capture-info.log"
grep -q 'security_capture_preflight=1' "$output/capture-info.log" || {
  echo 'Rebuild/deploy group-pmp-security-capture with observer preflight support' >&2; exit 2;
}
grep -q 'security_capture_checkpoint_ids=1' "$output/capture-info.log" || {
  echo 'Rebuild/deploy group-pmp-security-capture with exact checkpoint identities' >&2; exit 2;
}
grep -q 'security_capture_lifecycle=2' "$output/capture-info.log" &&
grep -q 'security_checkpoint_watchdog=2' "$output/crypto.log" || {
  echo 'Rebuild/deploy both runner and collector with checkpoint watchdog/lifecycle fix' >&2; exit 2;
}
grep -q 'security_capture_version=1 scan_workload_ciphers=aes-128-ecb' "$output/crypto.log" || {
  echo 'Rebuild/deploy extended runner' >&2; exit 2;
}
grep -q 'security_capture_input_bytes=1000000 security_capture_batch_requests=8' "$output/crypto.log" &&
grep -q 'security_capture_compact=1' "$output/capture-info.log" &&
grep -q 'security_capture_process_stop=1' "$output/capture-info.log" &&
grep -q 'security_capture_ring_accounting=2' "$output/crypto.log" &&
grep -aq 'keystone-security-capture-milestones-v2' ./group-pmp-sqlite-worker.eapp_riscv || {
  echo 'Rebuild/deploy 1MB runner, collector with stopped Host snapshots, and small-batch milestone worker' >&2; exit 2;
}
sha256sum ./group-pmp-test-runner ./group-pmp-sqlite-worker.eapp_riscv ./group-pmp-security-capture ./eyrie-rt ./loader.bin > "$output/artifacts.sha256"
for artifact in ./keystone_evidence.ko ./keystone-driver.ko ./keystone_driver.ko; do
  [ ! -r "$artifact" ] || sha256sum "$artifact" >> "$output/artifacts.sha256"
done
uname -a > "$output/kernel-build.txt"
cat /proc/version /proc/mounts /proc/swaps > "$output/environment.txt"
for p in /proc/sys/kernel/core_pattern /proc/sys/fs/suid_dumpable /sys/kernel/kexec_crash_loaded /proc/cmdline; do
  printf '\n=== %s ===\n' "$p" >> "$output/environment.txt"
  cat "$p" >> "$output/environment.txt" 2>&1 || true
done
df -P "$storage" "$output" >> "$output/environment.txt"
loaded_observer=0
if [ ! -e /dev/keystone-evidence ] && [ -r ./keystone_evidence.ko ]; then
  insmod ./keystone_evidence.ko controls=1 > "$output/observer-load.log" 2>&1 || {
    cat "$output/observer-load.log" >&2; exit 2;
  }
  loaded_observer=1
fi
if [ -e /dev/keystone-evidence ]; then
  printf '1\n' > /sys/module/keystone_evidence/parameters/controls || exit 2
  cat /sys/module/keystone_evidence/version > "$output/observer-version.txt"
else
  printf 'module unavailable; kernel coverage will remain incomplete\n' > "$output/observer-version.txt"
fi
if ! ./group-pmp-security-capture --preflight > "$output/preflight.log" 2>&1; then
  cat "$output/preflight.log" >&2
  echo '[security] prerequisites failed; no workload launched. Rebuild with SECURITY_EVIDENCE_KERNEL_BUILD set to the exact fully built board kernel, then deploy both kernel modules.' >&2
  exit 2
fi
./prepare-3w1hm-isolation.sh apply
unset GROUP_PMP_SECURITY_WORKER_SET GROUP_PMP_FIO_PROFILE GROUP_PMP_SQLITE_MERGE_PROFILE
unset GROUP_PMP_SECURITY_NONCE GROUP_PMP_SECURITY_CAPTURE_DIR GROUP_PMP_SECURITY_CAPTURE_POSITIVE
unset GROUP_PMP_SQLITE_NEIGHBOR_ONLY GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC GROUP_PMP_SQLITE_GANTT_CSV
matrix=$output/execution-matrix.csv
printf 'run_id,workload,mode,algorithm,total_bytes,workers,repetition,status,negative_hits,positive_injected,positive_detected,evidence\n' > "$matrix"
swap=false; [ "$(awk 'NR>1{n++} END{print n+0}' /proc/swaps)" -eq 0 ] || swap=true
dump=false
[ "$(cat /sys/kernel/kexec_crash_loaded 2>/dev/null || echo 0)" = 0 ] || dump=true
case "$(cat /proc/sys/kernel/core_pattern)" in '|'*) dump=true ;; esac
[ "$(ulimit -c)" = 0 ] || dump=true
printf 'core_limit=%s\n' "$(ulimit -c)" >> "$output/environment.txt"
printf 'warmup_timeout_ms=1800000; whole_capture_timeout_seconds=3600; security snapshots included\n' >> "$output/environment.txt"
printf 'negative_repetitions=%s; regional_controls=one-per-configuration\n' "$repetitions" >> "$output/environment.txt"
printf 'requested_total_bytes=1000000; effective_total_bytes=999840; record_bytes=240; security_batch_requests=8\n' >> "$output/environment.txt"
run_capture() {
  positive=$1; run_id=$2; reference=$3
  dir=$output/$run_id; mkdir -p "$dir"
  work=$(mktemp -d "$storage/.keystone-security-XXXXXXXX")
  nonce=$(od -An -N8 -tu8 /dev/urandom | tr -d ' \n')
  case "$nonce" in ''|0|*[!0-9]*) echo 'invalid run nonce' >&2; return 2 ;; esac
  printf '{"run_id":"%s","workload":"%s","mode":"%s","algorithm":"aes-128-ecb","total_bytes":1000000,"effective_total_bytes":999840,"security_batch_requests":8,"host_snapshot_protocol":1,"workers":%s,"repetition":%s,"positive":%s,"positive_run":"%s","nonce":"%s","swap_enabled":%s,"dump_enabled":%s,"cache_mode":"cold","random_seed":51,"environment_evidence":"../environment.txt","build_evidence":"../artifacts.sha256","kernel_evidence":"../kernel-build.txt","observer_evidence":"../observer-version.txt"}\n' \
    "$run_id" "$wl" "$io" "$n" "$rep" "$positive" "$reference" "$nonce" "$swap" "$dump" > "$dir/configuration.json"
  export GROUP_PMP_TEST_MODE=sqlite-bench GROUP_PMP_SQLITE_IO_MODE=$io
  export GROUP_PMP_SQLITE_MAX_WORKERS=4 GROUP_PMP_SQLITE_REPETITIONS=1 GROUP_PMP_SQLITE_TOTAL_BYTES=1000000
  export GROUP_PMP_SQLITE_CACHE_MODE=cold GROUP_PMP_SQLITE_RANDOM_SEED=51 GROUP_PMP_SQLITE_WORKLOAD_SET=random-pair
  export GROUP_PMP_SECURITY_CAPTURE_WORKERS=$n GROUP_PMP_SECURITY_CAPTURE_WORKLOAD=$wl
  export GROUP_PMP_SQLITE_STORAGE_DIR=$work GROUP_PMP_SQLITE_CSV=$dir/performance.csv GROUP_PMP_SQLITE_IO_RANGE_CSV=$dir/io.csv
  # Capture pauses are timed separately; retain finite preparation/run budgets.
  export GROUP_PMP_MIXED_TIMEOUT_SEC=3600 GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS=1800000
  if [ "$positive" = true ]; then
    export SECURITY_CAPTURE_POSITIVE=1 GROUP_PMP_SECURITY_CAPTURE_POSITIVE=1
  else unset SECURITY_CAPTURE_POSITIVE GROUP_PMP_SECURITY_CAPTURE_POSITIVE; fi
  dmesg > "$dir/kernel-before.log" 2>&1 || true
  status=captured-unverified
  printf '[security-capture-run] id=%s input=1MB workers=%s mode=%s positive=%s\n' "$run_id" "$n" "$io" "$positive"
  ./group-pmp-security-capture "$nonce" "$dir" "$work" -- ./group-pmp-test-runner > "$dir/run.log" 2>&1 || status=failed-or-incomplete
  dmesg > "$dir/kernel-after.log" 2>&1 || true
  printf '%s,%s,%s,aes-128-ecb,1000000,%s,%s,%s,,,,%s\n' "$run_id" "$wl" "$io" "$n" "$rep" "$status" "$run_id/run.log" >> "$matrix"
  printf '[security-capture-run] id=%s status=%s\n' "$run_id" "$status"
  rm -rf "$work"; work=
}
for wl in readrandom fillrandom; do
  for n in 1 4; do
    for io in sync-no-extent async-no-extent adaptive-extent; do
      rep=0; control=positive-$wl-N$n-$io
      run_capture true "$control" ''
      for rep in $(seq 1 "$repetitions"); do
        for algorithm in aes-128-ecb aes-128-gcm chacha20-poly1305; do
          id=$wl-N$n-$io-$algorithm-r$rep
          if [ "$algorithm" = aes-128-ecb ]; then run_capture false "$id" "$control"; else
            printf '%s,%s,%s,%s,1000000,%s,%s,unsupported,,,,standalone-AEAD-fixture-is-not-this-workload\n' "$id" "$wl" "$io" "$algorithm" "$n" "$rep" >> "$matrix"
          fi
        done
      done
    done
  done
done
printf '%s\n' '[security] capture finished, NOT a scan PASS. Copy this entire directory to the independent verifier.'
printf 'SECURITY_VERIFY_INDEPENDENT=1 sh ./run-security-experiments.sh verify 4 %s %s\n' "$repetitions" "$output"
if awk -F, 'NR>1 && $8=="failed-or-incomplete"{bad=1} END{exit bad?0:1}' "$matrix"; then
  echo '[security] workload/capture failures recorded; no successful expanded-scope conclusion' >&2
  exit 1
fi
