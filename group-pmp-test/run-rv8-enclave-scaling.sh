#!/bin/sh
set -eu
cd "$(dirname "$0")"
usage() {
  echo "usage: $0 [all|bigint|miniz|norx|aes|qsort|sha-512|dhrystone|primes] [both|sync|async] [max-workers:1..15] [repetitions:1..20] [60MB|100MB|200MB|300MB|400MB|500MB|sweep] [output-dir]" >&2
  echo "defaults: all both 15 5 sweep /rv8-bench; pure enclave compute, both labels use identical execution; MB denotes work scale" >&2
}
[ "$#" -le 6 ] || { usage; exit 2; }
kernel=${1:-all}; mode=${2:-both}; workers=${3:-15}; repeats=${4:-5}; size=${5:-sweep}
output=${6:-${GROUP_PMP_RV8_OUTPUT_DIR:-/rv8-bench}}
case "$kernel" in
  all) kernels="aes bigint dhrystone miniz norx primes qsort sha-512" ;;
  bigint|miniz|norx|aes|qsort|sha-512|dhrystone|primes) kernels=$kernel ;;
  sha512) kernels=sha-512 ;;
  *) usage; exit 2 ;;
esac
case "$mode" in
  both) modes="sync async" ;;
  sync|async) modes=$mode ;;
  *) usage; exit 2 ;;
esac
case "$workers:$repeats" in ''|*[!0-9:]*|:*|*:) usage; exit 2 ;; esac
[ "$workers" -ge 1 ] && [ "$workers" -le 15 ] &&
  [ "$repeats" -ge 1 ] && [ "$repeats" -le 20 ] || { usage; exit 2; }
case "$size" in
  sweep) sizes="60 100 200 300 400 500" ;;
  60MB|100MB|200MB|300MB|400MB|500MB) sizes=${size%MB} ;;
  *) usage; exit 2 ;;
esac
for artifact in group-pmp-test-runner group-pmp-sqlite-master.eapp_riscv eyrie-rt loader.bin; do
  [ -r "./$artifact" ] || { echo "[rv8][ERROR] missing $artifact; rebuild and deploy" >&2; exit 1; }
done
grep -aFq 'keystone-rv8-enclave-compute-v2' ./group-pmp-test-runner || {
  echo '[rv8][ERROR] stale runner; rebuild and deploy' >&2; exit 1;
}
grep -aFq 'keystone-rv8-control-only-v2' ./group-pmp-test-runner || {
  echo '[rv8][ERROR] runner lacks compute-only control; rebuild and deploy' >&2; exit 1;
}
for k in $kernels; do
  grep -aFq 'keystone-rv8-enclave-compute-v2' "./group-pmp-rv8-$k-worker.eapp_riscv" || {
    echo "[rv8][ERROR] missing/stale worker: $k" >&2; exit 1;
  }
done
mkdir -p "$output"
output=$(CDPATH= cd "$output" && pwd)
lock=${GROUP_PMP_RUN_LOCK_DIR:-/tmp/keystone-group-pmp-p10.lock}
if ! mkdir "$lock" 2>/dev/null; then
  owner=$(cat "$lock/pid" 2>/dev/null || true)
  if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
    echo "[rv8][ERROR] another benchmark owns the worker lanes: $owner" >&2; exit 1
  fi
  rm -f "$lock/pid"
  rmdir "$lock" && mkdir "$lock" || exit 1
fi
printf '%s\n' "$$" > "$lock/pid"
freq_locked=0
GROUP_PMP_CPU_FREQ_STATE=/tmp/group-pmp-rv8-cpufreq.$$
export GROUP_PMP_CPU_FREQ_STATE
cleanup() {
  if [ "$freq_locked" = 1 ]; then
    ./prepare-aes-benchmark-env.sh restore || true
    freq_locked=0
  fi
  rm -f "$lock/runner-status"
  rm -f "$lock/pid" "$GROUP_PMP_CPU_FREQ_STATE"
  rmdir "$lock" 2>/dev/null || true
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
freq_locked=1
./prepare-aes-benchmark-env.sh apply
./prepare-3w1hm-isolation.sh apply
stamp=$(date +%Y%m%d-%H%M%S)-$$
export GROUP_PMP_TEST_MODE=rv8-bench
unset GROUP_PMP_SQLITE_STORAGE_DIR GROUP_PMP_SQLITE_CACHE_MODE
export GROUP_PMP_RV8_MAX_WORKERS=$workers GROUP_PMP_RV8_REPETITIONS=$repeats
export GROUP_PMP_MIXED_TIMEOUT_SEC=${GROUP_PMP_RV8_TIMEOUT_SEC:-3600}
export GROUP_PMP_MIXED_STALL_TIMEOUT_SEC=${GROUP_PMP_MIXED_STALL_TIMEOUT_SEC:-600}
export GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS=180000
# Do not inherit security/diagnostic protocols or unrelated output requests.
unset GROUP_PMP_SECURITY_SENTINEL GROUP_PMP_SQLITE_GANTT_CSV GROUP_PMP_SQLITE_IO_RANGE_CSV
unset GROUP_PMP_SECURITY_NONCE GROUP_PMP_SECURITY_REGIONS GROUP_PMP_SECURITY_WORKER_SET
unset GROUP_PMP_SQLITE_NEIGHBOR_ONLY GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV
unset GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV GROUP_PMP_SQLITE_MERGE_PROFILE
[ "$repeats" -ge 5 ] || echo '[rv8][PREVIEW] fewer than five measured repetitions'
for mb in $sizes; do
  export GROUP_PMP_SQLITE_TOTAL_BYTES=$((mb * 1000000))
  for k in $kernels; do
    prefix=$output/rv8-$k-${mb}MB-1-$workers-$stamp
    for m in $modes; do
      export GROUP_PMP_RV8_KERNEL=$k
      export GROUP_PMP_SQLITE_IO_MODE=$m-no-extent
      export GROUP_PMP_RV8_CSV=$prefix-$m.csv GROUP_PMP_RV8_SAMPLES_CSV=$prefix-$m-samples.csv
      echo "[rv8] size=${mb}MB kernel=$k mode=$m workers=1..$workers repeats=$repeats csv=$GROUP_PMP_RV8_CSV"
      # POSIX sh has no pipefail. Preserve the runner status independently of tee.
      (
        set +e
        ./group-pmp-test-runner
        status=$?
        printf '%s\n' "$status" > "$lock/runner-status"
      ) 2>&1 | tee "$prefix-$m.log"
      status=$(cat "$lock/runner-status" 2>/dev/null || echo 1)
      if [ "$status" -ne 0 ]; then
        echo '[rv8][ERROR] failed run; samples/log preserved, no comparison published' >&2
        exit 1
      fi
      rm -f "$lock/runner-status"
    done
    if [ "$mode" = both ]; then
      awk -F, '
        NR==FNR { if (FNR>1) { s[$4]=$11; h[$4]=$18; b[$4]=$6; r[$4]=$5 } next }
        FNR==1 { print "kernel,workers,total_bytes,sample_count,sync_mb_per_sec_median,async_mb_per_sec_median,async_vs_sync_gain_pct,sync_host_operations_median,async_host_operations_median,host_operation_reduction_pct"; next }
        { n=$4; if (!(n in s) || s[n]<=0 || b[n]!=$6 || r[n]!=$5 || h[n]!=0 || $18!=0) exit 2;
          printf "%s,%d,%.0f,%d,%.9f,%.9f,%.6f,0,0,\n",$2,n,$6,$5,s[n],$11,100*($11/s[n]-1); count++ }
        END { if (count!=expected) exit 2 }
      ' expected="$workers" "$prefix-sync.csv" "$prefix-async.csv" > "$prefix-comparison.csv.tmp"
      mv "$prefix-comparison.csv.tmp" "$prefix-comparison.csv"
    fi
  done
done
echo "[rv8] complete: $output (summary, raw samples, logs and same-N comparisons)"
