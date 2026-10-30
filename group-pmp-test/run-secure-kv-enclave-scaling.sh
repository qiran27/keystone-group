#!/bin/sh
set -eu
cd "$(dirname "$0")"
. ./run-benchmark-cipher.sh
usage() {
  echo "  prefix option: --cipher aes-ecb-128|aes-gcm-128|chacha20-poly1305" >&2
  echo "usage: $0 [all|put|get|update] [all|both|sync|async|adaptive] [max-workers:1..15] [repetitions:1..20] [60MB..500MB|sweep] [hot|cold] [output-dir]" >&2
  echo 'defaults: all all 15 5 sweep cold /secure-kv-bench-{ecb,gcm,chacha}' >&2
  echo 'both=Async+Adaptive; all=Sync+Async+Adaptive; sweep=60,100,200,300,400,500MB' >&2
  echo 'KV_ENCLAVE_STORAGE_DIR defaults to /tmp (RAM-backed on this board); KV_ENCLAVE_OUTPUT_DIR overrides results' >&2
  echo 'Selectable cipher pipeline benchmark; test-only key initialization; NO rollback claim' >&2
}
[ "$#" -le 7 ] || { usage; exit 2; }
profile=${1:-all}; selection=${2:-all}; workers=${3:-15}; repeats=${4:-5}
size=${5:-sweep}; cache=${6:-cold}
output=${7:-${KV_ENCLAVE_OUTPUT_DIR:-/secure-kv-bench-$BENCH_CIPHER_SUFFIX}}
storage=${KV_ENCLAVE_STORAGE_DIR:-/tmp}
case "$profile" in all) profiles='put get update' ;; put|get|update) profiles=$profile ;; *) usage; exit 2 ;; esac
case "$selection" in
  all) modes='sync async adaptive' ;; both) modes='async adaptive' ;;
  sync|async|adaptive) modes=$selection ;; *) usage; exit 2 ;;
esac
case "$workers:$repeats" in ''|*[!0-9:]*|:*|*:) usage; exit 2 ;; esac
[ "$workers" -ge 1 ] && [ "$workers" -le 15 ] &&
  [ "$repeats" -ge 1 ] && [ "$repeats" -le 20 ] || { usage; exit 2; }
case "$size" in
  sweep) sizes='60 100 200 300 400 500' ;;
  *MB)
    mb=${size%MB}; case "$mb" in ''|*[!0-9]*) usage; exit 2 ;; esac
    [ "$mb" -ge 60 ] && [ "$mb" -le 500 ] || { usage; exit 2; }; sizes=$mb ;;
  *) usage; exit 2 ;;
esac
case "$cache" in hot|cold) ;; *) usage; exit 2 ;; esac
case "$output:$storage" in /*:/*) ;; *) echo '[secure-kv][ERROR] absolute data/result paths required' >&2; exit 2 ;; esac
if [ "${KV_ENCLAVE_DRY_RUN:-0}" = 1 ]; then
  for mb in $sizes; do for p in $profiles; do
    echo "[secure-kv][DRY-RUN] size=${mb}MB profile=$p modes=$modes workers=1..$workers repetitions=$repeats cache=$cache data=$storage results=$output"
  done; done
  exit 0
fi
for artifact in group-pmp-test-runner group-pmp-kv-worker.eapp_riscv group-pmp-sqlite-master.eapp_riscv eyrie-rt loader.bin; do
  [ -r "./$artifact" ] || { echo "[secure-kv][ERROR] missing $artifact; rebuild/deploy" >&2; exit 1; }
done
for artifact in group-pmp-test-runner group-pmp-kv-worker.eapp_riscv; do
  grep -aFq 'keystone-enclave-kv-pipeline-v1' "./$artifact" || {
    echo "[secure-kv][ERROR] stale KV artifact: $artifact; rebuild/deploy" >&2; exit 1;
  }
done
[ -x ./group-pmp-test-runner ] && [ -r ./run-secure-kv-comparison.sh ] || exit 1
require_benchmark_cipher ./group-pmp-test-runner ./group-pmp-kv-worker.eapp_riscv
mkdir -p "$output" "$storage"
output=$(CDPATH= cd "$output" && pwd -P); storage=$(CDPATH= cd "$storage" && pwd -P)
lock=${GROUP_PMP_RUN_LOCK_DIR:-/tmp/keystone-group-pmp-p10.lock}
# Never remove a lock owned by another test, even if its PID looks stale.
mkdir "$lock" 2>/dev/null || { echo '[secure-kv][ERROR] benchmark lock exists' >&2; exit 1; }
printf '%s\n' "$$" > "$lock/pid"
work=; freq_locked=0
GROUP_PMP_CPU_FREQ_STATE=/tmp/group-pmp-kv-cpufreq.$$
export GROUP_PMP_CPU_FREQ_STATE
cleanup() {
  if [ "$freq_locked" = 1 ]; then ./prepare-aes-benchmark-env.sh restore || true; fi
  case "$work" in "$storage"/.keystone-kv-*) rm -rf "$work" ;; esac
  rm -f "$lock/pid" "$GROUP_PMP_CPU_FREQ_STATE"
  rmdir "$lock" 2>/dev/null || true
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
freq_locked=1
./prepare-aes-benchmark-env.sh apply
./prepare-3w1hm-isolation.sh apply
stamp=${KV_ENCLAVE_RUN_ID:-$(date +%Y%m%d-%H%M%S)-$$}
case "$stamp" in ''|*[!a-zA-Z0-9_-]*) echo '[secure-kv][ERROR] invalid run id' >&2; exit 2 ;; esac
export GROUP_PMP_TEST_MODE=secure-kv-bench GROUP_PMP_SQLITE_CACHE_MODE=$cache
export GROUP_PMP_SQLITE_STORAGE_DIR=$storage GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER=4000000
export GROUP_PMP_KV_MAX_WORKERS=$workers GROUP_PMP_KV_REPETITIONS=$repeats
export GROUP_PMP_MIXED_TIMEOUT_SEC=${KV_ENCLAVE_TIMEOUT_SEC:-3600}
export GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS=${KV_ENCLAVE_WARMUP_TIMEOUT_MS:-1800000}
unset GROUP_PMP_SECURITY_SENTINEL GROUP_PMP_SECURITY_NONCE GROUP_PMP_SECURITY_WORKER_SET
unset GROUP_PMP_FIO_PROFILE GROUP_PMP_SQLITE_WORKLOAD_SET GROUP_PMP_SQLITE_NEIGHBOR_ONLY
unset GROUP_PMP_SQLITE_CLUSTER_MODE GROUP_PMP_SQLITE_GANTT_CSV GROUP_PMP_SQLITE_IO_RANGE_CSV
unset GROUP_PMP_SQLITE_ADDRESS_MODE GROUP_PMP_SQLITE_SEEDED_PAGE_PERMUTATION
[ ! -e "$output/kv-$stamp-artifact-info.log" ] || {
  echo '[secure-kv][ERROR] output collision; choose a new run id' >&2; exit 1;
}
./group-pmp-test-runner --artifact-info > "$output/kv-$stamp-artifact-info.log"
echo "[secure-kv] cipher=$GROUP_PMP_BENCH_CIPHER key_source=SM-platform-test-only no-rollback-protection"
[ "$repeats" -ge 5 ] || echo '[secure-kv][PREVIEW] fewer than five repetitions'
case "$selection" in
  adaptive|both|all)
    if [ -z "${GROUP_PMP_SQLITE_MERGE_PROFILE:-}" ]; then
      GROUP_PMP_SQLITE_MERGE_PROFILE=$output/kv-$stamp-$cache.profile
      samples=${GROUP_PMP_SQLITE_CALIBRATION_SAMPLES:-93}
      ./group-pmp-test-runner --sqlite-io-calibrate "$samples" "$GROUP_PMP_SQLITE_MERGE_PROFILE" > "$GROUP_PMP_SQLITE_MERGE_PROFILE.log" 2>&1
    fi
    [ -r "$GROUP_PMP_SQLITE_MERGE_PROFILE" ] || { echo '[secure-kv][ERROR] merge profile unavailable' >&2; exit 1; }
    export GROUP_PMP_SQLITE_MERGE_PROFILE ;;
esac
for mb in $sizes; do
  export GROUP_PMP_SQLITE_TOTAL_BYTES=$((mb * 1000000))
  for p in $profiles; do
    prefix=$output/secure-kv-$p-$cache-${mb}MB-1-$workers-$stamp
    for m in $modes; do
      for suffix in .csv -samples.csv -io.csv .log; do
        [ ! -e "$prefix-$m$suffix" ] || { echo '[secure-kv][ERROR] output collision; choose a new run id' >&2; exit 1; }
      done
      work=$(mktemp -d "$storage/.keystone-kv-XXXXXXXX")
      export GROUP_PMP_SQLITE_STORAGE_DIR=$work GROUP_PMP_KV_PROFILE=$p
      case "$m" in sync|async) GROUP_PMP_SQLITE_IO_MODE=$m-no-extent ;; adaptive) GROUP_PMP_SQLITE_IO_MODE=adaptive-extent ;; esac
      export GROUP_PMP_SQLITE_IO_MODE
      export GROUP_PMP_KV_CSV=$prefix-$m.csv GROUP_PMP_KV_SAMPLES_CSV=$prefix-$m-samples.csv GROUP_PMP_KV_IO_CSV=$prefix-$m-io.csv
      echo "[secure-kv] size=${mb}MB workload=$p mode=$m workers=1..$workers repeats=$repeats"
      (
        set +e
        ./group-pmp-test-runner
        status=$?
        printf '%s\n' "$status" > "$work/runner-status"
      ) 2>&1 | tee "$prefix-$m.log"
      status=$(cat "$work/runner-status" 2>/dev/null || echo 1)
      [ "$status" -eq 0 ] || { echo '[secure-kv][ERROR] failed; samples/log retained, no comparison published' >&2; exit 1; }
      rm -rf "$work"; work=
    done
    case "$selection" in
      all|both) sh ./run-secure-kv-comparison.sh "$prefix" "$workers" "$selection" ;;
    esac
  done
done
echo "[secure-kv] complete: $output"
