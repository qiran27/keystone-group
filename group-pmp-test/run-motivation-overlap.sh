#!/bin/sh
set -eu
cd "$(dirname "$0")"
usage() {
  echo "usage: $0 [repetitions=10] [sweep|60MB|100MB|200MB|300MB|400MB|500MB] [cold|hot] [data-dir=/myusb/wj/deploy] [output-dir=/motivation-overlap] [formal|diagnostic]" >&2
  echo 'Configurations: 1 Worker Sync, 1 Worker Async, 3 Workers Async; fixed total input. Formal accepts 3..100 runs per configuration/size (default 10); diagnostic accepts 1..100.' >&2
}
[ "$#" -le 6 ] || { usage; exit 2; }
repeats=${1:-10}; size=${2:-sweep}; cache=${3:-cold}
data=${4:-/myusb/wj/deploy}; output=${5:-/motivation-overlap}; kind=${6:-formal}
case "$repeats" in ''|*[!0-9]*) usage; exit 2 ;; esac
[ "$repeats" -ge 1 ] && [ "$repeats" -le 100 ] || { usage; exit 2; }
case "$kind" in
  formal) [ "$repeats" -ge 3 ] || { usage; exit 2; }; diagnostic=0 ;;
  diagnostic) diagnostic=1 ;;
  *) usage; exit 2 ;;
esac
architecture=${MOT_ARCHITECTURE:-0}
export MOT_BLOCK_BYTES=${MOT_BLOCK_BYTES:-65536}
case "$MOT_BLOCK_BYTES" in 4096|16384|65536) ;; *) echo 'unsupported motivation block size' >&2; exit 2 ;; esac
case "$architecture" in
  1) echo '[motivation] Minimal architecture: active Master, protected TSR task/result handoff, same storage/decrypt/check pipeline; no SQLite business.' >&2 ;;
  0) echo '[motivation] AUXILIARY controlled overlap test. For the minimal Master/TSR experiment use run-motivation-architecture.sh.' >&2 ;;
  *) usage; exit 2 ;;
esac
if [ "$architecture" = 1 ]; then
  export MOT_CIPHER=${MOT_CIPHER:-aes-ecb-128}
  case "$MOT_CIPHER" in aes-ecb-128|aes-gcm-128) ;; *) echo 'unsupported motivation cipher' >&2; exit 2 ;; esac
fi
case "$cache" in cold|hot) ;; *) usage; exit 2 ;; esac
case "$size" in
  sweep) sizes='60 100 200 300 400 500' ;;
  60MB|100MB|200MB|300MB|400MB|500MB) sizes=${size%MB} ;;
  *) usage; exit 2 ;;
esac
for f in group-pmp-test-runner group-pmp-motivation-worker.eapp_riscv eyrie-rt loader.bin; do
  [ -r "./$f" ] || { echo "[motivation] missing $f; rebuild and deploy" >&2; exit 1; }
done
grep -aFq 'keystone-motivation-epm-reservation-v2' ./group-pmp-test-runner || {
  echo '[motivation] runner lacks matched EPM reservation fix; rebuild and deploy runner' >&2; exit 1;
}
grep -aFq 'keystone-motivation-three-config-v2' ./group-pmp-test-runner || {
  echo '[motivation] runner lacks three-configuration experiment; rebuild and deploy' >&2; exit 1;
}
grep -aFq 'keystone-motivation-shared-uring-v3' ./group-pmp-test-runner || {
  echo '[motivation] runner lacks shared SQLite/FIO io_uring transport; rebuild and deploy' >&2; exit 1;
}
for f in group-pmp-test-runner group-pmp-motivation-worker.eapp_riscv; do
  grep -aFq 'keystone-worker-overlap-v7' "./$f" || { echo "[motivation] stale $f; deploy matching v7 runner and Worker" >&2; exit 1; }
done
grep -aFq 'keystone-motivation-blocking-ocall-v4' ./group-pmp-test-runner || {
  echo '[motivation] runner lacks blocking read OCALL contract v4; rebuild and deploy' >&2; exit 1;
}
if [ "$architecture" = 1 ]; then
  command -v python3 >/dev/null 2>&1 || { echo '[motivation] python3 is required to verify task witnesses and generate the timeline' >&2; exit 1; }
  for f in group-pmp-test-runner group-pmp-motivation-worker.eapp_riscv; do
    grep -aFq 'keystone-motivation-protected-task-v4' "./$f" || { echo "[motivation] stale $f; deploy matching protected-task v4 binaries" >&2; exit 1; }
  done
fi
[ -d "$data" ] && [ -w "$data" ] || { echo "[motivation] data directory not writable: $data" >&2; exit 1; }
data=$(CDPATH= cd "$data" && pwd)
mkdir -p "$output"
output=$(CDPATH= cd "$output" && pwd)
stamp=$(date +%Y%m%d-%H%M%S)-$$
if [ "$architecture" = 1 ]; then
  out=$output/$kind-$cache-${MOT_CIPHER:-aes-ecb-128}-${MOT_BLOCK_BYTES}B-$stamp
else
  out=$output/$kind-$cache-$stamp
fi
mkdir "$out"
lock=${GROUP_PMP_RUN_LOCK_DIR:-/tmp/keystone-group-pmp-p10.lock}
mkdir "$lock" 2>/dev/null || { echo '[motivation] benchmark lock exists; stop the other run or inspect stale lock' >&2; exit 1; }
printf '%s\n' "$$" > "$lock/pid"
work=; freq_locked=0
export GROUP_PMP_CPU_FREQ_STATE=/tmp/group-pmp-motivation-cpufreq.$$
cleanup() {
  [ "$freq_locked" = 0 ] || ./prepare-aes-benchmark-env.sh restore || true
  if [ -n "$work" ]; then
    # Only this invocation's uniquely created file, never a user's input file.
    rm -f "$work/cipher.bin"
    rmdir "$work" 2>/dev/null || true
  fi
  rm -f "$lock/pid" "$lock/runner-status" "$GROUP_PMP_CPU_FREQ_STATE"
  rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
work=$(mktemp -d "$data/.motivation-XXXXXXXX")
{
  printf 'command=sh %s %s %s %s %s %s %s\n' "$0" "$repeats" "$size" "$cache" "$data" "$output" "$kind"
  printf 'data_dir=%s\noutput_dir=%s\nseed=xorshift64:0x6d6f746976617431 XOR (block+1)\n' "$data" "$out"
  printf 'configurations=sync-1,async-1,async-3 active_master=%s host_cpu=0 worker_cpus=1..N io_threads=N slots_per_worker=2 backend=shared-io-uring-fixed\n' "$architecture"
  if [ "$architecture" = 1 ]; then
    echo 'task_transport=protected-TSR; one whole-range task per Worker; result grant revoked before Master aggregation'
    echo 'timing=master-first-dispatch-to-final-protected-aggregate; cache preparation once after all Workers warm'
    sha256sum run-motivation-architecture.sh
  else
    echo 'timing=shared-Host-start-release-to-final-validated-DONE; cache preparation once after all Workers warm'
  fi
  echo 'Sync=blocking read OCALL (handler returns only after CQE publication); Async=admission-only read OCALL plus two buffers'
  echo 'Storage, selected cipher, computation and group launch are shared; not an unmodified whole-system Keystone baseline'
  printf 'cipher=%s public-test-fixture-key-only; ECB is not authenticated encryption; input plaintext generated inside enclave\n' "${MOT_CIPHER:-aes-gcm-128}"
  printf 'block_bytes=%s full-byte-FNV-check=unchanged; stage-timestamps=diagnostic-only; sizes-analyzed-separately\n' "$MOT_BLOCK_BYTES"
  echo 'clock=rdtime; hot=whole-file-read; cold=fdatasync+fadvise-dontneed+mincore-zero-required'
  uname -a
  cat /proc/cpuinfo /proc/mounts
  df -P "$data"
  ./group-pmp-test-runner --artifact-info
  for f in group-pmp-test-runner group-pmp-motivation-worker.eapp_riscv eyrie-rt loader.bin run-motivation-overlap.sh motivation/summarize.py; do sha256sum "$f"; done
  [ ! -f motivation/source-sha256.txt ] || cat motivation/source-sha256.txt
} > "$out/environment.txt" 2>&1
freq_locked=1
./prepare-aes-benchmark-env.sh apply > "$out/frequency-setup.log" 2>&1
./prepare-3w1hm-isolation.sh apply > "$out/isolation-setup.log" 2>&1
for p in /sys/devices/system/cpu/cpufreq/policy*; do
  [ -d "$p" ] || continue
  for f in affected_cpus scaling_governor scaling_min_freq scaling_max_freq scaling_cur_freq; do
    printf '%s=' "$p/$f" >> "$out/environment.txt"
    cat "$p/$f" >> "$out/environment.txt" 2>/dev/null || true
  done
done
export GROUP_PMP_TEST_MODE=motivation MOT_CACHE=$cache MOT_DIAGNOSTIC=$diagnostic
export MOT_CSV=$out/samples.csv MOT_FILE=$work/cipher.bin
unset GROUP_PMP_SECURITY_SENTINEL GROUP_PMP_SECURITY_NONCE GROUP_PMP_SECURITY_REGIONS GROUP_PMP_SECURITY_WORKER_SET
unset GROUP_PMP_SQLITE_GANTT_CSV GROUP_PMP_SQLITE_IO_RANGE_CSV GROUP_PMP_SQLITE_MERGE_PROFILE
printf 'size_mb,object,file_bytes,sha256\n' > "$out/inputs.csv"
printf 'input_mb,repetition,order,mode,worker_enclaves,run_id\n' > "$out/order.csv"
run() {
  echo "[motivation] $MOT_RUN_ID ($kind); log=$out/$MOT_RUN_ID.log"
  if ./group-pmp-test-runner > "$out/$MOT_RUN_ID.log" 2>&1; then
    tail -n 2 "$out/$MOT_RUN_ID.log"
  else
    tail -n 30 "$out/$MOT_RUN_ID.log" >&2
    echo '[motivation] failed; log and any sample row retained. No replacement samples.' >&2
    exit 1
  fi
}
for mb in $sizes; do
  export MOT_BYTES=$((mb * 1000000))
  MOT_OBJECT=$(od -An -N8 -tu8 /dev/urandom | tr -d ' \n')
  case "$MOT_OBJECT" in ''|0|*[!0-9]*) echo 'cannot generate object nonce' >&2; exit 1 ;; esac
  export MOT_OBJECT MOT_MODE=prepare MOT_WORKERS=1 MOT_RUN_ID=prepare-${mb}MB MOT_EXPERIMENT_BLOCK=prepare MOT_ORDER=0
  run
  before=$(sha256sum "$MOT_FILE" | awk '{print $1}')
  bytes=$(wc -c < "$MOT_FILE" | tr -d ' ')
  printf '%s,%s,%s,%s\n' "$mb" "$MOT_OBJECT" "$bytes" "$before" >> "$out/inputs.csv"
  r=1
  while [ "$r" -le "$repeats" ]; do
    case $((r % 3)) in
      1) configurations='sync-1 async-1 async-3' ;;
      2) configurations='async-1 async-3 sync-1' ;;
      0) configurations='async-3 sync-1 async-1' ;;
    esac
    order=1
    for configuration in $configurations; do
      m=${configuration%-*}; n=${configuration##*-}
      export MOT_MODE=$m MOT_WORKERS=$n MOT_RUN_ID=${mb}MB-r$r-$configuration MOT_EXPERIMENT_BLOCK=${mb}MB-r$r MOT_ORDER=$order
      export MOT_TRACE=$out/$MOT_RUN_ID-trace.csv
      printf '%s,%s,%s,%s,%s,%s\n' "$mb" "$r" "$order" "$m" "$n" "$MOT_RUN_ID" >> "$out/order.csv"
      run
      order=$((order + 1))
    done
    r=$((r + 1))
  done
  if [ "$architecture" = 1 ] && [ "$kind" = formal ]; then
    # Separate instrumentation runs never enter the uninstrumented medians.
    export MOT_DIAGNOSTIC=1
    order=1
    for configuration in sync-1 async-1 async-3; do
      m=${configuration%-*}; n=${configuration##*-}
      export MOT_MODE=$m MOT_WORKERS=$n MOT_RUN_ID=${mb}MB-diagnostic-$configuration MOT_EXPERIMENT_BLOCK=${mb}MB-diagnostic MOT_ORDER=$order
      export MOT_TRACE=$out/$MOT_RUN_ID-trace.csv
      printf '%s,diagnostic,%s,%s,%s,%s\n' "$mb" "$order" "$m" "$n" "$MOT_RUN_ID" >> "$out/order.csv"
      run
      order=$((order + 1))
    done
    export MOT_DIAGNOSTIC=$diagnostic
  fi
  after=$(sha256sum "$MOT_FILE" | awk '{print $1}')
  [ "$before" = "$after" ] || { echo '[motivation] input changed during experiment' >&2; exit 1; }
  rm -f "$MOT_FILE"
done
if command -v python3 >/dev/null 2>&1; then
  python3 ./motivation/summarize.py "$out"
else
  echo "[motivation] summarize on analysis PC: python3 motivation/summarize.py $out --plot"
fi
echo "[motivation] complete: $out; formal results and diagnostic traces are separate"
