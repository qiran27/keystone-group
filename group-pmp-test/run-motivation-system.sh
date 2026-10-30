#!/bin/sh
# Primary architecture motivation: the real Master/TSR/Worker/Host path.
# Not an isolated buffer-overlap test or an unmodified upstream baseline.
set -eu
cd "$(dirname "$0")"
interface=sqlite
while [ "$#" -gt 0 ]; do
  case "$1" in
    --interface|--cipher)
      [ "$#" -ge 2 ] || { echo "missing $1 value" >&2; exit 2; }
      case "$1" in --interface) interface=$2 ;; --cipher) GROUP_PMP_BENCH_CIPHER=$2 ;; esac
      shift 2 ;;
    --*) echo "unknown option: $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
case "$interface" in sqlite|fio) ;; *) echo 'production interface must be sqlite or fio' >&2; exit 2 ;; esac
. ./run-benchmark-cipher.sh
usage() {
  echo 'usage: sh run-motivation-system.sh [--interface sqlite|fio] [--cipher aes-ecb-128|aes-gcm-128|chacha20-poly1305] [repetitions=10] [size=500MB] [cold|hot] [data-dir=/myusb/wj/deploy] [output-dir=/motivation-system] [formal|diagnostic]' >&2
  echo 'Architecture configurations: Sync1, Async1, Async3; formal accepts 3..20 repetitions, then three separate timeline runs.' >&2
}
[ "$#" -le 6 ] || { usage; exit 2; }
reps=${1:-10}; size=${2:-500MB}; cache=${3:-cold}
data=${4:-/myusb/wj/deploy}; output=${5:-/motivation-system}; kind=${6:-formal}
case "$reps" in ''|*[!0-9]*) usage; exit 2;; esac
[ "$reps" -ge 1 ] && [ "$reps" -le 20 ] || { usage; exit 2; }
case "$kind" in formal) [ "$reps" -ge 3 ] || { usage; exit 2; };; diagnostic) ;; *) usage; exit 2;; esac
case "$size" in 60MB|100MB|200MB|300MB|400MB|500MB) ;; *) usage; exit 2;; esac
case "$cache" in cold|hot) ;; *) usage; exit 2;; esac
[ -d "$data" ] && [ -w "$data" ] || { echo '[motivation-system] data directory is absent or not writable' >&2; exit 1; }
command -v python3 >/dev/null || { echo '[motivation-system] python3 is required for real-data summary and SVG figures' >&2; exit 1; }
for f in group-pmp-test-runner group-pmp-sqlite-worker.eapp_riscv; do
  grep -aFq 'keystone-motivation-real-system-v1' "$f" || {
    echo "[motivation-system] stale $f; rebuild and deploy real-system runner and Worker" >&2; exit 1;
  }
done
require_benchmark_cipher ./group-pmp-test-runner ./group-pmp-sqlite-worker.eapp_riscv
grep -aFq 'keystone-motivation-production-interface-v1' ./group-pmp-test-runner || {
  echo '[motivation-system] runner lacks production interface selection; rebuild and deploy' >&2; exit 1;
}
if [ "$interface" = fio ]; then
  grep -aFq 'keystone-fio-enclave-profile-v1' ./group-pmp-test-runner || {
    echo '[motivation-system] runner lacks production fio profile; rebuild and deploy' >&2; exit 1;
  }
fi
for f in group-pmp-sqlite-master.eapp_riscv eyrie-rt loader.bin; do
  [ -r "./$f" ] || { echo "[motivation-system] missing production artifact: $f; deploy the complete build" >&2; exit 1; }
done
grep -aFq 'keystone-sqlite-host-engine-v1' ./group-pmp-sqlite-master.eapp_riscv || {
  echo '[motivation-system] production task Master is missing its engine marker; rebuild/deploy' >&2; exit 1;
}
echo '[motivation-system] PRIMARY architecture experiment: real Master -> protected TSR task -> Worker -> Host I/O -> completion -> Master aggregation'
echo '[motivation-system] The separate run-motivation-overlap.sh results are controlled auxiliary measurements, not this architecture experiment.'
data=$(CDPATH= cd "$data" && pwd)
mkdir -p "$output"; output=$(CDPATH= cd "$output" && pwd)
out=$output/production-$interface-$kind-$BENCH_CIPHER_SUFFIX-$cache-$(date +%Y%m%d-%H%M%S)-$$
mkdir "$out"
work=
cleanup() {
  case "$work" in "$data"/.motivation-system-*) [ ! -d "$work" ] || rm -r "$work";; '') ;; *) echo 'refusing unsafe cleanup' >&2;; esac
  work=
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
# Prevent inherited diagnostics, baselines or tuning from changing this protocol.
for name in $(env | sed -n 's/^\(GROUP_PMP_SQLITE_[A-Za-z0-9_]*\|GROUP_PMP_SECURITY_[A-Za-z0-9_]*\|GROUP_PMP_MOTIVATION_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$name"; done
unset GROUP_PMP_FIO_PROFILE
export GROUP_PMP_MOTIVATION_SYSTEM=1 GROUP_PMP_SQLITE_RANDOM_SEED=1397519439
export GROUP_PMP_MOTIVATION_INTERFACE=$interface
if [ "$interface" = fio ]; then export GROUP_PMP_FIO_PROFILE=seq-read-2m; fi
: "${GROUP_PMP_MIXED_STALL_TIMEOUT_SEC:=600}"
export GROUP_PMP_MIXED_STALL_TIMEOUT_SEC
export GROUP_PMP_SQLITE_OUTPUT_DIR=$out
{
  printf 'experiment=Extent-I/O real-system motivation\nsize=%s\ncache=%s\ncipher=%s\nrepetitions=%s\nkind=%s\ndata_dir=%s\n' "$size" "$cache" "$GROUP_PMP_BENCH_CIPHER" "$reps" "$kind" "$data"
  printf 'interface=%s\nexecution_path=production-worker-vfs-and-host-service; no private motivation Backend\n' "$interface"
  echo 'configurations=sync-1,async-1,async-3; real master/worker; production sequential-read; 2x2MB UTM per Worker; no clustering'
  echo 'experiment_role=primary-architecture-motivation; controller=group-pmp-sqlite-master.eapp_riscv; protected-TSR-task-dispatch-and-result-return=production'
  echo 'Sync=production SQLite ciphertext-BLOB service; Async=production metadata+external-ciphertext asynchronous service; gains are whole-system, not overlap-only'
  echo 'timing=production master-first-dispatch-to-final-aggregate; traces are separate diagnostic runs'
  echo 'effective input is rounded down to full 240-byte records by the existing production workload; read actual total_bytes'
  uname -a
  cat /proc/mounts
  df -P "$data"
  ./group-pmp-test-runner --artifact-info
  for f in group-pmp-test-runner group-pmp-sqlite-worker.eapp_riscv group-pmp-sqlite-master.eapp_riscv eyrie-rt loader.bin run-motivation-architecture.sh run-motivation-system.sh run-p10-mixed-scaling.sh motivation/system-summary.py; do sha256sum "$f"; done
} > "$out/environment.txt" 2>&1
printf 'kind,run_id,repetition,order,mode,workers,performance_csv,io_csv,gantt_csv,crypto_csv,status,interface\n' > "$out/manifest.csv"
run_case() {
  run_kind=$1; rep=$2; order=$3; configuration=$4
  mode=${configuration%-*}; workers=${configuration##*-}
  case "$mode" in sync) io_mode=sync-no-extent;; async) io_mode=async-no-extent;; esac
  id=$run_kind-r$rep-$configuration
  folder=$out/$id; mkdir "$folder"
  work=$(mktemp -d "$data/.motivation-system-XXXXXXXX")
  export GROUP_PMP_SQLITE_STORAGE_DIR=$work GROUP_PMP_MOTIVATION_WORKERS=$workers
  export GROUP_PMP_SQLITE_CSV=$folder/performance.csv GROUP_PMP_SQLITE_IO_RANGE_CSV=$folder/io.csv
  gantt=; crypto=
  if [ "$run_kind" = timeline ]; then
    gantt=$id/host-events.csv; crypto=$id/crypto.csv
    export GROUP_PMP_SQLITE_GANTT_CSV=$out/$gantt GROUP_PMP_MOTIVATION_CRYPTO_CSV=$out/$crypto
    export GROUP_PMP_SQLITE_GANTT_MAX_EVENTS=131072
  else
    unset GROUP_PMP_SQLITE_GANTT_CSV GROUP_PMP_MOTIVATION_CRYPTO_CSV
  fi
  echo "[motivation-system] $id input=$size cipher=$GROUP_PMP_BENCH_CIPHER; log=$folder/run.log"
  printf '%s\n' "$id" > "$out/current-run.txt"
  status=complete
  if ! sh ./run-p10-mixed-scaling.sh --cipher "$GROUP_PMP_BENCH_CIPHER" sqlite-bench "$io_mode" "$workers" 1 "$size" "$cache" > "$folder/run.log" 2>&1; then status=failed; fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$run_kind" "$id" "$rep" "$order" "$mode" "$workers" "$id/performance.csv" "$id/io.csv" "$gantt" "$crypto" "$status" "$interface" >> "$out/manifest.csv"
  cleanup
  if [ "$status" != complete ]; then
    tail -n 35 "$folder/run.log" >&2
    echo '[motivation-system] stopped; raw failure retained, no replacement samples' >&2; exit 1
  fi
  tail -n 2 "$folder/run.log"
}
r=1
while [ "$r" -le "$reps" ]; do
  case $((r % 3)) in 1) cases='sync-1 async-1 async-3';; 2) cases='async-1 async-3 sync-1';; 0) cases='async-3 sync-1 async-1';; esac
  n=1
  for c in $cases; do run_case "$kind" "$r" "$n" "$c"; n=$((n+1)); done
  r=$((r+1))
done
# Three separate trace runs are never pooled into the performance medians.
n=1
for c in sync-1 async-1 async-3; do run_case timeline 1 "$n" "$c"; n=$((n+1)); done
python3 ./motivation/system-summary.py "$out"
echo "[motivation-system] complete: $out; performance.svg and timeline.svg; measured data only"
