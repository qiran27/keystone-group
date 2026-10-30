#!/bin/sh
set -eu
cd "$(dirname "$0")"
usage() {
  echo "usage: $0 [--cipher all|aes-ecb-128|aes-gcm-128|chacha20-poly1305] [repetitions:1..20] [60MB|100MB|200MB|300MB|400MB|500MB|sweep] [output-dir]" >&2
  echo 'defaults: all, 3 sweep /crypto-compute-bench; ECB then GCM then ChaCha, one cipher at a time, one Worker' >&2
}
cipher=all
if [ "${1:-}" = --cipher ]; then
  [ "$#" -ge 2 ] || { usage; exit 2; }
  cipher=$2; shift 2
fi
case "$cipher" in
  all|aes-ecb-128|aes-gcm-128|chacha20-poly1305) ;;
  chachaploy1305) cipher=chacha20-poly1305 ;;
  *) usage; exit 2 ;;
esac
[ "$#" -le 3 ] || { usage; exit 2; }
repeats=${1:-3}; size=${2:-sweep}; output=${3:-/crypto-compute-bench}
case "$repeats" in ''|*[!0-9]*) usage; exit 2 ;; esac
[ "$repeats" -ge 1 ] && [ "$repeats" -le 20 ] || { usage; exit 2; }
case "$size" in 60MB|100MB|200MB|300MB|400MB|500MB|sweep) ;; *) usage; exit 2 ;; esac
case "$output" in /*) ;; *) echo '[crypto-compute] output path must be absolute' >&2; exit 2 ;; esac
command -v python3 >/dev/null || { echo '[crypto-compute] python3 is required for sample validation/CSV summaries' >&2; exit 1; }
mkdir -p "$output"
output=$(CDPATH= cd "$output" && pwd -P)
run_dir=$(mktemp -d "$output/run-$cipher-$(date +%Y%m%d-%H%M%S)-XXXXXXXX")
python3 ./crypto-compute/summarize.py plan "$repeats" "$size" "$run_dir/plan.csv" --cipher "$cipher"
if [ "${CRYPTO_COMPUTE_DRY_RUN:-0}" = 1 ]; then
  cat "$run_dir/plan.csv"
  echo "[crypto-compute] DRY-RUN only; plan=$run_dir/plan.csv"
  exit 0
fi
for artifact in group-pmp-test-runner group-pmp-crypto-compute-worker.eapp_riscv eyrie-rt loader.bin; do
  [ -r "./$artifact" ] || { echo "[crypto-compute] missing $artifact; rebuild/deploy" >&2; exit 1; }
done
for artifact in group-pmp-test-runner group-pmp-crypto-compute-worker.eapp_riscv; do
  grep -aFq 'keystone-crypto-compute-startup-v2' "./$artifact" || {
    echo "[crypto-compute] stale $artifact; rebuild/deploy" >&2; exit 1;
  }
done
lock=${GROUP_PMP_RUN_LOCK_DIR:-/tmp/keystone-group-pmp-p10.lock}
if ! mkdir "$lock" 2>/dev/null; then
  owner=$(cat "$lock/pid" 2>/dev/null || true)
  if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
    echo "[crypto-compute] another benchmark owns the worker harts: $owner" >&2; exit 1
  fi
  rm -f "$lock/pid"
  rmdir "$lock" && mkdir "$lock" || exit 1
fi
printf '%s\n' "$$" > "$lock/pid"
freq_locked=0
GROUP_PMP_CPU_FREQ_STATE=/tmp/group-pmp-crypto-compute-cpufreq.$$
export GROUP_PMP_CPU_FREQ_STATE
cleanup() {
  if [ "$freq_locked" = 1 ]; then ./prepare-aes-benchmark-env.sh restore || true; fi
  rm -f "$lock/pid" "$GROUP_PMP_CPU_FREQ_STATE"
  rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
freq_locked=1
./prepare-aes-benchmark-env.sh apply > "$run_dir/environment.log" 2>&1
./prepare-3w1hm-isolation.sh apply >> "$run_dir/environment.log" 2>&1
unset GROUP_PMP_TEST_MODE GROUP_PMP_SECURITY_REGIONS GROUP_PMP_SECURITY_SENTINEL
unset GROUP_PMP_SECURITY_NONCE GROUP_PMP_SECURITY_WORKER_SET
GROUP_PMP_BENCH_CIPHER=aes-ecb-128
export GROUP_PMP_BENCH_CIPHER
./group-pmp-test-runner --crypto-compute-info > "$run_dir/artifact-info.log"
./group-pmp-test-runner --artifact-info >> "$run_dir/artifact-info.log"
sha256sum ./group-pmp-test-runner ./group-pmp-crypto-compute-worker.eapp_riscv \
  ./eyrie-rt ./loader.bin ./run-crypto-compute-bench.sh ./crypto-compute/summarize.py \
  > "$run_dir/artifact-sha256.txt"
uname -a >> "$run_dir/environment.log"
while IFS=, read -r algorithm operation bytes sample; do
  [ "$algorithm" != cipher ] || continue
  log="$run_dir/${algorithm}-${operation}-${bytes}-r${sample}.log"
  echo "[crypto-compute] $algorithm $operation ${bytes}B round=$sample log=$log"
  if ! ./group-pmp-test-runner --crypto-compute "$algorithm" "$operation" "$bytes" "$sample" "$run_dir/samples.csv" > "$log" 2>&1; then
    echo "[crypto-compute] FAILED; retained raw CSV/log: $log" >&2
    tail -n 60 "$log" >&2
    exit 1
  fi
done < "$run_dir/plan.csv"
python3 ./crypto-compute/summarize.py summarize "$run_dir"
echo "[crypto-compute] COMPLETE results=$run_dir"
