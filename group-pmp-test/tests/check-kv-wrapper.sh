#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
root=$(pwd -P)
work=$(mktemp -d /tmp/kv-wrapper-test.XXXXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/app" "$work/data" "$work/results"
cp run-secure-kv-enclave-scaling.sh run-secure-kv-comparison.sh run-benchmark-cipher.sh "$work/app/"
cat > "$work/app/group-pmp-test-runner" <<'EOF'
#!/bin/sh
# keystone-enclave-kv-pipeline-v1
set -eu
case "${1:-}" in
  --artifact-info) echo 'artifact=fixture sqlite_extent_policy=51'; exit 0 ;;
  --sqlite-io-calibrate) [ "$GROUP_PMP_SQLITE_STORAGE_DIR" = "$KV_ENCLAVE_STORAGE_DIR" ]; echo fixture > "$3"; echo '[fixture] calibration'; exit 0 ;;
esac
echo "$GROUP_PMP_KV_PROFILE $GROUP_PMP_SQLITE_IO_MODE $GROUP_PMP_SQLITE_TOTAL_BYTES" >> "$KV_TEST_CALLS"
case "$GROUP_PMP_SQLITE_STORAGE_DIR" in "$KV_ENCLAVE_STORAGE_DIR"/.keystone-kv-*) ;; *) exit 9 ;; esac
echo ciphertext > "$GROUP_PMP_SQLITE_STORAGE_DIR/data.bin"
if [ "${KV_TEST_FAIL:-0}" = 1 ]; then echo partial > "$GROUP_PMP_KV_SAMPLES_CSV"; exit 7; fi
echo 'version,workload,io_mode,cache_mode,address_mode,worker_count,total_bytes,samples,seconds_median,seconds_min,seconds_max,seconds_p95,mb_per_sec_median,mb_per_sec_min,mb_per_sec_max,ops_per_sec_median,ops_per_sec_min,ops_per_sec_max,validated' > "$GROUP_PMP_KV_CSV"
echo 'version,workload,io_mode,cache_mode,address_mode,worker_count,total_bytes,samples,logical_requests_median,host_data_operations_median,validated' > "$GROUP_PMP_KV_IO_CSV"
echo actual-samples > "$GROUP_PMP_KV_SAMPLES_CSV"
case "$GROUP_PMP_SQLITE_IO_MODE" in sync-no-extent) rate=20; ops=100 ;; async-no-extent) rate=30; ops=100 ;; adaptive-extent) rate=33; ops=75 ;; esac
for n in $(seq 1 "$GROUP_PMP_KV_MAX_WORKERS"); do
  prefix="1,$GROUP_PMP_KV_PROFILE,$GROUP_PMP_SQLITE_IO_MODE,$GROUP_PMP_SQLITE_CACHE_MODE,locality-random-v1,$n,$GROUP_PMP_SQLITE_TOTAL_BYTES,$GROUP_PMP_KV_REPETITIONS"
  echo "$prefix,3,2,4,4,$rate,19,34,100,90,110,1" >> "$GROUP_PMP_KV_CSV"
  echo "$prefix,100,$ops,1" >> "$GROUP_PMP_KV_IO_CSV"
done
EOF
cat > "$work/app/prepare-aes-benchmark-env.sh" <<'EOF'
#!/bin/sh
printf '%s\n' "$1" >> "$KV_TEST_FREQUENCY"
EOF
cat > "$work/app/prepare-3w1hm-isolation.sh" <<'EOF'
#!/bin/sh
exit 0
EOF
printf '%s\n' keystone-enclave-kv-pipeline-v1 > "$work/app/group-pmp-kv-worker.eapp_riscv"
touch "$work/app/group-pmp-sqlite-master.eapp_riscv" "$work/app/eyrie-rt" "$work/app/loader.bin"
chmod +x "$work/app/group-pmp-test-runner" "$work/app/prepare-aes-benchmark-env.sh" "$work/app/prepare-3w1hm-isolation.sh"
export KV_ENCLAVE_STORAGE_DIR=$work/data KV_ENCLAVE_OUTPUT_DIR=$work/results
export KV_TEST_CALLS=$work/calls KV_TEST_FREQUENCY=$work/frequency
export GROUP_PMP_RUN_LOCK_DIR=$work/lock KV_ENCLAVE_RUN_ID=fixture
sh "$work/app/run-secure-kv-enclave-scaling.sh" all all 2 3 sweep cold > "$work/run.log"
[ "$(wc -l < "$work/calls")" -eq 54 ]
[ "$(find "$work/results" -name '*-comparison.csv' | wc -l)" -eq 18 ]
[ "$(find "$work/results" -name '*-samples.csv' | wc -l)" -eq 54 ]
[ "$(find "$work/data" -mindepth 1 | wc -l)" -eq 0 ]
[ ! -d "$work/lock" ]
[ "$(tail -n 1 "$work/frequency")" = restore ]
for csv in "$work/results/"*-comparison.csv; do
  awk -F, 'NR>1 {if($5!=50 || $6!=65 || $7!=10 || $14!=25) exit 1} END {if(NR!=3) exit 1}' "$csv"
done
KV_ENCLAVE_RUN_ID=pair sh "$work/app/run-secure-kv-enclave-scaling.sh" get both 1 1 60MB hot > "$work/pair.log"
awk -F, 'NR==2 {if($2!="NA" || $7!=10 || $14!=25) exit 1}' "$work/results/secure-kv-get-hot-60MB-1-1-pair-comparison.csv"
if KV_TEST_FAIL=1 KV_ENCLAVE_RUN_ID=failed sh "$work/app/run-secure-kv-enclave-scaling.sh" put all 1 1 60MB cold > "$work/fail.log" 2>&1; then exit 1; fi
[ ! -e "$work/results/secure-kv-put-cold-60MB-1-1-failed-comparison.csv" ]
grep -q partial "$work/results/secure-kv-put-cold-60MB-1-1-failed-sync-samples.csv"
[ "$(find "$work/data" -mindepth 1 | wc -l)" -eq 0 ]
[ ! -d "$work/lock" ]
[ "$(tail -n 1 "$work/frequency")" = restore ]
if KV_ENCLAVE_RUN_ID=fixture sh "$work/app/run-secure-kv-enclave-scaling.sh" all all 2 3 60MB cold > "$work/collision.log" 2>&1; then exit 1; fi
sed -i '/keystone-enclave-kv-pipeline-v1/d' "$work/app/group-pmp-test-runner"
if sh "$work/app/run-secure-kv-enclave-scaling.sh" put sync 1 1 60MB cold > "$work/stale.log" 2>&1; then exit 1; fi
grep -q 'stale KV artifact' "$work/stale.log"
if KV_ENCLAVE_DRY_RUN=1 sh "$root/run-secure-kv-enclave-scaling.sh" all all 16 3 sweep cold >/dev/null 2>&1; then exit 1; fi
KV_ENCLAVE_DRY_RUN=1 sh "$root/run-secure-kv-enclave-scaling.sh" all all 15 5 sweep cold > "$work/dry.log"
[ "$(wc -l < "$work/dry.log")" -eq 18 ]
echo 'KV wrapper: six sizes, three profiles/modes, real samples, median comparisons, cleanup and fail-fast PASS'
