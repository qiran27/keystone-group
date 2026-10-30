#!/bin/sh
set -eu
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d /tmp/rv8-wrapper-test.XXXXXX)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
cp "$root/run-rv8-enclave-scaling.sh" "$fixture/"
cd "$fixture"
# Fixture data only; never a performance measurement.
cat > group-pmp-test-runner <<'EOF'
#!/bin/sh
# keystone-rv8-enclave-compute-v2
# keystone-rv8-control-only-v2
[ "${FAIL_FIXTURE:-0}" = 0 ] || exit 7
test "$GROUP_PMP_TEST_MODE" = rv8-bench || exit 8
test -z "${GROUP_PMP_SQLITE_STORAGE_DIR:-}" || exit 9
test "$GROUP_PMP_MIXED_STALL_TIMEOUT_SEC" = "${EXPECT_STALL:-600}" || exit 10
printf 'fixture-samples\n' > "$GROUP_PMP_RV8_SAMPLES_CSV"
printf 'version,kernel,mode,workers,sample_count,total_bytes,seconds_median,seconds_min,seconds_max,seconds_p95,mb_per_sec_median,mb_per_sec_min,mb_per_sec_max,kernel_cpu_seconds_median,kernel_mb_per_cpu_second_median,transport_aes_cpu_seconds_median,logical_requests_median,host_data_operations_median,doorbells_median,completion_waits_median,kernel_blocks_median,validated\n' > "$GROUP_PMP_RV8_CSV"
rate=100; test "$GROUP_PMP_SQLITE_IO_MODE" != async-no-extent || rate=110
for n in $(seq 1 "$GROUP_PMP_RV8_MAX_WORKERS"); do
  printf '2,%s,%s,%d,%d,%d,1,0.9,1.1,1.1,%d,90,120,0.5,100,0,0,0,0,0,100,1\n' \
    "$GROUP_PMP_RV8_KERNEL" "$GROUP_PMP_SQLITE_IO_MODE" "$n" \
    "$GROUP_PMP_RV8_REPETITIONS" "$GROUP_PMP_SQLITE_TOTAL_BYTES" "$rate" >> "$GROUP_PMP_RV8_CSV"
done
EOF
cat > prepare-aes-benchmark-env.sh <<'EOF'
#!/bin/sh
printf '%s\n' "$1" >> "$FIXTURE_FREQ_LOG"
EOF
cp prepare-aes-benchmark-env.sh prepare-3w1hm-isolation.sh
chmod +x ./*.sh group-pmp-test-runner
for file in group-pmp-sqlite-master.eapp_riscv eyrie-rt loader.bin; do printf 'fixture\n' > "$file"; done
for k in bigint miniz norx aes qsort sha-512 dhrystone primes; do
  printf 'keystone-rv8-enclave-compute-v2\n' > "group-pmp-rv8-$k-worker.eapp_riscv"
done
export GROUP_PMP_RUN_LOCK_DIR=$fixture/lock FIXTURE_STORAGE_LOG=$fixture/storage.log
export FIXTURE_FREQ_LOG=$fixture/freq.log
cp group-pmp-test-runner runner-with-init
sed '/keystone-rv8-control-only-v2/d' runner-with-init > group-pmp-test-runner
if sh ./run-rv8-enclave-scaling.sh aes both 1 1 60MB "$fixture/stale-results" >"$fixture/stale.log" 2>&1; then
  echo 'RV8 runner without OCALL initialization was accepted' >&2; exit 1;
fi
grep -q 'runner lacks compute-only control' "$fixture/stale.log"
test ! -e "$fixture/stale-results" && test ! -e "$GROUP_PMP_RUN_LOCK_DIR"
test ! -e "$FIXTURE_FREQ_LOG"
cp runner-with-init group-pmp-test-runner
sh ./run-rv8-enclave-scaling.sh all both 2 3 sweep "$fixture/results with spaces" >/dev/null
test "$(find "$fixture/results with spaces" -name '*-comparison.csv' | wc -l)" -eq 48
test "$(find "$fixture/results with spaces" -name '*-samples.csv' | wc -l)" -eq 96
for csv in "$fixture/results with spaces/"*-comparison.csv; do
  awk -F, 'NR>1 && ($7!=10 || $8!=0 || $9!=0 || $10!="") {exit 1} END {if (NR!=3) exit 1}' "$csv"
done
test ! -e "$GROUP_PMP_RUN_LOCK_DIR"
test "$(grep -c '^restore$' "$FIXTURE_FREQ_LOG")" -eq 1
EXPECT_STALL=900 GROUP_PMP_MIXED_STALL_TIMEOUT_SEC=900 sh ./run-rv8-enclave-scaling.sh aes both 1 1 60MB "$fixture/timeout-override" >/dev/null
if sh ./run-rv8-enclave-scaling.sh all both 16 5 sweep "$fixture/invalid" >/dev/null 2>&1; then exit 1; fi
if sh ./run-rv8-enclave-scaling.sh all adaptive 2 5 sweep "$fixture/invalid" >/dev/null 2>&1; then exit 1; fi
if FAIL_FIXTURE=1 sh ./run-rv8-enclave-scaling.sh sha-512 both 2 1 60MB "$fixture/failed" >/dev/null 2>&1; then exit 1; fi
test ! -e "$GROUP_PMP_RUN_LOCK_DIR"
test "$(find "$fixture/failed" -name '*comparison.csv' | wc -l)" -eq 0
if sh ./run-rv8-enclave-scaling.sh transfer both 1 1 60MB "$fixture/invalid" >/dev/null 2>&1; then exit 1; fi
echo 'rv8 six-size/eight-kernel compute wrapper, comparisons, cleanup, failure propagation PASS'
