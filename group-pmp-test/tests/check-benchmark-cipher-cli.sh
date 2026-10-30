#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
root=$(pwd -P)
unset GROUP_PMP_BENCH_CIPHER GROUP_PMP_SQLITE_OUTPUT_DIR FIO_ENCLAVE_OUTPUT_DIR KV_ENCLAVE_OUTPUT_DIR
for spec in aes-ecb-128:ecb aes-gcm-128:gcm chacha20-poly1305:chacha; do
  cipher=${spec%:*}; suffix=${spec#*:}
  sqlite=$(GROUP_PMP_SQLITE_SWEEP_DRY_RUN=1 sh ./run-p10-mixed-scaling.sh --cipher "$cipher" sqlite-bench all 9 3 sweep cold)
  [ "$(printf '%s\n' "$sqlite" | grep -c "GROUP_PMP_SQLITE_OUTPUT_DIR=/sqlite-bench-$suffix ")" -eq 6 ]
  fio=$(FIO_ENCLAVE_DRY_RUN=1 FIO_ENCLAVE_JOB_DIR="$root/fio-bench/jobs" sh ./run-fio-enclave-scaling.sh --cipher "$cipher" all all 9 3 sweep cold)
  [ "$(printf '%s\n' "$fio" | grep -c "results=/fio-bench-$suffix")" -eq 30 ]
  kv=$(KV_ENCLAVE_DRY_RUN=1 sh ./run-secure-kv-enclave-scaling.sh --cipher "$cipher" all all 9 3 sweep cold)
  [ "$(printf '%s\n' "$kv" | grep -c "results=/secure-kv-bench-$suffix")" -eq 18 ]
done
env_only=$(GROUP_PMP_BENCH_CIPHER=gcm KV_ENCLAVE_DRY_RUN=1 sh ./run-secure-kv-enclave-scaling.sh get all 9 3 60MB cold)
printf '%s\n' "$env_only" | grep -q 'results=/secure-kv-bench-gcm'
override=$(GROUP_PMP_BENCH_CIPHER=gcm KV_ENCLAVE_DRY_RUN=1 sh ./run-secure-kv-enclave-scaling.sh --cipher chacha get all 9 3 60MB cold /tmp/custom-results)
printf '%s\n' "$override" | grep -q 'results=/tmp/custom-results'
for script in run-p10-mixed-scaling.sh run-fio-enclave-scaling.sh run-secure-kv-enclave-scaling.sh; do
  if sh "./$script" --cipher invalid >/dev/null 2>&1; then exit 1; fi
  if sh "./$script" --cipher >/dev/null 2>&1; then exit 1; fi
done
# Prefix parsing must retain all positional arguments and export to sweep children.
sh -c 'set -- --cipher gcm a b; . ./run-benchmark-cipher.sh; [ "$#" = 2 ] && [ "$1" = a ] && [ "$2" = b ]; sh -c '\''[ "$GROUP_PMP_BENCH_CIPHER" = aes-gcm-128 ]'\'''
echo 'Cipher CLI: three algorithms, six sizes, three launchers, override and child inheritance PASS'
