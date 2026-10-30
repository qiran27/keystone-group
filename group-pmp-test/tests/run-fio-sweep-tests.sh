#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
source_dir=$(pwd -P)
root=$(mktemp -d)
root=$(CDPATH= cd "$root" && pwd -P)
case "$root" in
  /tmp/*) ;;
  *) echo "unsafe test directory: $root" >&2; exit 1 ;;
esac
trap 'rm -r "$root"' EXIT HUP INT TERM
mkdir -p "$root/jobs"
cp "$source_dir/run-fio-enclave-scaling.sh" "$source_dir/run-benchmark-cipher.sh" "$root/"
cp "$source_dir/fio-bench/jobs/"*.fio "$root/jobs/"
cat > "$root/group-pmp-test-runner" <<'EOF'
#!/bin/sh
echo keystone-fio-enclave-profile-v1
EOF
cat > "$root/run-p10-mixed-scaling.sh" <<'EOF'
#!/bin/sh
set -eu
[ "$1" = sqlite-bench ] && [ "$3" = 3 ] &&
  [ "$4" = 1 ] && [ "$6" = cold ]
case "$2" in
  all) selected='sync async adaptive' ;;
  sync-no-extent) selected=sync ;;
  async-no-extent) selected=async ;;
  adaptive-extent) selected=adaptive ;;
  *) exit 1 ;;
esac
[ -d "$GROUP_PMP_SQLITE_STORAGE_DIR" ]
[ "$GROUP_PMP_SQLITE_OUTPUT_DIR" = "$FIO_ENCLAVE_OUTPUT_DIR" ]
case "$GROUP_PMP_SQLITE_STORAGE_DIR" in
  "$FIO_SWEEP_EXPECT_STORAGE"/.keystone-fio-enclave-*) ;;
  *) echo 'data did not use selected storage root' >&2; exit 1 ;;
esac
if [ "${FIO_SWEEP_FORCE_FAIL:-0}" = 1 ]; then
  touch "$GROUP_PMP_SQLITE_STORAGE_DIR/partial-ciphertext"
  printf 'partial measured result\n' > "$GROUP_PMP_SQLITE_NO_EXTENT_CSV"
  exit 42
fi
printf '%s\n' "$5" >> "$FIO_SWEEP_TEST_CALLS"
size_mb=${5%MB}
bytes=$((size_mb * 1000000))
for result_mode in $selected; do
  case "$result_mode" in
    sync)
      label=sync-no-extent
      performance=$GROUP_PMP_SQLITE_NO_EXTENT_CSV
      ranges=$GROUP_PMP_SQLITE_NO_EXTENT_IO_RANGE_CSV
      middle_rate=100 ;;
    async)
      label=async-no-extent
      performance=$GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_CSV
      ranges=$GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_IO_RANGE_CSV
      middle_rate=15 ;;
    adaptive)
      label=adaptive-extent
      performance=$GROUP_PMP_SQLITE_EXTENT_CSV
      ranges=$GROUP_PMP_SQLITE_EXTENT_IO_RANGE_CSV
      middle_rate=15 ;;
  esac
  if [ "$2" != all ]; then
    [ "$GROUP_PMP_SQLITE_CSV" = "$performance" ] &&
      [ "$GROUP_PMP_SQLITE_IO_RANGE_CSV" = "$ranges" ]
  fi
  {
    echo 'io_mode,address_mode,cache_mode,workload,worker_count,total_bytes,mb_per_sec_min,mb_per_sec_median,mb_per_sec_max,mb_per_sec_p05,mb_per_sec_p95,seconds_min,seconds_median,seconds_max,seconds_p95,speedup_vs_one,throughput_ratio_vs_sync_no_extent_same_workers,throughput_ratio_vs_async_no_extent_same_workers'
    echo "$label,locality-random-v1,cold,fio-$GROUP_PMP_FIO_PROFILE,1,$bytes,8,10,12,8,12,5,6,7.5,7.5,1,1,1"
    if [ "$result_mode" = async ]; then
      echo "$label,locality-random-v1,cold,fio-$GROUP_PMP_FIO_PROFILE,2,$bytes,5,15,40,5,40,0.5,0.6,0.7,0.7,10,10,10"
    else
      echo "$label,locality-random-v1,cold,fio-$GROUP_PMP_FIO_PROFILE,2,$bytes,$((middle_rate - 10)),$middle_rate,$((middle_rate + 10)),$((middle_rate - 10)),$((middle_rate + 10)),0.5,0.6,0.7,0.7,10,10,10"
    fi
    echo "$label,locality-random-v1,cold,fio-$GROUP_PMP_FIO_PROFILE,3,$bytes,10,12,14,10,14,4.3,5,6,6,1.2,1,1"
  } > "$performance"
  printf 'io_mode,physical_request_count\n%s,42\n' "$result_mode" > "$ranges"
  cp "$performance" "$FIO_SWEEP_SNAPSHOTS/$(basename "$performance")"
  cp "$ranges" "$FIO_SWEEP_SNAPSHOTS/$(basename "$ranges")"
done
EOF
chmod +x "$root/group-pmp-test-runner" "$root/run-p10-mixed-scaling.sh"
export FIO_ENCLAVE_DIR=$root/jobs
export FIO_ENCLAVE_STORAGE=usb
export FIO_SWEEP_EXPECT_STORAGE=$root/jobs
# A leftover old setting must not create a second result directory.
export FIO_ENCLAVE_REAL_DIR=$root/removed-real
export FIO_ENCLAVE_OUTPUT_DIR=$root/output
export FIO_ENCLAVE_ALLOW_ROOT_FS=1
export FIO_ENCLAVE_RUN_ID=sweep-test
export FIO_SWEEP_TEST_CALLS=$root/calls
export FIO_SWEEP_SNAPSHOTS=$root/expected-results
mkdir -p "$FIO_SWEEP_SNAPSHOTS"
sh "$root/run-fio-enclave-scaling.sh" rand-read-4k all 3 1 sweep cold > "$root/log"
cat > "$root/expected" <<'EOF'
60MB
100MB
200MB
300MB
400MB
500MB
EOF
cmp "$root/expected" "$root/calls"
for size in 60 100 200 300 400 500; do
  for name in sync async adaptive sync-io async-io adaptive-io; do
    result=fio-enclave-rand-read-4k-cold-${size}MB-1-3-sweep-test-${name}.csv
    cmp "$root/output/$result" "$FIO_SWEEP_SNAPSHOTS/$result"
  done
  prefix=$root/output/fio-enclave-rand-read-4k-cold-${size}MB-1-3-sweep-test
  awk -F, 'NR == 3 { if ($7 != 90 || $8 != 100 || $9 != 110 || $16 != 10) exit 1 } END { if (NR != 4) exit 1 }' "${prefix}-sync.csv"
  awk -F, 'NR == 3 { if ($7 != 5 || $8 != 15 || $9 != 40) exit 1 } END { if (NR != 4) exit 1 }' "${prefix}-async.csv"
done
[ ! -e "$root/removed-real" ]
[ "$(find "$root/output" -type f | wc -l)" -eq 36 ]
[ "$(find "$root/jobs" -maxdepth 1 -type d -name '.keystone-fio-enclave-*' | wc -l)" -eq 0 ]
if sh "$root/run-fio-enclave-scaling.sh" rand-read-4k all 3 1 sweep cold > "$root/collision-log" 2>&1; then
  echo 'existing result was overwritten' >&2
  exit 1
fi
[ "$(wc -l < "$root/calls")" -eq 6 ]
# Single-mode outputs also go straight to the chosen result directory.
for selected in sync async adaptive; do
  export FIO_ENCLAVE_RUN_ID=single-$selected
  sh "$root/run-fio-enclave-scaling.sh" rand-read-4k "$selected" 3 1 60MB cold > "$root/single-$selected-log"
  for suffix in "$selected" "$selected-io"; do
    result=fio-enclave-rand-read-4k-cold-60MB-1-3-single-${selected}-${suffix}.csv
    cmp "$root/output/$result" "$FIO_SWEEP_SNAPSHOTS/$result"
  done
done
[ "$(find "$root/output" -type f | wc -l)" -eq 42 ]
[ ! -e "$root/removed-real" ]
export FIO_ENCLAVE_RUN_ID=all-profiles
sh "$root/run-fio-enclave-scaling.sh" all all 3 1 60MB cold > "$root/all-profiles-log"
for job in seq-write-2m seq-read-2m rand-write-4k rand-read-4k rand-read-100k; do
  for suffix in sync async adaptive sync-io async-io adaptive-io; do
    result=fio-enclave-${job}-cold-60MB-1-3-all-profiles-${suffix}.csv
    cmp "$root/output/$result" "$FIO_SWEEP_SNAPSHOTS/$result"
  done
done
[ "$(find "$root/output" -type f | wc -l)" -eq 72 ]
[ ! -e "$root/removed-real" ]
export FIO_ENCLAVE_DRY_RUN=1
sh "$root/run-fio-enclave-scaling.sh" rand-read-4k all 3 sweep cold > "$root/dry-run"
[ "$(grep -c 'samples=5' "$root/dry-run")" -eq 6 ]
# Local storage must not depend on a USB mount or writable job definitions.
unset FIO_ENCLAVE_DRY_RUN FIO_ENCLAVE_DIR FIO_ENCLAVE_ALLOW_ROOT_FS
export FIO_ENCLAVE_STORAGE=local
export FIO_ENCLAVE_JOB_DIR=$root/jobs
export FIO_ENCLAVE_STORAGE_DIR=$root/local-data
export FIO_SWEEP_EXPECT_STORAGE=$root/local-data
export FIO_ENCLAVE_OUTPUT_DIR=$root/local-output
export FIO_ENCLAVE_RUN_ID=local-test
chmod a-w "$root/jobs"
sh "$root/run-fio-enclave-scaling.sh" rand-read-4k all 3 1 sweep cold > "$root/local-log"
[ "$(find "$root/local-output" -type f | wc -l)" -eq 36 ]
for result in "$root/local-output/"*.csv; do
  cmp "$result" "$FIO_SWEEP_SNAPSHOTS/$(basename "$result")"
done
[ ! -e "$root/removed-real" ]
[ "$(find "$root/local-data" -mindepth 1 | wc -l)" -eq 0 ]
export FIO_SWEEP_FORCE_FAIL=1 FIO_ENCLAVE_RUN_ID=failed-local
if sh "$root/run-fio-enclave-scaling.sh" rand-read-4k all 3 1 60MB cold > "$root/failed-log" 2>&1; then
  echo 'failed local benchmark incorrectly succeeded' >&2; exit 1
fi
[ "$(find "$root/local-data" -mindepth 1 | wc -l)" -eq 0 ]
grep -Fxq 'partial measured result' "$root/local-output/fio-enclave-rand-read-4k-cold-60MB-1-3-failed-local-sync.csv"
unset FIO_SWEEP_FORCE_FAIL FIO_ENCLAVE_STORAGE_DIR FIO_ENCLAVE_REAL_DIR FIO_ENCLAVE_OUTPUT_DIR
export FIO_ENCLAVE_DRY_RUN=1
sh "$root/run-fio-enclave-scaling.sh" rand-read-4k all 3 1 sweep cold > "$root/local-default"
[ "$(grep -c 'storage=/tmp/<private-directory> results=/fio-bench' "$root/local-default")" -eq 6 ]
sh "$root/run-fio-enclave-scaling.sh" all all 15 5 sweep cold > "$root/all-profiles-default"
[ "$(grep -c 'samples=5' "$root/all-profiles-default")" -eq 30 ]
export FIO_ENCLAVE_STORAGE=usb
sh "$root/run-fio-enclave-scaling.sh" rand-read-4k all 3 1 sweep cold > "$root/usb-default"
[ "$(grep -c 'results=/fio-bench' "$root/usb-default")" -eq 6 ]
unset FIO_ENCLAVE_DRY_RUN
export FIO_ENCLAVE_STORAGE=usb FIO_ENCLAVE_STORAGE_DIR=$root/local-data
if sh "$root/run-fio-enclave-scaling.sh" rand-read-4k all 3 1 60MB cold > "$root/usb-root-log" 2>&1; then
  echo 'USB mode accepted the root filesystem' >&2; exit 1
fi
grep -q 'data directory must be on USB' "$root/usb-root-log"
# Simulate a USB data mount with root-filesystem results. Only data is required
# to be on USB; directory creation and the wrapper still run normally.
mkdir -p "$root/mock-bin"
cat > "$root/mock-bin/df" <<'EOF'
#!/bin/sh
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
case "$2" in
  "$FIO_ENCLAVE_STORAGE_DIR") printf '/dev/mockusb 999999 1 999998 1%% /myusb\n' ;;
  *) printf '/dev/mockroot 999999 1 999998 1%% /\n' ;;
esac
EOF
chmod +x "$root/mock-bin/df"
export FIO_ENCLAVE_OUTPUT_DIR=$root/usb-root-results FIO_ENCLAVE_RUN_ID=usb-root-results
PATH="$root/mock-bin:$PATH" sh "$root/run-fio-enclave-scaling.sh" rand-read-4k async 3 1 60MB cold > "$root/usb-results-log"
[ "$(find "$root/usb-root-results" -name '*.csv' | wc -l)" -eq 2 ]
[ "$(find "$root/local-data" -mindepth 1 | wc -l)" -eq 0 ]
export FIO_ENCLAVE_STORAGE=invalid FIO_ENCLAVE_DRY_RUN=1
if sh "$root/run-fio-enclave-scaling.sh" rand-read-4k all 3 1 60MB cold > "$root/invalid-log" 2>&1; then
  echo 'invalid storage mode accepted' >&2; exit 1
fi
chmod u+w "$root/jobs"
echo 'fio sweep tests PASS'
