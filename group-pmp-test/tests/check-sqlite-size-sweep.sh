#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
lock=/tmp/keystone-sqlite-sweep-check-$$.lock
storage=$(mktemp -d /tmp/keystone-sqlite-sweep-storage-check.XXXXXXXX)
trap 'rm -r "$storage"' EXIT HUP INT TERM

preview()
{
  GROUP_PMP_RUN_LOCK_DIR="$lock" GROUP_PMP_SQLITE_SWEEP_DRY_RUN=1 \
    sh "$root/run-p10-mixed-scaling.sh" "$@"
}

default=$(preview sqlite-bench random-pair 15 sweep cold)
[ "$(printf '%s\n' "$default" | grep -c '\[DRY-RUN\]')" -eq 6 ]
printf '%s\n' "$default" | grep -Fq 'storage=private-per-size cleanup=after-child-exit'
printf '%s\n' "$default" | grep -Fq 'GROUP_PMP_SQLITE_OUTPUT_DIR=/sqlite-bench-ecb '
for size in 60 100 200 300 400 500; do
  printf '%s\n' "$default" | grep -Fq "sqlite-bench random-pair 15 5 ${size}MB cold"
  printf '%s\n' "$default" | grep -Fq "sqlite-merge-cost-random-pair-cold-${size}MB.profile"
  printf '%s\n' "$default" | grep -Fq "GROUP_PMP_SQLITE_STORAGE_DIR=<private-${size}MB-dir>"
done

custom=$(preview sqlite-bench all 15 7 sweep direct)
[ "$(printf '%s\n' "$custom" | grep -c '\[DRY-RUN\]')" -eq 6 ]
printf '%s\n' "$custom" | grep -Fq 'sqlite-bench all 15 7 60MB direct'
printf '%s\n' "$custom" | grep -Fq 'sqlite-bench all 15 7 500MB direct'

custom_dir=$(GROUP_PMP_SQLITE_OUTPUT_DIR="$storage/results with spaces" preview sqlite-bench all 15 1 sweep cold)
[ "$(printf '%s\n' "$custom_dir" | grep -Fc "GROUP_PMP_SQLITE_OUTPUT_DIR=$storage/results with spaces ")" -eq 6 ]
if GROUP_PMP_SQLITE_OUTPUT_DIR=relative preview sqlite-bench all 15 1 sweep cold >/dev/null 2>&1; then
  echo 'relative result directory must fail' >&2; exit 1
fi

three=$(preview sqlite-bench all 15 3 sweep cold)
[ "$(printf '%s\n' "$three" | grep -c '\[DRY-RUN\]')" -eq 6 ]
printf '%s\n' "$three" | grep -Fq 'sqlite-bench all 15 3 60MB cold'
printf '%s\n' "$three" | grep -Fq 'sqlite-bench all 15 3 500MB cold'

if preview sqlite-bench both 16 sweep cold >/dev/null 2>&1; then
  echo '60MB must reject 16 workers' >&2; exit 1
fi
if preview sqlite-bench both 15 21 sweep cold >/dev/null 2>&1; then
  echo 'unsupported repetition count must fail' >&2; exit 1
fi
if GROUP_PMP_MIXED_CSV=/same.csv preview sqlite-bench both 15 sweep cold >/dev/null 2>&1; then
  echo 'sweep must reject a shared output filename' >&2; exit 1
fi
GROUP_PMP_SQLITE_STORAGE_DIR="$storage" GROUP_PMP_SQLITE_OUTPUT_DIR="$storage/results with spaces" \
  GROUP_PMP_SQLITE_SWEEP_STORAGE_TEST=1 \
  GROUP_PMP_RUN_LOCK_DIR="$lock" sh "$root/run-p10-mixed-scaling.sh" \
  sqlite-bench random-pair 15 1 sweep cold > "$storage/test.log"
for size in 60 100 200 300 400 500; do
  [ -f "$storage/results with spaces/sqlite-merge-cost-random-pair-cold-${size}MB.profile.log" ]
  grep -Fq "complete size=${size}MB temporary_data=removed" "$storage/test.log"
done
if find "$storage" -maxdepth 1 -type d -name '.keystone-sqlite-sweep-*' | grep -q .; then
  echo 'per-size temporary storage was not removed' >&2; exit 1
fi
[ ! -e "$lock" ]
echo 'SQLite six-size sweep: default/custom repetitions, unique profiles, guards, private storage cleanup and lock cleanup PASS'
