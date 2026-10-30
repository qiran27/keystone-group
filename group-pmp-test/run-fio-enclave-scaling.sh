#!/bin/sh
set -eu
cd "$(dirname "$0")"
. ./run-benchmark-cipher.sh

usage() {
  echo "  prefix option: --cipher aes-ecb-128|aes-gcm-128|chacha20-poly1305" >&2
  echo "usage: $0 <seq-write-2m|seq-read-2m|rand-write-4k|rand-read-4k|rand-read-100k|all> <sync|async|adaptive|all> [max-workers] [repetitions] [total-size|sweep] [hot|cold|direct]" >&2
  echo "       $0 <job> <mode> [max-workers] sweep [hot|cold|direct]" >&2
  echo "  sweep sizes: 60,100,200,300,400,500 MB; repetitions default to 5" >&2
  echo "  storage: FIO_ENCLAVE_STORAGE=local|usb (default local)" >&2
  echo "  local data defaults to /tmp like SQLite (tmpfs on this board, NOT SD disk); override FIO_ENCLAVE_STORAGE_DIR=/root/fio-data" >&2
  echo "  job definitions: FIO_ENCLAVE_JOB_DIR (default script directory); legacy FIO_ENCLAVE_DIR overrides both jobs/data" >&2
  echo "  measured CSVs: /fio-bench-{ecb,gcm,chacha}/ for local and USB storage; no outlier replacement" >&2
  echo "  override result directory: FIO_ENCLAVE_OUTPUT_DIR" >&2
  echo "  override example: FIO_ENCLAVE_OUTPUT_DIR=/myusb/fio-bench $0 all all 15 1 sweep cold" >&2
  echo "  Enclave profile translates fio rw/bs; it does not execute the fio binary or reproduce fio's random generator." >&2
}

if [ "${1:-}" = --check ]; then
  [ "$#" -eq 1 ] || { usage; exit 2; }
  set -- all all 15 1 60MB cold
  check_only=1
fi
[ "$#" -ge 2 ] && [ "$#" -le 6 ] || { usage; exit 2; }
jobs=$1
mode=$2
workers=${3:-15}
if [ "${4:-}" = sweep ]; then
  [ "$#" -le 5 ] || { usage; exit 2; }
  repetitions=5
  total_size=sweep
  cache=${5:-cold}
else
  repetitions=${4:-5}
  total_size=${5:-60MB}
  cache=${6:-cold}
fi
case "$jobs" in
  seq-write-2m|seq-read-2m|rand-write-4k|rand-read-4k|rand-read-100k|all) ;;
  *) usage; exit 2 ;;
esac
case "$mode" in
  sync) sqlite_mode=sync-no-extent ;;
  async) sqlite_mode=async-no-extent ;;
  adaptive) sqlite_mode=adaptive-extent ;;
  all) sqlite_mode=all ;;
  *) usage; exit 2 ;;
esac
case "$workers:$repetitions" in
  *[!0-9:]*|:*|*:) usage; exit 2 ;;
esac
[ "$workers" -ge 1 ] && [ "$workers" -le 15 ] &&
  [ "$repetitions" -ge 1 ] && [ "$repetitions" -le 20 ] || { usage; exit 2; }
if [ "$total_size" = sweep ]; then
  sizes='60MB 100MB 200MB 300MB 400MB 500MB'
else
  case "$total_size" in
    *MB) size_mb=${total_size%MB} ;;
    *) usage; exit 2 ;;
  esac
  case "$size_mb" in
    ''|*[!0-9]*) usage; exit 2 ;;
  esac
  [ "$size_mb" -ge 1 ] && [ "$size_mb" -le 16384 ] || { usage; exit 2; }
  sizes=$total_size
fi
case "$cache" in
  hot|cold|direct) ;;
  *) usage; exit 2 ;;
esac
if [ "$cache" = direct ]; then
  case "$jobs" in
    rand-write-4k|rand-read-4k) ;;
    *)
      echo '[fio-enclave][ERROR] direct mode is limited to page-aligned 4k profiles; sequential/100k jobs use decimal-byte blocks' >&2
      exit 2 ;;
  esac
fi

storage=${FIO_ENCLAVE_STORAGE:-local}
case "$storage" in
  local) default_data=/tmp ;;
  usb) default_data=/myusb/wj/deploy ;;
  *) echo '[fio-enclave][ERROR] FIO_ENCLAVE_STORAGE must be local or usb' >&2; exit 2 ;;
esac
default_jobs=$(pwd -P)
if [ ! -r "$default_jobs/seq-write-2m.fio" ] && [ -d "$default_jobs/fio-bench/jobs" ]; then
  default_jobs=$default_jobs/fio-bench/jobs
fi
if [ "$storage" = usb ]; then default_jobs=$default_data; fi
job_dir=${FIO_ENCLAVE_JOB_DIR:-${FIO_ENCLAVE_DIR:-$default_jobs}}
storage_dir=${FIO_ENCLAVE_STORAGE_DIR:-${FIO_ENCLAVE_DIR:-$default_data}}
output_dir=${FIO_ENCLAVE_OUTPUT_DIR:-/fio-bench-$BENCH_CIPHER_SUFFIX}
case "$job_dir" in
  /*) ;;
  *) echo "[fio-enclave][ERROR] job directory must be absolute" >&2; exit 2 ;;
esac
case "$storage_dir" in
  /*) ;;
  *) echo '[fio-enclave][ERROR] FIO_ENCLAVE_STORAGE_DIR must be absolute' >&2; exit 2 ;;
esac
case "$output_dir" in
  /*) ;;
  *) echo "[fio-enclave][ERROR] FIO_ENCLAVE_OUTPUT_DIR must be absolute" >&2; exit 2 ;;
esac
[ -d "$job_dir" ] && [ -r "$job_dir" ] || {
  echo "[fio-enclave][ERROR] job directory is absent or not readable: $job_dir" >&2
  echo '[fio-enclave][ERROR] set FIO_ENCLAVE_JOB_DIR to the directory containing the five .fio job files' >&2
  exit 1
}
job_dir=$(CDPATH= cd "$job_dir" && pwd -P)
if [ "${check_only:-0}" != 1 ] && [ "${FIO_ENCLAVE_DRY_RUN:-0}" != 1 ]; then
  mkdir -p "$storage_dir"
  [ -d "$storage_dir" ] && [ -w "$storage_dir" ] || {
    echo "[fio-enclave][ERROR] data directory is not writable: $storage_dir" >&2; exit 1;
  }
  storage_dir=$(CDPATH= cd "$storage_dir" && pwd -P)
fi
if [ "$storage" = usb ] && [ "${check_only:-0}" != 1 ] && [ "${FIO_ENCLAVE_DRY_RUN:-0}" != 1 ] &&
   [ "${FIO_ENCLAVE_ALLOW_ROOT_FS:-0}" != 1 ]; then
  root_device=$(df -P / | awk 'NR == 2 { print $1 }')
  job_device=$(df -P "$storage_dir" | awk 'NR == 2 { print $1 }')
  if [ -z "$job_device" ] || [ "$job_device" = "$root_device" ]; then
    echo "[fio-enclave][ERROR] data directory must be on USB: $storage_dir" >&2
    exit 1
  fi
fi
if [ "${check_only:-0}" != 1 ] && [ "${FIO_ENCLAVE_DRY_RUN:-0}" != 1 ]; then
  mkdir -p "$output_dir" || {
    echo "[fio-enclave][ERROR] cannot create result directory: $output_dir" >&2
    exit 1
  }
  [ -w "$output_dir" ] || {
    echo "[fio-enclave][ERROR] result directory is not writable: $output_dir" >&2
    exit 1
  }
  output_dir=$(CDPATH= cd "$output_dir" && pwd -P)
fi

check_job() {
  job=$1
  case "$job" in
    seq-write-2m) rw=write; bs=2000000 ;;
    seq-read-2m) rw=read; bs=2000000 ;;
    rand-write-4k) rw=randwrite; bs=4k ;;
    rand-read-4k) rw=randread; bs=4k ;;
    rand-read-100k) rw=randread; bs=100000 ;;
  esac
  path=$job_dir/$job.fio
  if [ ! -r "$path" ] || ! grep -Fxq "rw=$rw" "$path" ||
     ! grep -Fxq "bs=$bs" "$path" ||
     ! grep -Fxq 'filename=${FIO_FILE}' "$path" ||
     ! grep -Fxq 'size=${FIO_SIZE}' "$path"; then
    echo "[fio-enclave][ERROR] missing/incompatible job definition: $path" >&2
    return 1
  fi
}

for item in seq-write-2m seq-read-2m rand-write-4k rand-read-4k rand-read-100k; do
  if [ "$jobs" = all ] || [ "$jobs" = "$item" ]; then
    check_job "$item"
  fi
done
[ "${check_only:-0}" = 1 ] && {
  echo "[fio-enclave] job profiles ready: $job_dir"
  exit 0
}
if [ "${FIO_ENCLAVE_DRY_RUN:-0}" = 1 ]; then
  for size in $sizes; do
    for item in seq-write-2m seq-read-2m rand-write-4k rand-read-4k rand-read-100k; do
      [ "$jobs" = all ] || [ "$jobs" = "$item" ] || continue
      echo "[fio-enclave][DRY-RUN] job=$item mode=$sqlite_mode workers=1..$workers samples=$repetitions size=$size cache=$cache storage_mode=$storage jobs=$job_dir storage=$storage_dir/<private-directory> results=$output_dir"
    done
  done
  exit 0
fi
[ -x ./run-p10-mixed-scaling.sh ] && [ -x ./group-pmp-test-runner ] || {
  echo '[fio-enclave][ERROR] missing executable group-pmp-test-runner or run-p10-mixed-scaling.sh' >&2
  exit 1
}
if ! grep -aFq 'keystone-fio-enclave-profile-v1' ./group-pmp-test-runner; then
  echo '[fio-enclave][ERROR] runner predates fio profile integration; rebuild and redeploy' >&2
  exit 1
fi
run_id=${FIO_ENCLAVE_RUN_ID:-$(date +%Y%m%d-%H%M%S)-$$}
case "$run_id" in
  ''|*[!a-zA-Z0-9_-]*) echo '[fio-enclave][ERROR] invalid run id' >&2; exit 2 ;;
esac

data_dir=
echo "[fio-enclave] storage_mode=$storage jobs=$job_dir data_root=$storage_dir"
df -P "$storage_dir"
echo '[fio-enclave] tmpfs data is RAM-backed; cold does not imply physical disk I/O'
cleanup_data() {
  case "$data_dir" in
    "$storage_dir"/.keystone-fio-enclave-*)
      [ -d "$data_dir" ] && rm -r "$data_dir" ;;
    '') ;;
    *) echo "[fio-enclave][ERROR] refusing cleanup outside private directory: $data_dir" >&2; return 1 ;;
  esac
  data_dir=
}
trap 'cleanup_data' EXIT
trap 'exit 130' INT TERM
trap 'exit 129' HUP

for size in $sizes; do
  for item in seq-write-2m seq-read-2m rand-write-4k rand-read-4k rand-read-100k; do
    [ "$jobs" = all ] || [ "$jobs" = "$item" ] || continue
    data_dir=$(mktemp -d "$storage_dir/.keystone-fio-enclave-${item}.XXXXXXXX") || exit 1
    name=fio-enclave-${item}-${cache}-${size}-1-${workers}-${run_id}
    prefix=$output_dir/$name
    export GROUP_PMP_FIO_PROFILE=$item
    export GROUP_PMP_SQLITE_STORAGE_DIR=$data_dir
    export GROUP_PMP_SQLITE_OUTPUT_DIR=$output_dir
    export GROUP_PMP_SQLITE_NO_EXTENT_CSV=${prefix}-sync.csv
    export GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_CSV=${prefix}-async.csv
    export GROUP_PMP_SQLITE_EXTENT_CSV=${prefix}-adaptive.csv
    export GROUP_PMP_SQLITE_NO_EXTENT_IO_RANGE_CSV=${prefix}-sync-io.csv
    export GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_IO_RANGE_CSV=${prefix}-async-io.csv
    export GROUP_PMP_SQLITE_EXTENT_IO_RANGE_CSV=${prefix}-adaptive-io.csv
    for result in "$GROUP_PMP_SQLITE_NO_EXTENT_CSV" \
        "$GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_CSV" \
        "$GROUP_PMP_SQLITE_EXTENT_CSV" \
        "$GROUP_PMP_SQLITE_NO_EXTENT_IO_RANGE_CSV" \
        "$GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_IO_RANGE_CSV" \
        "$GROUP_PMP_SQLITE_EXTENT_IO_RANGE_CSV"; do
      if [ -e "$result" ]; then
        echo "[fio-enclave][ERROR] refusing to overwrite previous result: $result" >&2
        exit 1
      fi
    done
    case "$mode" in
      sync) output=$GROUP_PMP_SQLITE_NO_EXTENT_CSV; io_output=$GROUP_PMP_SQLITE_NO_EXTENT_IO_RANGE_CSV ;;
      async) output=$GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_CSV; io_output=$GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_IO_RANGE_CSV ;;
      adaptive) output=$GROUP_PMP_SQLITE_EXTENT_CSV; io_output=$GROUP_PMP_SQLITE_EXTENT_IO_RANGE_CSV ;;
      all) output=; io_output= ;;
    esac
    if [ -n "$output" ]; then
      GROUP_PMP_SQLITE_CSV=$output
      GROUP_PMP_SQLITE_IO_RANGE_CSV=$io_output
      export GROUP_PMP_SQLITE_CSV GROUP_PMP_SQLITE_IO_RANGE_CSV
    else
      unset GROUP_PMP_SQLITE_CSV GROUP_PMP_SQLITE_IO_RANGE_CSV
    fi
    echo "[fio-enclave] job=$item modes=$mode workers=1..$workers samples=$repetitions size=$size cache=$cache storage=$data_dir results=$prefix-*"
    echo '[fio-enclave] fio rw/bs profile only; enclave address generator=locality-random-v1; results include AES, metadata and enclave scheduling'
    if ! ./run-p10-mixed-scaling.sh sqlite-bench "$sqlite_mode" "$workers" "$repetitions" "$size" "$cache"; then
      echo "[fio-enclave][ERROR] failed job=$item size=$size; completed CSVs remain at $prefix-*" >&2
      exit 1
    fi
    cleanup_data
  done
  echo "[fio-enclave] complete size=$size temporary_data=removed results=$output_dir"
done
