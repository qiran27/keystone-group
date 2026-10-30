#!/bin/sh
set -eu

usage()
{
  echo "usage: $0 --check | <seq-write-2m|seq-read-2m|rand-write-4k|rand-read-4k|rand-read-100k> <size> <disposable-file>" >&2
  echo "  Native Host reference only; not a worker-enclave Sync/Async/Adaptive result." >&2
  echo "  FIO_JOB_DIR defaults to /myusb/deploy/ (directory containing the .fio files)." >&2
}

job_dir=${FIO_JOB_DIR:-/myusb/deploy/}
case "$job_dir" in
  /*) ;;
  *) echo "[fio-native][ERROR] FIO_JOB_DIR must be absolute: $job_dir" >&2; exit 2 ;;
esac

check_jobs()
{
  for job in seq-write-2m seq-read-2m rand-write-4k rand-read-4k rand-read-100k; do
    if [ ! -r "$job_dir/$job.fio" ]; then
      echo "[fio-native][ERROR] missing job: $job_dir/$job.fio" >&2
      return 1
    fi
  done
  echo "[fio-native] five job files ready: $job_dir"
}

if [ "${1:-}" = --check ]; then
  [ "$#" -eq 1 ] || { usage; exit 2; }
  check_jobs
  exit
fi

[ "$#" -eq 3 ] || { usage; exit 2; }
job=$1
case "$job" in
  seq-write-2m|seq-read-2m|rand-write-4k|rand-read-4k|rand-read-100k) ;;
  *) usage; exit 2 ;;
esac
case "$2" in
  *[!0-9]*|'') echo "[fio-native][ERROR] size must be a positive byte count" >&2; exit 2 ;;
esac
[ "$2" -gt 0 ] || { usage; exit 2; }
case "$3" in
  /*) ;;
  *) echo "[fio-native][ERROR] data file path must be absolute" >&2; exit 2 ;;
esac
check_jobs
if [ ! -r "$job_dir/$job.fio" ]; then
  exit 1
fi
if ! command -v fio >/dev/null 2>&1; then
  echo "[fio-native][ERROR] fio is not installed on this Host" >&2
  exit 1
fi
case "$job" in
  *read*)
    [ -f "$3" ] || { echo "[fio-native][ERROR] prefilled read file missing: $3" >&2; exit 1; }
    ;;
  *write*)
    if [ -e "$3" ] && [ "${FIO_ALLOW_OVERWRITE:-0}" != 1 ]; then
      echo "[fio-native][ERROR] refusing to overwrite existing file: $3" >&2
      exit 1
    fi
    ;;
esac
FIO_SIZE=$2
FIO_FILE=$3
export FIO_SIZE FIO_FILE
echo "[fio-native] reference workload=$job size_bytes=$FIO_SIZE job_file=$job_dir/$job.fio data_file=$FIO_FILE"
exec fio "$job_dir/$job.fio"
