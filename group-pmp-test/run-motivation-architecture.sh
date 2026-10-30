#!/bin/sh
set -eu
cd "$(dirname "$0")"
usage() {
  echo "usage: $0 [--interface minimal|sqlite|fio] [--cipher algorithm] [--block-size 4KB|16KB|64KB|sweep] [repetitions=3] [size=500MB] [cold|hot] [data-dir] [output-dir] [formal|diagnostic]" >&2
  echo 'minimal: same-backend 64KB read/decrypt/full validation; sqlite/fio: direct production 2MB sequential-read interfaces, separate results.' >&2
}
cipher=${MOT_CIPHER:-aes-ecb-128}
block=64KB
interface=minimal
block_set=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --cipher|--block-size|--interface)
      [ "$#" -ge 2 ] || { echo "missing $1 value" >&2; exit 2; }
      case "$1" in
        --cipher) cipher=$2 ;;
        --block-size) block=$2; block_set=1 ;;
        --interface) interface=$2 ;;
      esac
      shift 2 ;;
    --*) echo "unknown option: $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
[ "$#" -le 6 ] || { echo 'too many positional arguments' >&2; exit 2; }
case "$interface" in
  sqlite|fio)
    [ "$block_set" = 0 ] || { echo 'production interfaces use their existing 2MB granularity; --block-size applies only to minimal' >&2; exit 2; }
    exec sh ./run-motivation-system.sh --interface "$interface" --cipher "$cipher" \
      "${1:-3}" "${2:-500MB}" "${3:-cold}" "${4:-/myusb/wj/deploy}" \
      "${5:-/motivation-architecture}" "${6:-formal}"
    ;;
  minimal) ;;
  *) echo 'interface must be minimal, sqlite or fio' >&2; exit 2 ;;
esac
case "$cipher" in aes-ecb-128|aes-gcm-128) ;; *) echo 'cipher must be aes-ecb-128 or aes-gcm-128' >&2; exit 2 ;; esac
case "$block" in
  4KB) MOT_BLOCK_BYTES=4096 ;;
  16KB) MOT_BLOCK_BYTES=16384 ;;
  64KB) MOT_BLOCK_BYTES=65536 ;;
  sweep)
    for b in 4KB 16KB 64KB; do
      sh "$0" --cipher "$cipher" --block-size "$b" "$@"
    done
    exit 0 ;;
  *) echo 'block size must be 4KB, 16KB, 64KB or sweep (binary byte counts)' >&2; exit 2 ;;
esac
export MOT_BLOCK_BYTES
export MOT_ARCHITECTURE=1 MOT_CIPHER=$cipher
exec sh ./run-motivation-overlap.sh "${1:-3}" "${2:-500MB}" "${3:-cold}" \
  "${4:-/myusb/wj/deploy}" "${5:-/motivation-architecture}" "${6:-formal}"
