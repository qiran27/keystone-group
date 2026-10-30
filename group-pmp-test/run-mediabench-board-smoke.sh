#!/bin/sh
set -eu

usage() {
  printf 'usage: %s <mpeg4enc|mpeg4dec|jpg2000enc|jpg2000dec|h264enc|h264dec|all> [input-root] [output-root]\n' "$0" >&2
  printf 'defaults: input-root=/myusb/wj/deploy/mediabench-ii output-root=/myusb/MediaBench-II/board-smoke\n' >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 3 ] || usage
selection=$1
input_root=${2:-/myusb/wj/deploy/mediabench-ii}
output_root=${3:-/myusb/MediaBench-II/board-smoke}
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)

case "$selection" in
  all) codecs='mpeg4enc mpeg4dec jpg2000enc jpg2000dec h264enc h264dec' ;;
  mpeg4enc|mpeg4dec|jpg2000enc|jpg2000dec|h264enc|h264dec)
    codecs=$selection ;;
  *) usage ;;
esac

for codec in $codecs; do
  input_dir="$input_root/$codec/input_base"
  cipher_dir="$output_root/$codec/input-cipher"
  result_dir="$output_root/$codec/output-cipher"
  [ -d "$input_dir" ] || {
    printf '[media][ERROR] input directory absent: %s\n' "$input_dir" >&2
    exit 1
  }
  mkdir -p "$cipher_dir" "$result_dir"
  printf '[media] codec=%s stage input=%s\n' "$codec" "$input_dir"
  "$script_dir/group-pmp-mediabench-board-runner" --stage \
    "$codec" "$input_dir" "$cipher_dir"
  printf '[media] codec=%s enclave run\n' "$codec"
  (cd "$script_dir" && ./group-pmp-mediabench-board-runner --run \
    "$codec" "$cipher_dir" "$result_dir")
done
