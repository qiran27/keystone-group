#!/bin/sh
# Shared-path ablation; no hardware preparation outside the existing runner.
set -eu
if [ "$#" -gt 5 ]; then
  echo "usage: $0 [max-workers=15] [samples=1] [total-size=60MB] [cache=cold] [output-dir]" >&2
  exit 2
fi
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
workers=${1:-15}
samples=${2:-1}
size=${3:-60MB}
cache=${4:-cold}
output=${5:-/sqlite-cluster-ablation-$(date +%Y%m%d-%H%M%S)}
mkdir "$output"
output=$(CDPATH= cd -- "$output" && pwd)
cd "$here"
: "${GROUP_PMP_SQLITE_ADDRESS_MODE:=locality-random-v1}"
export GROUP_PMP_SQLITE_ADDRESS_MODE
GROUP_PMP_SQLITE_CALIBRATION_OUTPUT=$output/merge-cost.profile
export GROUP_PMP_SQLITE_CALIBRATION_OUTPUT
unset GROUP_PMP_SQLITE_NO_EXTENT_BASELINE_CSV GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV
unset GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV GROUP_PMP_SQLITE_GANTT_CSV
for variant in async adaptive plan-only; do
  GROUP_PMP_SQLITE_CLUSTER_MODE=merge
  mode=adaptive-extent
  [ "$variant" != async ] || mode=async-no-extent
  [ "$variant" != plan-only ] || GROUP_PMP_SQLITE_CLUSTER_MODE=plan-only
  GROUP_PMP_SQLITE_CSV=$output/$variant.csv
  GROUP_PMP_SQLITE_IO_RANGE_CSV=$output/$variant-io.csv
  export GROUP_PMP_SQLITE_CLUSTER_MODE GROUP_PMP_SQLITE_CSV GROUP_PMP_SQLITE_IO_RANGE_CSV
  echo "[cluster-ablation] variant=$variant output=$GROUP_PMP_SQLITE_CSV"
  sh ./run-p10-mixed-scaling.sh sqlite-bench "$mode" "$workers" "$samples" "$size" "$cache"
  if [ "$variant" = adaptive ]; then
    GROUP_PMP_SQLITE_MERGE_PROFILE=${GROUP_PMP_SQLITE_MERGE_PROFILE:-$GROUP_PMP_SQLITE_CALIBRATION_OUTPUT}
    export GROUP_PMP_SQLITE_MERGE_PROFILE
  fi
  if [ "$variant" = async ]; then
    GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV=$GROUP_PMP_SQLITE_CSV
    export GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV
  fi
done
echo "[cluster-ablation] complete: $output"
