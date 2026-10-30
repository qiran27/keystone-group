#!/bin/sh
# Independent, one-case diagnostics. Never used as a performance baseline.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
workers=${1:-15}
size=${2:-512MB}
workload=${3:-both}
output=${4:-/sqlite-neighbor-diagnostic}
case "$workers" in ''|*[!0-9]*) echo 'workers must be 1..64' >&2; exit 1;; esac
[ "$workers" -ge 1 ] && [ "$workers" -le 64 ] || exit 1
case "$workload" in readseq) ids=6;; readrand100k) ids=8;; both) ids='6 8';;
  *) echo 'usage: sh run-sqlite-neighbor-diagnostic.sh [workers] [size] [readseq|readrand100k|both] [output-directory]' >&2; exit 1;;
esac
if ! grep -aqF 'keystone-sqlite-neighbor-admission-diagnostic-v2' ./group-pmp-test-runner; then
  echo 'Diagnostic runner v2 is missing; rebuild and deploy the Host runner first.' >&2
  exit 1
fi
mkdir -p "$output"
export GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC=1 GROUP_PMP_SQLITE_NEIGHBOR_ONLY=1
export GROUP_PMP_SQLITE_NEIGHBOR_WORKERS="$workers" GROUP_PMP_SQLITE_NEIGHBOR_SAMPLE=1
export GROUP_PMP_SQLITE_GANTT_MAX_EVENTS=${GROUP_PMP_SQLITE_GANTT_MAX_EVENTS:-524288}
for id in $ids; do
  if [ "$id" = 6 ]; then name=readseq; else name=readrand100k; fi
  trace="$output/$name-N$workers-$size.csv"
  if [ -e "$trace" ]; then
    echo "Refusing to overwrite diagnostic: $trace; choose another output directory." >&2
    exit 1
  fi
  export GROUP_PMP_SQLITE_NEIGHBOR_WORKLOAD="$id" GROUP_PMP_SQLITE_GANTT_CSV="$trace"
  echo "[diagnostic] $name N=$workers size=$size; one selected case, not 120 cases"
  sh ./run-p10-mixed-scaling.sh sqlite-bench adaptive-extent "$workers" 1 "$size" cold
  echo "[diagnostic] inspect with: python3 analyze-sqlite-neighbors.py '$trace' --output '$trace.audit.json'"
done
