#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_BIN="${BENCH_BIN:-$SCRIPT_DIR/sqlite-bench}"
DB_DIR="${DB_DIR:-/tmp/keystone-sqlite-bench-native}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/results}"
NUM="${NUM:-1000000}"
READS="${READS:--1}"
VALUE_SIZE="${VALUE_SIZE:-100}"
WAL="${WAL:-1}"
BENCHMARKS="${BENCHMARKS:-fillseq,fillseqbatch,fillrandom,fillrandbatch,overwrite,readseq,readrandom,readrand100K}"

mkdir -p "$OUT_DIR"

if [ ! -x "$BENCH_BIN" ]; then
  make -C "$SCRIPT_DIR" sqlite-bench
fi

rm -rf "$DB_DIR"
mkdir -p "$DB_DIR"

stamp="$(date +%Y%m%d-%H%M%S)"
log="$OUT_DIR/native-$stamp.log"

echo "[sqlite-bench] binary: $BENCH_BIN"
echo "[sqlite-bench] db dir:  $DB_DIR"
echo "[sqlite-bench] log:     $log"
echo "[sqlite-bench] workloads: $BENCHMARKS"

"$BENCH_BIN" \
  --benchmarks="$BENCHMARKS" \
  --num="$NUM" \
  --reads="$READS" \
  --value_size="$VALUE_SIZE" \
  --WAL_enabled="$WAL" \
  --db="$DB_DIR/" \
  2>&1 | tee "$log"

echo "[sqlite-bench] native result log: $log"
