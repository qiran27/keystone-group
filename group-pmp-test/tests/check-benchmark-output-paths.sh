#!/bin/sh
set -eu
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d /tmp/benchmark-output-check.XXXXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM

for script in run-p10-mixed-scaling.sh run-fio-enclave-scaling.sh run-rv8-enclave-scaling.sh run-secure-kv-enclave-scaling.sh; do
  sh -n "$root/$script"
done

# Execute the actual RV8 option prefix, stopping before artifact/board work.
awk '/^for artifact in / {exit} {print}' "$root/run-rv8-enclave-scaling.sh" > "$work/rv8-options.sh"
printf '\nprintf "%%s\\n" "$output"\n' >> "$work/rv8-options.sh"
unset GROUP_PMP_RV8_OUTPUT_DIR KV_ENCLAVE_OUTPUT_DIR GROUP_PMP_SQLITE_OUTPUT_DIR
[ "$(sh "$work/rv8-options.sh" all both 15 5 sweep)" = /rv8-bench ]
[ "$(GROUP_PMP_RV8_OUTPUT_DIR="$work/custom" sh "$work/rv8-options.sh" all both 15 5 sweep)" = "$work/custom" ]
[ "$(GROUP_PMP_RV8_OUTPUT_DIR="$work/ignored" sh "$work/rv8-options.sh" all both 15 5 sweep "$work/argument")" = "$work/argument" ]

KV_ENCLAVE_DRY_RUN=1 sh "$root/run-secure-kv-enclave-scaling.sh" all all 15 5 sweep cold > "$work/kv-default"
[ "$(grep -c 'results=/secure-kv-bench$' "$work/kv-default")" -eq 18 ]
KV_ENCLAVE_DRY_RUN=1 KV_ENCLAVE_OUTPUT_DIR="$work/kv-custom" \
  sh "$root/run-secure-kv-enclave-scaling.sh" get both 15 1 60MB cold > "$work/kv-custom.log"
grep -Fq "results=$work/kv-custom" "$work/kv-custom.log"
KV_ENCLAVE_DRY_RUN=1 KV_ENCLAVE_OUTPUT_DIR="$work/ignored" \
  sh "$root/run-secure-kv-enclave-scaling.sh" get both 15 1 60MB cold "$work/kv-argument" > "$work/kv-argument.log"
grep -Fq "results=$work/kv-argument" "$work/kv-argument.log"

# Execute the production named-mode resolver without running I/O or touching
# the root result directories. This covers all/both/random-pair mode outputs.
awk '/^run_sqlite_named_mode\(\)/ {emit=1} emit && /^set \+e$/ {exit} emit {print}' \
  "$root/run-p10-mixed-scaling.sh" > "$work/sqlite-named-mode.sh"
cat >> "$work/sqlite-named-mode.sh" <<'EOF'
run_sqlite_runner() { printf 'RESOLVED:%s,%s\n' "$GROUP_PMP_SQLITE_CSV" "$GROUP_PMP_SQLITE_IO_RANGE_CSV"; }
sqlite_cache_file_suffix=-cold-locality-random-v1
sqlite_total_mb=60
max_workers=15
GROUP_PMP_SQLITE_CACHE_MODE=cold
GROUP_PMP_SQLITE_OUTPUT_DIR=${TEST_OUTPUT_DIR:-/sqlite-bench}
for selected in sync-no-extent async-no-extent adaptive-extent; do run_sqlite_named_mode "$selected"; done
EOF
sh "$work/sqlite-named-mode.sh" > "$work/sqlite-default"
for selected in sync-no-extent async-no-extent adaptive-extent; do
  grep -Fxq "RESOLVED:/sqlite-bench/sqlite-bench-$selected-cold-locality-random-v1-60MB-1-15.csv,/sqlite-bench/sqlite-io-ranges-$selected-cold-locality-random-v1-60MB-1-15.csv" "$work/sqlite-default"
done
TEST_OUTPUT_DIR="$work/sqlite custom" sh "$work/sqlite-named-mode.sh" > "$work/sqlite-custom"
[ "$(grep -Fc "RESOLVED:$work/sqlite custom/sqlite-bench-" "$work/sqlite-custom")" -eq 3 ]
GROUP_PMP_SQLITE_EXTENT_CSV="$work/explicit.csv" GROUP_PMP_SQLITE_EXTENT_IO_RANGE_CSV="$work/explicit-io.csv" \
  sh "$work/sqlite-named-mode.sh" > "$work/sqlite-explicit"
grep -Fxq "RESOLVED:$work/explicit.csv,$work/explicit-io.csv" "$work/sqlite-explicit"

# The standalone-mode block has separate defaults and must agree with the
# named-mode resolver. Keep its existing baseline checks and precedence.
cat > "$work/sqlite-single.sh" <<'EOF'
set -eu
sqlite_io_mode=$1
GROUP_PMP_SQLITE_OUTPUT_DIR=/sqlite-bench
sqlite_cache_file_suffix=-cold-locality-random-v1
sqlite_total_mb=60
max_workers=15
EOF
awk '
  /^  if \[ "\$sqlite_io_mode" != both \]/ {emit=1}
  emit && /^  export GROUP_PMP_SQLITE_REPETITIONS$/ {exit}
  emit {print}
' "$root/run-p10-mixed-scaling.sh" >> "$work/sqlite-single.sh"
printf '\nprintf "RESOLVED:%%s,%%s\\n" "$GROUP_PMP_SQLITE_CSV" "$GROUP_PMP_SQLITE_IO_RANGE_CSV"\n' >> "$work/sqlite-single.sh"
for selected in sync-no-extent async-no-extent adaptive-extent; do
  actual=$(sh "$work/sqlite-single.sh" "$selected")
  [ "$actual" = "RESOLVED:/sqlite-bench/sqlite-bench-$selected-cold-locality-random-v1-60MB-1-15.csv,/sqlite-bench/sqlite-io-ranges-$selected-cold-locality-random-v1-60MB-1-15.csv" ]
done
[ "$(GROUP_PMP_SQLITE_CSV="$work/perf.csv" GROUP_PMP_SQLITE_IO_RANGE_CSV="$work/io.csv" sh "$work/sqlite-single.sh" adaptive-extent)" = "RESOLVED:$work/perf.csv,$work/io.csv" ]

echo 'Benchmark output paths: root defaults, custom directories and explicit CSV precedence PASS'
