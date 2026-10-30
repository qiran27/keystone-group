#!/bin/sh
set -eu
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
build=${1:?usage: check-crypto-compute.sh absolute-build-directory}
mkdir -p "$build"
build=$(CDPATH= cd "$build" && pwd)
sh "$root/tests/build-benchmark-aead.sh" "$build" >/dev/null
${CC:-gcc} -std=c11 -O3 -Wall -Wextra -Werror -DAES_FULL_UNROLL=1 \
  -I"$root/eapp" "$root/eapp/crypto-compute.c" "$root/eapp/group-pmp-crypto.c" \
  "$root/eapp/aes_core.c" "$root/tests/crypto-compute-test.c" \
  "$build/benchmark-aead.a" -o "$build/crypto-compute-test"
"$build/crypto-compute-test"
python3 "$root/tests/test-crypto-compute-summary.py"
sh -n "$root/run-crypto-compute-bench.sh"
bash -n "$root/rebuild-and-test.sh"
CRYPTO_COMPUTE_DRY_RUN=1 sh "$root/run-crypto-compute-bench.sh" 3 sweep "$build/plans" > "$build/dry-run.log"
python3 - "$build/plans" <<'PY'
import csv, pathlib, sys
paths = list(pathlib.Path(sys.argv[1]).glob('run-*/plan.csv'))
assert paths
with paths[-1].open() as f:
    rows = list(csv.DictReader(f))
assert len(rows) == 108
algorithms = ('aes-ecb-128','aes-gcm-128','chacha20-poly1305')
assert [r['cipher'] for r in rows] == [c for c in algorithms for _ in range(36)]
print('PASS: default shell sweep plans 108 measurements, one complete cipher at a time; no board access')
PY
