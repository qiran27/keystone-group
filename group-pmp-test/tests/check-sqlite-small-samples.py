#!/usr/bin/env python3
"""Run the actual shell parser/sample policy without leasing any board CPU."""
import os
from pathlib import Path
import subprocess


root = Path(__file__).resolve().parent.parent
source = (root / "run-p10-mixed-scaling.sh").read_text()
parser = source[source.index("usage()\n"):source.index("\nmixed_marker=")]
samples = source[source.index('  if [ -n "$requested_repetitions" ]; then'):
                 source.index('  : "${GROUP_PMP_SQLITE_RANDOM_SEED:=')]
policy = source[source.index('  GROUP_PMP_SQLITE_CACHE_MODE=$requested_cache_mode'):
                source.index('  if [ "$GROUP_PMP_SQLITE_CACHE_MODE" = hot ]; then')]
shell = ('set -eu\nGROUP_PMP_MIXED_REPETITIONS=5\n' +
         (root / "run-benchmark-cipher.sh").read_text() + '\n' + parser + samples + policy +
         '\nprintf "RESULT %s %s %s\\n" "$sqlite_io_mode" '
         '"$GROUP_PMP_SQLITE_REPETITIONS" "$sqlite_sample_policy"\n')
env = {k: v for k, v in os.environ.items() if not k.startswith("GROUP_PMP_")}
for mode in ("all", "both", "random-pair", "adaptive-extent", "async-no-extent", "sync-no-extent"):
    for rounds, size, expected in ((1, "60MB", "single-cold-cache-preview"),
                                   (1, "512MB", "single-cold-cache-preview"),
                                   (3, "60MB", "multi-sample-preview"),
                                   (3, "512MB", "multi-sample-preview"),
                                   (5, "60MB", "randomized-small-data-multi-sample-statistics"),
                                   (20, "60MB", "randomized-small-data-multi-sample-statistics"),
                                   (5, "512MB", "randomized-multi-sample-statistics")):
        result = subprocess.run(["sh", "-s", "--", "sqlite-bench", mode, "15",
                                 str(rounds), size, "cold"], input=shell,
                                text=True, capture_output=True, env=env)
        assert result.returncode == 0, result.stderr
        assert f"RESULT {mode} {rounds} {expected}" in result.stdout, result.stdout
for rounds, size in ((0, "60MB"), (21, "60MB"), (5, "30MB")):
    result = subprocess.run(["sh", "-s", "--", "sqlite-bench", "all", "15",
                             str(rounds), size, "cold"], input=shell,
                            text=True, capture_output=True, env=env)
    assert result.returncode == 2, result.stdout + result.stderr
named_start = source.index("run_sqlite_named_mode()\n")
named = source[named_start:source.index("\nset +e\n", named_start)]
named_shell = '''set -eu
GROUP_PMP_SQLITE_OUTPUT_DIR=
max_workers=15
sqlite_total_mb=512
sqlite_cache_file_suffix=-cold-random-pair
GROUP_PMP_SQLITE_CACHE_MODE=cold
run_sqlite_runner() {
  printf 'FILE %s %s %s %s\\n' "$GROUP_PMP_SQLITE_IO_MODE" "$GROUP_PMP_SQLITE_CSV" \\
    "$GROUP_PMP_SQLITE_IO_RANGE_CSV" "${GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV:-}"
}
''' + named + '''
run_sqlite_named_mode async-no-extent
async_csv=$GROUP_PMP_SQLITE_CSV
run_sqlite_named_mode adaptive-extent "" "$async_csv"
'''
result = subprocess.run(["sh", "-s"], input=named_shell, text=True,
                        capture_output=True, env=env)
assert result.returncode == 0, result.stderr
lines = [line for line in result.stdout.splitlines() if line.startswith("FILE ")]
assert len(lines) == 2, lines
assert lines[0] == ("FILE async-no-extent "
    "/sqlite-bench-async-no-extent-cold-random-pair-512MB-1-15.csv "
    "/sqlite-io-ranges-async-no-extent-cold-random-pair-512MB-1-15.csv ")
assert lines[1] == ("FILE adaptive-extent "
    "/sqlite-bench-adaptive-extent-cold-random-pair-512MB-1-15.csv "
    "/sqlite-io-ranges-adaptive-extent-cold-random-pair-512MB-1-15.csv "
    "/sqlite-bench-async-no-extent-cold-random-pair-512MB-1-15.csv")
print("SQLite shell arguments: 60/512 MB, random-pair paths and Async baseline, one-round preview, guards PASS")
