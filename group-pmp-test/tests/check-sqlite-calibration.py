#!/usr/bin/env python3
"""Exercise the production calibration preflight without leasing board CPUs."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = (root / "run-p10-mixed-scaling.sh").read_text()
start = source.index('if [ "$benchmark" = sqlite-bench ]; then', source.index('run_sqlite_runner()'))
block = source[start:source.index('run_sqlite_named_mode()', start)]
policy = re.search(r'^sqlite_extent_policy_version=(\d+)$', source, re.M)[1]
env = {k: v for k, v in os.environ.items() if not k.startswith("GROUP_PMP_")}
with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    runner = directory / "group-pmp-test-runner"
    runner.write_text('''#!/bin/sh
set -eu
echo "$*" >> calls
[ "$1" = --sqlite-io-calibrate ]
[ "$2" = 93 ]
[ "${MOCK_FAILURE:-0}" = 0 ] || exit 1
printf 'profile\n' > "$3"
''')
    runner.chmod(0o755)
    shell = f'''set -eu
benchmark=sqlite-bench
sqlite_io_mode=$1
sqlite_extent_policy_version={policy}
GROUP_PMP_SQLITE_STORAGE_DIR=.
GROUP_PMP_SQLITE_OUTPUT_DIR=.
GROUP_PMP_SQLITE_CACHE_MODE=cold
''' + block + '\necho COMPLETE\n'
    for mode, calls in (("async-no-extent", 0), ("sync-no-extent", 0),
                        ("adaptive-extent", 1), ("both", 1), ("all", 1), ("random-pair", 1)):
        call_file = directory / "calls"
        call_file.unlink(missing_ok=True)
        result = subprocess.run(["sh", "-s", "--", mode], input=shell, env=env,
                                cwd=directory, text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
        actual = len(call_file.read_text().splitlines()) if call_file.exists() else 0
        assert actual == calls, (mode, actual)
    supplied = dict(env, GROUP_PMP_SQLITE_MERGE_PROFILE="existing.profile")
    (directory / "calls").unlink()
    result = subprocess.run(["sh", "-s", "--", "adaptive-extent"], input=shell, env=supplied,
                            cwd=directory, text=True, capture_output=True)
    assert result.returncode == 0 and not (directory / "calls").exists()
    failed = dict(env, MOCK_FAILURE="1")
    result = subprocess.run(["sh", "-s", "--", "adaptive-extent"], input=shell, env=failed,
                            cwd=directory, text=True, capture_output=True)
    assert result.returncode != 0 and "COMPLETE" not in result.stdout
print("mixed calibration shell: once before timed runs, Async untouched, reuse and fail-stop PASS")
