#!/usr/bin/env python3
"""Run the real ablation wrapper with a fake benchmark, never touch a lease."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="sqlite-cluster-wrapper-") as tmp:
    directory = Path(tmp)
    wrapper = directory / "run-sqlite-cluster-ablation.sh"
    wrapper.write_text((root / wrapper.name).read_text())
    runner = directory / "run-p10-mixed-scaling.sh"
    runner.write_text('''#!/bin/sh
set -eu
printf '%s|%s|%s|%s|%s|%s|%s\\n' "$*" "$GROUP_PMP_SQLITE_CLUSTER_MODE" \
  "$GROUP_PMP_SQLITE_ADDRESS_MODE" "$GROUP_PMP_SQLITE_CSV" \
  "$GROUP_PMP_SQLITE_IO_RANGE_CSV" "${GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV:-}" \
  "${GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV:-}" >> "$TEST_CALLS"
printf 'fixture\\n' > "$GROUP_PMP_SQLITE_CSV"
printf 'fixture\\n' > "$GROUP_PMP_SQLITE_IO_RANGE_CSV"
''')
    env = {k: v for k, v in os.environ.items() if not k.startswith("GROUP_PMP_")}
    env["TEST_CALLS"] = str(directory / "calls")
    env["GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV"] = "/stale.csv"
    output = directory / "output"
    args = ["sh", str(wrapper), "15", "1", "60MB", "cold", str(output)]
    subprocess.run(args, env=env, check=True, capture_output=True)
    calls = (directory / "calls").read_text().splitlines()
    assert len(calls) == 3
    for i, name in enumerate(("async", "adaptive", "plan-only")):
        row = calls[i].split("|")
        mode = "async-no-extent" if i == 0 else "adaptive-extent"
        assert row[0] == f"sqlite-bench {mode} 15 1 60MB cold"
        assert row[1] == ("plan-only" if i == 2 else "merge")
        assert row[2] == "locality-random-v1"
        assert row[3] == str(output / f"{name}.csv")
        assert row[4] == str(output / f"{name}-io.csv")
        assert row[5] == ("" if i == 0 else str(output / "async.csv"))
        assert not row[6]
    assert len(list(output.glob("*.csv"))) == 6
    assert subprocess.run(args, env=env, capture_output=True).returncode != 0
    assert (directory / "calls").read_text().splitlines() == calls
print("cluster wrapper: three variants, same stream, fresh Async baseline, six outputs, no overwrite PASS")
