#!/usr/bin/env python3
"""Exercise the real startup artifact checks without opening a driver or CPU lease."""
import os
from pathlib import Path
import re
import subprocess
import tempfile


root = Path(__file__).resolve().parent.parent
source = (root / "run-p10-mixed-scaling.sh").read_text()
runner = (root / "host/group-pmp-test-runner.cpp").read_text()
schema = int(re.search(r"kSqliteCsvSchemaVersion = UINT64_C\((\d+)\)", runner)[1])
policy = int(re.search(r"kGroupPmpSqliteExtentIoPolicyVersion = UINT64_C\((\d+)\)",
                      (root / "host/sqlite-extent-io.hpp").read_text())[1])
marker = f"keystone-sqlite-csv-schema-v{schema}"
assert f'"{marker}"' in runner
assert f'SQLITE_CSV_SCHEMA_MARKER="{marker}"' in (root / "rebuild-and-test.sh").read_text()

# Keep the real parser, marker checks and --artifact-info validation. Stop
# immediately before loader/runtime checks, well before any device interaction.
prefix = source[:source.index('  if [ ! -f ./loader.bin ] ||')]
shell = prefix + 'fi\nprintf "ARTIFACT-CONTRACT-PASS\\n"\n'
markers = re.findall(r"^\w+_marker=(keystone-[\w-]+)$", prefix, re.M)
markers = [m for m in markers if not m.startswith("keystone-sqlite-csv-schema-v")]

with tempfile.TemporaryDirectory(prefix="sqlite-artifact-contract-") as directory:
    tmp = Path(directory)
    script = tmp / "run-p10-mixed-scaling.sh"
    script.write_text(shell)
    (tmp / "run-benchmark-cipher.sh").write_text((root / "run-benchmark-cipher.sh").read_text())
    (tmp / "prepare-3w1hm-isolation.sh").write_text("# keystone-hsm-lease-recovery-v1\n")
    artifact = tmp / "group-pmp-test-runner"
    env = {k: v for k, v in os.environ.items() if not k.startswith("GROUP_PMP_")}
    env["GROUP_PMP_RUN_LOCK_DIR"] = str(tmp / "lock")

    def check(mode, embedded, reported_schema, reported_policy, capacity=256, ring=None):
        ring = ring if ring is not None else (131072 if capacity == 256 else 262144)
        utm = 4141056 if capacity == 256 else 4272128
        info = (f"artifact=group-pmp-test-runner sqlite_csv_schema={reported_schema} "
                f"sqlite_extent_policy={reported_policy} sqlite_vfs_batch_max={capacity} "
                f"sqlite_vfs_ring_bytes={ring} sqlite_vfs_utm_bytes={utm}")
        artifact.write_text("#!/bin/sh\n" + "".join(f"# {m}\n" for m in markers) +
                            f"# {embedded}\n" + f"printf '%s\\n' '{info}'\n")
        artifact.chmod(0o755)
        result = subprocess.run(["sh", str(script), "sqlite-bench", mode,
                                 "15", "1", "60MB", "cold"],
                                text=True, capture_output=True, env=env)
        assert not (tmp / "lock").exists(), "startup must release its run lock"
        return result

    for mode in ("sync-no-extent", "async-no-extent", "adaptive-extent", "both", "all"):
        result = check(mode, marker, schema, policy)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ARTIFACT-CONTRACT-PASS" in result.stdout

    for mode in ("async-no-extent", "adaptive-extent"):
        result = check(mode, marker, schema, policy, 488)
        assert result.returncode == 0, result.stdout + result.stderr
    result = check("adaptive-extent", marker, schema, policy, 488, 131072)
    assert result.returncode == 1 and "ring size" in result.stderr
    result = check("adaptive-extent", marker, schema, policy, 512)
    assert result.returncode == 1 and "descriptor capacity" in result.stderr

    result = check("async-no-extent", f"keystone-sqlite-csv-schema-v{schema - 1}", schema, policy)
    assert result.returncode == 1 and "ARTIFACT-CONTRACT-PASS" not in result.stdout
    assert f"CSV schema v{schema}:" in result.stderr and marker in result.stderr
    result = check("adaptive-extent", marker, schema - 1, policy)
    assert result.returncode == 1 and f"incompatible CSV schema: expected={schema}" in result.stderr
    result = check("adaptive-extent", marker, schema, policy - 1)
    assert result.returncode == 1 and f"incompatible extent I/O policy: expected={policy}" in result.stderr

print(f"SQLite artifact contract: matching schema {schema}/policy {policy} accepted in five modes; "
      "stale marker/schema/policy rejected, accurate message and lock cleanup PASS")
