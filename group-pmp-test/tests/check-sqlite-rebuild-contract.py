#!/usr/bin/env python3
"""Run the real rebuild source preflight, without staging/building/deploying."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


root = Path(__file__).resolve().parent.parent
script = (root / "rebuild-and-test.sh").read_text()
entry = '\nmain "$@"'
assert script.count(entry) == 1
definitions = script[:script.rindex(entry)]
directory = 'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"'
assert definitions.count(directory) == 1
definitions = definitions.replace(directory, "SCRIPT_DIR=" + shlex.quote(str(root)))
env = {key: value for key, value in os.environ.items()
       if not key.startswith("GROUP_PMP_") and key not in ("PROJECT_ROOT", "HOSTCC")}


def run(body, capacity=None, extra=None):
    variables = dict(env)
    if capacity is not None:
        variables["GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT"] = capacity
    variables.update(extra or {})
    return subprocess.run(["bash", "-s"], input=definitions + "\n" + body,
                          env=variables, text=True, capture_output=True)


for capacity in (None, "256", "488"):
    result = run("verify_loader_source\nverify_mixed_sources\necho PREFLIGHT-PASS\n", capacity)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PREFLIGHT-PASS" in result.stdout

for capacity in ("0", "512", "256; exit 0"):
    result = run("verify_sqlite_ring_contract\necho UNEXPECTED-PASS\n", capacity)
    assert result.returncode != 0 and "UNEXPECTED-PASS" not in result.stdout
    assert "must be 256 or 488" in result.stdout + result.stderr

result = run("verify_sqlite_ring_contract\necho UNEXPECTED-PASS\n",
             extra={"HOSTCC": "sqlite-missing-test-compiler"})
assert result.returncode != 0 and "UNEXPECTED-PASS" not in result.stdout
assert "compiler" in result.stdout + result.stderr

# Test semantic values, not macro spelling. Keep dependencies local so a
# canonical header cannot accidentally hide a stale staged definition.
with tempfile.TemporaryDirectory(prefix="sqlite-rebuild-contract-") as directory:
    temp = Path(directory)
    eapp = temp / "eapp"
    eapp.mkdir()
    for name in ("group-pmp-sqlite-shared.h", "group-pmp-sqlite-pipeline-timing.h"):
        (eapp / name).write_bytes((root / "eapp" / name).read_bytes())
    header = (root / "eapp/group-pmp-sqlite-vfs-shared.h").read_text()
    body = "SCRIPT_DIR=" + shlex.quote(str(temp)) + "\nverify_sqlite_ring_contract\n"

    def altered(old, new, capacity, expected):
        assert header.count(old) == 1
        (eapp / "group-pmp-sqlite-vfs-shared.h").write_text(header.replace(old, new))
        result = run(body, capacity)
        assert (result.returncode == 0) == expected, result.stdout + result.stderr

    batch = "((uint64_t)GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT)"
    ring = "(GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT == 256 ? UINT64_C(131072) : UINT64_C(262144))"
    altered(batch, "(UINT64_C(0) + GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT)", "256", True)
    altered(batch, "(UINT64_C(0) + GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT)", "488", True)
    altered(batch, "UINT64_C(256)", "488", False)
    altered(ring, "UINT64_C(131072)", "488", False)
    altered(ring, "UINT64_C(262144)", "256", False)
    altered("(UINT64_C(17000) + GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT)",
            "UINT64_C(17)", "256", False)

print("Rebuild preflight: default/256/488 PASS; equivalent expressions accepted; "
      "wrong capacity/ring/wire version and missing compiler rejected")
