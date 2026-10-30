#!/usr/bin/env python3
"""Check source-path resolution and source-build wiring without a board toolchain."""

import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bash", default="bash")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    script = source / "rebuild-and-test.sh"
    text = script.read_text(encoding="utf-8")
    env = dict(os.environ)
    for name in ("PROJECT_ROOT", "KEYSTONE_SDK_SRC_DIR", "KEYSTONE_EYRIE_RUNTIME",
                 "KEYSTONE_SDK_DIR", "KEYSTONE_SM_DIR", "KEYSTONE_DRIVER_DIR",
                 "GROUP_PMP_BUILD_DIR", "GROUP_PMP_STANDALONE"):
        env.pop(name, None)

    def run(argv, expected=0, **kwargs):
        result = subprocess.run([args.bash, *argv], env=env, text=True,
                                capture_output=True, **kwargs)
        assert result.returncode == expected, result.stdout + result.stderr
        return result.stdout

    run(["-n", script.as_posix()])
    output = run([script.as_posix(), "--check-paths"])
    assert "github-keystone-group/sdk" in output
    assert "sdk-install" in output
    run([script.as_posix(), "--unknown"], expected=2)
    with tempfile.TemporaryDirectory(prefix="keystone standalone ") as tmp:
        root = Path(tmp)
        for relative in ("sdk/CMakeLists.txt", "runtime/CMakeLists.txt",
                         "sm/src/enclave.c", "driver/keystone.c"):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.touch()
        env.update(KEYSTONE_SDK_SRC_DIR=(root / "sdk").as_posix(),
                   KEYSTONE_EYRIE_RUNTIME=(root / "runtime").as_posix(),
                   KEYSTONE_SM_DIR=(root / "sm").as_posix(),
                   KEYSTONE_DRIVER_DIR=(root / "driver").as_posix(),
                   GROUP_PMP_BUILD_DIR=(root / "out").as_posix())
        output = run([script.as_posix(), "--check-paths"])
        assert "keystone standalone " in output
        assert not (root / "out").exists(), "path check must not build"
        env["KEYSTONE_SDK_DIR"] = env["KEYSTONE_SDK_SRC_DIR"]
        run([script.as_posix(), "--check-paths"], expected=2)
        env["KEYSTONE_SDK_DIR"] = (root / "install").as_posix()
        env["KEYSTONE_EYRIE_RUNTIME"] = (root / "missing").as_posix()
        run([script.as_posix(), "--check-paths"], expected=1)

    build = re.search(r"^build_example\(\) \{\n.*?^\}", text, re.M | re.S).group()
    assert '--target install' in build
    assert '-DKEYSTONE_BUILD_TESTS=OFF' in build
    assert '-DKEYSTONE_EYRIE_RUNTIME="$KEYSTONE_EYRIE_RUNTIME"' in build
    assert 'cmake --build . --target group-pmp-test --clean-first' in build
    assert 'cmake_source="$SCRIPT_DIR/cmake/standalone"' in build
    assert 'KEYSTONE_KERNEL_BUILD:-${SECURITY_EVIDENCE_KERNEL_BUILD:-}' in text
    print("PASS: shell syntax, default/custom paths, spaces, invalid paths, SDK source/install separation, source-build wiring")


if __name__ == "__main__":
    main()
