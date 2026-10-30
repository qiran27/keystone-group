#!/usr/bin/env python3
"""Exercise the real Buildroot source staging function in a clean directory."""

import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


def run(command, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cxx", default=os.environ.get("CXX", "g++"))
    args = parser.parse_args()
    source = Path(__file__).resolve().parent.parent
    project = source.parent if (source.parent / "sdk").is_dir() else source.parent.parent
    script = (source / "rebuild-and-test.sh").read_text()
    function = re.search(r"^sync_sources\(\) \{\n.*?^\}", script, re.M | re.S)
    if function is None:
        raise AssertionError("sync_sources function not found")
    host_sources = sorted(p for p in (source / "host").iterdir()
                          if p.suffix in (".c", ".cpp", ".h", ".hpp"))
    assert host_sources

    with tempfile.TemporaryDirectory(prefix="keystone-source-sync-") as tmp:
        buildroot = Path(tmp)
        examples = buildroot / "build" / "keystone-examples-test"
        target = examples / source.name
        legacy_project = project
        if not (project / "examples/CMakeLists.txt").exists():
            legacy_project = buildroot / "legacy-project"
            (legacy_project / "examples").mkdir(parents=True)
            (legacy_project / "examples/CMakeLists.txt").write_text(
                "# Legacy top-level staging fixture\n")
        env = dict(os.environ, SCRIPT_DIR=str(source), PROJECT_ROOT=str(legacy_project),
                   BUILDROOT_DIR=str(buildroot), EXAMPLE_NAME=source.name,
                   GROUP_PMP_STANDALONE="0",
                   KEYSTONE_SDK_DIR=str(buildroot / "host/share/keystone/sdk"),
                   KEYSTONE_SDK_SRC_DIR=str(project / "sdk"))
        shell = ("set -eu\n"
                 "echo_info() { :; }\n"
                 "echo_warning() { printf '%s\\n' \"$*\" >&2; }\n"
                 "echo_error() { printf '%s\\n' \"$*\" >&2; }\n" +
                 function.group() + '\nsync_sources "$1"\n')
        for attempt in ("clean", "incremental"):
            run(["bash", "-s", "--", str(examples)], input=shell, env=env)
            for original in host_sources:
                staged = target / "host" / original.name
                if not staged.is_file():
                    raise AssertionError(f"{attempt}: missing staged {staged.name}")
                if original.read_bytes() != staged.read_bytes():
                    raise AssertionError(f"{attempt}: stale staged {staged.name}")
            if attempt == "clean":
                (target / "host" / "group-warmup-watchdog.hpp").unlink()
                (target / "host" / "sqlite-submission-timing.hpp").write_text(
                    '#error "stale staged header"\n')
            address_header = Path("sqlite-bench-master/sqlite-locality-address.h")
            assert (source / address_header).read_bytes() == (target / address_header).read_bytes()
            for original in (source / "security").rglob("*"):
                if original.is_file():
                    assert original.read_bytes() == (target / original.relative_to(source)).read_bytes()
            for directory in ("rv8-bench-master/src", "rv8-bench-master/port"):
                for original in (source / directory).iterdir():
                    if original.suffix in (".c", ".cc", ".h"):
                        assert original.read_bytes() == (target / original.relative_to(source)).read_bytes()
            pure_worker = Path("eapp/group-pmp-rv8-worker.c")
            assert (source / pure_worker).read_bytes() == (target / pure_worker).read_bytes()
            for name in ("eapp/benchmark-cipher.c", "eapp/benchmark-cipher.h"):
                assert (source / name).read_bytes() == (target / name).read_bytes()

        # Do not include canonical Host/eapp directories: headers must be staged.
        run(shlex.split(args.cxx) + [
            "-std=c++11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-function", "-pthread", "-fsyntax-only",
            "-I" + str(project / "sdk" / "include"),
            "-I" + str(target / "eapp"),
            str(target / "host" / "group-pmp-test-runner.cpp"),
        ])
        run(shlex.split(os.environ.get("CC", "gcc")) + [
            "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-fsyntax-only",
            "-I" + str(project / "sdk" / "include"),
            "-I" + str(project / "sdk" / "include" / "app"),
            "-I" + str(target / "eapp"),
            "-I" + str(target / "sqlite-bench-master"),
            "-I" + str(target / "rv8-bench-master" / "port"),
            str(target / "sqlite-bench-master" / "keystone_enclave_store.c"),
            str(target / "eapp" / "group-pmp-sqlite-worker.c"),
            str(target / "eapp" / "group-pmp-rv8-worker.c"),
        ])
    print(f"Buildroot source sync PASS: {len(host_sources)} Host files, "
          "clean/incremental staging, shared address header and staged runner/worker compilation")


if __name__ == "__main__":
    main()
