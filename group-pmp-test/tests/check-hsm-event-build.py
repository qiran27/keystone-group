#!/usr/bin/env python3
"""Compile the HSM event bridge against a prepared board kernel, without rebuilding it."""

import argparse
import pathlib
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--board-root", type=pathlib.Path, required=True)
    parser.add_argument("--keystone-root", type=pathlib.Path, required=True)
    parser.add_argument("--recorded-root", default="/home/yx/Desktop/mirrors/VisionFive2_devl")
    args = parser.parse_args()
    board = args.board_root.resolve()
    keystone = args.keystone_root.resolve()
    build = board / "work/linux"
    replacements = [
        (args.recorded_root + "/linux/drivers/keystone-driver", str(keystone / "linux-keystone-driver")),
        (args.recorded_root + "/sdk", str(keystone / "sdk")),
        (args.recorded_root, str(board)),
    ]
    cases = [
        ("arch/riscv/kernel/smp", board / "linux/arch/riscv/kernel/smp.c"),
        ("arch/riscv/kernel/cpu_ops_sbi", board / "linux/arch/riscv/kernel/cpu_ops_sbi.c"),
        ("drivers/keystone-driver/keystone-ioctl", keystone / "linux-keystone-driver/keystone-group.c"),
    ]
    with tempfile.TemporaryDirectory(prefix="keystone-hsm-build-") as temporary:
        for template, source in cases:
            path = pathlib.Path(template)
            command_file = build / path.parent / ("." + path.name + ".o.cmd")
            command = command_file.read_text().splitlines()[0].split(":=", 1)[1]
            for old, new in replacements:
                command = command.replace(old, new)
            original = shlex.split(command)
            # Reuse the real kernel flags, but never overwrite its objects/dependencies.
            flags = []
            skip = False
            for token in original:
                if skip:
                    skip = False
                    continue
                if token == "-o":
                    skip = True
                    continue
                if token.startswith("-Wp,-MMD,") or token.endswith(".c"):
                    continue
                flags.append(token)
            for enabled in (False, True):
                output = pathlib.Path(temporary) / (source.stem + ("-hsm" if enabled else "-normal") + ".o")
                # Override after forced kconfig includes, also when the saved config enables HSM.
                unit = '#undef CONFIG_RISCV_HSM_CPU_LEASE\n'
                if enabled:
                    unit += '#define CONFIG_RISCV_HSM_CPU_LEASE 1\n'
                unit += '#include "' + str(source) + '"\n'
                subprocess.run(flags + ["-x", "c", "-o", str(output), "-"],
                               input=unit, text=True, cwd=build, check=True)
                print("PASS", source.name, "HSM=" + str(int(enabled)), flush=True)
    print("Object compilation only; firmware link and on-board IPI timing still require board verification.")


if __name__ == "__main__":
    main()
