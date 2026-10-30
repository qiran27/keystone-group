#!/usr/bin/env python3
"""Compile the current lease driver against a prepared VisionFive2 kernel."""

import argparse
from pathlib import Path
import shlex
import subprocess
import tempfile


parser = argparse.ArgumentParser()
parser.add_argument("board", type=Path)
args = parser.parse_args()
board = args.board.resolve()
project = Path(__file__).resolve().parents[3]
kernel_build = board / "work/linux"
command_file = kernel_build / "drivers/keystone-driver/.keystone-ioctl.o.cmd"
command = command_file.read_text().splitlines()[0].split(":=", 1)[1]
tokens = shlex.split(command)
compiler = board / "work/buildroot_initramfs/host/bin/riscv64-buildroot-linux-gnu-gcc"
old_board = tokens[0].split("/work/buildroot_initramfs/", 1)[0]
tokens = [t.replace(old_board, str(board)) for t in tokens]
tokens[0] = str(compiler)
tokens = [t for t in tokens if not t.startswith("-Wp,-MMD,")]
tokens = [t.replace(str(board / "sdk/include/shared"),
                    str(project / "sdk/include/shared")) for t in tokens]
tokens = [t.replace("keystone_ioctl", "keystone_group") for t in tokens]
tokens[tokens.index("-c") + 1:] = [
    "-Werror", "-DCONFIG_RISCV_HSM_CPU_LEASE=1",
    "-o", "OUTPUT", str(project / "linux-keystone-driver/keystone-group.c")]
with tempfile.TemporaryDirectory(prefix="keystone-driver-hsm-") as tmp:
    tokens[tokens.index("OUTPUT")] = str(Path(tmp) / "keystone-group.o")
    subprocess.run(tokens, cwd=kernel_build, check=True)
print("RISC-V driver HSM lease compilation PASS (prepared kernel, HSM enabled)")
