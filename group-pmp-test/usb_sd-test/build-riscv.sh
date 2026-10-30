#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=${1:-"$script_dir/usb-sd-bench.riscv64"}

if [ -n "${RISCV_CC:-}" ]; then
  compiler=$RISCV_CC
elif command -v riscv64-buildroot-linux-gnu-gcc >/dev/null 2>&1; then
  compiler=riscv64-buildroot-linux-gnu-gcc
elif command -v riscv64-linux-gnu-gcc >/dev/null 2>&1; then
  compiler=riscv64-linux-gnu-gcc
elif [ -x "$script_dir/../../../../VisionFive2_devl/work/buildroot_initramfs/host/bin/riscv64-buildroot-linux-gnu-gcc" ]; then
  compiler=$script_dir/../../../../VisionFive2_devl/work/buildroot_initramfs/host/bin/riscv64-buildroot-linux-gnu-gcc
else
  echo "RISC-V compiler not found; set RISCV_CC or add it to PATH" >&2
  exit 1
fi

"$compiler" -std=c11 -O2 -Wall -Wextra -Werror -D_FILE_OFFSET_BITS=64 \
  -march=rv64gc -mabi=lp64d "$script_dir/usb-sd-bench.c" -o "$output"
echo "RISC-V benchmark built: $output"
