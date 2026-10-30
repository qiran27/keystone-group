#!/bin/sh
set -eu
root=$(CDPATH= cd "$(dirname "$0")" && pwd)
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || {
  echo 'usage: build-evidence-module.sh prepared-board-kernel-build-dir [output.ko]' >&2; exit 2;
}
kernel=$(CDPATH= cd "$1" && pwd -P)
[ -r "$kernel/Module.symvers" ] && [ -r "$kernel/.config" ] || {
  echo 'Use the exact configured and fully built board kernel, not headers or modules_prepare alone' >&2; exit 2;
}
work=$(mktemp -d)
trap 'rm -r "$work"' EXIT HUP INT TERM
cp "$root/kernel/Makefile" "$root/kernel/keystone_evidence.c" "$root/kernel/evidence-uapi.h" "$work/"
make -C "$kernel" M="$work" ARCH="${ARCH:-riscv}" \
  CROSS_COMPILE="${CROSS_COMPILE:-riscv64-buildroot-linux-gnu-}" modules
cp "$work/keystone_evidence.ko" "${2:-./keystone_evidence.ko}"
