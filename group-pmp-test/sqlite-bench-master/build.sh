#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_TYPE="${1:-riscv}"
KEYSTONE_DIR="${KEYSTONE_DIR:-/home/wuju/keystone_yx}"
BUILDROOT_HOST="${KEYSTONE_DIR}/build-starfive/visionfive264/buildroot.build/host"

if [ "${BUILD_TYPE}" = "native" ]; then
    echo "=== Native Linux build ==="
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j"$(nproc)"

    echo ""
    echo "=== Build complete ==="
    echo "Binary:"
    echo "  build/sqlite-bench"
    exit 0
fi

echo "=== Cross-compiling sqlite-bench for RISC-V ==="

CROSS_COMPILE="${BUILDROOT_HOST}/bin/riscv64-buildroot-linux-gnu-"
if [ ! -f "${CROSS_COMPILE}gcc" ]; then
    echo "ERROR: Cross compiler not found: ${CROSS_COMPILE}gcc"
    echo "Set KEYSTONE_DIR or build buildroot first."
    exit 1
fi

mkdir -p build-riscv
cd build-riscv
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="${CROSS_COMPILE}gcc" \
    -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_SYSTEM_PROCESSOR=riscv64
make -j"$(nproc)"

echo ""
echo "=== Build complete ==="
echo "Binary:"
echo "  build-riscv/sqlite-bench"
echo ""
echo "Example deploy:"
echo "  scp build-riscv/sqlite-bench root@board-b:/root/"
echo ""
echo "Example run on board:"
echo "  ./sqlite-bench --keystone_mode=1 --total_mb=512 --batch_mb=8 --resident_mb=8 --benchmarks=fillseq,fillseqbatch,fillrandom,fillrandbatch,overwrite,readseq,readrandom,readrand100K --WAL_enabled=0 --db=/myusb/sqlite-native/ --sec_base=0x16000000 --sec_size=0x4000"
echo "Note: Keystone mode on RISC-V uses JH7110 SEC PIO via /dev/mem, so run as root."
