#!/bin/sh
set -eu
if [ "$#" -ne 3 ]; then
  echo "usage: $0 riscv-gcc opensbi-source opensbi-autoconf-header" >&2
  exit 2
fi
cc=$1
opensbi=$2
autoconf=$3
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
example=$(CDPATH= cd -- "$here/.." && pwd)
project=$(CDPATH= cd -- "$example/../.." && pwd)
build=$(mktemp -d /tmp/keystone-sqlite-oncpu.XXXXXX)
trap 'rm -f "$build/enclave.o" "$build/ipi.o" "$build/sbi_trap_hack.o" "$build/store.o" "$build/worker.o"; rmdir "$build"' EXIT HUP INT TERM
for name in enclave ipi sbi_trap_hack; do
"$cc" -c "$project/sm/src/$name.c" -o "$build/$name.o" \
  -O2 -Wall -Werror -ffreestanding -nostdlib -fno-stack-protector \
  -fno-strict-aliasing -mabi=lp64d -march=rv64imafdc_zicsr_zifencei \
  -mcmodel=medany -mstrict-align -D__riscv_xlen=64 \
  '-DTARGET_PLATFORM_HEADER=<platform/starfive/visionfive2/platform.h>' \
  -I"$project/sm/src" -I"$project/sdk/include/shared" \
  -I"$opensbi/include" -include "$autoconf"
done
for name in store worker; do
  case $name in
    store) source=$example/sqlite-bench-master/keystone_enclave_store.c ;;
    worker) source=$example/eapp/group-pmp-sqlite-worker.c ;;
  esac
  "$cc" -c "$source" -o "$build/$name.o" -O3 -Wall -Wextra -Werror \
    -mabi=lp64d -march=rv64imafdc_zicsr_zifencei \
    -I"$project/sdk/include" -I"$project/sdk/include/app" \
    -I"$example/eapp" -I"$example/sqlite-bench-master"
done
echo 'RISC-V SM, SQLite store and worker compilation PASS'
