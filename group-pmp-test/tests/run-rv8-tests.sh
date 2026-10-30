#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
build=${RV8_TEST_BUILD_DIR:-.test-rv8-compute}
mkdir -p "$build"
sources="rv8-bench-master/src/aes.c rv8-bench-master/src/miniz.c rv8-bench-master/src/norx.c rv8-bench-master/src/qsort.c rv8-bench-master/src/sha512.c rv8-bench-master/src/dhrystone.c rv8-bench-master/src/primes.c"
objects=""
for source in $sources; do
  object="$build/$(basename "$source").o"
  gcc -std=gnu11 -O3 -DRV8_BENCH_LIBRARY=1 -c "$source" -o "$object"
  objects="$objects $object"
done
# Match the worker's minimal libc headers, not the host's full string.h.
g++ -std=c++11 -O3 -fno-exceptions -DRV8_BENCH_LIBRARY=1 \
  -Isqlite-bench-master -I../../sdk/include/app \
  -c rv8-bench-master/src/bigint.cc -o "$build/bigint.o"
for profile in 1 2 3 4 5 6 7 8; do
  gcc -std=gnu11 -O3 -Wall -Wextra -Werror -DRV8_PROFILE=$profile \
    -c rv8-bench-master/port/rv8-kernels.c -o "$build/adapter-$profile.o"
  gcc -std=gnu11 -O2 -DRV8_PROFILE=$profile -c tests/rv8-kernels-test.c -o "$build/test-$profile.o"
  extra=""; compiler=gcc
  if [ "$profile" = 1 ]; then extra="$build/bigint.o"; compiler=g++; fi
  $compiler "$build/test-$profile.o" "$build/adapter-$profile.o" $objects $extra -o "$build/kernel-$profile"
  "$build/kernel-$profile"
done
gcc -std=gnu11 -fsyntax-only -Wall -Wextra -Werror -I../../sdk/include \
  -I../../sdk/include/app -I../../sdk/include/edge -Ieapp -Irv8-bench-master/port \
  eapp/group-pmp-rv8-worker.c
gcc -std=gnu11 -O2 -Wall -Wextra -Werror -DRV8_PROFILE=6 -I../../sdk/include \
  -Ieapp -Irv8-bench-master/port tests/rv8-worker-test.c "$build/adapter-6.o" $objects \
  -o "$build/worker-protocol"
"$build/worker-protocol"
gcc -std=gnu11 -O2 -I../../sdk/include/edge -c ../../sdk/src/edge/edge_dispatch.c -o "$build/edge.o"
g++ -std=c++11 -O2 -I../../sdk/include tests/rv8-ocall-init-test.cpp "$build/edge.o" \
  -Wl,--wrap=register_call -o "$build/host-control"
"$build/host-control" "$build"
sh tests/check-rv8-wrapper.sh
sh -n run-rv8-enclave-scaling.sh
bash -n rebuild-and-test.sh
echo 'RV8 eight compute kernels, worker syntax, control-only entry and wrapper PASS'
