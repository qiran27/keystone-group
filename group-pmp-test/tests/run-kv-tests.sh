#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
build=${KV_TEST_BUILD_DIR:-.test-kv}
mkdir -p "$build"
aead=$(sh tests/build-benchmark-aead.sh "$build")
gcc -std=gnu11 -O3 -Wall -Wextra -Werror -Wmaybe-uninitialized \
  -DGROUP_PMP_KV_WORKER=1 -include tests/store-native-boundary.h \
  -I../../sdk/include -I../../sdk/include/app -Ieapp \
  -c sqlite-bench-master/keystone_enclave_store.c -o "$build/store-production.o"
gcc -std=gnu11 -O2 -Wall -Wextra -Werror -DGROUP_PMP_KV_WORKER=1 \
  -Itests/include-shadow -I../../sdk/include -Ieapp tests/kv-store-test.c \
  secure-kv/kv-record.c eapp/group-pmp-crypto.c eapp/aes_core.c "$aead" \
  -Wno-unused-function -Wno-unused-const-variable -Wno-sign-compare \
  -Wno-misleading-indentation -o "$build/kv-store"
"$build/kv-store"
gcc -std=gnu11 -O2 -Wall -Wextra -Werror -I../../sdk/include/edge \
  -c ../../sdk/src/edge/edge_dispatch.c -o "$build/edge-dispatch.o"
g++ -std=c++11 -O2 -Wall -Wextra -Werror -I../../sdk/include \
  tests/kv-phase-test.cpp "$build/edge-dispatch.o" -Wl,--wrap=register_call \
  -o "$build/kv-phase"
"$build/kv-phase" "$build"
sh -n run-secure-kv-enclave-scaling.sh
sh -n run-secure-kv-comparison.sh
bash -n rebuild-and-test.sh
g++ -std=c++11 -fsyntax-only -I../../sdk/include -I../../sdk/include/host \
  -I../../sdk/include/edge -Ieapp host/group-pmp-test-runner.cpp
gcc -std=gnu11 -fsyntax-only -DGROUP_PMP_KV_WORKER=1 \
  -I../../sdk/include -I../../sdk/include/app -I../../sdk/include/edge \
  -Ieapp -Isqlite-bench-master eapp/group-pmp-sqlite-worker.c
sh tests/check-kv-wrapper.sh
echo 'KV native store, runner syntax, comparison and wrapper PASS'
