#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
build=${BENCHMARK_CIPHER_TEST_BUILD:-.test-benchmark-cipher}
mkdir -p "$build"
aead=$(sh tests/build-benchmark-aead.sh "$build")
vendor=security/vendor/mbedtls-3.6.7
gcc -std=c11 -O2 -Wall -Wextra -Werror -DMBEDTLS_CONFIG_FILE='"aead-config.h"' \
  -Isecurity -I"$vendor/include" -I"$vendor/library" \
  tests/benchmark-aead-test.c security/security-aead.c "$aead" -o "$build/unit"
"$build/unit"
gcc -std=gnu11 -O2 -Wall -Wextra -Werror -Itests/include-shadow -I../../sdk/include -Ieapp \
  tests/benchmark-aead-store-test.c eapp/group-pmp-crypto.c eapp/aes_core.c "$aead" -o "$build/store"
"$build/store"
for script in run-benchmark-cipher.sh run-p10-mixed-scaling.sh run-fio-enclave-scaling.sh run-secure-kv-enclave-scaling.sh; do sh -n "$script"; done
g++ -std=c++11 -fsyntax-only -I../../sdk/include -I../../sdk/include/host \
  -I../../sdk/include/edge -Ieapp host/group-pmp-test-runner.cpp
