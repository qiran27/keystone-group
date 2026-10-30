#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
build=$(mktemp -d /tmp/group-security-test.XXXXXX)
# All generated paths are in this private mktemp directory.
trap 'rm -rf "$build"' EXIT HUP INT TERM
vendor=$root/security/vendor/mbedtls-3.6.7
sources=
for unit in aes gcm block_cipher chacha20 poly1305 chachapoly platform_util constant_time; do
  sources="$sources $vendor/library/$unit.c"
done
${CC:-gcc} -std=c11 -O2 -Wall -Wextra -Werror \
  -DMBEDTLS_CONFIG_FILE='"aead-config.h"' \
  -I"$root/security" -I"$vendor/include" -I"$vendor/library" \
  "$root/tests/security-aead-test.c" "$root/security/security-aead.c" $sources \
  -o "$build/aead-test"
"$build/aead-test"
# Use the enclave SDK's actual allocator/string implementation, not just libc.
sdk_memory_names='-Dmalloc=security_sdk_malloc -Dcalloc=security_sdk_calloc
  -Dfree=security_sdk_free -Drealloc=security_sdk_realloc
  -Dmemalign=security_sdk_memalign -Dvalloc=security_sdk_valloc
  -Dpvalloc=security_sdk_pvalloc -Dcfree=security_sdk_cfree
  -Dmalloc_trim=security_sdk_malloc_trim -Dmalloc_usable_size=security_sdk_malloc_usable_size
  -Dmalloc_stats=security_sdk_malloc_stats -Dmallopt=security_sdk_mallopt
  -Dmallinfo=security_sdk_mallinfo -Dmemcpy=security_sdk_memcpy
  -Dmemset=security_sdk_memset -Dmemcmp=security_sdk_memcmp
  -Dmemmove=security_sdk_memmove -Dstrlen=security_sdk_strlen'
${CC:-gcc} -std=gnu11 -O2 -fno-builtin -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
  $sdk_memory_names -DMBEDTLS_CONFIG_FILE='"aead-config.h"' \
  -I"$root/security" -I"$vendor/include" -I"$vendor/library" \
  "$root/tests/security-sdk-memory-test.c" "$root/security/security-aead.c" \
  $sources "$root/../../sdk/src/app/tiny-malloc.c" "$root/../../sdk/src/app/string.c" \
  -no-pie -Wl,--defsym=__malloc_start=security_sdk_heap -o "$build/sdk-memory-test"
timeout 20 "$build/sdk-memory-test"
# GCM and its block-cipher path must have no unresolved heap calls.
# platform_util also defines an unrelated zeroize-and-free API, not used here.
for source in "$root/security/security-aead.c" $sources; do
  case "$source" in */platform_util.c) continue ;; esac
  object="$build/noheap-$(basename "$source" .c).o"
  ${CC:-gcc} -std=c11 -O2 -DMBEDTLS_CONFIG_FILE='"aead-config.h"' \
    -I"$root/security" -I"$vendor/include" -I"$vendor/library" \
    -c "$source" -o "$object"
  if nm -u "$object" | grep -Eq '[[:space:]](malloc|calloc|realloc|free)$'; then
    echo "Security crypto unexpectedly depends on heap: $source" >&2
    exit 1
  fi
done
sdk=$root/../../sdk/include
${CC:-gcc} -std=c11 -O2 -Wall -Wextra -Werror -I"$sdk/edge" \
  "$root/tests/security-edge-dispatch-test.c" "$root/../../sdk/src/edge/edge_dispatch.c" \
  -o "$build/edge-dispatch-test"
"$build/edge-dispatch-test"
for target in 1 2 3 4; do
  for write in 0 1; do
    ${CC:-gcc} -std=gnu11 -O2 -Wall -Wextra -Werror \
      -DSECURITY_TARGET="$target" -DSECURITY_WRITE="$write" \
      -I"$sdk" -I"$sdk/app" -I"$root/eapp" \
      "$root/tests/security-access-transport-test.c" -o "$build/access-test"
    (ulimit -c 0; "$build/access-test")
  done
done
${CC:-gcc} -std=gnu11 -O2 -Wall -Wextra -Werror -Dmain=security_fixture_main \
  -I"$sdk" -I"$sdk/app" -I"$root/eapp" \
  -c "$root/eapp/group-pmp-security-aead.c" -o "$build/aead-eapp.o"
${CC:-gcc} -std=gnu11 -O2 -Wall -Wextra -Werror \
  -DMBEDTLS_CONFIG_FILE='"aead-config.h"' \
  -I"$root/security" -I"$vendor/include" -I"$vendor/library" \
  "$root/tests/security-aead-transport-test.c" "$build/aead-eapp.o" \
  "$root/security/security-aead.c" $sources -o "$build/transport-test"
"$build/transport-test"
${CXX:-g++} -std=c++11 -O2 -Wall -Wextra -Werror -pthread \
  "$root/security/security-scan.cpp" -o "$build/scanner"
${CXX:-g++} -std=c++11 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/security-scan-fixture.cpp" -o "$build/fixture"
"$build/scanner" --security-scan-info | grep -q 'security_scanner_fixture_version=4 scope=registered-ciphertext-only'
mkdir "$build/data"
"$build/scanner" 88771235 "$build/data" "$build/healthy.csv" "$build/healthy.regions" \
  -- "$build/fixture" "$build/data/cipher.bin" healthy
status=0
"$build/scanner" 88771236 "$build/data" "$build/leak.csv" "$build/leak.regions" \
  -- "$build/fixture" "$build/data/cipher.bin" leak || status=$?
[ "$status" = 1 ] || { echo 'Scanner did not detect the injected cross-chunk leak' >&2; exit 1; }
for fixture in no-control no-checkpoint unreadable-control; do
  status=0
  "$build/scanner" 88771237 "$build/data" "$build/$fixture.csv" "$build/$fixture.regions" \
    -- "$build/fixture" "$build/data/cipher.bin" "$fixture" || status=$?
  [ "$status" = 2 ] || { echo 'Scanner falsely accepted incomplete coverage' >&2; exit 1; }
done
for fixture in host-healthy host-removed unregistered-leak; do
  "$build/scanner" 88771238 "$build/data" "$build/$fixture.csv" "$build/$fixture.regions" \
    -- "$build/fixture" "$build/data/cipher.bin" "$fixture"
done
grep -q 'host-ciphertext-buffer' "$build/host-healthy.csv"
for fixture in host-leak file-leak; do
  status=0
  "$build/scanner" 88771239 "$build/data" "$build/$fixture.csv" "$build/$fixture.regions" \
    -- "$build/fixture" "$build/data/cipher.bin" "$fixture" || status=$?
  [ "$status" = 1 ] || { echo 'Scanner did not detect a registered buffer/file leak' >&2; exit 1; }
done
${CC:-gcc} -std=gnu11 -Wall -Wextra -Werror -fsyntax-only \
  -I"$sdk" -I"$sdk/app" -I"$root/eapp" -I"$root/sqlite-bench-master" \
  "$root/eapp/group-pmp-security-access.c" "$root/eapp/group-pmp-security-aead.c" \
  "$root/eapp/group-pmp-sqlite-worker.c"
${CXX:-g++} -std=c++11 -pthread -fsyntax-only \
  -I"$sdk" -I"$sdk/edge" -I"$root/eapp" \
  "$root/host/group-pmp-test-runner.cpp"
sh -n "$root/run-security-experiments.sh"
bash -n "$root/rebuild-and-test.sh"
python3 "$root/tests/check-security-contract.py"
echo 'Native security regression and production syntax PASS; board PMP execution remains unverified'
