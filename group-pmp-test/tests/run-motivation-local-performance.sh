#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
bytes=${1:-500000000}; repetitions=${2:-10}; cache=${3:-cold}
output=${4:-/var/tmp/motivation-native-v4-$(date +%Y%m%d-%H%M%S)-$$}
mkdir "$output"
output=$(CDPATH= cd "$output" && pwd)
build=$(mktemp -d /tmp/motivation-native-build-XXXXXXXX)
trap 'rm -rf "$build"' EXIT
archive=$(sh tests/build-benchmark-aead.sh "$build")
gcc -std=c11 -O2 -Wall -Wextra -Werror -DMBEDTLS_CONFIG_FILE='"aead-config.h"' \
  -Isecurity -Isecurity/vendor/mbedtls-3.6.7/include -c motivation/core.c -o "$build/core.o"
gcc -std=c11 -O2 -Wall -Wextra -Werror -I../../sdk/include -c motivation/architecture.c -o "$build/architecture.o"
gcc -std=c11 -O2 -Wall -Wextra -Werror -c eapp/aes_core.c -o "$build/aes.o"
g++ -std=c++11 -O2 -Wall -Wextra -Werror -pthread -I../../sdk/include tests/motivation-local-performance.cpp \
  "$build/core.o" "$build/architecture.o" "$build/aes.o" "$archive" -o "$build/local-performance"
cp "$build/local-performance" "$output/local-performance"
{
  uname -a
  df -P "$output"
  lscpu
  sha256sum "$output/local-performance" motivation/core.c motivation/backend.hpp \
    motivation/protocol.h motivation/uring-io.hpp host/io-uring-transport.hpp eapp/aes_core.c \
    motivation/architecture.c motivation/architecture.h tests/motivation-tsr-model.hpp \
    tests/motivation-local-performance.cpp tests/run-motivation-local-performance.sh
} > "$output/build-environment.txt"
MOT_LOCAL_KEEP_INPUT=1 "$output/local-performance" "$output" "$bytes" "$repetitions" "$cache" > "$output/run.log" 2>&1 || {
  cat "$output/run.log" >&2;exit 1;
}
sha256sum "$output/cipher.bin" > "$output/input-sha256.txt"
wc -c < "$output/cipher.bin" > "$output/input-ciphertext-bytes.txt"
rm -f "$output/cipher.bin"
python3 motivation/summarize.py "$output"
sha256sum "$output/samples.csv" "$output/"*-trace.csv > "$output/data-sha256.txt"
if [ "${MOT_LOCAL_ARCHITECTURE:-0}" = 1 ]; then
  sha256sum "$output/"*-tasks.csv >> "$output/data-sha256.txt"
fi
cat "$output/run.log"
cat "$output/summary.csv"
echo "Native Linux only; no RISC-V enclave/OCALL timings. Evidence: $output"
