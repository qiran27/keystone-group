#!/bin/sh
set -eu
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
mkdir -p "$1"
build=$(CDPATH= cd "$1" && pwd)
vendor=$root/security/vendor/mbedtls-3.6.7
objects=
for source in "$root/eapp/benchmark-cipher.c" \
    "$vendor/library/aes.c" "$vendor/library/gcm.c" "$vendor/library/block_cipher.c" \
    "$vendor/library/chacha20.c" "$vendor/library/poly1305.c" "$vendor/library/chachapoly.c" \
    "$vendor/library/platform_util.c" "$vendor/library/constant_time.c"; do
  obj="$build/aead-$(basename "$source" .c).o"
  ${CC:-gcc} -std=c11 -O2 -Wall -Wextra -Werror -DMBEDTLS_CONFIG_FILE='"aead-config.h"' \
    -I"$root/security" -I"$vendor/include" -I"$vendor/library" -c "$source" -o "$obj"
  objects="$objects $obj"
done
ar rcs "$build/benchmark-aead.a" $objects
printf '%s\n' "$build/benchmark-aead.a"
