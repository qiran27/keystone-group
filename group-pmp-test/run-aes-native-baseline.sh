#!/bin/sh
set -eu

cd "$(dirname "$0")"

# The benchmark deliberately uses the OpenSSL build selected by the cross
# toolchain. Deploy it privately so boards with OpenSSL 1.1 and 3.x can run the
# same artifact without replacing their system libcrypto.
PRIVATE_CRYPTO_LIB_DIR="${NATIVE_CRYPTO_LIB_DIR:-$PWD/lib}"
if [ -d "$PRIVATE_CRYPTO_LIB_DIR" ]; then
  LD_LIBRARY_PATH="$PRIVATE_CRYPTO_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export LD_LIBRARY_PATH
fi

BENCHMARK="${NATIVE_CRYPTO_BENCHMARK:-./crypto-native-baseline}"
CPU="${NATIVE_CRYPTO_CPU:-1}"
SIZES_MB="${NATIVE_CRYPTO_SIZES_MB:-10 50 100 200 500}"
SAMPLES="${NATIVE_CRYPTO_SAMPLES:-5}"
WARMUP="${NATIVE_CRYPTO_WARMUP:-1}"
ALGORITHMS="${NATIVE_CRYPTO_ALGORITHMS:-aes128 rsa2048 ecdsa sm2 sha256 sm3 sm4}"
CSV_FILE="${NATIVE_CRYPTO_CSV:-./native-crypto-results.csv}"
NATIVE_CRYPTO_MATRIX_MARKER=keystone-native-crypto-ecc-sha256-v1
NATIVE_CRYPTO_PORTABLE_OPENSSL_MARKER=keystone-native-crypto-portable-openssl-v1
NATIVE_CRYPTO_COUNTER_MARKER=keystone-native-counter-perf-v1
NATIVE_CRYPTO_LOCAL_ECC_SM2_MARKER=keystone-native-crypto-supplied-sm2-micro-ecc-v2

case "$CPU" in
  ''|*[!0-9]*)
    echo "[CRYPTO-NATIVE] invalid NATIVE_CRYPTO_CPU: $CPU" >&2
    exit 2
    ;;
esac
case "$SAMPLES" in
  ''|*[!0-9]*)
    echo "[CRYPTO-NATIVE] invalid NATIVE_CRYPTO_SAMPLES: $SAMPLES" >&2
    exit 2
    ;;
esac
case "$WARMUP" in
  ''|*[!0-9]*)
    echo "[CRYPTO-NATIVE] invalid NATIVE_CRYPTO_WARMUP: $WARMUP" >&2
    exit 2
    ;;
esac

if [ "$SAMPLES" -lt 1 ] || [ "$SAMPLES" -gt 100 ]; then
  echo "[CRYPTO-NATIVE] NATIVE_CRYPTO_SAMPLES must be in [1, 100]" >&2
  exit 2
fi
if [ "$WARMUP" -gt 20 ]; then
  echo "[CRYPTO-NATIVE] NATIVE_CRYPTO_WARMUP must be in [0, 20]" >&2
  exit 2
fi
if [ "$SAMPLES" -ne 5 ]; then
  echo "[CRYPTO-NATIVE] note: requested samples=$SAMPLES; the standard matrix uses 5" >&2
fi
if [ ! -x "$BENCHMARK" ]; then
  echo "[CRYPTO-NATIVE] missing executable: $BENCHMARK" >&2
  exit 1
fi
if ! grep -aFq "$NATIVE_CRYPTO_MATRIX_MARKER" "$BENCHMARK"; then
  echo "[CRYPTO-NATIVE] stale benchmark without ECC/SHA-256 support: $BENCHMARK" >&2
  exit 1
fi
if ! grep -aFq "$NATIVE_CRYPTO_PORTABLE_OPENSSL_MARKER" "$BENCHMARK"; then
  echo "[CRYPTO-NATIVE] stale benchmark without portable OpenSSL deployment support: $BENCHMARK" >&2
  exit 1
fi
if ! grep -aFq "$NATIVE_CRYPTO_COUNTER_MARKER" "$BENCHMARK"; then
  echo "[CRYPTO-NATIVE] stale benchmark with non-portable rdcycle timing: $BENCHMARK" >&2
  exit 1
fi
if ! grep -aFq "$NATIVE_CRYPTO_LOCAL_ECC_SM2_MARKER" "$BENCHMARK"; then
  echo "[CRYPTO-NATIVE] stale benchmark without supplied SM2/micro-ecc backends: $BENCHMARK" >&2
  exit 1
fi
if command -v ldd >/dev/null 2>&1; then
  missing_libraries=$(ldd "$BENCHMARK" 2>/dev/null |
    awk '/not found/ { print $1 }' | tr '\n' ' ' || true)
  if [ -n "$missing_libraries" ]; then
    echo "[CRYPTO-NATIVE] missing runtime libraries: $missing_libraries" >&2
    echo "[CRYPTO-NATIVE] expected private libraries under: $PRIVATE_CRYPTO_LIB_DIR" >&2
    echo "[CRYPTO-NATIVE] rebuild and redeploy the complete deploy directory" >&2
    exit 1
  fi
fi

operations_for_algorithm() {
  case "$1" in
    aes128|sm4)
      printf '%s\n' "encrypt decrypt"
      ;;
    rsa2048|ecdsa|sm2)
      printf '%s\n' "hash-sign hash-verify"
      ;;
    sha256|sm3)
      printf '%s\n' "hash"
      ;;
    *)
      echo "[CRYPTO-NATIVE] unsupported algorithm: $1" >&2
      exit 2
      ;;
  esac
}

validate_sizes() {
  for size in $SIZES_MB; do
    case "$size" in
      ''|*[!0-9]*)
        echo "[CRYPTO-NATIVE] invalid size in NATIVE_CRYPTO_SIZES_MB: $size" >&2
        exit 2
        ;;
    esac
    if [ "$size" -le 0 ]; then
      echo "[CRYPTO-NATIVE] size must be positive: $size" >&2
      exit 2
    fi
  done
}

freq_state="${TMPDIR:-/tmp}/group-pmp-native-crypto-cpufreq.$$"
GROUP_PMP_CPU_FREQ_STATE=$freq_state
export GROUP_PMP_CPU_FREQ_STATE
freq_locked=0

if ! grep -q 'keystone-worker-cpufreq-v2' \
    ./prepare-aes-benchmark-env.sh; then
  echo "[CRYPTO-NATIVE] stale prepare-aes-benchmark-env.sh; rebuild and redeploy" >&2
  exit 1
fi

restore_frequency()
{
  if [ "$freq_locked" = 1 ]; then
    freq_locked=0
    if [ -r "$freq_state" ]; then
      sh ./prepare-aes-benchmark-env.sh restore ||
        echo "[CRYPTO-NATIVE][ERROR] failed to restore worker CPU frequency" >&2
    fi
  fi
  rm -f "$freq_state"
}

trap 'restore_frequency' EXIT HUP INT TERM
freq_locked=1
set +e
sh ./prepare-aes-benchmark-env.sh apply
freq_status=$?
set -e
if [ "$freq_status" -ne 0 ]; then
  echo "[CRYPTO-NATIVE] worker CPU frequency apply failed: status=$freq_status" >&2
  exit "$freq_status"
fi
validate_sizes

csv_dir=$(dirname "$CSV_FILE")
csv_base=$(basename "$CSV_FILE")
mkdir -p "$csv_dir"
CSV_TMP="$csv_dir/.${csv_base}.tmp.$$"
trap 'rm -f "$CSV_TMP"; restore_frequency' EXIT HUP INT TERM

printf '%s\n' \
  "algorithm,operation,implementation,cpu,data_mb,bytes,stream_chunk_bytes,round,seconds,counter_ticks,primitive_counter_ticks,ticks_per_byte,mb_per_sec,checksum,verify,march,mabi,counter_source" \
  > "$CSV_TMP"

echo "[CRYPTO-NATIVE] cpu=$CPU sizes_mb=\"$SIZES_MB\" samples=$SAMPLES warmup=$WARMUP" >&2
echo "[CRYPTO-NATIVE] algorithms=\"$ALGORITHMS\" output=$CSV_FILE" >&2

expected_rows=0
for algorithm in $ALGORITHMS; do
  operations=$(operations_for_algorithm "$algorithm")
  for size_mb in $SIZES_MB; do
    bytes=$((size_mb * 1000000))
    for operation in $operations; do
      echo "[CRYPTO-NATIVE] run algorithm=$algorithm operation=$operation size_mb=$size_mb" >&2
      "$BENCHMARK" \
        --algorithm "$algorithm" \
        --operation "$operation" \
        --cpu "$CPU" \
        --bytes "$bytes" \
        --samples "$SAMPLES" \
        --warmup "$WARMUP" \
        --csv >> "$CSV_TMP"
      expected_rows=$((expected_rows + SAMPLES))
    done
  done
done

rows=$(awk 'END { print NR - 1 }' "$CSV_TMP")
if [ "$rows" -ne "$expected_rows" ]; then
  echo "[CRYPTO-NATIVE] incomplete CSV: rows=$rows expected=$expected_rows" >&2
  exit 1
fi
if ! awk -F, 'NR > 1 && (NF != 18 || $15 != "PASS") { exit 1 }' "$CSV_TMP"; then
  echo "[CRYPTO-NATIVE] malformed or failed result row in CSV" >&2
  exit 1
fi
mv -f "$CSV_TMP" "$CSV_FILE"
restore_frequency
trap - EXIT HUP INT TERM

echo "[CRYPTO-NATIVE] PASS rows=$rows csv=$CSV_FILE"
