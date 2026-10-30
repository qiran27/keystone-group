# Sourced by benchmark launchers; --cipher must precede positional arguments.
if [ "${1:-}" = --cipher ]; then
  [ "$#" -ge 2 ] || { echo '--cipher requires an algorithm' >&2; exit 2; }
  GROUP_PMP_BENCH_CIPHER=$2
  shift 2
fi
case "${GROUP_PMP_BENCH_CIPHER:-aes-ecb-128}" in
  aes-ecb-128|aes-128-ecb|ecb) GROUP_PMP_BENCH_CIPHER=aes-ecb-128; BENCH_CIPHER_SUFFIX=ecb ;;
  aes-gcm-128|aes-128-gcm|gcm) GROUP_PMP_BENCH_CIPHER=aes-gcm-128; BENCH_CIPHER_SUFFIX=gcm ;;
  chacha20-poly1305|ChaCha20-Poly1305|chacha) GROUP_PMP_BENCH_CIPHER=chacha20-poly1305; BENCH_CIPHER_SUFFIX=chacha ;;
  *) echo 'cipher must be aes-ecb-128, aes-gcm-128 or chacha20-poly1305' >&2; exit 2 ;;
esac
export GROUP_PMP_BENCH_CIPHER

require_benchmark_cipher() {
  [ "$GROUP_PMP_BENCH_CIPHER" != aes-ecb-128 ] || return 0
  for cipher_artifact in "$@"; do
    grep -aq 'keystone-benchmark-cipher-v1' "$cipher_artifact" || {
      echo "Missing selectable-cipher support: $cipher_artifact; rebuild/deploy" >&2
      exit 1
    }
  done
}
