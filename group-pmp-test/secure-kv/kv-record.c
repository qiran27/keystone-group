#include "kv-record.h"
#include <string.h>
static const volatile char marker[] __attribute__((used)) = KV_BENCH_MARKER;
static uint64_t value_word(uint64_t key, uint32_t owner, uint32_t version,
                           uint64_t index) {
  uint64_t x = key ^ ((uint64_t)owner << 32) ^ version ^
      (index * UINT64_C(0x9e3779b97f4a7c15));
  x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
  return x ^ (x >> 31);
}
/* Explicit little-endian layout avoids ABI padding and native-endian records. */
static uint8_t record_byte(uint64_t key, uint32_t owner, uint32_t version,
                            size_t offset) {
  if (offset < 8) return (uint8_t)(key >> (offset * 8));
  if (offset < 12) return (uint8_t)(owner >> ((offset - 8) * 8));
  return (uint8_t)(version >> ((offset - 12) * 8));
}
int kv_record_make(uint8_t* output, size_t length, uint64_t key,
                   uint32_t owner, uint32_t version) {
  size_t i;
  if (marker[0] != 'k' || !output || length < KV_RECORD_HEADER_BYTES) return -1;
  for (i = 0; i < KV_RECORD_HEADER_BYTES; ++i)
    output[i] = record_byte(key, owner, version, i);
  for (i = KV_RECORD_HEADER_BYTES; i < length; i += 8) {
    uint64_t word = value_word(key, owner, version, i / 8);
    size_t n = length - i < 8 ? length - i : 8;
    for (size_t j = 0; j < n; ++j) output[i + j] = (uint8_t)(word >> (j * 8));
  }
  return 0;
}
int kv_record_check(const uint8_t* input, size_t length, uint64_t key,
                    uint32_t owner, uint32_t version, uint64_t* digest) {
  uint64_t sum = key ^ ((uint64_t)owner << 32) ^ version ^ length;
  if (!input || length < KV_RECORD_HEADER_BYTES) return -1;
  for (size_t i = 0; i < KV_RECORD_HEADER_BYTES; ++i)
    if (input[i] != record_byte(key, owner, version, i)) return -1;
  for (size_t i = KV_RECORD_HEADER_BYTES; i < length; i += 8) {
    uint64_t word = value_word(key, owner, version, i / 8);
    size_t n = length - i < 8 ? length - i : 8;
    for (size_t j = 0; j < n; ++j)
      if (input[i + j] != (uint8_t)(word >> (j * 8))) return -1;
    sum += word;
  }
  if (digest) *digest += sum; /* Independent of buffer completion order. */
  return 0;
}
