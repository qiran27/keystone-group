#ifndef KEYSTONE_SQLITE_LOCALITY_ADDRESS_H
#define KEYSTONE_SQLITE_LOCALITY_ADDRESS_H
#include <stdint.h>

/* A bounded cycle-walk permutation; no table, duplicate pages or future I/O. */
static inline uint64_t sqlite_permute_unit(uint64_t index, uint64_t count,
                                         uint64_t seed) {
  unsigned bits = 0;
  uint64_t domain = 1;
  while (domain < count) { domain <<= 1; ++bits; }
  if (bits & 1U) { domain <<= 1; ++bits; }
  const unsigned half_bits = bits / 2;
  const uint64_t mask = (UINT64_C(1) << half_bits) - 1;
  uint64_t value = index;
  do {
    uint64_t left = value >> half_bits, right = value & mask;
    for (unsigned round = 0; round < 6; ++round) {
      uint64_t mixed = right ^ seed ^ (UINT64_C(0x94d049bb133111eb) * (round + 1));
      mixed ^= mixed >> 30; mixed *= UINT64_C(0xbf58476d1ce4e5b9);
      mixed ^= mixed >> 27; mixed *= UINT64_C(0x94d049bb133111eb);
      mixed ^= mixed >> 31;
      value = ((right & mask) << half_bits) | ((left ^ mixed) & mask);
      left = value >> half_bits; right = value & mask;
    }
  } while (value >= count);
  return value;
}

/* Each four generated pages contain one adjacent pair and two single pages.
 * Domains are disjoint and internally permuted without repetition. This is a
 * locality-bearing random workload, not uniform independent random I/O.
 * Sync, Async and Adaptive call this same function with identical seed inputs. */
static inline uint64_t sqlite_locality_page(uint64_t index, uint64_t task_bytes,
                                          uint64_t worker_index) {
  const uint64_t blocks = (task_bytes / 4096) / 4;
  if (!blocks || index >= blocks * 4) return index;
  const uint64_t block = index / 4, part = index % 4;
  const uint64_t seed = UINT64_C(0x9e3779b97f4a7c15) ^
      (worker_index + 1) * UINT64_C(0xbf58476d1ce4e5b9) ^ task_bytes;
  if (part < 2) return 2 * sqlite_permute_unit(block, blocks, seed) + part;
  return part * blocks + sqlite_permute_unit(block, blocks,
      seed ^ (part * UINT64_C(0xd6e8feb86659fd93)));
}
#endif
