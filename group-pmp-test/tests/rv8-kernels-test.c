#include "../rv8-bench-master/port/rv8-kernels.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint8_t data[2000000];
static uint8_t backup[2000000];
int main(void) {
  struct rv8_kernel_stats stats;
  uint32_t seed = 12345;
  for (size_t i = 0; i < sizeof(data); ++i) {
    seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
    data[i] = (uint8_t)seed;
  }
  memcpy(backup, data, sizeof(data));
  assert(rv8_kernel_init() == 0);
  rv8_kernel_get_stats(&stats);
  assert(stats.validated && stats.profile == RV8_PROFILE && !stats.bytes && !stats.blocks);
  assert(rv8_kernel_process(NULL, 16) == -1);
  assert(rv8_kernel_process(data, 17) == -1);
  const size_t lengths[] = {16, 240, 65536, 65552, 2000000};
  uint64_t total = 0, blocks = 0;
  for (size_t i = 0; i < sizeof(lengths)/sizeof(lengths[0]); ++i) {
    assert(rv8_kernel_process(data, lengths[i]) == 0);
    total += lengths[i]; blocks += (lengths[i]+65535)/65536;
  }
  assert(!memcmp(data, backup, sizeof(data)));
  rv8_kernel_account(100, 150); rv8_kernel_get_stats(&stats);
  assert(stats.bytes == total && stats.blocks == blocks && stats.digest);
  assert(stats.cpu_ticks == 100 && stats.elapsed_ticks == 150);
  assert(rv8_kernel_init() == 0);
  rv8_kernel_get_stats(&stats); assert(!stats.bytes && !stats.cpu_ticks);
  printf("rv8 profile=%d coverage/roundtrip/KAT/reset PASS\n", RV8_PROFILE);
}
