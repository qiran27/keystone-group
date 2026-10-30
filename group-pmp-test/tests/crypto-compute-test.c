#define _POSIX_C_SOURCE 200809L
#include "crypto-compute.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>

static int native_clock(struct crypto_compute_stamp* s) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
  s->wall_ticks = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
  s->cpu_ticks = s->wall_ticks; s->cycles = s->wall_ticks;
  return 0;
}
static int failed_clock(struct crypto_compute_stamp* s) {
  (void)s; return -1;
}

int main(void) {
  _Static_assert(CRYPTO_COMPUTE_FREE_BYTES >= 3 * CRYPTO_COMPUTE_BLOCK_BYTES + 4 * 1024 * 1024,
                 "ELF BSS buffers must not consume the runtime headroom");
  _Static_assert(CRYPTO_COMPUTE_FREE_BYTES % 4096 == 0, "page-rounded EPM reservation");
  const uint64_t sizes[] = {16, 4096, CRYPTO_COMPUTE_BLOCK_BYTES + 16};
  struct crypto_compute_config c = {CRYPTO_COMPUTE_MAGIC, CRYPTO_COMPUTE_VERSION, 0, 1, 16, 1};
  struct crypto_compute_result r;
  unsigned checks = 0;
  for (c.algorithm = 0; c.algorithm < 3; ++c.algorithm)
    for (c.operation = 1; c.operation <= 2; ++c.operation)
      for (unsigned i = 0; i < sizeof(sizes)/sizeof(sizes[0]); ++i) {
        c.total_bytes = sizes[i];
        assert(crypto_compute_run(&c, native_clock, &r) == 0);
        assert(r.validated && !r.error_code && r.processed_bytes == sizes[i]);
        assert(r.blocks == (sizes[i]+CRYPTO_COMPUTE_BLOCK_BYTES-1)/CRYPTO_COMPUTE_BLOCK_BYTES);
        assert(r.cpu_ticks && r.cpu_ticks == r.wall_ticks);
        checks++;
      }
  c.algorithm = 0; c.operation = 1; c.total_bytes = 16;
  assert(crypto_compute_run(&c, failed_clock, &r) != 0 && !r.validated && r.error_code == 4);
  c.total_bytes = 15;
  assert(crypto_compute_run(&c, native_clock, &r) != 0 && !r.validated);
  c.total_bytes = 500000016;
  assert(crypto_compute_run(&c, native_clock, &r) != 0 && !r.validated);
  c.total_bytes = 16; c.algorithm = 3;
  assert(crypto_compute_run(&c, native_clock, &r) != 0 && !r.validated);
  puts("PASS: 18 native-only crypto roundtrips, tail blocks, invalid inputs and clock failure; NOT enclave measurements");
  return checks == 18 ? 0 : 1;
}
