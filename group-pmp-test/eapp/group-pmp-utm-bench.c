#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "group-pmp-common.h"

int
main(void) {
  static uint8_t buffer[GROUP_PMP_UTM_BENCH_CHUNK_BYTES];
  uint64_t total = 0;
  uint64_t checksum = 0;
  uint64_t start_cycles = group_pmp_rdcycle();

  while (total < GROUP_PMP_BENCH_BATCH_BYTES) {
    uint64_t chunk = GROUP_PMP_UTM_BENCH_CHUNK_BYTES;
    if (GROUP_PMP_BENCH_BATCH_BYTES - total < chunk)
      chunk = GROUP_PMP_BENCH_BATCH_BYTES - total;

    memset(buffer, 0, sizeof(buffer));
    if (copy_from_shared(buffer, GROUP_PMP_UTM_BENCH_OFFSET, chunk) != 0)
      return 1;
    for (uint64_t i = 0; i < chunk; ++i) {
      if (buffer[i] != group_pmp_bench_plain_byte(i))
        return 2;
      checksum = checksum * UINT64_C(131) + buffer[i];
    }
    total += chunk;
  }

  printf("[P10][path] path=utm-copy data_mb=%lu cycles=%lu checksum=%lu "
         "chunk=%u offset=%u\n",
         (uint64_t)(GROUP_PMP_BENCH_BATCH_BYTES / UINT64_C(1000000)),
         group_pmp_rdcycle() - start_cycles, checksum,
         GROUP_PMP_UTM_BENCH_CHUNK_BYTES, GROUP_PMP_UTM_BENCH_OFFSET);
  fflush(stdout);
  return 0;
}
