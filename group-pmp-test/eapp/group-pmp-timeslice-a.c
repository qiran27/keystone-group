#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  volatile uint64_t progress = 0;

  for (int i = 0; i < GROUP_PMP_TIMESLICE_ITERS; i++) {
    progress++;
    group_pmp_enclave_yield();
  }

  return progress == GROUP_PMP_TIMESLICE_ITERS ? 0 : 101;
}
