#include <stdint.h>

/*
 * Keep a worker in enclave context until HOST revokes the worker lease. The
 * volatile counter prevents the loop from being optimized away; successful
 * completion is the lease-release path returning the saved HOST frame, not
 * an eapp exit.
 */
int
main(void) {
  volatile uint64_t progress = 0;

  for (;;) {
    progress++;
    __asm__ __volatile__("" ::: "memory");
  }
}
