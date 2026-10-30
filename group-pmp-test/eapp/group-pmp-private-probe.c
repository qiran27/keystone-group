#include <stdint.h>
#include <stdio.h>

#include "syscall.h"

#ifndef RUNTIME_SYSCALL_GROUP_PRIVATE_REGION_INFO
#define RUNTIME_SYSCALL_GROUP_PRIVATE_REGION_INFO 1029
#endif

#include "group-pmp-common.h"

static int
get_private_region_info(struct group_private_region_info* info) {
  return SYSCALL_2(
      RUNTIME_SYSCALL_GROUP_PRIVATE_REGION_INFO, info, sizeof(*info));
}

int
main(void) {
  struct group_private_region_info info;
  int rc = get_private_region_info(&info);
  if (rc != 0 || info.private_va_base == 0 || info.private_size == 0) {
    printf("[group-pmp-private-probe] info failed rc=%d base=0x%lx size=0x%lx\n",
        rc, info.private_va_base, info.private_size);
    return 90;
  }

  uintptr_t probe_addr = info.private_va_base + info.private_size;
  printf("[group-pmp-private-probe] private base=0x%lx size=0x%lx probe=0x%lx\n",
      info.private_va_base, info.private_size, probe_addr);

  /*
   * If the runtime mapped the whole group EPM pool as one contiguous private
   * view, this address would still be reachable. It must not be present:
   * each member should only see its own slice plus explicit shared regions.
   */
  printf("[group-pmp-private-probe] intentionally probing unmapped next-slice va=0x%lx\n",
      probe_addr);
  fflush(stdout);
  volatile unsigned char value = *(volatile unsigned char*)probe_addr;
  printf("[group-pmp-private-probe] unexpected read value=%u\n", value);
  return 91;
}
