#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  volatile uint64_t progress = 0;

  memset(&layout, 0, sizeof(layout));
  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 111;
  if ((layout.role != GROUP_ROLE_AUXILIARY &&
       layout.role != GROUP_ROLE_WORKER) ||
      (layout.role == GROUP_ROLE_AUXILIARY &&
       layout.allowed_slice_mask != 0) ||
      (layout.role == GROUP_ROLE_WORKER &&
       layout.allowed_slice_mask == 0))
    return 112;

  for (int i = 0; i < GROUP_PMP_TIMESLICE_ITERS; i++) {
    progress += 2;
    group_pmp_enclave_yield();
  }

  return progress == 2 * GROUP_PMP_TIMESLICE_ITERS ? 0 : 113;
}
