#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 261;
  if (layout.role != GROUP_ROLE_MASTER)
    return 262;

  if (group_pmp_yxstm_acquire_mask(
          GROUP_PMP_MW_WORKER_SLICE_MASK,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_AGGREGATE) == 0) {
    group_pmp_yxstm_release_mask(GROUP_PMP_MW_WORKER_SLICE_MASK);
    return 263;
  }

  return 0;
}
