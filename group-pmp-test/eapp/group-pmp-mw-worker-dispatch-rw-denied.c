#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  uint64_t slice;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 231;
  if (layout.role != GROUP_ROLE_WORKER ||
      layout.worker_slice_id == (uintptr_t)-1)
    return 232;

  slice = layout.worker_slice_id;
  if (group_pmp_yxstm_acquire_slice(
          slice,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_DISPATCH) == 0) {
    group_pmp_yxstm_release_slice(slice);
    return 233;
  }

  return 0;
}
