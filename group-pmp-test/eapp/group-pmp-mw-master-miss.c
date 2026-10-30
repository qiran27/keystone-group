#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  volatile uint64_t* words = group_pmp_yxstm_words();

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 311;
  if (layout.role != GROUP_ROLE_MASTER)
    return 312;

  if (group_pmp_yxstm_acquire_mask(
          GROUP_PMP_MW_WORKER_SLICE_MASK,
          KEYSTONE_YXSTM_PERM_R,
          YXSTM_PHASE_AGGREGATE) != 0)
    return 313;

  for (uint64_t slice = 1; slice < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT; slice++) {
    uintptr_t base = group_pmp_yxstm_slice_word_base(&layout, slice);
    if (words[base + 0] == GROUP_PMP_MW_MAGIC &&
        words[base + 3] == GROUP_PMP_MW_STATUS_DISPATCHED) {
      group_pmp_yxstm_release_mask(GROUP_PMP_MW_WORKER_SLICE_MASK);
      return 314;
    }
  }

  if (group_pmp_yxstm_release_mask(GROUP_PMP_MW_WORKER_SLICE_MASK) != 0)
    return 315;

  return 0;
}
