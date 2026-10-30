#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  volatile uint64_t* words = group_pmp_yxstm_words();
  uint64_t slice;
  uintptr_t base;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 281;
  if (layout.role != GROUP_ROLE_WORKER ||
      layout.worker_slice_id == (uintptr_t)-1)
    return 282;

  slice = layout.worker_slice_id;
  base = group_pmp_yxstm_slice_word_base(&layout, slice);
  if (group_pmp_yxstm_acquire_slice(
          slice,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_AGGREGATE) != 0)
    return 283;

  words[base] = UINT64_C(0x484f4c445949454c);
  group_pmp_enclave_yield();
  return 0;
}
