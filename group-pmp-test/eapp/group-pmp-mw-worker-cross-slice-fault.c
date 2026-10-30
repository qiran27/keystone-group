#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  volatile uint64_t* words = group_pmp_yxstm_words();
  uint64_t own_slice;
  uint64_t other_slice;
  uintptr_t other_base;
  volatile uint64_t value;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 241;
  if (layout.role != GROUP_ROLE_WORKER ||
      layout.worker_slice_id == (uintptr_t)-1)
    return 242;

  own_slice = layout.worker_slice_id;
  other_slice = own_slice == 1 ? 2 : 1;
  other_base = group_pmp_yxstm_slice_word_base(&layout, other_slice);

  value = words[other_base];
  (void)value;
  return 243;
}
