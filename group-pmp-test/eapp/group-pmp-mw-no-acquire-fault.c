#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  volatile uint64_t* words = group_pmp_yxstm_words();
  uintptr_t word_base;
  volatile uint64_t value;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 281;
  if (layout.role != GROUP_ROLE_WORKER ||
      layout.worker_slice_id == (uintptr_t)-1)
    return 282;

  word_base = group_pmp_yxstm_slice_word_base(
      &layout, layout.worker_slice_id);
  value = words[word_base];
  (void)value;
  return 283;
}
