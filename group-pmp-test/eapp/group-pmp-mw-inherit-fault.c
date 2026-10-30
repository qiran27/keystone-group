#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  volatile uint64_t* words = group_pmp_yxstm_words();
  uintptr_t base;
  volatile uint64_t value;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 291;
  if (layout.role != GROUP_ROLE_WORKER ||
      layout.worker_slice_id == (uintptr_t)-1)
    return 292;

  base = group_pmp_yxstm_slice_word_base(&layout, layout.worker_slice_id);
  value = words[base];
  (void)value;
  return 293;
}
