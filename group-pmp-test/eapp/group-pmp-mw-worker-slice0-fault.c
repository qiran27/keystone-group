#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  volatile uint64_t* words = group_pmp_yxstm_words();
  volatile uint64_t value;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 251;
  if (layout.role != GROUP_ROLE_WORKER)
    return 252;

  value = words[group_pmp_yxstm_slice_word_base(
      &layout, KEYSTONE_YXSTM_MASTER_SLICE_ID)];
  (void)value;
  return 253;
}
