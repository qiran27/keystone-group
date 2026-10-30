#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  volatile uint64_t value;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 331;
  if (layout.role != GROUP_ROLE_MASTER)
    return 332;

  value = group_pmp_yxstm_words()[0];
  (void)value;
  return 333;
}
