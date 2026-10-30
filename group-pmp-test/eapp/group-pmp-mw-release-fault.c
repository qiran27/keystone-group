#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  struct keystone_yxstm_protocol_state state;
  struct keystone_yxstm_phase_transition request;
  volatile uint64_t* words = group_pmp_yxstm_words();
  uintptr_t base;
  volatile uint64_t value;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 271;
  if (layout.role != GROUP_ROLE_MASTER)
    return 272;
  if (group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0 ||
      state.phase != YXSTM_PHASE_IDLE)
    return 273;

  request.expected_epoch = state.phase_epoch;
  request.next_phase = YXSTM_PHASE_DISPATCH;
  request.active_worker_mask = GROUP_PMP_MW_WORKER_SLICE_MASK;
  request.sequence = state.sequence + 1;
  request.payload_length = sizeof(uint64_t);
  request.timeout_cycles = UINT64_C(10000000000);
  if (group_pmp_yxstm_phase_transition(&request) != 0)
    return 274;
  if (group_pmp_yxstm_acquire_mask(
          GROUP_PMP_MW_WORKER_SLICE_MASK,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_DISPATCH) != 0)
    return 275;

  base = group_pmp_yxstm_slice_word_base(&layout, 1);
  words[base] = UINT64_C(0x52454c4541534554);
  if (group_pmp_yxstm_release_mask(GROUP_PMP_MW_WORKER_SLICE_MASK) != 0)
    return 276;

  value = words[base];
  (void)value;
  return 277;
}
