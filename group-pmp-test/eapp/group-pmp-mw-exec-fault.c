#include <stdint.h>

#include "group-pmp-common.h"

typedef void (*yxstm_code_fn)(void);

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  struct keystone_yxstm_protocol_state state;
  struct keystone_yxstm_phase_transition request;
  volatile uint32_t* yxstm_word;
  uintptr_t word_base;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0) {
    return 301;
  }
  if (layout.role != GROUP_ROLE_MASTER)
    return 302;
  if (group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0 ||
      state.phase != YXSTM_PHASE_IDLE)
    return 303;

  request.expected_epoch = state.phase_epoch;
  request.next_phase = YXSTM_PHASE_DISPATCH;
  request.active_worker_mask = GROUP_PMP_MW_WORKER_SLICE_MASK;
  request.sequence = state.sequence + 1;
  request.payload_length = sizeof(uint32_t);
  request.timeout_cycles = UINT64_C(10000000000);
  if (group_pmp_yxstm_phase_transition(&request) != 0)
    return 304;
  if (group_pmp_yxstm_acquire_mask(
          GROUP_PMP_MW_WORKER_SLICE_MASK,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_DISPATCH) != 0)
    return 305;

  word_base = group_pmp_yxstm_slice_word_base(&layout, 1);
  yxstm_word = (volatile uint32_t*)(uintptr_t)
      (GROUP_PMP_YXSTM_VA + word_base * sizeof(uint64_t));

  *yxstm_word = UINT32_C(0x00008067);
  __sync_synchronize();
  ((yxstm_code_fn)(uintptr_t)yxstm_word)();
  return 306;
}
