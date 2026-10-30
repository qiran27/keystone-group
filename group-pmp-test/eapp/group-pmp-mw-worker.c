#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  struct keystone_yxstm_protocol_state state;
  volatile uint64_t* words = group_pmp_yxstm_words();
  uint64_t slice;
  uintptr_t base;
  uint64_t input;
  uint64_t result;
  uint64_t spin;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0) {
    return 211;
  }
  if (layout.role != GROUP_ROLE_WORKER ||
      layout.worker_slice_id == (uintptr_t)-1 ||
      layout.worker_slice_id == KEYSTONE_YXSTM_MASTER_SLICE_ID ||
      layout.allowed_slice_mask != (UINT64_C(1) << layout.worker_slice_id)) {
    return 212;
  }

  slice = layout.worker_slice_id;
  base = group_pmp_yxstm_slice_word_base(&layout, slice);

  for (spin = 0; spin < UINT64_C(20000000); spin++) {
    if (group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0)
      return 213;
    if (state.rollback_reason != YXSTM_ROLLBACK_NONE)
      return 228;
    if (state.phase == YXSTM_PHASE_DISPATCH &&
        (state.active_worker_mask & (UINT64_C(1) << slice)) &&
        state.published_sequence == state.sequence)
      break;
  }
  if (spin == UINT64_C(20000000))
    return 214;

  if (group_pmp_yxstm_acquire_slice(
          slice,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_DISPATCH) == 0)
    return 215;

  if (group_pmp_yxstm_acquire_slice(
          slice, KEYSTONE_YXSTM_PERM_R, YXSTM_PHASE_DISPATCH) != 0) {
    return 216;
  }

  if (words[base + 0] != GROUP_PMP_MW_MAGIC ||
      words[base + 3] != GROUP_PMP_MW_STATUS_DISPATCHED) {
    group_pmp_yxstm_release_slice(slice);
    return 216;
  }
  input = words[base + 1];
  if (input != group_pmp_mw_input(slice)) {
    group_pmp_yxstm_release_slice(slice);
    return 217;
  }

  if (group_pmp_yxstm_release_slice(slice) != 0) {
    return 218;
  }
  if (group_pmp_yxstm_phase_ack(state.phase_epoch,
                                YXSTM_ACK_DISPATCH_READY) != 0)
    return 219;

  for (spin = 0; spin < UINT64_C(20000000); spin++) {
    if (group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0)
      return 220;
    if (state.rollback_reason != YXSTM_ROLLBACK_NONE)
      return 229;
    if (state.phase == YXSTM_PHASE_COMPUTE)
      break;
  }
  if (spin == UINT64_C(20000000))
    return 221;
  result = group_pmp_mw_result(slice, input);
  __sync_synchronize();
  if (group_pmp_yxstm_phase_ack(state.phase_epoch,
                                YXSTM_ACK_COMPUTE_DONE) != 0)
    return 222;

  for (spin = 0; spin < UINT64_C(20000000); spin++) {
    if (group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0)
      return 223;
    if (state.rollback_reason != YXSTM_ROLLBACK_NONE)
      return 230;
    if (state.phase == YXSTM_PHASE_AGGREGATE)
      break;
  }
  if (spin == UINT64_C(20000000))
    return 224;
  if (group_pmp_yxstm_acquire_slice(
          slice,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_AGGREGATE) != 0) {
    return 225;
  }

  words[base + 2] = result;
  words[base + 3] = GROUP_PMP_MW_STATUS_DONE;
  __sync_synchronize();

  if (group_pmp_yxstm_release_slice(slice) != 0) {
    return 226;
  }
  if (group_pmp_yxstm_phase_ack(state.phase_epoch,
                                YXSTM_ACK_AGGREGATE_READY) != 0)
    return 227;

  return 0;
}
