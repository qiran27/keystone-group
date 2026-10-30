#include <stdint.h>

#include "group-pmp-common.h"

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  struct keystone_yxstm_protocol_state state;
  struct keystone_yxstm_phase_transition request;
  volatile uint64_t* words = group_pmp_yxstm_words();
  uint64_t spin;
  uint64_t stale_epoch;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0) {
    return 201;
  }
  if (layout.role != GROUP_ROLE_MASTER ||
      layout.allowed_slice_mask !=
          ((UINT64_C(1) << KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT) - 1)) {
    return 202;
  }

  if (group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0 ||
      state.phase != YXSTM_PHASE_IDLE) {
    return 203;
  }
  request.expected_epoch = state.phase_epoch;
  stale_epoch = state.phase_epoch;
  request.next_phase = YXSTM_PHASE_DISPATCH;
  request.active_worker_mask = GROUP_PMP_MW_WORKER_SLICE_MASK;
  request.sequence = state.sequence + 1;
  request.payload_length = 4 * sizeof(uint64_t);
  request.timeout_cycles = UINT64_C(10000000000);
  if (group_pmp_yxstm_phase_transition(&request) != 0 ||
      group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0) {
    return 204;
  }
  if (group_pmp_yxstm_acquire_mask_epoch(
          GROUP_PMP_MW_WORKER_SLICE_MASK,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_DISPATCH, stale_epoch) == 0)
    return 205;

  if (group_pmp_yxstm_acquire_mask(
          GROUP_PMP_MW_WORKER_SLICE_MASK,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_DISPATCH) != 0) {
    return 206;
  }
  if (group_pmp_yxstm_acquire_mask(
          GROUP_PMP_MW_WORKER_SLICE_MASK,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_DISPATCH) == 0)
    return 207;

  for (uint64_t slice = 1; slice < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT; slice++) {
    uintptr_t base = group_pmp_yxstm_slice_word_base(&layout, slice);
    uint64_t input = group_pmp_mw_input(slice);

    words[base + 0] = GROUP_PMP_MW_MAGIC;
    words[base + 1] = input;
    words[base + 2] = 0;
    words[base + 3] = GROUP_PMP_MW_STATUS_DISPATCHED;
  }
  __sync_synchronize();

  if (group_pmp_yxstm_release_mask(UINT64_C(0x2)) == 0)
    return 208;
  if (group_pmp_yxstm_release_mask(GROUP_PMP_MW_WORKER_SLICE_MASK) != 0) {
    return 209;
  }
  if (group_pmp_yxstm_phase_ack(
          state.phase_epoch, YXSTM_ACK_DISPATCH_PUBLISHED) != 0)
    return 210;

  for (spin = 0; spin < UINT64_C(20000000); spin++) {
    if (group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0)
      return 207;
    if (state.rollback_reason != YXSTM_ROLLBACK_NONE)
      return 223;
    if (state.phase != YXSTM_PHASE_DISPATCH)
      return 208;
    if (state.ready_bitmap == state.active_worker_mask)
      break;
    if (group_pmp_master_host_yield() != 0)
      return 226;
  }
  if (spin == UINT64_C(20000000))
    return 209;

  request.expected_epoch = state.phase_epoch;
  request.next_phase = YXSTM_PHASE_COMPUTE;
  request.active_worker_mask = 0;
  request.sequence = state.sequence;
  request.payload_length = 0;
  request.timeout_cycles = UINT64_C(10000000000);
  if (group_pmp_yxstm_phase_transition(&request) != 0)
    return 210;

  for (spin = 0; spin < UINT64_C(20000000); spin++) {
    if (group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0)
      return 211;
    if (state.rollback_reason != YXSTM_ROLLBACK_NONE)
      return 224;
    if (state.phase != YXSTM_PHASE_COMPUTE)
      return 212;
    if (state.done_bitmap == state.active_worker_mask)
      break;
    if (group_pmp_master_host_yield() != 0)
      return 227;
  }
  if (spin == UINT64_C(20000000))
    return 213;

  request.expected_epoch = state.phase_epoch;
  request.next_phase = YXSTM_PHASE_AGGREGATE;
  request.sequence = state.sequence;
  request.timeout_cycles = UINT64_C(10000000000);
  if (group_pmp_yxstm_phase_transition(&request) != 0)
    return 214;

  for (spin = 0; spin < UINT64_C(20000000); spin++) {
    if (group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0)
      return 215;
    if (state.rollback_reason != YXSTM_ROLLBACK_NONE)
      return 225;
    if (state.phase != YXSTM_PHASE_AGGREGATE)
      return 216;
    if (state.ready_bitmap == state.active_worker_mask)
      break;
    if (group_pmp_master_host_yield() != 0)
      return 228;
  }
  if (spin == UINT64_C(20000000))
    return 217;

  if (group_pmp_yxstm_acquire_mask(
          GROUP_PMP_MW_WORKER_SLICE_MASK,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_AGGREGATE) == 0)
    return 218;
  if (group_pmp_yxstm_acquire_mask(
          GROUP_PMP_MW_WORKER_SLICE_MASK,
          KEYSTONE_YXSTM_PERM_R,
          YXSTM_PHASE_AGGREGATE) != 0)
    return 219;
  __sync_synchronize();
  for (uint64_t slice = 1; slice < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT; slice++) {
    uintptr_t base = group_pmp_yxstm_slice_word_base(&layout, slice);
    uint64_t input = group_pmp_mw_input(slice);
    if (words[base + 0] != GROUP_PMP_MW_MAGIC ||
        words[base + 1] != input ||
        words[base + 2] != group_pmp_mw_result(slice, input) ||
        words[base + 3] != GROUP_PMP_MW_STATUS_DONE) {
      group_pmp_yxstm_release_mask(GROUP_PMP_MW_WORKER_SLICE_MASK);
      return 219;
    }
  }
  if (group_pmp_yxstm_release_mask(GROUP_PMP_MW_WORKER_SLICE_MASK) != 0)
    return 220;

  if (group_pmp_yxstm_query_protocol(&state, sizeof(state)) != 0)
    return 221;
  request.expected_epoch = state.phase_epoch;
  request.next_phase = YXSTM_PHASE_IDLE;
  request.sequence = state.sequence;
  request.timeout_cycles = 0;
  if (group_pmp_yxstm_phase_transition(&request) != 0) {
    return 222;
  }

  return 0;
}
