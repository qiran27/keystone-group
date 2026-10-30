#include <stdint.h>
#include <string.h>

#include "group-pmp-common.h"

#define TASK_BYTES (64 * 1024)
#ifndef GROUP_PMP_TASK_BATCHES
#define GROUP_PMP_TASK_BATCHES 100
#endif

GROUP_PMP_DEFINE_PROTOCOL_MAILBOX(g_task_mailbox_page);

struct worker_bank_context {
  uint64_t dispatch_epoch;
  uint64_t compute_epoch;
  uint64_t aggregate_epoch;
  struct keystone_group_task_descriptor task;
};

static uint64_t worker_transform(volatile uint8_t* payload, uint64_t length,
                                 uint64_t lane_id)
{
  uint64_t digest = 0;
  uint64_t i;
  uint8_t key = (uint8_t)(0x30 + lane_id);

  for (i = 0; i < length; i++) {
    uint8_t value = payload[i] ^ key;
    payload[i] = value;
    digest = digest * UINT64_C(131) + value;
  }
  return digest;
}

static void fill_grant(struct keystone_yxstm_task_bank_grant* grant,
                       const struct keystone_yxstm_task_bank_state* state,
                       uint64_t slice_mask, uint64_t permissions)
{
  memset(grant, 0, sizeof(*grant));
  grant->bank_id = state->bank_id;
  grant->slice_mask = slice_mask;
  grant->permissions = permissions;
  grant->phase = state->phase;
  grant->expected_phase_epoch = state->phase_epoch;
  grant->expected_task_epoch = state->task_epoch;
  grant->task_digest = state->task_digest;
}

static int ack_bank(const struct keystone_yxstm_task_bank_state* state,
                    uint64_t event)
{
  struct keystone_yxstm_task_bank_ack ack;

  memset(&ack, 0, sizeof(ack));
  ack.bank_id = state->bank_id;
  ack.expected_phase_epoch = state->phase_epoch;
  ack.expected_task_epoch = state->task_epoch;
  ack.event = event;
  ack.task_digest = state->task_digest;
  return group_pmp_yxstm_task_bank_ack(&ack);
}

int main(void)
{
  struct keystone_yxstm_layout_info layout;
  struct worker_bank_context banks[KEYSTONE_YXSTM_TASK_BANK_COUNT];
  const volatile struct keystone_yxstm_protocol_mailbox* mailbox =
      group_pmp_protocol_mailbox(g_task_mailbox_page);
  uint64_t slice;
  uint64_t slice_mask;
  uint64_t idle_spins = 0;
  uint64_t completed_tasks = 0;

  memset(banks, 0, sizeof(banks));
  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0 ||
      layout.role != GROUP_ROLE_WORKER ||
      layout.bank_count != KEYSTONE_YXSTM_TASK_BANK_COUNT ||
      layout.worker_slice_id == (uintptr_t)-1 ||
      group_pmp_register_protocol_mailbox(g_task_mailbox_page, 0) != 0)
    return 1;
  slice = layout.worker_slice_id;
  slice_mask = UINT64_C(1) << slice;

  while (idle_spins < GROUP_PMP_BENCH_POLL_LIMIT) {
    uint64_t bank_id;
    int progressed = 0;

    for (bank_id = 0; bank_id < KEYSTONE_YXSTM_TASK_BANK_COUNT; bank_id++) {
      struct keystone_yxstm_task_bank_state state;
      struct keystone_yxstm_task_bank_grant grant;
      struct worker_bank_context* context = &banks[bank_id];

      if (group_pmp_task_bank_mailbox_snapshot(
              mailbox, bank_id, &state) != 0)
        continue;
      if (state.rollback_reason != YXSTM_ROLLBACK_NONE)
        return 2;
      if (state.phase == YXSTM_PHASE_DISPATCH &&
          state.published_sequence == state.sequence &&
          (state.active_worker_mask & slice_mask) &&
          context->dispatch_epoch != state.phase_epoch) {
        volatile struct keystone_group_task_descriptor* source;

        fill_grant(&grant, &state, slice_mask, KEYSTONE_YXSTM_PERM_R);
        if (group_pmp_yxstm_task_bank_acquire(&grant) != 0)
          return 3;
        source = group_pmp_task_descriptor(&layout, bank_id, slice);
        memcpy(&context->task, (const void*)(uintptr_t)source,
               sizeof(context->task));
        if (context->task.abi.version != KEYSTONE_ABI_VERSION ||
            context->task.abi.struct_size != sizeof(context->task) ||
            context->task.input_bank != bank_id ||
            context->task.output_bank != bank_id ||
            context->task.task_epoch != state.task_epoch ||
            context->task.length > TASK_BYTES ||
            context->task.opcode != KEYSTONE_GROUP_TASK_OPCODE_COPY ||
            !context->task.commit_token ||
            context->task.preferred_lane_mask != slice_mask ||
            context->task.active_worker_mask != slice_mask ||
            (context->task.deadline &&
             group_pmp_rdtime() >= context->task.deadline)) {
          (void)group_pmp_yxstm_task_bank_release(&grant);
          return 4;
        }
        if (group_pmp_yxstm_task_bank_release(&grant) != 0 ||
            ack_bank(&state, YXSTM_ACK_DISPATCH_READY) != 0)
          return 5;
        context->dispatch_epoch = state.phase_epoch;
        progressed = 1;
      } else if (state.phase == YXSTM_PHASE_COMPUTE &&
                 (state.active_worker_mask & slice_mask) &&
                 context->dispatch_epoch &&
                 context->compute_epoch != state.phase_epoch) {
        if (ack_bank(&state, YXSTM_ACK_COMPUTE_DONE) != 0)
          return 6;
        context->compute_epoch = state.phase_epoch;
        progressed = 1;
      } else if (state.phase == YXSTM_PHASE_AGGREGATE &&
                 (state.active_worker_mask & slice_mask) &&
                 context->compute_epoch &&
                 context->aggregate_epoch != state.phase_epoch) {
        volatile struct keystone_group_task_descriptor* target;
        volatile uint8_t* payload;

        fill_grant(&grant, &state, slice_mask,
                   KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W);
        if (group_pmp_yxstm_task_bank_acquire(&grant) != 0)
          return 7;
        target = group_pmp_task_descriptor(&layout, bank_id, slice);
        payload = group_pmp_task_payload(&layout, bank_id, slice);
        context->task.digest = worker_transform(
            payload, context->task.length, slice);
        memcpy((void*)(uintptr_t)target, &context->task,
               sizeof(context->task));
        __sync_synchronize();
        if (group_pmp_yxstm_task_bank_release(&grant) != 0 ||
            ack_bank(&state, YXSTM_ACK_AGGREGATE_READY) != 0)
          return 8;
        context->aggregate_epoch = state.phase_epoch;
        completed_tasks++;
        progressed = 1;
      }
    }
    if (completed_tasks >= GROUP_PMP_TASK_BATCHES)
      return 0;
    if (progressed)
      idle_spins = 0;
    else {
      idle_spins++;
      __asm__ __volatile__("nop");
    }
  }
  return 9;
}
