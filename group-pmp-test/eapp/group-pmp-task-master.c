#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "group_task.h"
#include "group-pmp-common.h"

#define TASK_JOB_ID UINT64_C(0x535041524b)
#define TASK_STAGE_ID UINT64_C(0)
#ifndef GROUP_PMP_TASK_BATCHES
#define GROUP_PMP_TASK_BATCHES 100
#endif
#define TASK_BATCHES GROUP_PMP_TASK_BATCHES
#define TASK_WORKERS 3
#define TASK_BYTES (64 * 1024)
#define TASK_TIMEOUT_CYCLES UINT64_C(30000000000)

GROUP_PMP_DEFINE_PROTOCOL_MAILBOX(g_task_mailbox_page);

static struct keystone_group_task_scheduler g_scheduler;
static struct keystone_group_task_scheduler g_policy_test_scheduler;

static const volatile struct keystone_yxstm_protocol_mailbox*
task_mailbox(void)
{
  return group_pmp_protocol_mailbox(g_task_mailbox_page);
}

static uint64_t task_batch_digest(
    const struct keystone_group_task_descriptor tasks[TASK_WORKERS])
{
  uint64_t digest = UINT64_C(0x9e3779b97f4a7c15);
  uint64_t i;

  for (i = 0; i < TASK_WORKERS; i++) {
    digest ^= tasks[i].commit_token + (digest << 7) + (digest >> 3);
    digest ^= tasks[i].task_id * UINT64_C(0x100000001b3);
  }
  return digest ? digest : 1;
}

static uint8_t task_input_byte(uint64_t task_id, uint64_t offset)
{
  return (uint8_t)((task_id * 29 + offset * 17 + 0x5a) & 0xff);
}

static uint64_t task_output_digest(uint64_t task_id, uint64_t lane_id)
{
  uint64_t digest = 0;
  uint64_t i;
  uint8_t key = (uint8_t)(0x30 + lane_id);

  for (i = 0; i < TASK_BYTES; i++)
    digest = digest * UINT64_C(131) + (task_input_byte(task_id, i) ^ key);
  return digest;
}

static int wait_bank(uint64_t bank_id, uint64_t phase,
                     uint64_t sequence, uint64_t required_bitmap,
                     int wait_done,
                     struct keystone_yxstm_task_bank_state* state)
{
  uint64_t spin;

  for (spin = 0; spin < GROUP_PMP_BENCH_POLL_LIMIT; spin++) {
    uint64_t bitmap;

    if (group_pmp_task_bank_mailbox_snapshot(
            task_mailbox(), bank_id, state) != 0) {
      if (group_pmp_master_host_yield() != 0)
        return -1;
      continue;
    }
    if (state->rollback_reason != YXSTM_ROLLBACK_NONE)
      return -1;
    bitmap = wait_done ? state->done_bitmap : state->ready_bitmap;
    if (state->phase == phase && (!sequence || state->sequence == sequence) &&
        (bitmap & required_bitmap) == required_bitmap)
      return 0;
    /* CPU0 is the housekeeping CPU; wait for worker events in HOST context. */
    if (group_pmp_master_host_yield() != 0)
      return -1;
  }
  return -1;
}

static int transition_bank(
    const struct keystone_yxstm_task_bank_state* state,
    uint64_t next_phase, uint64_t active_mask,
    uint64_t payload_length, uint64_t task_epoch,
    uint64_t task_digest)
{
  struct keystone_yxstm_task_bank_transition request;

  memset(&request, 0, sizeof(request));
  request.bank_id = state->bank_id;
  request.expected_phase_epoch = state->phase_epoch;
  request.next_phase = next_phase;
  request.active_worker_mask = active_mask;
  request.sequence = state->phase == YXSTM_PHASE_IDLE ?
      state->sequence + 1 : state->sequence;
  request.payload_length = payload_length;
  request.timeout_cycles = TASK_TIMEOUT_CYCLES;
  request.task_epoch = task_epoch;
  request.task_digest = task_digest;
  return group_pmp_yxstm_task_bank_transition(&request);
}

static void fill_task(struct keystone_group_task_descriptor* task,
                      uint64_t batch, uint64_t lane)
{
  memset(task, 0, sizeof(*task));
  KEYSTONE_ABI_INIT(task, KEYSTONE_GROUP_ABI_FEATURES);
  task->job_id = TASK_JOB_ID;
  task->stage_id = TASK_STAGE_ID;
  task->task_id = batch * TASK_WORKERS + lane;
  task->attempt_id = 0;
  task->partition_id = task->task_id - 1;
  task->input_bank = batch % KEYSTONE_YXSTM_TASK_BANK_COUNT;
  task->output_bank = task->input_bank;
  task->input_offset = 0;
  task->output_offset = 0;
  task->length = TASK_BYTES;
  task->opcode = KEYSTONE_GROUP_TASK_OPCODE_COPY;
  task->task_epoch = batch + 2;
  task->digest = 0;
  task->deadline = 0;
  task->preferred_lane_mask = UINT64_C(1) << lane;
  task->active_worker_mask = UINT64_C(1) << lane;
  task->flags = KEYSTONE_GROUP_TASK_FLAG_RETRYABLE |
                KEYSTONE_GROUP_TASK_FLAG_IDEMPOTENT |
                KEYSTONE_GROUP_TASK_FLAG_BARRIER;
  task->weight = lane;
  task->max_attempts = 3;
  task->commit_token = (TASK_JOB_ID << 16) ^ task->task_id;
}

static int scheduler_policy_selftest(void)
{
  struct keystone_group_stage_descriptor stage;
  struct keystone_group_stage_descriptor dependent_stage;
  struct keystone_group_task_descriptor task;
  struct keystone_group_task_descriptor dependent_task;
  struct keystone_group_task_descriptor dispatched[3];
  struct keystone_group_task_result result;
  uint64_t lanes[3];
  uint64_t i;
  int ret;

  keystone_group_task_scheduler_init(
      &g_policy_test_scheduler, KEYSTONE_GROUP_TASK_SCHED_FAIR, 0xe);
  memset(&stage, 0, sizeof(stage));
  stage.job_id = TASK_JOB_ID + 1;
  stage.stage_id = 0;
  stage.required_workers = 1;
  if (keystone_group_task_add_stage(&g_policy_test_scheduler, &stage) != 0)
    return 1;
  for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; i++) {
    fill_task(&task, 0, 1);
    task.job_id = stage.job_id;
    task.task_id = i + 1;
    task.partition_id = i;
    task.flags = KEYSTONE_GROUP_TASK_FLAG_RETRYABLE |
                 KEYSTONE_GROUP_TASK_FLAG_IDEMPOTENT;
    task.commit_token ^= i + 1;
    if (keystone_group_task_submit(&g_policy_test_scheduler, &task) != 0)
      return 2;
  }
  fill_task(&task, 0, 1);
  task.job_id = stage.job_id;
  task.task_id = 1000;
  task.flags = KEYSTONE_GROUP_TASK_FLAG_RETRYABLE;
  if (keystone_group_task_submit(&g_policy_test_scheduler, &task) !=
      KEYSTONE_GROUP_TASK_ERR_FULL)
    return 3;
  if (keystone_group_task_cancel(
          &g_policy_test_scheduler, stage.job_id, 0, 64) != 0)
    return 4;
  if (keystone_group_task_submit(&g_policy_test_scheduler, &task) != 0)
    return 5;

  keystone_group_task_scheduler_init(
      &g_policy_test_scheduler, KEYSTONE_GROUP_TASK_SCHED_FIFO, 0xe);
  if (keystone_group_task_add_stage(&g_policy_test_scheduler, &stage) != 0)
    return 6;
  dependent_stage = stage;
  dependent_stage.stage_id = 1;
  dependent_stage.dependency_mask = UINT64_C(1) << stage.stage_id;
  if (keystone_group_task_add_stage(
          &g_policy_test_scheduler, &dependent_stage) != 0)
    return 7;
  fill_task(&task, 0, 1);
  task.job_id = stage.job_id;
  task.flags = KEYSTONE_GROUP_TASK_FLAG_RETRYABLE |
               KEYSTONE_GROUP_TASK_FLAG_IDEMPOTENT;
  dependent_task = task;
  dependent_task.stage_id = dependent_stage.stage_id;
  dependent_task.task_id += 100;
  dependent_task.partition_id += 100;
  dependent_task.commit_token ^= UINT64_C(0x10000);
  if (keystone_group_task_submit(&g_policy_test_scheduler, &task) != 0 ||
      keystone_group_task_submit(
          &g_policy_test_scheduler, &dependent_task) != 0 ||
      keystone_group_task_dispatch(
          &g_policy_test_scheduler, dispatched, lanes, 1) != 1)
    return 8;
  memset(&result, 0, sizeof(result));
  KEYSTONE_ABI_INIT(&result, KEYSTONE_GROUP_ABI_FEATURES);
  result.job_id = dispatched[0].job_id;
  result.stage_id = dispatched[0].stage_id;
  result.task_id = dispatched[0].task_id;
  result.attempt_id = dispatched[0].attempt_id;
  result.partition_id = dispatched[0].partition_id;
  result.lane_id = lanes[0];
  result.bank_id = dispatched[0].output_bank;
  result.task_epoch = dispatched[0].task_epoch;
  result.commit_token = dispatched[0].commit_token;
  ret = keystone_group_task_fail(&g_policy_test_scheduler, &result);
  if (ret != 0 || keystone_group_task_dispatch(
          &g_policy_test_scheduler, dispatched, lanes, 1) != 1 ||
      dispatched[0].attempt_id != 1)
    return 9;
  result.attempt_id = dispatched[0].attempt_id;
  result.digest = 0x1234;
  if (keystone_group_task_complete(&g_policy_test_scheduler, &result) != 0 ||
      keystone_group_task_complete(&g_policy_test_scheduler, &result) != 0)
    return 10;
  if (keystone_group_task_dispatch(
          &g_policy_test_scheduler, dispatched, lanes, 1) != 1 ||
      dispatched[0].stage_id != dependent_stage.stage_id)
    return 11;
  result.stage_id = dispatched[0].stage_id;
  result.task_id = dispatched[0].task_id;
  result.attempt_id = dispatched[0].attempt_id;
  result.partition_id = dispatched[0].partition_id;
  result.lane_id = lanes[0];
  result.bank_id = dispatched[0].output_bank;
  result.task_epoch = dispatched[0].task_epoch;
  result.commit_token = dispatched[0].commit_token;
  result.digest = 0x5678;
  if (keystone_group_task_complete(&g_policy_test_scheduler, &result) != 0)
    return 12;
  keystone_group_task_scheduler_init(
      &g_policy_test_scheduler, KEYSTONE_GROUP_TASK_SCHED_FIFO, 0xe);
  if (keystone_group_task_add_stage(&g_policy_test_scheduler, &stage) != 0)
    return 13;
  fill_task(&task, 0, 1);
  task.job_id = stage.job_id;
  task.flags = KEYSTONE_GROUP_TASK_FLAG_RETRYABLE;
  task.deadline = 200;
  if (keystone_group_task_submit(&g_policy_test_scheduler, &task) != 0 ||
      keystone_group_task_advance_time(&g_policy_test_scheduler, 200) != 0 ||
      g_policy_test_scheduler.deadline_expired_count != 1 ||
      g_policy_test_scheduler.failed_count != 1 ||
      !keystone_group_task_idle(&g_policy_test_scheduler))
    return 14;
  keystone_group_task_scheduler_init(
      &g_policy_test_scheduler, KEYSTONE_GROUP_TASK_SCHED_ROUND_ROBIN, 0xe);
  stage.job_id = TASK_JOB_ID + 10;
  dependent_stage = stage;
  dependent_stage.job_id = TASK_JOB_ID + 11;
  if (keystone_group_task_add_stage(&g_policy_test_scheduler, &stage) != 0 ||
      keystone_group_task_add_stage(
          &g_policy_test_scheduler, &dependent_stage) != 0)
    return 15;
  fill_task(&task, 0, 1);
  task.job_id = stage.job_id;
  task.flags = KEYSTONE_GROUP_TASK_FLAG_IDEMPOTENT;
  fill_task(&dependent_task, 0, 2);
  dependent_task.job_id = dependent_stage.job_id;
  dependent_task.flags = KEYSTONE_GROUP_TASK_FLAG_IDEMPOTENT;
  if (keystone_group_task_submit(&g_policy_test_scheduler, &task) != 0 ||
      keystone_group_task_submit(
          &g_policy_test_scheduler, &dependent_task) != 0 ||
      keystone_group_task_dispatch(
          &g_policy_test_scheduler, dispatched, lanes, 2) != 2 ||
      dispatched[0].job_id != stage.job_id ||
      dispatched[1].job_id != dependent_stage.job_id)
    return 16;
  return 0;
}

static int dispatch_bank(
    const struct keystone_yxstm_layout_info* layout,
    uint64_t bank_id,
    const struct keystone_group_task_descriptor tasks[TASK_WORKERS],
    const uint64_t lanes[TASK_WORKERS], int enter_compute,
    uint64_t* batch_digest_out)
{
  struct keystone_yxstm_task_bank_state state;
  struct keystone_yxstm_task_bank_grant grant;
  struct keystone_yxstm_task_bank_ack ack;
  uint64_t active_mask = 0;
  uint64_t batch_digest = task_batch_digest(tasks);
  uint64_t i;

  if (group_pmp_task_bank_mailbox_snapshot(
          task_mailbox(), bank_id, &state) != 0 ||
      state.phase != YXSTM_PHASE_IDLE)
    return 1;
  for (i = 0; i < TASK_WORKERS; i++)
    active_mask |= UINT64_C(1) << lanes[i];
  if (transition_bank(&state, YXSTM_PHASE_DISPATCH, active_mask,
                      TASK_BYTES, tasks[0].task_epoch,
                      batch_digest) != 0 ||
      group_pmp_task_bank_mailbox_snapshot(
          task_mailbox(), bank_id, &state) != 0)
    return 2;

  memset(&grant, 0, sizeof(grant));
  grant.bank_id = bank_id;
  grant.slice_mask = active_mask;
  grant.permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
  grant.phase = YXSTM_PHASE_DISPATCH;
  grant.expected_phase_epoch = state.phase_epoch;
  grant.expected_task_epoch = state.task_epoch;
  grant.task_digest = state.task_digest;
  if (group_pmp_yxstm_task_bank_acquire(&grant) != 0)
    return 3;
  for (i = 0; i < TASK_WORKERS; i++) {
    volatile struct keystone_group_task_descriptor* target =
        group_pmp_task_descriptor(layout, bank_id, lanes[i]);
    volatile uint8_t* payload =
        group_pmp_task_payload(layout, bank_id, lanes[i]);
    uint64_t offset;

    memcpy((void*)(uintptr_t)target, &tasks[i], sizeof(tasks[i]));
    for (offset = 0; offset < tasks[i].length; offset++)
      payload[offset] = task_input_byte(tasks[i].task_id, offset);
  }
  __sync_synchronize();
  if (group_pmp_yxstm_task_bank_release(&grant) != 0)
    return 4;
  memset(&ack, 0, sizeof(ack));
  ack.bank_id = bank_id;
  ack.expected_phase_epoch = state.phase_epoch;
  ack.expected_task_epoch = state.task_epoch;
  ack.event = YXSTM_ACK_DISPATCH_PUBLISHED;
  ack.task_digest = state.task_digest;
  if (group_pmp_yxstm_task_bank_ack(&ack) != 0 ||
      wait_bank(bank_id, YXSTM_PHASE_DISPATCH, state.sequence,
                active_mask, 0, &state) != 0)
    return 5;
  if (enter_compute &&
      transition_bank(&state, YXSTM_PHASE_COMPUTE, active_mask,
                      TASK_BYTES, state.task_epoch,
                      state.task_digest) != 0)
    return 6;
  *batch_digest_out = batch_digest;
  return 0;
}

static int enter_compute_bank(uint64_t bank_id)
{
  struct keystone_yxstm_task_bank_state state;

  if (group_pmp_task_bank_mailbox_snapshot(
          task_mailbox(), bank_id, &state) != 0 ||
      state.phase != YXSTM_PHASE_DISPATCH)
    return 1;
  return transition_bank(&state, YXSTM_PHASE_COMPUTE,
                         state.active_worker_mask,
                         state.payload_length, state.task_epoch,
                         state.task_digest);
}

static int start_aggregate_bank(uint64_t bank_id, uint64_t active_mask)
{
  struct keystone_yxstm_task_bank_state state;

  if (wait_bank(bank_id, YXSTM_PHASE_COMPUTE, 0,
                active_mask, 1, &state) != 0)
    return 1;
  return transition_bank(&state, YXSTM_PHASE_AGGREGATE, active_mask,
                         state.payload_length, state.task_epoch,
                         state.task_digest);
}

static int finish_aggregate_bank(
    const struct keystone_yxstm_layout_info* layout,
    uint64_t bank_id,
    const struct keystone_group_task_descriptor tasks[TASK_WORKERS],
    const uint64_t lanes[TASK_WORKERS])
{
  struct keystone_yxstm_task_bank_state state;
  struct keystone_yxstm_task_bank_grant grant;
  uint64_t active_mask = 0;
  uint64_t i;

  for (i = 0; i < TASK_WORKERS; i++)
    active_mask |= UINT64_C(1) << lanes[i];
  if (group_pmp_task_bank_mailbox_snapshot(
          task_mailbox(), bank_id, &state) != 0 ||
      state.phase != YXSTM_PHASE_AGGREGATE ||
      wait_bank(bank_id, YXSTM_PHASE_AGGREGATE, state.sequence,
                active_mask, 0, &state) != 0)
    return 1;
  memset(&grant, 0, sizeof(grant));
  grant.bank_id = bank_id;
  grant.slice_mask = active_mask;
  grant.permissions = KEYSTONE_YXSTM_PERM_R;
  grant.phase = YXSTM_PHASE_AGGREGATE;
  grant.expected_phase_epoch = state.phase_epoch;
  grant.expected_task_epoch = state.task_epoch;
  grant.task_digest = state.task_digest;
  if (group_pmp_yxstm_task_bank_acquire(&grant) != 0)
    return 2;
  for (i = 0; i < TASK_WORKERS; i++) {
    struct keystone_group_task_descriptor completed;
    struct keystone_group_task_result result;
    volatile struct keystone_group_task_descriptor* source =
        group_pmp_task_descriptor(layout, bank_id, lanes[i]);
    uint64_t expected = task_output_digest(tasks[i].task_id, lanes[i]);

    memcpy(&completed, (const void*)(uintptr_t)source, sizeof(completed));
    if (completed.job_id != tasks[i].job_id ||
        completed.stage_id != tasks[i].stage_id ||
        completed.task_id != tasks[i].task_id ||
        completed.attempt_id != tasks[i].attempt_id ||
        completed.partition_id != tasks[i].partition_id ||
        completed.task_epoch != tasks[i].task_epoch ||
        completed.commit_token != tasks[i].commit_token ||
        completed.digest != expected) {
      (void)group_pmp_yxstm_task_bank_release(&grant);
      return 3;
    }
    memset(&result, 0, sizeof(result));
    KEYSTONE_ABI_INIT(&result, KEYSTONE_GROUP_ABI_FEATURES);
    result.job_id = completed.job_id;
    result.stage_id = completed.stage_id;
    result.task_id = completed.task_id;
    result.attempt_id = completed.attempt_id;
    result.partition_id = completed.partition_id;
    result.lane_id = lanes[i];
    result.bank_id = bank_id;
    result.task_epoch = completed.task_epoch;
    result.status = KEYSTONE_GROUP_TASK_STATE_SUCCEEDED;
    result.digest = completed.digest;
    result.commit_token = completed.commit_token;
    result.completed_at = group_pmp_rdtime();
    if (keystone_group_task_complete(&g_scheduler, &result) != 0 ||
        keystone_group_task_complete(&g_scheduler, &result) != 0) {
      (void)group_pmp_yxstm_task_bank_release(&grant);
      return 4;
    }
  }
  if (group_pmp_yxstm_task_bank_release(&grant) != 0 ||
      group_pmp_task_bank_mailbox_snapshot(
          task_mailbox(), bank_id, &state) != 0 ||
      transition_bank(&state, YXSTM_PHASE_IDLE, active_mask,
                      0, state.task_epoch, state.task_digest) != 0)
    return 5;
  return 0;
}

int main(void)
{
  struct keystone_yxstm_layout_info layout;
  struct keystone_group_stage_descriptor stage;
  struct keystone_group_task_descriptor
      bank_tasks[KEYSTONE_YXSTM_TASK_BANK_COUNT][TASK_WORKERS];
  struct keystone_group_task_descriptor selected[TASK_WORKERS];
  uint64_t bank_lanes[KEYSTONE_YXSTM_TASK_BANK_COUNT][TASK_WORKERS];
  uint64_t selected_lanes[TASK_WORKERS];
  uint64_t bank_active_mask[KEYSTONE_YXSTM_TASK_BANK_COUNT] = {0, 0};
  uint64_t digest_accumulator = 0;
  uint64_t batch_digest = 0;
  uint64_t stage_state = 0;
  uint64_t batch_id;
  uint64_t lane;
  int ret;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0 ||
      layout.role != GROUP_ROLE_MASTER ||
      layout.bank_count != KEYSTONE_YXSTM_TASK_BANK_COUNT ||
      layout.bank_slice_size < TASK_BYTES +
          sizeof(struct keystone_yxstm_channel_header) +
          sizeof(struct keystone_group_task_descriptor) ||
      group_pmp_register_protocol_mailbox(
          g_task_mailbox_page,
          KEYSTONE_YXSTM_MAILBOX_FLAG_PERF_QUIET) != 0)
    return 1;
  ret = scheduler_policy_selftest();
  if (ret != 0)
    return 10 + ret;

  keystone_group_task_scheduler_init(
      &g_scheduler, KEYSTONE_GROUP_TASK_SCHED_FAIR, 0xe);
  memset(&stage, 0, sizeof(stage));
  stage.job_id = TASK_JOB_ID;
  stage.stage_id = TASK_STAGE_ID;
  stage.required_workers = TASK_WORKERS;
  stage.flags = KEYSTONE_GROUP_STAGE_FLAG_BARRIER;
  if (keystone_group_task_add_stage(&g_scheduler, &stage) != 0)
    return 30;
  for (batch_id = 0; batch_id < TASK_BATCHES; batch_id++)
    for (lane = 1; lane <= TASK_WORKERS; lane++) {
      struct keystone_group_task_descriptor task;
      fill_task(&task, batch_id, lane);
      if (keystone_group_task_submit(
              &g_scheduler, &task) != 0)
        return 31;
    }

  if (keystone_group_task_dispatch(
          &g_scheduler, selected, selected_lanes, TASK_WORKERS) !=
      TASK_WORKERS)
    return 32;
  memcpy(bank_tasks[0], selected, sizeof(selected));
  memcpy(bank_lanes[0], selected_lanes, sizeof(selected_lanes));
  for (lane = 0; lane < TASK_WORKERS; lane++)
    bank_active_mask[0] |= UINT64_C(1) << bank_lanes[0][lane];
  if (dispatch_bank(&layout, 0, bank_tasks[0], bank_lanes[0], 1,
                    &batch_digest) != 0)
    return 33;
  digest_accumulator ^= batch_digest;

  for (batch_id = 1; batch_id < TASK_BATCHES; batch_id++) {
    uint64_t bank_id = batch_id % KEYSTONE_YXSTM_TASK_BANK_COUNT;
    uint64_t previous_bank =
        (batch_id - 1) % KEYSTONE_YXSTM_TASK_BANK_COUNT;

    if (keystone_group_task_prefetch(
            &g_scheduler, selected, selected_lanes, TASK_WORKERS) !=
        TASK_WORKERS)
      return 34;
    memcpy(bank_tasks[bank_id], selected, sizeof(selected));
    memcpy(bank_lanes[bank_id], selected_lanes, sizeof(selected_lanes));
    bank_active_mask[bank_id] = 0;
    for (lane = 0; lane < TASK_WORKERS; lane++)
      bank_active_mask[bank_id] |=
          UINT64_C(1) << bank_lanes[bank_id][lane];

    if (start_aggregate_bank(
            previous_bank, bank_active_mask[previous_bank]) != 0)
      return 35;
    /* Transform/aggregate the previous bank while publishing this bank. */
    if (dispatch_bank(&layout, bank_id, bank_tasks[bank_id],
                      bank_lanes[bank_id], 0, &batch_digest) != 0)
      return 36;
    digest_accumulator ^= batch_digest;
    if (finish_aggregate_bank(&layout, previous_bank,
                              bank_tasks[previous_bank],
                              bank_lanes[previous_bank]) != 0)
      return 37;
    if (keystone_group_task_activate_prefetched(
            &g_scheduler, bank_id, selected, selected_lanes,
            TASK_WORKERS) != TASK_WORKERS ||
        enter_compute_bank(bank_id) != 0)
      return 38;
  }
  {
    uint64_t last_bank =
        (TASK_BATCHES - 1) % KEYSTONE_YXSTM_TASK_BANK_COUNT;
    if (start_aggregate_bank(last_bank, bank_active_mask[last_bank]) != 0 ||
        finish_aggregate_bank(&layout, last_bank,
                              bank_tasks[last_bank],
                              bank_lanes[last_bank]) != 0)
      return 39;
  }
  if (!keystone_group_task_idle(&g_scheduler) ||
      keystone_group_task_stage_state(
          &g_scheduler, TASK_JOB_ID, TASK_STAGE_ID, &stage_state) != 0 ||
      stage_state != KEYSTONE_GROUP_STAGE_SUCCEEDED)
    return 40;

  printf("[TASK][PASS] mode=fair executors=3 batches=%lu double_buffer=1 "
         "completed=%lu digest=0x%lx\n",
         (unsigned long)TASK_BATCHES,
         (unsigned long)g_scheduler.completed_count,
         (unsigned long)digest_accumulator);
  return 0;
}
