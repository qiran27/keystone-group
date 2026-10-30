#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "group-pmp-common.h"

#ifndef GROUP_PMP_AES_OPERATION
#error "GROUP_PMP_AES_OPERATION must be defined"
#endif

GROUP_PMP_DEFINE_PROTOCOL_MAILBOX(g_protocol_mailbox_page);

struct p10_metrics {
  uint64_t master_dispatch_cycles;
  uint64_t worker_compute_wall_cycles;
  uint64_t worker_compute_cycles_max;
  uint64_t worker_compute_cycles_total;
  uint64_t master_aggregate_cycles;
  uint64_t protocol_cycles;
  uint64_t pipeline_e2e_cycles;
  uint64_t digest;
  uint64_t direct_va;
  uint64_t rounds;
};

static const char*
operation_name(void) {
#if GROUP_PMP_AES_OPERATION == GROUP_PMP_BENCH_AES_ENCRYPT
  return "encrypt";
#elif GROUP_PMP_AES_OPERATION == GROUP_PMP_BENCH_AES_DECRYPT
  return "decrypt";
#else
  return "unknown";
#endif
}

static int
mailbox_state(struct keystone_yxstm_protocol_state* state) {
  return group_pmp_protocol_mailbox_snapshot(
      group_pmp_protocol_mailbox(g_protocol_mailbox_page), state);
}

static int
wait_for_phase_state(uint64_t phase, uint64_t sequence,
                     uint64_t expected_mask, int bitmap_kind,
                     struct keystone_yxstm_protocol_state* state) {
  uint64_t poll_count = 0;

  for (;;) {
    if (mailbox_state(state) != 0)
      return 1;
    if (state->rollback_reason != YXSTM_ROLLBACK_NONE)
      return 2;
    if (state->phase == phase &&
        (sequence == UINT64_MAX || state->sequence == sequence) &&
        (bitmap_kind != 1 || state->ready_bitmap == expected_mask) &&
        (bitmap_kind != 2 || state->done_bitmap == expected_mask))
      return 0;
    if (group_pmp_protocol_deadline_expired(state))
      return 3;
    if (bitmap_kind != 0) {
      if (group_pmp_master_host_yield() != 0)
        return 4;
    } else {
      group_pmp_poll_service_host(&poll_count);
    }
  }
}

static int
transition_phase(uint64_t next_phase, uint64_t active_worker_mask,
                 uint64_t sequence, uint64_t payload_length,
                 uint64_t timeout_cycles, uint64_t* phase_epoch,
                 uint64_t* protocol_cycles) {
  struct keystone_yxstm_phase_transition request;
  struct keystone_yxstm_protocol_state state;
  uint64_t started = group_pmp_rdcycle();
  uint64_t old_epoch = *phase_epoch;
  int transition_ret;
  int wait_ret;

  memset(&request, 0, sizeof(request));
  memset(&state, 0, sizeof(state));
  KEYSTONE_ABI_INIT(&request, KEYSTONE_YXSTM_ABI_FEATURES);
  request.expected_epoch = old_epoch;
  request.next_phase = next_phase;
  request.active_worker_mask = active_worker_mask;
  request.sequence = sequence;
  request.payload_length = payload_length;
  request.timeout_cycles = timeout_cycles;
  transition_ret = group_pmp_yxstm_phase_transition(&request);
  if (transition_ret != 0) {
    printf("[P10][master-fail] op=%s stage=transition next_phase=%lu "
           "sm_error=%d old_epoch=%lu sequence=%lu active=0x%lx\n",
           operation_name(), (unsigned long)next_phase, transition_ret,
           (unsigned long)old_epoch, (unsigned long)sequence,
           (unsigned long)active_worker_mask);
    fflush(stdout);
    return 1;
  }
  wait_ret = wait_for_phase_state(
      next_phase,
      next_phase == YXSTM_PHASE_IDLE ? UINT64_MAX : sequence,
      0, 0, &state);
  if (wait_ret != 0 || state.phase_epoch <= old_epoch) {
    printf("[P10][master-fail] op=%s stage=observe next_phase=%lu "
           "reason=%d old_epoch=%lu seen_phase=%lu seen_epoch=%lu "
           "sequence=%lu seen_sequence=%lu active=0x%lx rollback=%lu "
           "deadline=%lu now=%lu\n",
           operation_name(), (unsigned long)next_phase, wait_ret,
           (unsigned long)old_epoch, (unsigned long)state.phase,
           (unsigned long)state.phase_epoch, (unsigned long)sequence,
           (unsigned long)state.sequence,
           (unsigned long)state.active_worker_mask,
           (unsigned long)state.rollback_reason,
           (unsigned long)state.deadline,
           (unsigned long)group_pmp_rdtime());
    fflush(stdout);
    return 2;
  }
  *phase_epoch = state.phase_epoch;
  *protocol_cycles += group_pmp_rdcycle() - started;
  return 0;
}

static int
timed_acquire_mask(uint64_t mask, uint64_t permissions, uint64_t phase,
                   uint64_t phase_epoch, uint64_t* protocol_cycles) {
  uint64_t started = group_pmp_rdcycle();
  int ret = group_pmp_yxstm_acquire_mask_epoch(
      mask, permissions, phase, phase_epoch);
  *protocol_cycles += group_pmp_rdcycle() - started;
  return ret;
}

static int
timed_release_mask(uint64_t mask, uint64_t phase_epoch,
                   uint64_t* protocol_cycles) {
  uint64_t started = group_pmp_rdcycle();
  int ret = group_pmp_yxstm_release_mask_epoch(mask, phase_epoch);
  *protocol_cycles += group_pmp_rdcycle() - started;
  return ret;
}

static int
timed_phase_ack(uint64_t phase_epoch, uint64_t event,
                uint64_t* protocol_cycles) {
  uint64_t started = group_pmp_rdcycle();
  int ret = group_pmp_yxstm_phase_ack(phase_epoch, event);
  *protocol_cycles += group_pmp_rdcycle() - started;
  return ret;
}

static int
timed_wait_for_bitmap(uint64_t phase, uint64_t sequence,
                      uint64_t mask, int bitmap_kind,
                      struct keystone_yxstm_protocol_state* state,
                      uint64_t* protocol_cycles) {
  uint64_t started = group_pmp_rdcycle();
  int ret = wait_for_phase_state(
      phase, sequence, mask, bitmap_kind, state);
  *protocol_cycles += group_pmp_rdcycle() - started;
  return ret;
}

static uint64_t
dispatch_round(const struct keystone_yxstm_layout_info* layout,
               uint64_t worker_count, uint64_t sequence, uint64_t round,
               uint64_t total_offset, uint64_t* round_bytes) {
  const uint8_t* input =
      (const uint8_t*)(uintptr_t)GROUP_PMP_BENCH_INPUT_VA;
  uint64_t payload_capacity = group_pmp_bench_payload_capacity(layout);
  uint64_t remaining = GROUP_PMP_BENCH_BATCH_BYTES - total_offset;
  uint64_t dispatched = 0;
  uint64_t started = group_pmp_rdcycle();

  for (uint64_t slice = 1; slice <= worker_count; ++slice) {
    volatile struct group_pmp_bench_header* header =
        group_pmp_bench_header(layout, slice);
    volatile uint8_t* payload = group_pmp_bench_payload(layout, slice);
    uint64_t length = remaining > payload_capacity ?
        payload_capacity : remaining;

    header->magic = GROUP_PMP_BENCH_MAGIC;
    header->version = GROUP_PMP_BENCH_VERSION;
    header->operation = GROUP_PMP_AES_OPERATION;
    header->worker_count = worker_count;
    header->round = round;
    header->sequence = sequence;
    header->global_offset = total_offset + dispatched;
    header->data_length = length;
    header->observed_payload_va = 0;
    header->worker_cycles = 0;
    header->checksum = 0;
    header->reserved = 0;
    if (length)
      memcpy((void*)(uintptr_t)payload,
             input + total_offset + dispatched, length);
    dispatched += length;
    remaining -= length;
  }
  __sync_synchronize();
  *round_bytes = dispatched;
  return group_pmp_rdcycle() - started;
}

static int
aggregate_digests(const struct keystone_yxstm_layout_info* layout,
                  uint64_t worker_count, uint64_t mask,
                  uint64_t sequence, uint64_t round,
                  uint64_t round_offset, uint64_t round_bytes,
                  struct p10_metrics* metrics) {
  uint64_t consumed = 0;
  uint64_t started = group_pmp_rdcycle();

  for (uint64_t slice = 1; slice <= worker_count; ++slice) {
    volatile struct group_pmp_bench_header* header =
        group_pmp_bench_header(layout, slice);
    uintptr_t expected_va = (uintptr_t)group_pmp_bench_payload(layout, slice);
    uint64_t length = header->data_length;

    if (!(mask & (UINT64_C(1) << slice)) ||
        header->magic != GROUP_PMP_BENCH_MAGIC ||
        header->version != GROUP_PMP_BENCH_VERSION ||
        header->operation != GROUP_PMP_AES_OPERATION ||
        header->worker_count != worker_count ||
        header->round != round || header->sequence != sequence ||
        header->global_offset != round_offset + consumed ||
        consumed > round_bytes ||
        length > round_bytes - consumed)
      return 1;
    if (header->observed_payload_va != expected_va)
      metrics->direct_va = 0;
    if (header->worker_cycles > metrics->worker_compute_cycles_max)
      metrics->worker_compute_cycles_max = header->worker_cycles;
    metrics->worker_compute_cycles_total += header->worker_cycles;
    metrics->digest = (metrics->digest * UINT64_C(0x100000001b3)) ^
                      header->checksum;
    consumed += length;
  }
  if (consumed != round_bytes)
    return 2;
  metrics->master_aggregate_cycles += group_pmp_rdcycle() - started;
  return 0;
}

static int
verify_round_outside_timing(
    const struct keystone_yxstm_layout_info* layout,
    uint64_t worker_count, uint64_t round, uint64_t round_offset,
    uint64_t round_bytes, uint64_t mask, uint64_t phase_epoch) {
  struct group_pmp_bench_expected_table expected;
  uint64_t consumed = 0;

  memcpy(&expected, (const void*)(uintptr_t)GROUP_PMP_BENCH_EXPECTED_VA,
         sizeof(expected));
  if (expected.magic != GROUP_PMP_BENCH_EXPECTED_MAGIC ||
      expected.version != GROUP_PMP_BENCH_VERSION ||
      expected.operation != GROUP_PMP_AES_OPERATION ||
      expected.record_count > GROUP_PMP_BENCH_EXPECTED_MAX_RECORDS)
    return 1;

  if (group_pmp_yxstm_acquire_mask_epoch(
          mask, KEYSTONE_YXSTM_PERM_R, YXSTM_PHASE_AGGREGATE,
          phase_epoch) != 0)
    return 2;

  for (uint64_t slice = 1; slice <= worker_count; ++slice) {
    volatile struct group_pmp_bench_header* header =
        group_pmp_bench_header(layout, slice);
    const struct group_pmp_bench_expected_record* record = NULL;
    uint64_t length = header->data_length;

    if (consumed > round_bytes || length > round_bytes - consumed) {
      (void)group_pmp_yxstm_release_mask_epoch(mask, phase_epoch);
      return 3;
    }

    for (uint64_t i = 0; i < expected.record_count; ++i) {
      const struct group_pmp_bench_expected_record* candidate =
          &expected.records[i];
      if (candidate->operation == GROUP_PMP_AES_OPERATION &&
          candidate->worker_count == worker_count &&
          candidate->round == round && candidate->slice_id == slice &&
          candidate->global_offset == round_offset + consumed &&
          candidate->data_length == length) {
        record = candidate;
        break;
      }
    }
    if (record == NULL || record->checksum != header->checksum) {
      (void)group_pmp_yxstm_release_mask_epoch(mask, phase_epoch);
      return 4;
    }
    consumed += length;
  }

  if (group_pmp_yxstm_release_mask_epoch(mask, phase_epoch) != 0)
    return 5;
  return consumed == round_bytes ? 0 : 6;
}

static int
run_worker_count(const struct keystone_yxstm_layout_info* layout,
                  uint64_t worker_count) {
  struct keystone_yxstm_protocol_state state;
  struct p10_metrics metrics;
  uint64_t mask = group_pmp_worker_mask_for_count(worker_count);
  uint64_t payload_capacity = group_pmp_bench_payload_capacity(layout);
  uint64_t total_offset = 0;
  uint64_t phase_epoch;

  memset(&metrics, 0, sizeof(metrics));
  metrics.direct_va = 1;
  if (!mask || !payload_capacity || mailbox_state(&state) != 0 ||
      state.phase != YXSTM_PHASE_IDLE)
    return 100;
  phase_epoch = state.phase_epoch;

  while (total_offset < GROUP_PMP_BENCH_BATCH_BYTES) {
    uint64_t sequence = state.sequence + 1;
    uint64_t round_offset = total_offset;
    uint64_t round_limit = payload_capacity * worker_count;
    uint64_t round_bytes = GROUP_PMP_BENCH_BATCH_BYTES - total_offset;
    uint64_t phase_payload_length;
    uint64_t round_e2e_started;
    uint64_t worker_wall_started;
    int rc;

    if (round_bytes > round_limit)
      round_bytes = round_limit;
    phase_payload_length = round_bytes > payload_capacity ?
        payload_capacity : round_bytes;
    metrics.rounds++;
    round_e2e_started = group_pmp_rdcycle();

    rc = transition_phase(YXSTM_PHASE_DISPATCH, mask, sequence,
                          phase_payload_length,
                          GROUP_PMP_BENCH_PROTOCOL_TIMEOUT_TICKS,
                          &phase_epoch, &metrics.protocol_cycles);
    if (rc)
      return 110 + rc;
    if (timed_acquire_mask(mask,
            KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
            YXSTM_PHASE_DISPATCH, phase_epoch,
            &metrics.protocol_cycles) != 0)
      return 120;

    metrics.master_dispatch_cycles += dispatch_round(
        layout, worker_count, sequence, metrics.rounds,
        round_offset, &round_bytes);
    if (timed_release_mask(mask, phase_epoch,
                           &metrics.protocol_cycles) != 0 ||
        timed_phase_ack(phase_epoch, YXSTM_ACK_DISPATCH_PUBLISHED,
                        &metrics.protocol_cycles) != 0)
      return 121;
    if (timed_wait_for_bitmap(YXSTM_PHASE_DISPATCH, sequence, mask, 1,
                              &state, &metrics.protocol_cycles) != 0)
      return 122;

    rc = transition_phase(YXSTM_PHASE_COMPUTE, 0, sequence, 0,
                          GROUP_PMP_BENCH_PROTOCOL_TIMEOUT_TICKS,
                          &phase_epoch,
                          &metrics.protocol_cycles);
    if (rc)
      return 130 + rc;
    if (timed_wait_for_bitmap(YXSTM_PHASE_COMPUTE, sequence, mask, 2,
                              &state, &metrics.protocol_cycles) != 0)
      return 131;

    worker_wall_started = group_pmp_rdcycle();
    rc = transition_phase(YXSTM_PHASE_AGGREGATE, 0, sequence, 0,
                          GROUP_PMP_BENCH_PROTOCOL_TIMEOUT_TICKS,
                          &phase_epoch,
                          &metrics.protocol_cycles);
    if (rc)
      return 140 + rc;
    if (wait_for_phase_state(YXSTM_PHASE_AGGREGATE, sequence,
                             mask, 1, &state) != 0)
      return 141;
    metrics.worker_compute_wall_cycles +=
        group_pmp_rdcycle() - worker_wall_started;

    if (timed_acquire_mask(mask, KEYSTONE_YXSTM_PERM_R,
                           YXSTM_PHASE_AGGREGATE, phase_epoch,
                           &metrics.protocol_cycles) != 0)
      return 150;
    rc = aggregate_digests(layout, worker_count, mask, sequence,
                           metrics.rounds, round_offset, round_bytes,
                           &metrics);
    if (timed_release_mask(mask, phase_epoch,
                           &metrics.protocol_cycles) != 0)
      return 151;
    if (rc)
      return 152 + rc;
    metrics.pipeline_e2e_cycles +=
        group_pmp_rdcycle() - round_e2e_started;

    if (verify_round_outside_timing(layout, worker_count, metrics.rounds,
                                    round_offset, round_bytes, mask,
                                    phase_epoch) != 0)
      return 160;
    total_offset += round_bytes;

    round_e2e_started = group_pmp_rdcycle();
    rc = transition_phase(YXSTM_PHASE_IDLE, 0, sequence, 0, 0,
                          &phase_epoch, &metrics.protocol_cycles);
    if (rc)
      return 170 + rc;
    metrics.pipeline_e2e_cycles +=
        group_pmp_rdcycle() - round_e2e_started;
    if (mailbox_state(&state) != 0)
      return 180;
  }

  printf("[P10][aes] op=%s workers=%lu data_mb=%lu rounds=%lu "
         "master_dispatch_cycles=%lu worker_compute_wall_cycles=%lu "
         "worker_compute_cycles_max=%lu worker_compute_cycles_total=%lu "
         "master_aggregate_cycles=%lu protocol_cycles=%lu "
         "pipeline_e2e_cycles=%lu digest=%lu direct_va=%lu verify=1\n",
         operation_name(), (unsigned long)worker_count,
         (unsigned long)(GROUP_PMP_BENCH_BATCH_BYTES / UINT64_C(1000000)),
         (unsigned long)metrics.rounds,
         (unsigned long)metrics.master_dispatch_cycles,
         (unsigned long)metrics.worker_compute_wall_cycles,
         (unsigned long)metrics.worker_compute_cycles_max,
         (unsigned long)metrics.worker_compute_cycles_total,
         (unsigned long)metrics.master_aggregate_cycles,
         (unsigned long)metrics.protocol_cycles,
         (unsigned long)metrics.pipeline_e2e_cycles,
         (unsigned long)metrics.digest,
         (unsigned long)metrics.direct_va);
  fflush(stdout);
  return 0;
}

static int
run_stop_round(const struct keystone_yxstm_layout_info* layout) {
  struct keystone_yxstm_protocol_state state;
  uint64_t mask = GROUP_PMP_MW_WORKER_SLICE_MASK;
  uint64_t phase_epoch;
  uint64_t sequence;
  uint64_t ignored_cycles = 0;

  if (mailbox_state(&state) != 0 || state.phase != YXSTM_PHASE_IDLE)
    return 1;
  phase_epoch = state.phase_epoch;
  sequence = state.sequence + 1;
  if (transition_phase(YXSTM_PHASE_DISPATCH, mask, sequence, 0,
                       GROUP_PMP_BENCH_PROTOCOL_TIMEOUT_TICKS,
                       &phase_epoch,
                       &ignored_cycles) != 0 ||
      timed_acquire_mask(mask,
          KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
          YXSTM_PHASE_DISPATCH, phase_epoch, &ignored_cycles) != 0)
    return 2;

  for (uint64_t slice = 1;
       slice < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT; ++slice) {
    volatile struct group_pmp_bench_header* header =
        group_pmp_bench_header(layout, slice);
    memset((void*)(uintptr_t)header, 0, sizeof(*header));
    header->magic = GROUP_PMP_BENCH_MAGIC;
    header->version = GROUP_PMP_BENCH_VERSION;
    header->operation = GROUP_PMP_BENCH_STOP;
    header->worker_count = 3;
    header->sequence = sequence;
  }
  __sync_synchronize();
  if (timed_release_mask(mask, phase_epoch, &ignored_cycles) != 0 ||
      timed_phase_ack(phase_epoch, YXSTM_ACK_DISPATCH_PUBLISHED,
                      &ignored_cycles) != 0 ||
      timed_wait_for_bitmap(YXSTM_PHASE_DISPATCH, sequence, mask, 1,
                            &state, &ignored_cycles) != 0)
    return 3;
  if (transition_phase(YXSTM_PHASE_COMPUTE, 0, sequence, 0,
                       GROUP_PMP_BENCH_PROTOCOL_TIMEOUT_TICKS,
                       &phase_epoch,
                       &ignored_cycles) != 0 ||
      timed_wait_for_bitmap(YXSTM_PHASE_COMPUTE, sequence, mask, 2,
                            &state, &ignored_cycles) != 0)
    return 4;
  if (transition_phase(YXSTM_PHASE_AGGREGATE, 0, sequence, 0,
                       GROUP_PMP_BENCH_PROTOCOL_TIMEOUT_TICKS,
                       &phase_epoch,
                       &ignored_cycles) != 0 ||
      timed_wait_for_bitmap(YXSTM_PHASE_AGGREGATE, sequence, mask, 1,
                            &state, &ignored_cycles) != 0)
    return 5;
  return transition_phase(YXSTM_PHASE_IDLE, 0, sequence, 0, 0,
                          &phase_epoch, &ignored_cycles);
}

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  int rc;

  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 1;
  if (layout.role != GROUP_ROLE_MASTER ||
      layout.slice_count != KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT ||
      layout.slice_size != UINT64_C(8) * 1024 * 1024 ||
      layout.allowed_slice_mask !=
          ((UINT64_C(1) << KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT) - 1))
    return 2;
  if (group_pmp_register_protocol_mailbox(
          g_protocol_mailbox_page,
          KEYSTONE_YXSTM_MAILBOX_FLAG_PERF_QUIET) != 0)
    return 3;

  for (uint64_t worker_count = 1; worker_count <= 3; ++worker_count) {
    rc = run_worker_count(&layout, worker_count);
    if (rc != 0)
      return rc;
  }

  rc = run_stop_round(&layout);
  return rc;
}
