#include <stdint.h>
#include <stdio.h>

#include "aes_core.h"
#include "group-pmp-common.h"

GROUP_PMP_DEFINE_PROTOCOL_MAILBOX(g_protocol_mailbox_page);

static const uint8_t kAes128Key[16] = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x11, 0x33, 0x55, 0x77, 0x99, 0xbb, 0xdd, 0xff,
};

static int
mailbox_state(struct keystone_yxstm_protocol_state* state) {
  return group_pmp_protocol_mailbox_snapshot(
      group_pmp_protocol_mailbox(g_protocol_mailbox_page), state);
}

static int
wait_for_dispatch(struct keystone_yxstm_protocol_state* state,
                  uint64_t slice, uint64_t last_sequence) {
  uint64_t poll_count = 0;
  uint64_t slice_bit = UINT64_C(1) << slice;

  for (;;) {
    if (mailbox_state(state) != 0)
      return 10;
    if (state->rollback_reason != YXSTM_ROLLBACK_NONE)
      return 11;
    if (state->phase == YXSTM_PHASE_DISPATCH &&
        state->sequence != last_sequence &&
        state->published_sequence == state->sequence &&
        (state->active_worker_mask & slice_bit))
      return 0;
    /*
     * A phase deadline belongs only to the workers selected for that round.
     * P10 deliberately runs 1-, 2-, then 3-worker rounds while all three
     * workers remain resident. An idle worker must wait for a later dispatch,
     * not terminate when another worker's round reaches its deadline.
     */
    if ((state->active_worker_mask & slice_bit) &&
        group_pmp_protocol_deadline_expired(state))
      return 12;
    group_pmp_poll_service_host(&poll_count);
  }
}

static void
report_wait_failure(const char* stage, int reason, uint64_t slice,
                    const struct keystone_yxstm_protocol_state* state) {
  printf("[P10][worker-fail] slice=%lu stage=%s reason=%d phase=%lu "
         "phase_epoch=%lu sequence=%lu active=0x%lx ready=0x%lx "
         "done=0x%lx rollback=%lu deadline=%lu now=%lu\n",
         (unsigned long)slice, stage, reason,
         (unsigned long)state->phase,
         (unsigned long)state->phase_epoch,
         (unsigned long)state->sequence,
         (unsigned long)state->active_worker_mask,
         (unsigned long)state->ready_bitmap,
         (unsigned long)state->done_bitmap,
         (unsigned long)state->rollback_reason,
         (unsigned long)state->deadline,
         (unsigned long)group_pmp_rdtime());
  fflush(stdout);
}

static int
wait_for_phase(struct keystone_yxstm_protocol_state* state,
               uint64_t phase, uint64_t sequence) {
  uint64_t poll_count = 0;

  for (;;) {
    if (mailbox_state(state) != 0)
      return 20;
    if (state->rollback_reason != YXSTM_ROLLBACK_NONE)
      return 21;
    if (state->phase == phase && state->sequence == sequence)
      return 0;
    if (group_pmp_protocol_deadline_expired(state))
      return 22;
    group_pmp_poll_service_host(&poll_count);
  }
}

static int
wait_for_phase_advance(struct keystone_yxstm_protocol_state* state,
                       uint64_t phase, uint64_t sequence) {
  uint64_t poll_count = 0;

  for (;;) {
    if (mailbox_state(state) != 0)
      return 30;
    if (state->rollback_reason != YXSTM_ROLLBACK_NONE)
      return 31;
    if (state->phase != phase || state->sequence != sequence)
      return 0;
    if (group_pmp_protocol_deadline_expired(state))
      return 32;
    group_pmp_poll_service_host(&poll_count);
  }
}

static int
transform_payload(uint64_t operation, void* encrypt_ctx, void* decrypt_ctx,
                  uint8_t* payload, uint64_t len, uint64_t slice,
                  uint64_t phase_epoch, uint64_t* digest_out,
                  uint64_t* compute_cycles_out) {
  uint64_t digest = 0;
  uint64_t compute_cycles = 0;
  uint64_t base = 0;

#if GROUP_PMP_AES_COOPERATIVE_SERVICE
  while (base < len) {
    uint64_t chunk_end = base + GROUP_PMP_BENCH_COMPUTE_SERVICE_BYTES;
    uint64_t started;

    if (chunk_end < base || chunk_end > len)
      chunk_end = len;
    started = group_pmp_rdcycle();
    for (; base < chunk_end; base += 16) {
      if (operation == GROUP_PMP_BENCH_AES_ENCRYPT)
        aes_encrypt(encrypt_ctx, payload + base, payload + base);
      else
        aes_decrypt(decrypt_ctx, payload + base, payload + base);
      digest = group_pmp_bench_digest_block(digest, payload + base);
    }
    compute_cycles += group_pmp_rdcycle() - started;

    if (base < len) {
      /*
       * Debug compatibility path. Production P10 relies on scheduler-owned
       * timer host service and keeps this grant across transparent preemption.
       */
      if (group_pmp_yxstm_release_slice_epoch(slice, phase_epoch) != 0)
        return 1;
      (void)group_pmp_enclave_yield();
      if (group_pmp_yxstm_acquire_slice_epoch(
              slice, KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
              YXSTM_PHASE_AGGREGATE, phase_epoch) != 0)
        return 2;
    }
  }
#else
  {
    uint64_t started = group_pmp_rdcycle();
    (void)slice;
    (void)phase_epoch;
    for (; base < len; base += 16) {
      if (operation == GROUP_PMP_BENCH_AES_ENCRYPT)
        aes_encrypt(encrypt_ctx, payload + base, payload + base);
      else
        aes_decrypt(decrypt_ctx, payload + base, payload + base);
      digest = group_pmp_bench_digest_block(digest, payload + base);
    }
    compute_cycles = group_pmp_rdcycle() - started;
  }
#endif

  *digest_out = digest;
  *compute_cycles_out = compute_cycles;
  return 0;
}

int
main(void) {
  struct keystone_yxstm_layout_info layout;
  struct keystone_yxstm_protocol_state state;
  volatile struct group_pmp_bench_header* header;
  uint8_t* payload;
  uint64_t slice;
  uint64_t last_sequence = 0;
  void* encrypt_ctx;
  void* decrypt_ctx;

  memset(&state, 0, sizeof(state));
  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0)
    return 1;
  if (layout.role != GROUP_ROLE_WORKER ||
      layout.worker_slice_id == (uintptr_t)-1 ||
      layout.allowed_slice_mask != (UINT64_C(1) << layout.worker_slice_id))
    return 2;
  if (group_pmp_register_protocol_mailbox(g_protocol_mailbox_page, 0) != 0)
    return 3;

  encrypt_ctx = aes_encrypt_init(kAes128Key, sizeof(kAes128Key));
  decrypt_ctx = aes_decrypt_init(kAes128Key, sizeof(kAes128Key));
  if (encrypt_ctx == NULL || decrypt_ctx == NULL)
    return 4;

  slice = layout.worker_slice_id;
  header = group_pmp_bench_header(&layout, slice);
  payload = (uint8_t*)(uintptr_t)group_pmp_bench_payload(&layout, slice);

  for (;;) {
    uint64_t sequence;
    uint64_t phase_epoch;
    uint64_t operation;
    uint64_t length;
    uint64_t digest;
    uint64_t compute_cycles;
    int transform_ret;

    int wait_ret = wait_for_dispatch(&state, slice, last_sequence);
    if (wait_ret != 0) {
      report_wait_failure("dispatch", wait_ret, slice, &state);
      return 10;
    }
    sequence = state.sequence;
    phase_epoch = state.phase_epoch;

    if (group_pmp_yxstm_acquire_slice_epoch(
            slice, KEYSTONE_YXSTM_PERM_R, YXSTM_PHASE_DISPATCH,
            phase_epoch) != 0)
      return 11;
    operation = header->operation;
    length = header->data_length;
    if (header->magic != GROUP_PMP_BENCH_MAGIC ||
        header->version != GROUP_PMP_BENCH_VERSION ||
        header->sequence != sequence ||
        length > group_pmp_bench_payload_capacity(&layout) ||
        (length & UINT64_C(15)) ||
        (operation != GROUP_PMP_BENCH_STOP &&
         operation != GROUP_PMP_BENCH_AES_ENCRYPT &&
         operation != GROUP_PMP_BENCH_AES_DECRYPT)) {
      (void)group_pmp_yxstm_release_slice_epoch(slice, phase_epoch);
      return 12;
    }
    if (group_pmp_yxstm_release_slice_epoch(slice, phase_epoch) != 0)
      return 13;
    if (group_pmp_yxstm_phase_ack(
            phase_epoch, YXSTM_ACK_DISPATCH_READY) != 0)
      return 14;

    wait_ret = wait_for_phase(&state, YXSTM_PHASE_COMPUTE, sequence);
    if (wait_ret != 0) {
      report_wait_failure("compute", wait_ret, slice, &state);
      return 15;
    }
    if (group_pmp_yxstm_phase_ack(
            state.phase_epoch, YXSTM_ACK_COMPUTE_DONE) != 0)
      return 16;

    wait_ret = wait_for_phase(&state, YXSTM_PHASE_AGGREGATE, sequence);
    if (wait_ret != 0) {
      report_wait_failure("aggregate", wait_ret, slice, &state);
      return 17;
    }
    phase_epoch = state.phase_epoch;
    if (group_pmp_yxstm_acquire_slice_epoch(
            slice, KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W,
            YXSTM_PHASE_AGGREGATE, phase_epoch) != 0)
      return 18;

    digest = 0;
    compute_cycles = 0;
    transform_ret = operation == GROUP_PMP_BENCH_STOP ? 0 :
        transform_payload(operation, encrypt_ctx, decrypt_ctx,
                          payload, length, slice, phase_epoch,
                          &digest, &compute_cycles);
    if (transform_ret != 0) {
      (void)group_pmp_yxstm_release_slice_epoch(slice, phase_epoch);
      return 22 + transform_ret;
    }
    header->checksum = digest;
    header->worker_cycles = compute_cycles;
    header->observed_payload_va = (uintptr_t)payload;
    __sync_synchronize();

    if (group_pmp_yxstm_release_slice_epoch(slice, phase_epoch) != 0)
      return 19;
    if (group_pmp_yxstm_phase_ack(
            phase_epoch, YXSTM_ACK_AGGREGATE_READY) != 0)
      return 20;
    wait_ret = wait_for_phase_advance(
        &state, YXSTM_PHASE_AGGREGATE, sequence);
    if (wait_ret != 0) {
      report_wait_failure("aggregate-advance", wait_ret, slice, &state);
      return 21;
    }

    last_sequence = sequence;
    if (operation == GROUP_PMP_BENCH_STOP)
      break;
  }

  aes_encrypt_deinit(encrypt_ctx);
  aes_decrypt_deinit(decrypt_ctx);
  return 0;
}
