#ifndef GROUP_PMP_COMMON_H
#define GROUP_PMP_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "syscall.h"
#include "group-pmp-bench-shared.h"
#include "group-pmp-mixed-shared.h"

#define GROUP_PMP_TIMESLICE_MAGIC UINT64_C(0x47504d5053434844)
#define GROUP_PMP_TIMESLICE_ITERS 32
#define GROUP_PMP_MW_MAGIC UINT64_C(0x47504d504d57504c)
#define GROUP_PMP_MW_WORKER_SLICE_MASK UINT64_C(0xe)
#define GROUP_PMP_MW_STATUS_EMPTY UINT64_C(0)
#define GROUP_PMP_MW_STATUS_DISPATCHED UINT64_C(1)
#define GROUP_PMP_MW_STATUS_DONE UINT64_C(2)
#define GROUP_PMP_BENCH_POLL_LIMIT UINT64_C(100000000)
#define GROUP_PMP_BENCH_POLL_YIELD_INTERVAL UINT64_C(262144)
#define GROUP_PMP_UTM_BENCH_CHUNK_BYTES (16 * 1024)
#define GROUP_PMP_UTM_BENCH_OFFSET 4096

#define GROUP_PMP_YXSTM_VA KEYSTONE_YXSTM_ENCLAVE_VA_BASE
#if defined(__riscv_xlen) && (__riscv_xlen == 32)
#define GROUP_PMP_BENCH_INPUT_VA ((uintptr_t)0x60000000UL + \
                                  GROUP_PMP_BENCH_INPUT_OFFSET)
#define GROUP_PMP_BENCH_EXPECTED_VA ((uintptr_t)0x60000000UL + \
                                     GROUP_PMP_BENCH_EXPECTED_OFFSET)
#else
#define GROUP_PMP_BENCH_INPUT_VA ((uintptr_t)0xffffffff60000000ULL + \
                                  GROUP_PMP_BENCH_INPUT_OFFSET)
#define GROUP_PMP_BENCH_EXPECTED_VA ((uintptr_t)0xffffffff60000000ULL + \
                                     GROUP_PMP_BENCH_EXPECTED_OFFSET)
#endif

#define GROUP_PMP_DEFINE_PROTOCOL_MAILBOX(name) \
  static const uint8_t name[KEYSTONE_YXSTM_MAILBOX_PAGE_SIZE] \
      __attribute__((section(".rodata.group_pmp_protocol_mailbox"), \
                     aligned(KEYSTONE_YXSTM_MAILBOX_PAGE_SIZE), used)) = {0}

static inline const volatile struct keystone_yxstm_protocol_mailbox*
group_pmp_protocol_mailbox(const uint8_t* page) {
  return (const volatile struct keystone_yxstm_protocol_mailbox*)
      (uintptr_t)page;
}

static inline int
group_pmp_register_protocol_mailbox(const uint8_t* page, uint64_t flags) {
  struct keystone_yxstm_mailbox_registration request;
  memset(&request, 0, sizeof(request));
  KEYSTONE_ABI_INIT(&request, KEYSTONE_YXSTM_ABI_FEATURES);
  request.mailbox_va = (uintptr_t)page;
  request.mailbox_size = KEYSTONE_YXSTM_MAILBOX_PAGE_SIZE;
  request.flags = flags;
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_REGISTER_MAILBOX,
                   &request,
                   sizeof(request));
}

static inline int
group_pmp_protocol_mailbox_snapshot(
    const volatile struct keystone_yxstm_protocol_mailbox* mailbox,
    struct keystone_yxstm_protocol_state* state) {
  for (uint64_t spin = 0; spin < GROUP_PMP_BENCH_POLL_LIMIT; ++spin) {
    uintptr_t before = mailbox->publish_sequence;
    uintptr_t after;
    if (before == 0 || (before & 1))
      continue;
    __sync_synchronize();
    if (mailbox->magic != KEYSTONE_YXSTM_MAILBOX_MAGIC ||
        mailbox->version != KEYSTONE_YXSTM_MAILBOX_VERSION)
      continue;
    memcpy(state, (const void*)(uintptr_t)&mailbox->state, sizeof(*state));
    __sync_synchronize();
    after = mailbox->publish_sequence;
    if (before == after && !(after & 1) &&
        state->abi.version == KEYSTONE_ABI_VERSION &&
        state->abi.struct_size == sizeof(*state) &&
        (state->abi.features & KEYSTONE_YXSTM_ABI_FEATURES) ==
            KEYSTONE_YXSTM_ABI_FEATURES)
      return 0;
  }
  return -1;
}

static inline int
group_pmp_task_bank_mailbox_snapshot(
    const volatile struct keystone_yxstm_protocol_mailbox* mailbox,
    uint64_t bank_id, struct keystone_yxstm_task_bank_state* state) {
  if (bank_id >= KEYSTONE_YXSTM_MAX_BANKS)
    return -1;
  for (uint64_t spin = 0; spin < GROUP_PMP_BENCH_POLL_LIMIT; ++spin) {
    uintptr_t before = mailbox->publish_sequence;
    uintptr_t after;
    if (before == 0 || (before & 1))
      continue;
    __sync_synchronize();
    if (mailbox->magic != KEYSTONE_YXSTM_MAILBOX_MAGIC ||
        mailbox->version != KEYSTONE_YXSTM_MAILBOX_VERSION ||
        mailbox->task_bank_count <= bank_id)
      continue;
    memcpy(state, (const void*)(uintptr_t)&mailbox->task_banks[bank_id],
           sizeof(*state));
    __sync_synchronize();
    after = mailbox->publish_sequence;
    if (before == after && !(after & 1) && state->bank_id == bank_id)
      return 0;
  }
  return -1;
}

static inline volatile uint64_t*
group_pmp_yxstm_words(void) {
  return (volatile uint64_t*)(uintptr_t)GROUP_PMP_YXSTM_VA;
}

static inline uintptr_t
group_pmp_yxstm_slice_word_base(
    const struct keystone_yxstm_layout_info* layout, uint64_t slice_id) {
  return (uintptr_t)slice_id * (layout->slice_size / sizeof(uint64_t)) +
         sizeof(struct keystone_yxstm_channel_header) / sizeof(uint64_t);
}

static inline uintptr_t
group_pmp_yxstm_bank_slice_va(
    const struct keystone_yxstm_layout_info* layout,
    uint64_t bank_id, uint64_t slice_id) {
  return layout->yxstm_va_base + bank_id * layout->bank_stride +
         slice_id * layout->bank_slice_size;
}

static inline volatile struct keystone_group_task_descriptor*
group_pmp_task_descriptor(
    const struct keystone_yxstm_layout_info* layout,
    uint64_t bank_id, uint64_t slice_id) {
  return (volatile struct keystone_group_task_descriptor*)(uintptr_t)
      (group_pmp_yxstm_bank_slice_va(layout, bank_id, slice_id) +
       sizeof(struct keystone_yxstm_channel_header));
}

static inline volatile uint8_t*
group_pmp_task_payload(
    const struct keystone_yxstm_layout_info* layout,
    uint64_t bank_id, uint64_t slice_id) {
  return (volatile uint8_t*)(uintptr_t)
      (group_pmp_yxstm_bank_slice_va(layout, bank_id, slice_id) +
       sizeof(struct keystone_yxstm_channel_header) +
       sizeof(struct keystone_group_task_descriptor));
}

static inline uint64_t
group_pmp_mw_input(uint64_t slice_id) {
  return UINT64_C(1000) + slice_id * UINT64_C(17);
}

static inline uint64_t
group_pmp_worker_mask_for_count(uint64_t worker_count) {
  if (worker_count == 0 ||
      worker_count >= KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT)
    return 0;
  return ((UINT64_C(1) << (worker_count + 1)) - 1) &
         GROUP_PMP_MW_WORKER_SLICE_MASK;
}

static inline volatile struct group_pmp_bench_header*
group_pmp_bench_header(
    const struct keystone_yxstm_layout_info* layout, uint64_t slice_id) {
  uintptr_t slice_va = layout->yxstm_va_base + slice_id * layout->slice_size;
  return (volatile struct group_pmp_bench_header*)(uintptr_t)
      (slice_va + sizeof(struct keystone_yxstm_channel_header));
}

static inline volatile uint8_t*
group_pmp_bench_payload(
    const struct keystone_yxstm_layout_info* layout, uint64_t slice_id) {
  return (volatile uint8_t*)(group_pmp_bench_header(layout, slice_id) + 1);
}

static inline uint64_t
group_pmp_bench_payload_capacity(
    const struct keystone_yxstm_layout_info* layout) {
  uint64_t overhead = sizeof(struct keystone_yxstm_channel_header) +
      sizeof(struct group_pmp_bench_header);
  return layout->slice_size > overhead ?
      (layout->slice_size - overhead) & ~UINT64_C(15) : 0;
}

static inline volatile uint8_t*
group_pmp_mixed_slot_payload(
    const struct keystone_yxstm_layout_info* layout, uint64_t lane_id,
    uint64_t slot_offset) {
  uintptr_t slot_va = layout->yxstm_va_base +
      (lane_id + 1) * layout->bank_slice_size + slot_offset;
  return (volatile uint8_t*)slot_va;
}

static inline uint64_t
group_pmp_mixed_slot_payload_capacity(
    const struct keystone_yxstm_layout_info* layout) {
  return layout->slot_payload_size & ~UINT64_C(15);
}

static inline int
group_pmp_yxstm_query_slot_info(struct keystone_yxstm_slot_info* info,
                                uint64_t lane_id, uint64_t slot_id) {
  memset(info, 0, sizeof(*info));
  KEYSTONE_ABI_INIT(info, KEYSTONE_YXSTM_ABI_FEATURES);
  info->lane_id = lane_id;
  info->slot_id = slot_id;
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_QUERY_SLOT,
                   info, sizeof(*info));
}

static inline int
group_pmp_yxstm_slot_command(struct keystone_yxstm_slot_command* command) {
  KEYSTONE_ABI_INIT(command, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_SLOT_COMMAND,
                   command, sizeof(*command));
}

static inline uint64_t
group_pmp_rdcycle(void) {
  uint64_t value;
  __asm__ __volatile__("rdcycle %0" : "=r"(value));
  return value;
}

static inline uint64_t
group_pmp_rdtime(void) {
  uint64_t value;
  __asm__ __volatile__("rdtime %0" : "=r"(value));
  return value;
}

static inline int
group_pmp_protocol_deadline_expired(
    const struct keystone_yxstm_protocol_state* state) {
  return state->deadline != 0 && group_pmp_rdtime() >= state->deadline;
}

static inline uint8_t
group_pmp_bench_plain_byte(uint64_t offset) {
  return (uint8_t)((offset * UINT64_C(131) + UINT64_C(0x5a)) & 0xff);
}

static inline uint64_t
group_pmp_bench_digest_block(uint64_t digest, const uint8_t block[16]) {
  uint64_t low;
  uint64_t high;

  memcpy(&low, block, sizeof(low));
  memcpy(&high, block + sizeof(low), sizeof(high));
  digest ^= low + UINT64_C(0x9e3779b97f4a7c15) +
            (digest << 6) + (digest >> 2);
  digest = (digest << 17) | (digest >> (64 - 17));
  return digest ^ high;
}

static inline uint64_t
group_pmp_bench_checksum_bytes(const volatile uint8_t* data, uint64_t len) {
  uint64_t checksum = 0;
  for (uint64_t i = 0; i < len; ++i)
    checksum = checksum * UINT64_C(131) + data[i];
  return checksum;
}

static inline uint64_t
group_pmp_bench_checksum_expected_plain(uint64_t offset, uint64_t len) {
  uint64_t checksum = 0;
  for (uint64_t i = 0; i < len; ++i)
    checksum = checksum * UINT64_C(131) + group_pmp_bench_plain_byte(offset + i);
  return checksum;
}

static inline uint64_t
group_pmp_mw_result(uint64_t slice_id, uint64_t input) {
  return input * UINT64_C(3) + slice_id;
}

static inline int
group_pmp_yxstm_query_layout(
    struct keystone_yxstm_layout_info* info, size_t info_len) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_QUERY_LAYOUT, info, info_len);
}

static inline int
group_pmp_yxstm_query_protocol(
    struct keystone_yxstm_protocol_state* state, size_t state_len) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_QUERY_PROTOCOL, state, state_len);
}

static inline int
group_pmp_yxstm_phase_transition(
    const struct keystone_yxstm_phase_transition* request) {
  struct keystone_yxstm_phase_transition local = *request;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_PHASE_TRANSITION,
                   &local, sizeof(local));
}

static inline int
group_pmp_yxstm_phase_ack(uint64_t expected_epoch, uint64_t event) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_PHASE_ACK,
                   expected_epoch, event);
}

static inline int
group_pmp_yxstm_task_bank_transition(
    const struct keystone_yxstm_task_bank_transition* request) {
  struct keystone_yxstm_task_bank_transition local = *request;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_TASK_BANK_TRANSITION,
                   &local, sizeof(local));
}

static inline int
group_pmp_yxstm_task_bank_acquire(
    const struct keystone_yxstm_task_bank_grant* request) {
  struct keystone_yxstm_task_bank_grant local = *request;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_TASK_BANK_ACQUIRE,
                   &local, sizeof(local));
}

static inline int
group_pmp_yxstm_task_bank_release(
    const struct keystone_yxstm_task_bank_grant* request) {
  struct keystone_yxstm_task_bank_grant local = *request;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_TASK_BANK_RELEASE,
                   &local, sizeof(local));
}

static inline int
group_pmp_yxstm_task_bank_ack(
    const struct keystone_yxstm_task_bank_ack* request) {
  struct keystone_yxstm_task_bank_ack local = *request;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_TASK_BANK_ACK,
                   &local, sizeof(local));
}

static inline int
group_pmp_lane_turn(uint64_t operation, uint64_t lane_id,
                    uint64_t lane_rank, uint64_t sequence,
                    uint64_t turn_id) {
  struct keystone_group_lane_turn request;

  memset(&request, 0, sizeof(request));
  KEYSTONE_ABI_INIT(&request, KEYSTONE_YXSTM_ABI_FEATURES);
  request.operation = operation;
  request.lane_id = lane_id;
  request.lane_rank = lane_rank;
  request.sequence = sequence;
  request.turn_id = turn_id;
  return SYSCALL_2(RUNTIME_SYSCALL_GROUP_LANE_TURN,
                   &request, sizeof(request));
}

static inline int
group_pmp_task_bank_wait(uint64_t bank_id, uint64_t lane_id,
                         uint64_t lane_rank, uint64_t sequence,
                         uint64_t phase, uint64_t task_epoch) {
  struct keystone_group_lane_turn request;

  memset(&request, 0, sizeof(request));
  KEYSTONE_ABI_INIT(&request, KEYSTONE_YXSTM_ABI_FEATURES);
  request.operation = KEYSTONE_GROUP_LANE_TURN_WAIT_BANK;
  request.lane_id = lane_id;
  request.lane_rank = lane_rank;
  request.sequence = sequence;
  request.turn_id = bank_id;
  request.reserved[0] = phase;
  request.reserved[1] = task_epoch;
  return SYSCALL_2(RUNTIME_SYSCALL_GROUP_LANE_TURN,
                   &request, sizeof(request));
}

static inline int
group_pmp_yxstm_acquire_slice_epoch(
    uint64_t slice_id, uint64_t flags, uint64_t phase,
    uint64_t expected_epoch) {
  return SYSCALL_4(RUNTIME_SYSCALL_YXSTM_ACQUIRE_SLICE,
                   slice_id, flags, phase, expected_epoch);
}

static inline int
group_pmp_yxstm_acquire_slice(
    uint64_t slice_id, uint64_t flags, uint64_t phase) {
  struct keystone_yxstm_protocol_state state;
  int ret = group_pmp_yxstm_query_protocol(&state, sizeof(state));
  if (ret)
    return ret;
  return group_pmp_yxstm_acquire_slice_epoch(
      slice_id, flags, phase, state.phase_epoch);
}

static inline int
group_pmp_yxstm_release_slice(uint64_t slice_id) {
  struct keystone_yxstm_protocol_state state;
  int ret = group_pmp_yxstm_query_protocol(&state, sizeof(state));
  if (ret)
    return ret;
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_RELEASE_SLICE,
                   slice_id, state.phase_epoch);
}

static inline int
group_pmp_yxstm_release_slice_epoch(
    uint64_t slice_id, uint64_t expected_epoch) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_RELEASE_SLICE,
                   slice_id, expected_epoch);
}

static inline int
group_pmp_yxstm_acquire_mask_epoch(
    uint64_t slice_mask, uint64_t flags, uint64_t phase,
    uint64_t expected_epoch) {
  return SYSCALL_4(RUNTIME_SYSCALL_YXSTM_ACQUIRE_MASK,
                   slice_mask, flags, phase, expected_epoch);
}

static inline int
group_pmp_yxstm_acquire_mask(
    uint64_t slice_mask, uint64_t flags, uint64_t phase) {
  struct keystone_yxstm_protocol_state state;
  int ret = group_pmp_yxstm_query_protocol(&state, sizeof(state));
  if (ret)
    return ret;
  return group_pmp_yxstm_acquire_mask_epoch(
      slice_mask, flags, phase, state.phase_epoch);
}

static inline int
group_pmp_yxstm_release_mask(uint64_t slice_mask) {
  struct keystone_yxstm_protocol_state state;
  int ret = group_pmp_yxstm_query_protocol(&state, sizeof(state));
  if (ret)
    return ret;
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_RELEASE_MASK,
                   slice_mask, state.phase_epoch);
}

static inline int
group_pmp_yxstm_release_mask_epoch(
    uint64_t slice_mask, uint64_t expected_epoch) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_RELEASE_MASK,
                   slice_mask, expected_epoch);
}

static inline int
group_pmp_enclave_yield(void) {
  return SYSCALL_0(RUNTIME_SYSCALL_YIELD);
}

/* In 3W_1HM mode the master has no same-hart peer, so yield returns CPU0
 * to the HOST. group_run_master() resumes it after the driver event wait. */
static inline int
group_pmp_master_host_yield(void) {
  return group_pmp_enclave_yield();
}

static inline void
group_pmp_poll_service_host(uint64_t* poll_count) {
#if GROUP_PMP_AES_COOPERATIVE_SERVICE
  (*poll_count)++;
  if ((*poll_count % GROUP_PMP_BENCH_POLL_YIELD_INTERVAL) == 0)
    (void)group_pmp_enclave_yield();
#else
  (void)poll_count;
#endif
}

#endif
