#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aes_core.h"
#include "group-pmp-aes-baseline-shared.h"
#include "group-pmp-common.h"

static const uint8_t kAes128Key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t kKnownPlaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static const uint8_t kKnownCiphertext[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
};

#define MIXED_WORKER_WAIT_DIAG_MARKER "keystone-mixed-worker-wait-diag-v2"
static const volatile char mixed_worker_wait_diag_marker[]
    __attribute__((used)) = MIXED_WORKER_WAIT_DIAG_MARKER;
static const volatile char mixed_lane_dynamic_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_MIXED_ARTIFACT_MARKER;

static int
publish_result(struct group_pmp_mixed_worker_result* result,
               uint64_t state) {
  uint64_t published = state;

  result->status = GROUP_PMP_MIXED_STATE_EMPTY;
  if (copy_to_shared_utm(GROUP_PMP_MIXED_RESULT_OFFSET,
                         result, sizeof(*result)) != 0)
    return -1;
  __sync_synchronize();
  result->status = state;
  return copy_to_shared_utm(
      GROUP_PMP_MIXED_RESULT_OFFSET +
          offsetof(struct group_pmp_mixed_worker_result, status),
      &published, sizeof(published));
}

static uint64_t
payload_digest(const volatile uint8_t* payload, uint64_t length) {
  uint8_t block[16];
  uint64_t digest = UINT64_C(0xcbf29ce484222325);
  const uint64_t offsets[4] = {
      0, length > 4096 ? 4096 : 0, length / 2, length - 16};
  uint64_t sample;

  for (sample = 0; sample < 4; ++sample) {
    memcpy(block, (const void*)(uintptr_t)(payload + offsets[sample]),
           sizeof(block));
    digest = group_pmp_bench_digest_block(digest, block);
  }
  return digest ? digest : UINT64_C(1);
}

static uint64_t
sequential_read64(const volatile uint8_t* payload, uint64_t length) {
  const volatile uint64_t* words =
      (const volatile uint64_t*)(const void*)payload;
  uint64_t value = 0;
  uint64_t index;

  for (index = 0; index < length / sizeof(*words); ++index)
    value += words[index] ^ index;
  return value;
}

static uint64_t
sequential_rewrite64(volatile uint8_t* payload, uint64_t length) {
  volatile uint64_t* words = (volatile uint64_t*)(void*)payload;
  uint64_t value = 0;
  uint64_t index;

  for (index = 0; index < length / sizeof(*words); ++index) {
    uint64_t word = words[index];
    words[index] = word;
    value ^= word + index;
  }
  return value;
}

static uint64_t
page_stride_read(const volatile uint8_t* payload, uint64_t length,
                 uint64_t* accesses) {
  uint64_t value = 0;
  uint64_t count = 0;
  uint64_t pass;
  uint64_t offset;

  for (pass = 0; pass < 64; ++pass) {
    for (offset = 0; offset < length; offset += UINT64_C(4096)) {
      value += payload[offset] + pass;
      count++;
    }
  }
  *accesses += count;
  return value;
}

static int
task_ocalls(uint64_t mode, uint64_t* count, uint64_t* time_ticks) {
  uint64_t calls = group_pmp_mixed_expected_ocalls(mode);
  uint64_t index;

  for (index = 0; index < calls; ++index) {
    uint64_t ack = 0;
    uint64_t payload = UINT64_C(0x4f43414c4c544153) ^ index;
    uint64_t started_time = group_pmp_rdtime();

    if (ocall(1, &payload, sizeof(payload), &ack, sizeof(ack)) != 0)
      return -1;
    *time_ticks += group_pmp_rdtime() - started_time;
    if (ack != UINT64_C(0x47504d504f43414c))
      return -1;
    (*count)++;
  }
  return 0;
}

static int
slot_command_timed(struct keystone_yxstm_slot_command* command,
                   uint64_t* protocol_cycles,
                   uint64_t* protocol_time_ticks) {
  uint64_t started_time = group_pmp_rdtime();
  uint64_t started = group_pmp_rdcycle();
  int ret = group_pmp_yxstm_slot_command(command);
  *protocol_cycles += group_pmp_rdcycle() - started;
  *protocol_time_ticks += group_pmp_rdtime() - started_time;
  return ret;
}

int
main(void) {
  struct group_pmp_mixed_worker_config config;
  struct group_pmp_mixed_worker_result result;
  struct keystone_yxstm_layout_info layout;
  struct keystone_yxstm_slot_info slot_info;
  volatile uint8_t* payload;
  uint8_t known_ciphertext[16];
  uint8_t warm_block[16];
  uint64_t processed = 0;
  uint64_t digest = UINT64_C(0xcbf29ce484222325);
  void* aes;

  /* Keep a deploy-time marker in the eapp for stale artifact detection. */
  (void)mixed_worker_wait_diag_marker[0];
  if (mixed_lane_dynamic_artifact_marker[0] != 'k')
    return 12;

  memset(&config, 0, sizeof(config));
  memset(&result, 0, sizeof(result));
  memset(&layout, 0, sizeof(layout));
  memset(&slot_info, 0, sizeof(slot_info));
  if (copy_from_shared(&config, GROUP_PMP_MIXED_CONFIG_OFFSET,
                       sizeof(config)) != 0 ||
      config.magic != GROUP_PMP_MIXED_MAGIC ||
      config.version != GROUP_PMP_MIXED_VERSION ||
      config.worker_index >= config.worker_count ||
      config.worker_count > GROUP_PMP_MIXED_MAX_WORKERS ||
      config.lane_id >= GROUP_PMP_MIXED_LANES ||
      config.lane_rank >= config.lane_depth ||
      config.lane_depth > GROUP_PMP_MIXED_MAX_LANE_DEPTH ||
      (config.diagnostic_flags & ~GROUP_PMP_MIXED_DIAG_MEMORY) ||
      !config.data_bytes || (config.data_bytes & UINT64_C(15)) ||
      config.data_bytes >
          config.worker_count * GROUP_PMP_MIXED_WORKER_BYTES)
    return 1;
  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0 ||
      layout.role != GROUP_ROLE_WORKER ||
      layout.worker_slice_id != config.lane_id + 1 ||
      layout.slot_id != config.lane_rank ||
      layout.slot_count != config.lane_depth ||
      layout.worker_lane_size != KEYSTONE_YXSTM_WORKER_LANE_SIZE ||
      layout.slot_payload_size !=
          keystone_yxstm_slot_payload_capacity(layout.slot_count) ||
      !layout.slot_payload_size ||
      group_pmp_yxstm_query_slot_info(
          &slot_info, config.lane_id, config.lane_rank) != 0 ||
      slot_info.state != YXSTM_SLOT_FREE ||
      slot_info.epoch != layout.slot_epoch)
    return 2;

  aes = aes_encrypt_init(kAes128Key, sizeof(kAes128Key));
  if (!aes)
    return 3;
  aes_encrypt(aes, kKnownPlaintext, known_ciphertext);
  result.known_answer_ok =
      memcmp(known_ciphertext, kKnownCiphertext, sizeof(known_ciphertext)) == 0;
  if (!result.known_answer_ok)
    return 4;
  memcpy(warm_block, kKnownPlaintext, sizeof(warm_block));
  for (uint64_t warm = 0; warm < 4096; ++warm)
    aes_encrypt(aes, warm_block, warm_block);
  if (config.diagnostic_flags & GROUP_PMP_MIXED_DIAG_MEMORY) {
    uint64_t started_time = group_pmp_rdtime();
    uint64_t started_cycle = group_pmp_rdcycle();
    uint64_t blocks = GROUP_PMP_AES_BASELINE_BYTES / 16;

    for (uint64_t block = 0; block < blocks; ++block)
      aes_encrypt(aes, warm_block, warm_block);
    result.diagnostic_hot_aes_cycles =
        group_pmp_rdcycle() - started_cycle;
    result.diagnostic_hot_aes_time_ticks =
        group_pmp_rdtime() - started_time;
    result.diagnostic_hot_aes_bytes = GROUP_PMP_AES_BASELINE_BYTES;
    result.diagnostic_read_sink ^= warm_block[0];
  }

  result.magic = GROUP_PMP_MIXED_MAGIC;
  result.version = GROUP_PMP_MIXED_VERSION;
  result.worker_index = config.worker_index;
  result.worker_count = config.worker_count;
  result.lane_id = config.lane_id;
  result.lane_rank = config.lane_rank;
  result.data_bytes = config.data_bytes;
  result.mapping_pte_flags = layout.mapping_pte_flags;
  result.mapping_leaf_count = layout.mapping_leaf_count;
  result.mapping_min_leaf_size = layout.mapping_min_leaf_size;
  result.mapping_max_leaf_size = layout.mapping_max_leaf_size;
  result.mapping_cache_mode = layout.mapping_cache_mode;
  result.mapping_nx = layout.mapping_nx;
  result.mapping_linear = layout.mapping_linear;
  result.mapping_alias_count = layout.mapping_alias_count;
  result.mapping_page_table_pages = layout.mapping_page_table_pages;
  result.mapping_tlb_counter_supported =
      layout.mapping_tlb_counter_supported;
  result.hidden_copy_bytes = layout.mapping_hidden_copy_bytes;
  result.in_place = 1;
  {
    struct keystone_yxstm_slot_command denied;
    memset(&denied, 0, sizeof(denied));
    denied.operation = KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_ACQUIRE;
    denied.lane_id = config.lane_id;
    denied.slot_id = config.lane_depth > 1 ?
        (config.lane_rank + 1) % config.lane_depth : config.lane_depth;
    denied.expected_epoch = slot_info.epoch;
    denied.permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
    result.cross_slot_denied =
        group_pmp_yxstm_slot_command(&denied) != 0;
  }
  if (!result.cross_slot_denied ||
      publish_result(&result, GROUP_PMP_MIXED_STATE_WARMED) != 0)
    return 5;

  payload = group_pmp_mixed_slot_payload(
      &layout, config.lane_id, layout.slot_offset);
  result.observed_payload_va = (uintptr_t)payload;
  result.start_cycle = group_pmp_rdcycle();
  if (publish_result(&result, GROUP_PMP_MIXED_STATE_RUNNING) != 0)
    return 6;

  while (processed < config.data_bytes) {
    struct keystone_yxstm_slot_command command;
    int wait_ret;
    uint64_t aes_started;
    uint64_t aes_started_time;
    uint64_t chunk_digest;

    memset(&command, 0, sizeof(command));
    command.operation = KEYSTONE_YXSTM_SLOT_WORKER_WAIT_ACQUIRE_BEGIN;
    command.lane_id = config.lane_id;
    command.slot_id = config.lane_rank;
    command.permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
    {
      uint64_t wait_started_time = group_pmp_rdtime();
    wait_ret = group_pmp_yxstm_slot_command(&command);
      result.ready_wait_time_ticks +=
          group_pmp_rdtime() - wait_started_time;
    }
    if (wait_ret != 0)
      return wait_ret;
    if (command.result != KEYSTONE_YXSTM_SLOT_RESULT_READY)
      return 71;
    if (command.state != YXSTM_SLOT_COMPUTING)
      return 72;
    if (command.payload_size == 0)
      return 73;
    if (command.payload_size > layout.slot_payload_size)
      return 74;
    /*
     * WAIT_READY returns one SM-validated identity snapshot. Preserve the
     * static offset/size from the initial query and consume the dynamic task
     * fields atomically instead of issuing a second, racy query.
     */
    slot_info.state = command.state;
    slot_info.payload_size = command.payload_size;
    slot_info.batch_id = command.batch_id;
    slot_info.task_id = command.task_id;
    slot_info.sequence = command.sequence;
    slot_info.epoch = command.expected_epoch;
    slot_info.permissions = command.permissions;
    slot_info.digest = command.digest;

    /* Task identity is protected SM metadata; the mapped slot is payload-only. */
    if (slot_info.task_id != config.worker_index + 1 ||
        slot_info.batch_id != result.batch_count + 1 ||
        processed + slot_info.payload_size > config.data_bytes)
      return 9;

    if (config.diagnostic_flags & GROUP_PMP_MIXED_DIAG_MEMORY) {
      uint64_t diagnostic_length =
          GROUP_PMP_AES_BASELINE_BYTES - result.diagnostic_bytes;
      uint64_t started_time;
      uint64_t started_cycle;

      if (diagnostic_length > slot_info.payload_size)
        diagnostic_length = slot_info.payload_size;
      diagnostic_length &= ~UINT64_C(15);
      if (diagnostic_length) {
        __sync_synchronize();
        started_time = group_pmp_rdtime();
        started_cycle = group_pmp_rdcycle();
        result.diagnostic_read_sink ^=
            sequential_read64(payload, diagnostic_length);
        result.yxstm_read_cycles += group_pmp_rdcycle() - started_cycle;
        result.yxstm_read_time_ticks +=
            group_pmp_rdtime() - started_time;

        __sync_synchronize();
        started_time = group_pmp_rdtime();
        started_cycle = group_pmp_rdcycle();
        result.diagnostic_read_sink ^=
            sequential_rewrite64(payload, diagnostic_length);
        result.yxstm_write_cycles += group_pmp_rdcycle() - started_cycle;
        result.yxstm_write_time_ticks +=
            group_pmp_rdtime() - started_time;

        __sync_synchronize();
        started_time = group_pmp_rdtime();
        started_cycle = group_pmp_rdcycle();
        result.diagnostic_stride_sink ^=
            page_stride_read(payload, diagnostic_length,
                             &result.yxstm_page_stride_accesses);
        result.yxstm_page_stride_cycles +=
            group_pmp_rdcycle() - started_cycle;
        result.yxstm_page_stride_time_ticks +=
            group_pmp_rdtime() - started_time;
        result.diagnostic_bytes += diagnostic_length;
      }
    }

    aes_started_time = group_pmp_rdtime();
    aes_started = group_pmp_rdcycle();
    if ((config.diagnostic_flags & GROUP_PMP_MIXED_DIAG_MEMORY) &&
        result.diagnostic_aes_bytes < GROUP_PMP_AES_BASELINE_BYTES) {
      uint64_t diagnostic_length =
          GROUP_PMP_AES_BASELINE_BYTES - result.diagnostic_aes_bytes;
      uint64_t diagnostic_started_time;
      uint64_t diagnostic_started_cycle;

      if (diagnostic_length > slot_info.payload_size)
        diagnostic_length = slot_info.payload_size;
      diagnostic_length &= ~UINT64_C(15);
      diagnostic_started_time = group_pmp_rdtime();
      diagnostic_started_cycle = group_pmp_rdcycle();
      aes_encrypt_blocks(aes, (const uint8_t*)(uintptr_t)payload,
                         (uint8_t*)(uintptr_t)payload,
                         diagnostic_length / 16);
      result.diagnostic_aes_cycles +=
          group_pmp_rdcycle() - diagnostic_started_cycle;
      result.diagnostic_aes_time_ticks +=
          group_pmp_rdtime() - diagnostic_started_time;
      result.diagnostic_aes_bytes += diagnostic_length;
      if (diagnostic_length < slot_info.payload_size)
        aes_encrypt_blocks(
            aes,
            (const uint8_t*)(uintptr_t)(payload + diagnostic_length),
            (uint8_t*)(uintptr_t)(payload + diagnostic_length),
            (slot_info.payload_size - diagnostic_length) / 16);
    } else {
      aes_encrypt_blocks(aes, (const uint8_t*)(uintptr_t)payload,
                         (uint8_t*)(uintptr_t)payload,
                         slot_info.payload_size / 16);
    }
    result.aes_cycles += group_pmp_rdcycle() - aes_started;
    result.aes_time_ticks += group_pmp_rdtime() - aes_started_time;
    command.operation = KEYSTONE_YXSTM_SLOT_WORKER_AES_EXEC_END;
    if (slot_command_timed(&command, &result.protocol_cycles,
                           &result.protocol_time_ticks) != 0 ||
        command.state != YXSTM_SLOT_COMPUTING)
      return 76;
    {
      uint64_t digest_started_time = group_pmp_rdtime();
      uint64_t digest_started_cycle = group_pmp_rdcycle();
      chunk_digest = payload_digest(payload, slot_info.payload_size);
      result.digest_cycles += group_pmp_rdcycle() - digest_started_cycle;
      result.digest_time_ticks +=
          group_pmp_rdtime() - digest_started_time;
      result.digest_bytes += UINT64_C(64);
    }
    digest ^= chunk_digest + UINT64_C(0x9e3779b97f4a7c15) +
              (digest << 6) + (digest >> 2);
    __sync_synchronize();
    command.operation = KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_DONE;
    command.digest = chunk_digest;
    if (slot_command_timed(&command, &result.protocol_cycles,
                           &result.protocol_time_ticks) != 0 ||
        command.state != YXSTM_SLOT_DONE ||
        command.permissions != 0 ||
        command.digest != chunk_digest)
      return 10;
    /*
     * COMPUTE_DONE is the atomic ownership/revocation check. Once it returns,
     * the master may immediately advance DONE to AGGREGATING, FREE, or the
     * next READY batch, so a second state query would be inherently racy.
     */
    result.grant_revoke_ok = 1;
    processed += command.payload_size;
    result.batch_count++;
  }

  if (task_ocalls(config.ocall_mode, &result.ocall_count,
                  &result.ocall_time_ticks) != 0)
    return 11;
  result.end_cycle = group_pmp_rdcycle();
  result.payload_alignment =
      result.observed_payload_va & UINT64_C(4095);
  result.digest = digest;
  aes_encrypt_deinit(aes);
  if (!result.grant_revoke_ok ||
      publish_result(&result, GROUP_PMP_MIXED_STATE_COMPLETED) != 0)
    return 12;
  return 0;
}
