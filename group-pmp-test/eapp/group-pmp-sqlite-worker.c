#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "group-pmp-common.h"
#include "group-pmp-sqlite-shared.h"
#include "benchmark-cipher.h"
#include "keystone_enclave_store.h"
#include "../motivation/system-trace.h"
#ifdef GROUP_PMP_KV_WORKER
_Static_assert(GROUP_PMP_SQLITE_VFS_RESULT_OFFSET +
    sizeof(struct group_pmp_mixed_worker_result) <= KV_RESULT_OFFSET,
    "KV result overlaps existing worker result");
_Static_assert(KV_RESULT_OFFSET + sizeof(struct kv_bench_stats) <= 4096,
    "KV result must remain in control UTM");
#endif
#include "../security/security-sentinel.h"
#include "shared/sm_err.h"

static const volatile char sqlite_artifact_marker[] __attribute__((used)) =
    GROUP_PMP_SQLITE_ARTIFACT_MARKER;
static const volatile char sqlite_group_abi_marker[] __attribute__((used)) =
    KEYSTONE_GROUP_ABI_MARKER;
static const volatile char sqlite_store_marker[] __attribute__((used)) =
    KEYSTONE_ENCLAVE_STORE_MARKER;
static const volatile char sqlite_host_store_abi_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_ASYNC_VFS_MARKER;
GROUP_PMP_DEFINE_PROTOCOL_MAILBOX(sqlite_exec_clock_page);
static const volatile char cipher_marker[] __attribute__((used)) = BENCHMARK_CIPHER_MARKER;
static const uint8_t sqlite_aes128_key[16] = {
  0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
  0x11, 0x33, 0x55, 0x77, 0x99, 0xbb, 0xdd, 0xff
};

static int publish_result(struct group_pmp_mixed_worker_result* result,
                          uint64_t state) {
  uint64_t published = state;
  result->status = GROUP_PMP_MIXED_STATE_EMPTY;
  if (copy_to_shared_utm(GROUP_PMP_SQLITE_VFS_RESULT_OFFSET,
                         result, sizeof(*result)) != 0)
    return -1;
  __sync_synchronize();
  result->status = state;
  return copy_to_shared_utm(
      GROUP_PMP_SQLITE_VFS_RESULT_OFFSET +
          offsetof(struct group_pmp_mixed_worker_result, status),
      &published, sizeof(published));
}

static uint64_t packet_digest(const volatile uint8_t* packet,
                              uint64_t packet_size) {
  uint64_t digest = UINT64_C(1469598103934665603);
  uint64_t offset;
  for (offset = 0; offset < packet_size; offset += 64) {
    uint64_t sample = 0;
    uint64_t remaining = packet_size - offset;
    uint64_t width = remaining < sizeof(sample) ? remaining : sizeof(sample);
    memcpy(&sample, (const void*)(uintptr_t)(packet + offset), (size_t)width);
    digest ^= sample;
    digest *= UINT64_C(1099511628211);
  }
  return digest ? digest : UINT64_C(1);
}

static void copy_store_stats(struct group_pmp_mixed_worker_result* result) {
  struct group_pmp_sqlite_vfs_stats stats;
  memset(&stats, 0, sizeof(stats));
  keystone_enclave_store_get_stats(&stats);
  result->ocall_count = stats.batch_submit_count;
  result->ocall_time_ticks = stats.ocall_ticks + stats.wait_ticks;
  result->hidden_copy_bytes = stats.read_bytes + stats.write_bytes;
  result->vfs_read_bytes = stats.read_bytes;
  result->vfs_write_bytes = stats.write_bytes;
  result->vfs_encrypt_cycles = stats.encrypt_cycles;
  result->vfs_decrypt_cycles = stats.decrypt_cycles;
  result->vfs_submit_count = stats.submit_count;
  result->vfs_wait_count = stats.wait_count;
  result->vfs_yield_count = stats.yield_count;
  result->vfs_wait_ticks = stats.wait_ticks;
  result->vfs_batch_submit_count = stats.batch_submit_count;
  result->vfs_blocked_completion_count = stats.blocked_completion_count;
  result->vfs_queue_depth_peak = stats.queue_depth_peak;
  result->vfs_ring_doorbell_count = stats.ring_doorbell_count;
  result->vfs_ring_request_count = stats.ring_request_count;
  result->vfs_completion_batch_count = stats.completion_batch_count;
  result->vfs_crypto_io_sample_ticks = stats.crypto_io_sample_ticks;
  result->vfs_crypto_io_overlap_ticks = stats.crypto_io_overlap_ticks;
  result->vfs_both_buffers_wait_ticks = stats.both_buffers_wait_ticks;
  result->vfs_completion_local_reaps = stats.completion_local_reaps;
  result->vfs_buffer_reuses = stats.buffer_reuses;
  result->vfs_last_error = keystone_enclave_store_last_error();
  result->aes_cycles = stats.encrypt_cycles + stats.decrypt_cycles;
  result->aes_time_ticks =
      stats.encrypt_time_ticks + stats.decrypt_time_ticks;
  result->aes_elapsed_time_ticks = stats.crypto_elapsed_ticks;
  result->pipeline = stats.pipeline;
}

int main(void) {
  struct group_pmp_mixed_worker_config config;
  struct group_pmp_mixed_worker_result result;
  struct keystone_yxstm_layout_info layout;
  struct keystone_yxstm_slot_info slot;
  struct group_pmp_sqlite_vfs_config store_config;
  volatile uint8_t* packet;
  uint64_t workload;
  uint64_t processed = 0;
  uint64_t digest = UINT64_C(0x53514c495445);
  uint64_t failure_stage = 1;
  int rc = 1;

  if (cipher_marker[0] != 'k' || sqlite_artifact_marker[0] != 'k' || sqlite_group_abi_marker[0] != 'k' ||
      sqlite_store_marker[0] != 'k' || sqlite_host_store_abi_marker[0] != 'k')
    return 90;
  memset(&config, 0, sizeof(config));
  memset(&result, 0, sizeof(result));
  memset(&layout, 0, sizeof(layout));
  memset(&slot, 0, sizeof(slot));
  memset(&store_config, 0, sizeof(store_config));
  if (copy_from_shared(&config, GROUP_PMP_SQLITE_VFS_CONFIG_OFFSET,
                       sizeof(config)) != 0 ||
      config.magic != GROUP_PMP_MIXED_MAGIC ||
      config.version != GROUP_PMP_MIXED_VERSION ||
      config.worker_index >= config.worker_count ||
      config.lane_id >= GROUP_PMP_MIXED_LANES ||
      config.lane_rank >= config.lane_depth || !config.data_bytes)
    goto out;
  workload = config.reserved[0];
  if (!group_pmp_sqlite_valid_workload(workload) ||
      config.data_bytes % group_pmp_sqlite_value_size(workload) != 0)
    goto out;
#ifdef GROUP_PMP_KV_WORKER
  if (workload != GROUP_PMP_SQLITE_FILLRANDOM &&
      workload != GROUP_PMP_SQLITE_READRANDOM &&
      workload != GROUP_PMP_SQLITE_OVERWRITE) goto out;
#endif

  result.magic = GROUP_PMP_MIXED_MAGIC;
  result.version = GROUP_PMP_MIXED_VERSION;
  result.worker_index = config.worker_index;
  result.worker_count = config.worker_count;
  result.lane_id = config.lane_id;
  result.lane_rank = config.lane_rank;
  result.data_bytes = config.data_bytes;
  failure_stage = 2;
  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0 ||
      layout.role != GROUP_ROLE_WORKER ||
      layout.worker_slice_id != config.lane_id + 1 ||
      layout.slot_id != config.lane_rank ||
      layout.slot_count != config.lane_depth || !layout.slot_payload_size ||
      group_pmp_yxstm_query_slot_info(
          &slot, config.lane_id, config.lane_rank) != 0 ||
      slot.state != YXSTM_SLOT_FREE)
    goto out;

  store_config.run_id = config.seed ^ config.worker_index ^ (workload << 48);
  store_config.worker_index = config.worker_index;
  store_config.worker_count = config.worker_count;
  store_config.workload = workload;
  store_config.logical_base = config.reserved[1];
  store_config.file_base = config.reserved[2];
  store_config.direct_layout =
      (config.diagnostic_flags & GROUP_PMP_SQLITE_DIRECT_LAYOUT) != 0;
  store_config.cipher_algorithm = (config.diagnostic_flags &
      BENCHMARK_CIPHER_FLAG_MASK) >> BENCHMARK_CIPHER_FLAG_SHIFT;
  memcpy(store_config.aes128_key, sqlite_aes128_key,
         sizeof(store_config.aes128_key));

  /* Write plaintext generation and read-database prefill happen before the
   * WARMED barrier, outside the measured full-flow interval. */
  failure_stage = UINT64_C(300001);
  if (group_pmp_register_protocol_mailbox(
          sqlite_exec_clock_page, KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK |
              KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK_ONLY) != 0 ||
      keystone_enclave_store_set_exec_clock(
          (const volatile struct keystone_member_exec_clock*)(uintptr_t)
              (sqlite_exec_clock_page + KEYSTONE_EXEC_CLOCK_OFFSET)) != 0 ||
      keystone_enclave_store_configure(&store_config,
                                       config.data_bytes) != 0 ||
      ((config.diagnostic_flags & GROUP_PMP_SECURITY_SENTINEL_FLAG) &&
       keystone_enclave_store_set_security_sentinel(config.seed) != 0) ||
       keystone_enclave_store_set_paired_reads(
           (config.diagnostic_flags & GROUP_PMP_SQLITE_PAIRED_READS) != 0) != 0 ||
      keystone_enclave_store_set_intent_lookahead(
          (config.diagnostic_flags & GROUP_PMP_SQLITE_INTENT_LOOKAHEAD) != 0) != 0 ||
      keystone_enclave_store_prepare() != 0 ||
      keystone_enclave_store_begin_measurement() != 0)
    goto out;
  if (keystone_enclave_store_set_system_trace(
          (config.diagnostic_flags & MOT_SYSTEM_TRACE_FLAG) != 0) != 0) goto out;

  result.known_answer_ok = 1;
  result.in_place = 0;
  result.mapping_pte_flags = layout.mapping_pte_flags;
  result.mapping_leaf_count = layout.mapping_leaf_count;
  result.mapping_min_leaf_size = layout.mapping_min_leaf_size;
  result.mapping_max_leaf_size = layout.mapping_max_leaf_size;
  result.mapping_cache_mode = layout.mapping_cache_mode;
  result.mapping_nx = layout.mapping_nx;
  result.mapping_linear = layout.mapping_linear;
  result.mapping_alias_count = layout.mapping_alias_count;
  result.mapping_page_table_pages = layout.mapping_page_table_pages;
  result.mapping_tlb_counter_supported = layout.mapping_tlb_counter_supported;
  {
    struct keystone_yxstm_slot_command denied;
    memset(&denied, 0, sizeof(denied));
    denied.operation = KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_ACQUIRE;
    denied.lane_id = config.lane_id;
    denied.slot_id = config.lane_depth > 1 ?
        (config.lane_rank + 1) % config.lane_depth : config.lane_depth;
    denied.expected_epoch = slot.epoch;
    denied.permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
    result.cross_slot_denied = group_pmp_yxstm_slot_command(&denied) != 0;
  }
  if (!result.cross_slot_denied) goto out;

  /* Unlike the warm FREE-slot acquire probe, this query has no task epoch
   * or READY-state precondition: denial isolates the ownership boundary. */
  if ((config.diagnostic_flags & GROUP_PMP_SECURITY_SENTINEL_FLAG) &&
      config.lane_depth > 1) {
    struct keystone_yxstm_slot_info foreign;
    int denied = group_pmp_yxstm_query_slot_info(&foreign, config.lane_id,
        (config.lane_rank + 1) % config.lane_depth);
    printf("[security-worker] worker=%lu foreign_slot_metadata_rc=%d expected_rc=%d\n",
           config.worker_index, denied, SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE);
    if (denied != SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE) goto out;
  }

  if (config.diagnostic_flags & GROUP_PMP_SECURITY_SENTINEL_FLAG)
    printf("[security-worker] worker=%lu lane=%lu slot=%lu cross_task_acquire=denied foreign_slot_exists=%lu sentinel=installed-in-EPM\n",
           config.worker_index, config.lane_id, config.lane_rank,
           (uint64_t)(config.lane_depth > 1));
  /* Redirected stdout can buffer these lines until enclave exit. Flush while
   * Host still drains warmup OCALLs, not after its VFS accounting reset. */
  if ((config.diagnostic_flags & GROUP_PMP_SECURITY_SENTINEL_FLAG) &&
      fflush(stdout) != 0) goto out;
  if (publish_result(&result, GROUP_PMP_MIXED_STATE_WARMED) != 0) goto out;
  packet = group_pmp_mixed_slot_payload(
      &layout, config.lane_id, layout.slot_offset);
  result.observed_payload_va = (uintptr_t)packet;
  result.start_cycle = group_pmp_rdcycle();
  if (publish_result(&result, GROUP_PMP_MIXED_STATE_RUNNING) != 0)
    goto out;

  while (processed < config.data_bytes) {
    struct keystone_yxstm_slot_command command;
    struct group_pmp_sqlite_packet_header header;
    uint64_t wait_started = group_pmp_rdtime();
    uint64_t operation_started;
    uint64_t operation_time_started;
    uint64_t batch_digest = UINT64_C(1469598103934665603);

    failure_stage = 5;
    memset(&command, 0, sizeof(command));
    command.operation = KEYSTONE_YXSTM_SLOT_WORKER_WAIT_ACQUIRE_BEGIN;
    command.lane_id = config.lane_id;
    command.slot_id = config.lane_rank;
    command.permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
    if (group_pmp_yxstm_slot_command(&command) != 0 ||
        command.result != KEYSTONE_YXSTM_SLOT_RESULT_READY ||
        command.state != YXSTM_SLOT_COMPUTING ||
        command.payload_size != sizeof(header))
      goto out;
    result.ready_wait_time_ticks += group_pmp_rdtime() - wait_started;
    memcpy(&header, (const void*)(uintptr_t)packet, sizeof(header));
    if (header.magic != GROUP_PMP_SQLITE_PACKET_MAGIC ||
        header.version != GROUP_PMP_SQLITE_PACKET_VERSION ||
        header.workload != workload ||
        header.worker_index != config.worker_index ||
        header.batch_id != result.batch_count + 1 ||
        header.value_size != group_pmp_sqlite_value_size(workload) ||
        !header.record_count ||
        header.logical_bytes != header.record_count * header.value_size ||
        header.reserved[0] != store_config.logical_base + processed ||
        processed + header.logical_bytes > config.data_bytes)
      goto out;

    failure_stage = 7;
    if (keystone_enclave_store_execute(&header, &batch_digest) != 0)
      goto out;
    header.payload_digest = batch_digest ? batch_digest : UINT64_C(1);
    memcpy((void*)(uintptr_t)packet, &header, sizeof(header));
    __sync_synchronize();

    command.operation = KEYSTONE_YXSTM_SLOT_WORKER_AES_EXEC_END;
    if (group_pmp_yxstm_slot_command(&command) != 0 ||
        command.state != YXSTM_SLOT_COMPUTING)
      goto out;
    command.operation = KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_DONE;
    command.digest = packet_digest(packet, sizeof(header));
    operation_started = group_pmp_rdcycle();
    operation_time_started = group_pmp_rdtime();
    if (group_pmp_yxstm_slot_command(&command) != 0 ||
        command.state != YXSTM_SLOT_DONE || command.permissions != 0)
      goto out;
    result.protocol_cycles += group_pmp_rdcycle() - operation_started;
    result.protocol_time_ticks += group_pmp_rdtime() - operation_time_started;
    result.grant_revoke_ok = 1;
    processed += header.logical_bytes;
    result.batch_count++;
    digest ^= header.payload_digest + UINT64_C(0x9e3779b97f4a7c15) +
              (digest << 6) + (digest >> 2);
  }

  failure_stage = 10;
  if (keystone_enclave_store_sync() != 0)
    goto out;
  copy_store_stats(&result);
  if (keystone_enclave_store_publish_system_trace() != 0) goto out;
  if (!result.ocall_count || !result.ocall_time_ticks)
    goto out;
  result.end_cycle = group_pmp_rdcycle();
  result.payload_alignment = result.observed_payload_va & UINT64_C(4095);
  result.digest = digest ? digest : UINT64_C(1);
#ifdef GROUP_PMP_KV_WORKER
  {
    struct kv_bench_stats kv;
    keystone_enclave_store_get_kv_stats(&kv);
    if (kv.bytes != config.data_bytes ||
        kv.puts + kv.gets != result.vfs_ring_request_count ||
        kv.gets != kv.validated_gets ||
        copy_to_shared_utm(KV_RESULT_OFFSET, &kv, sizeof(kv))) goto out;
  }
#endif
  if (!result.grant_revoke_ok ||
      publish_result(&result, GROUP_PMP_MIXED_STATE_COMPLETED) != 0)
    goto out;
  rc = 0;

out:
  if (rc != 0 && result.magic == GROUP_PMP_MIXED_MAGIC) {
    copy_store_stats(&result);
    result.end_cycle = group_pmp_rdcycle();
    result.digest = failure_stage;
    (void)publish_result(&result, GROUP_PMP_MIXED_STATE_FAILED);
  }
  keystone_enclave_store_destroy();
  return rc;
}
