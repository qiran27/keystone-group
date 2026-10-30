#ifndef GROUP_PMP_MIXED_SHARED_H
#define GROUP_PMP_MIXED_SHARED_H

#include <stdint.h>
#include "group-pmp-sqlite-pipeline-timing.h"

#define GROUP_PMP_MIXED_MAGIC UINT64_C(0x47504d504d495845)
#define GROUP_PMP_MIXED_VERSION UINT64_C(23)
#define GROUP_PMP_MIXED_ARTIFACT_MARKER "keystone-mixed-lane-dynamic-v1"
#define GROUP_PMP_MIXED_CONFIG_OFFSET UINT64_C(4096)
#define GROUP_PMP_MIXED_RESULT_OFFSET UINT64_C(8192)
#define GROUP_PMP_MIXED_WORKER_BYTES (UINT64_C(12) * UINT64_C(1000000))
#define GROUP_PMP_MIXED_CHUNK_BYTES GROUP_PMP_MIXED_WORKER_BYTES
#define GROUP_PMP_MIXED_MAX_WORKERS UINT64_C(64)
#define GROUP_PMP_MIXED_LANES UINT64_C(3)
#define GROUP_PMP_MIXED_BANK_COUNT UINT64_C(1)
#define GROUP_PMP_MIXED_OCALL_STRESS_COUNT UINT64_C(8)
#define GROUP_PMP_MIXED_MAX_LANE_DEPTH \
  ((GROUP_PMP_MIXED_MAX_WORKERS + GROUP_PMP_MIXED_LANES - UINT64_C(1)) / \
   GROUP_PMP_MIXED_LANES)
#define GROUP_PMP_MIXED_PROTOCOL_TIMEOUT_TICKS UINT64_C(120000000)

#define GROUP_PMP_MIXED_STATE_EMPTY UINT64_C(0)
#define GROUP_PMP_MIXED_STATE_WARMED UINT64_C(1)
#define GROUP_PMP_MIXED_STATE_RUNNING UINT64_C(2)
#define GROUP_PMP_MIXED_STATE_COMPLETED UINT64_C(3)
#define GROUP_PMP_MIXED_STATE_FAILED UINT64_C(4)

#define GROUP_PMP_MIXED_OCALL_PER_TASK UINT64_C(1)
#define GROUP_PMP_MIXED_OCALL_PER_CHUNK_STRESS UINT64_C(2)
#define GROUP_PMP_MIXED_DIAG_MEMORY UINT64_C(1)

static inline uint64_t
group_pmp_mixed_expected_ocalls(uint64_t mode) {
  return mode == GROUP_PMP_MIXED_OCALL_PER_CHUNK_STRESS ?
      GROUP_PMP_MIXED_OCALL_STRESS_COUNT : UINT64_C(1);
}

struct group_pmp_mixed_worker_config {
  uint64_t magic;
  uint64_t version;
  uint64_t worker_index;
  uint64_t worker_count;
  uint64_t lane_id;
  uint64_t lane_rank;
  uint64_t lane_depth;
  uint64_t max_lane_depth;
  uint64_t data_bytes;
  uint64_t chunk_bytes;
  uint64_t seed;
  uint64_t ocall_mode;
  uint64_t diagnostic_flags;
  uint64_t reserved[3];
};

struct group_pmp_mixed_worker_result {
  uint64_t magic;
  uint64_t version;
  uint64_t status;
  uint64_t worker_index;
  uint64_t worker_count;
  uint64_t lane_id;
  uint64_t lane_rank;
  uint64_t data_bytes;
  uint64_t start_cycle;
  uint64_t end_cycle;
  uint64_t aes_cycles;
  uint64_t aes_time_ticks;
  uint64_t protocol_cycles;
  uint64_t protocol_time_ticks;
  uint64_t ready_wait_time_ticks;
  uint64_t ocall_time_ticks;
  uint64_t ocall_count;
  uint64_t digest;
  uint64_t observed_payload_va;
  uint64_t known_answer_ok;
  uint64_t batch_count;
  uint64_t cross_slot_denied;
  uint64_t grant_revoke_ok;
  uint64_t yxstm_read_cycles;
  uint64_t yxstm_read_time_ticks;
  uint64_t yxstm_write_cycles;
  uint64_t yxstm_write_time_ticks;
  uint64_t yxstm_page_stride_cycles;
  uint64_t yxstm_page_stride_time_ticks;
  uint64_t yxstm_page_stride_accesses;
  uint64_t diagnostic_aes_cycles;
  uint64_t diagnostic_aes_time_ticks;
  uint64_t diagnostic_aes_bytes;
  uint64_t diagnostic_hot_aes_cycles;
  uint64_t diagnostic_hot_aes_time_ticks;
  uint64_t diagnostic_hot_aes_bytes;
  uint64_t digest_cycles;
  uint64_t digest_time_ticks;
  uint64_t digest_bytes;
  uint64_t diagnostic_bytes;
  uint64_t diagnostic_read_sink;
  uint64_t diagnostic_stride_sink;
  uint64_t mapping_pte_flags;
  uint64_t mapping_leaf_count;
  uint64_t mapping_min_leaf_size;
  uint64_t mapping_max_leaf_size;
  uint64_t mapping_cache_mode;
  uint64_t mapping_nx;
  uint64_t mapping_linear;
  uint64_t mapping_alias_count;
  uint64_t mapping_page_table_pages;
  uint64_t mapping_tlb_counter_supported;
  uint64_t payload_alignment;
  uint64_t hidden_copy_bytes;
  uint64_t in_place;
  uint64_t vfs_read_bytes;
  uint64_t vfs_write_bytes;
  uint64_t vfs_encrypt_cycles;
  uint64_t vfs_decrypt_cycles;
  uint64_t vfs_submit_count;
  uint64_t vfs_wait_count;
  uint64_t vfs_yield_count;
  uint64_t vfs_wait_ticks;
  uint64_t vfs_last_error;
  uint64_t vfs_batch_submit_count;
  uint64_t vfs_blocked_completion_count;
  uint64_t vfs_queue_depth_peak;
  uint64_t vfs_ring_doorbell_count;
  uint64_t vfs_ring_request_count;
  uint64_t vfs_completion_batch_count;
  uint64_t vfs_crypto_io_sample_ticks;
  uint64_t vfs_crypto_io_overlap_ticks;
  uint64_t vfs_both_buffers_wait_ticks;
  uint64_t vfs_completion_local_reaps;
  uint64_t vfs_buffer_reuses;
  uint64_t aes_elapsed_time_ticks;
  struct group_pmp_sqlite_pipeline_timing pipeline;
};

#if defined(__cplusplus)
static_assert(sizeof(struct group_pmp_mixed_worker_result) == 888,
              "mixed worker result ABI mismatch");
#else
_Static_assert(sizeof(struct group_pmp_mixed_worker_result) == 888,
               "mixed worker result ABI mismatch");
#endif

struct group_pmp_mixed_master_config {
  uint64_t magic;
  uint64_t version;
  uint64_t worker_count;
  uint64_t active_lanes;
  uint64_t lane_depth[GROUP_PMP_MIXED_LANES];
  uint64_t max_lane_depth;
  uint64_t data_bytes_per_worker;
  uint64_t total_data_bytes;
  uint64_t worker_data_bytes[GROUP_PMP_MIXED_MAX_WORKERS];
  uint64_t chunk_bytes;
  uint64_t ocall_mode;
  uint64_t diagnostic_flags;
  uint64_t reserved[3];
};

struct group_pmp_mixed_master_result {
  uint64_t magic;
  uint64_t version;
  uint64_t status;
  uint64_t worker_count;
  uint64_t active_lanes;
  uint64_t sequence;
  uint64_t dispatch_cycles;
  uint64_t dispatch_time_ticks;
  uint64_t dispatch_bytes;
  uint64_t compute_wall_cycles;
  uint64_t compute_wall_time_ticks;
  uint64_t aggregate_cycles;
  uint64_t aggregate_time_ticks;
  uint64_t aggregate_bytes;
  uint64_t protocol_cycles;
  uint64_t protocol_time_ticks;
  uint64_t task_e2e_cycles;
  uint64_t task_e2e_time_ticks;
  uint64_t aggregate_digest;
  uint64_t validation_ok;
  uint64_t slot_dispatches;
  uint64_t slot_aggregates;
  uint64_t slot_wait_yields;
  uint64_t lane_dispatches[GROUP_PMP_MIXED_LANES];
  uint64_t lane_aggregates[GROUP_PMP_MIXED_LANES];
  uint64_t lane_dispatch_bytes[GROUP_PMP_MIXED_LANES];
};

static inline uint64_t
group_pmp_mixed_slot_size(uint64_t lane_depth) {
  return keystone_yxstm_slot_mapping_size(lane_depth);
}

static inline uint64_t
group_pmp_mixed_stream_chunk_bytes(uint64_t lane_depth) {
  uint64_t slot_size = group_pmp_mixed_slot_size(lane_depth);
  uint64_t capacity = keystone_yxstm_slot_payload_capacity(lane_depth);

  if (!slot_size || !capacity || capacity > slot_size)
    return 0;
  return capacity < GROUP_PMP_MIXED_WORKER_BYTES ?
      capacity : GROUP_PMP_MIXED_WORKER_BYTES;
}

static inline uint64_t
group_pmp_mixed_stream_chunk_count(uint64_t lane_depth) {
  uint64_t chunk = group_pmp_mixed_stream_chunk_bytes(lane_depth);
  return chunk ? (GROUP_PMP_MIXED_WORKER_BYTES + chunk - 1) / chunk : 0;
}

static inline uint8_t
group_pmp_mixed_plain_byte(uint64_t lane_id, uint64_t offset) {
  return (uint8_t)((offset * UINT64_C(131) +
                    lane_id * UINT64_C(29) + UINT64_C(0x5a)) & 0xff);
}

static inline uint8_t
group_pmp_mixed_task_plain_byte(uint64_t worker_index, uint64_t offset) {
  return (uint8_t)((offset * UINT64_C(131) +
                    worker_index * UINT64_C(47) + UINT64_C(0x5a)) & 0xff);
}

static inline uint64_t
group_pmp_mixed_task_plain_word(uint64_t worker_index, uint64_t offset) {
  uint64_t word = 0;

  for (uint64_t byte = 0; byte < sizeof(word); ++byte)
    word |= (uint64_t)group_pmp_mixed_task_plain_byte(
                worker_index, offset + byte) << (byte * 8);
  return word;
}

static inline uint64_t
group_pmp_mixed_task_slot(uint64_t chunk_index, uint64_t lane_rank,
                          uint64_t max_lane_depth) {
  return lane_rank * group_pmp_mixed_stream_chunk_count(max_lane_depth) +
         chunk_index;
}

static inline uint64_t
group_pmp_mixed_task_digest(uint64_t worker_count, uint64_t lane_rank,
                            uint64_t chunk_index, uint64_t sequence) {
  uint64_t digest = UINT64_C(0x4d4958454442414e) ^
      (worker_count << 32) ^ (lane_rank << 16) ^ chunk_index ^ sequence;
  return digest ? digest : UINT64_C(1);
}

#endif
