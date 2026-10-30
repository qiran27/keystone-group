#ifndef GROUP_PMP_SQLITE_VFS_SHARED_H
#define GROUP_PMP_SQLITE_VFS_SHARED_H

#include <stdint.h>
#include "group-pmp-sqlite-shared.h"
#include "group-pmp-sqlite-pipeline-timing.h"

#ifndef GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT
#define GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT 256
#endif
#if GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT != 256 && GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT != 488
#error "SQLite descriptor limit must be 256 or 488"
#endif

#define GROUP_PMP_SQLITE_ASYNC_VFS_MARKER \
  "keystone-sqlite-host-extent-store-v3"
#define GROUP_PMP_SQLITE_CENTRAL_IO_MARKER \
  "keystone-sqlite-central-io-uring-v9"
#define GROUP_PMP_SQLITE_VFS_ABI_MARKER \
  "keystone-sqlite-vfs-abi-v17"
#define GROUP_PMP_SQLITE_BLOCKING_PIPELINE_MARKER \
  "keystone-sqlite-blocking-pipeline-v2"
#define GROUP_PMP_SQLITE_BATCH_OCALL_MARKER \
  "keystone-sqlite-batch-ocall-v1"
#define GROUP_PMP_SQLITE_CONTROL_ABI_MARKER \
  "keystone-sqlite-zero-length-control-v1"
#define GROUP_PMP_SQLITE_INDEPENDENT_SYNC_MARKER \
  "keystone-sqlite-independent-sync-v1"
#define GROUP_PMP_SQLITE_LANE_POOL_MARKER \
  "keystone-sqlite-lane-pool-v1"
#define GROUP_PMP_SQLITE_IMMEDIATE_OCALL_MARKER \
  "keystone-sqlite-immediate-ocall-v1"
#define GROUP_PMP_SQLITE_BATCHED_RANDOM_READ_MARKER \
  "keystone-sqlite-batched-random-read-v5"
#define GROUP_PMP_SQLITE_EXACT_IO_GRANULARITY_MARKER \
  "keystone-sqlite-exact-io-granularity-v1"
#define GROUP_PMP_SQLITE_DESCRIPTOR_BATCH_MARKER \
  "keystone-sqlite-request-completion-ring-v5"
#define GROUP_PMP_SQLITE_EFFECTIVE_BATCH_MARKER \
  "keystone-sqlite-effective-request-batching-v8"
#define GROUP_PMP_SQLITE_UTM_BUDDY_LAYOUT_MARKER \
  "keystone-sqlite-configurable-ring-v2"
#define GROUP_PMP_SQLITE_STATUS_COMMIT_MARKER \
  "keystone-sqlite-status-release-commit-v1"
#define GROUP_PMP_SQLITE_CRYPTO_TIMING_MARKER \
  "keystone-sqlite-crypto-oncpu-timing-v2"
#define GROUP_PMP_SQLITE_DOUBLE_BUFFER_MARKER \
  "keystone-sqlite-double-buffer-outstanding-v5"
#define GROUP_PMP_SQLITE_COMPLETION_FASTPATH_MARKER \
  "keystone-sqlite-completion-fastpath-v1"
#define GROUP_PMP_SQLITE_ROLLING_COLLECT_MARKER \
  "keystone-sqlite-rolling-collect-v1"
#define GROUP_PMP_SQLITE_COST_CLUSTER_MARKER \
  "keystone-sqlite-cost-aware-cluster-v3"
#define GROUP_PMP_SQLITE_CIPHER_CACHE_MARKER \
  "keystone-sqlite-utm-cipher-cache-v2"
#define GROUP_PMP_SQLITE_VFS_MAGIC UINT64_C(0x4b535153544f5231)
#define GROUP_PMP_SQLITE_VFS_VERSION (UINT64_C(17000) + GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT)
#define GROUP_PMP_SQLITE_FILE_LAYOUT_VERSION UINT64_C(3)
#define GROUP_PMP_SQLITE_INTENT_MAGIC UINT64_C(0x4b5351494e544e31)
#define GROUP_PMP_SQLITE_INTENT_VERSION UINT64_C(1)
#define GROUP_PMP_SQLITE_INTENT_MAX UINT64_C(8192)
#define GROUP_PMP_SQLITE_INTENT_WINDOW_BYTES UINT64_C(32000000)
#define GROUP_PMP_SQLITE_VFS_OCALL_ID UINT64_C(2)
#define GROUP_PMP_SQLITE_VFS_RING_MAGIC UINT64_C(0x4b535152494e4731)

#define GROUP_PMP_SQLITE_VFS_CONTROL_BYTES UINT64_C(4096)
#define GROUP_PMP_SQLITE_VFS_CONFIG_OFFSET UINT64_C(512)
#define GROUP_PMP_SQLITE_VFS_RESULT_OFFSET UINT64_C(1024)
#define GROUP_PMP_SQLITE_VFS_STATUS_OFFSET UINT64_C(2800)
#define GROUP_PMP_SQLITE_VFS_BUFFER_BYTES UINT64_C(2000000)
#define GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES UINT64_C(4096)
#define GROUP_PMP_SQLITE_VFS_BUFFER_SPAN \
  ((GROUP_PMP_SQLITE_VFS_BUFFER_BYTES + UINT64_C(4095)) & ~UINT64_C(4095))
#define GROUP_PMP_SQLITE_VFS_BUFFER_COUNT UINT64_C(2)
#define GROUP_PMP_SQLITE_VFS_INLINE_BATCH_MAX UINT64_C(2)
#define GROUP_PMP_SQLITE_VFS_LEGACY_BATCH_MAX UINT64_C(128)
#define GROUP_PMP_SQLITE_VFS_LEGACY_STATUS_COUNT UINT64_C(16)
/* Each of the two buffer-owned rings carries 256 descriptors. Together they
 * retain 512 outstanding requests without pushing the worker UTM above the
 * driver's 4 MiB buddy-allocation threshold. */
#define GROUP_PMP_SQLITE_VFS_BATCH_MAX ((uint64_t)GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT)
#define GROUP_PMP_SQLITE_VFS_HOST_BATCH_EXTENTS UINT64_C(1024)
/* Namespace bound only, not a file allocation unit. Buffered worker regions
 * are packed to their exact AES-aligned payload size; direct regions retain
 * page-aligned boundaries independently of UTM buffer capacity. */
#define GROUP_PMP_SQLITE_VFS_WORKER_FILE_STRIDE (UINT64_C(1) << 40)
#define GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET GROUP_PMP_SQLITE_VFS_CONTROL_BYTES
#define GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET \
  (GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + GROUP_PMP_SQLITE_VFS_BUFFER_SPAN)
#define GROUP_PMP_SQLITE_VFS_RING_BYTES \
  (GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT == 256 ? UINT64_C(131072) : UINT64_C(262144))
#define GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT \
  GROUP_PMP_SQLITE_VFS_BUFFER_COUNT
#define GROUP_PMP_SQLITE_VFS_RING_SLOT_BYTES \
  (GROUP_PMP_SQLITE_VFS_RING_BYTES / GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT)
#define GROUP_PMP_SQLITE_VFS_RING_OFFSET \
  (GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET + GROUP_PMP_SQLITE_VFS_BUFFER_SPAN)
#define GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot) \
  (GROUP_PMP_SQLITE_VFS_RING_OFFSET + \
   (uint64_t)(slot) * GROUP_PMP_SQLITE_VFS_RING_SLOT_BYTES)
#define GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET_FOR_SLOT(slot) \
  (GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot) + UINT64_C(128))
#define GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET \
  GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET_FOR_SLOT(0)
#define GROUP_PMP_SQLITE_VFS_DESCRIPTOR_BYTES \
  (GROUP_PMP_SQLITE_VFS_BATCH_MAX * \
   sizeof(struct group_pmp_sqlite_vfs_request))
#define GROUP_PMP_SQLITE_VFS_DESCRIPTOR_OFFSET \
  GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET
#define GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET_FOR_SLOT(slot) \
  (GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET_FOR_SLOT(slot) + \
   GROUP_PMP_SQLITE_VFS_DESCRIPTOR_BYTES)
#define GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET \
  GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET_FOR_SLOT(0)
#define GROUP_PMP_SQLITE_VFS_UTM_BYTES \
  (GROUP_PMP_SQLITE_VFS_RING_OFFSET + GROUP_PMP_SQLITE_VFS_RING_BYTES)
#define GROUP_PMP_SQLITE_VFS_BUDDY_LIMIT_BYTES UINT64_C(4194304)

enum group_pmp_sqlite_vfs_operation {
  GROUP_PMP_SQLITE_VFS_OP_INVALID = 0,
  GROUP_PMP_SQLITE_VFS_OP_RESET = 1,
  GROUP_PMP_SQLITE_VFS_OP_READ = 2,
  GROUP_PMP_SQLITE_VFS_OP_WRITE = 3,
  GROUP_PMP_SQLITE_VFS_OP_TRUNCATE = 4,
  GROUP_PMP_SQLITE_VFS_OP_DELETE = 5,
  GROUP_PMP_SQLITE_VFS_OP_SYNC = 6
};

enum group_pmp_sqlite_store_flags {
  GROUP_PMP_SQLITE_STORE_PREFILL = UINT64_C(1) << 0,
  GROUP_PMP_SQLITE_STORE_MEASURED = UINT64_C(1) << 1,
  GROUP_PMP_SQLITE_STORE_TXN_BEGIN = UINT64_C(1) << 2,
  GROUP_PMP_SQLITE_STORE_TXN_END = UINT64_C(1) << 3,
  /* Keep the enclave BLOCKED until this request completes. */
  GROUP_PMP_SQLITE_STORE_BLOCK_ON_COMPLETE = UINT64_C(1) << 4,
  /* Return after Host accepts the request. A later wait request binds the
   * storage completion to an SM BLOCKED/event wakeup transaction. */
  GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY = UINT64_C(1) << 5,
  /* Descriptor and completion are carried by the persistent UTM ring. */
  GROUP_PMP_SQLITE_STORE_RING = UINT64_C(1) << 6,
  /* Diagnostic snapshots only: they never grant permission or gate I/O. */
  GROUP_PMP_SQLITE_READSEQ_INITIAL = UINT64_C(1) << 7,
  GROUP_PMP_SQLITE_READSEQ_PEER_IO = UINT64_C(1) << 8,
  GROUP_PMP_SQLITE_READSEQ_PEER_READY = UINT64_C(1) << 9,
  GROUP_PMP_SQLITE_READSEQ_PEER_IDLE = UINT64_C(1) << 10
};

#define GROUP_PMP_SQLITE_READSEQ_DIAGNOSTICS \
  (GROUP_PMP_SQLITE_READSEQ_INITIAL | GROUP_PMP_SQLITE_READSEQ_PEER_IO | \
   GROUP_PMP_SQLITE_READSEQ_PEER_READY | GROUP_PMP_SQLITE_READSEQ_PEER_IDLE)

enum group_pmp_sqlite_vfs_state {
  GROUP_PMP_SQLITE_VFS_STATE_IDLE = 0,
  GROUP_PMP_SQLITE_VFS_STATE_PENDING = 1,
  GROUP_PMP_SQLITE_VFS_STATE_DONE = 2,
  GROUP_PMP_SQLITE_VFS_STATE_ERROR = 3
};

struct group_pmp_sqlite_vfs_request {
  uint64_t magic;
  uint64_t version;
  uint64_t operation;
  uint64_t request_id;
  uint64_t run_id;
  uint64_t worker_index;
  uint64_t worker_count;
  uint64_t workload;
  uint64_t file_id;
  uint64_t buffer_id;
  uint64_t buffer_offset;
  uint64_t length;
  uint64_t file_offset;
  uint64_t logical_size;
  uint64_t sequence;
  uint64_t task_id;
  uint8_t tag[16];
  uint64_t reserved[2];
  /* buffer_id names the physical 2 MB UTM payload buffer. descriptor_id is
   * the completion slot inside ring_slot. Keeping these identities separate
   * permits one ring doorbell to describe vectors spanning both buffers. */
  uint64_t descriptor_id;
  uint64_t ring_slot;
};

struct group_pmp_sqlite_vfs_ack {
  uint64_t magic;
  uint64_t version;
  uint64_t request_id;
  int64_t status;
};

/* Metadata only. No I/O or durability acknowledgement is implied by a plan.
 * The worker lends one FREE data buffer until this synchronous ACK returns.
 * Host replaces the intent array there with a uint32_t permutation. */
struct group_pmp_sqlite_io_intent {
  uint64_t file_offset;
  uint64_t length;
};

struct group_pmp_sqlite_intent_plan {
  uint64_t magic, version, request_id, run_id;
  uint64_t worker_index, worker_count, workload, operation;
  uint64_t buffer_id, buffer_offset, count, flags;
  uint64_t file_base, file_span;
};

struct group_pmp_sqlite_intent_ack {
  uint64_t magic, version, request_id, count;
  int64_t status;
};

struct group_pmp_sqlite_vfs_wait {
  uint64_t magic;
  uint64_t version;
  uint64_t run_id;
  uint64_t worker_index;
  uint64_t request_id;
  uint64_t buffer_id;
  uint64_t flags;
};

/* Additive packet: wait for either independently owned ring, not both. */
struct group_pmp_sqlite_vfs_wait_any {
  struct group_pmp_sqlite_vfs_wait buffers[2];
};

/* Legacy inline/indirect batches remain ABI-compatible. The production path
 * uses the persistent request/completion ring after both 2 MB payload buffers;
 * ring metadata never consumes payload capacity. */
struct group_pmp_sqlite_vfs_batch {
  uint64_t magic;
  uint64_t version;
  uint64_t count;
  uint64_t flags;
  struct group_pmp_sqlite_vfs_request
      requests[GROUP_PMP_SQLITE_VFS_INLINE_BATCH_MAX];
};

struct group_pmp_sqlite_vfs_indirect_batch {
  uint64_t magic;
  uint64_t version;
  uint64_t count;
  uint64_t flags;
  uint64_t descriptor_offset;
  uint64_t descriptor_bytes;
};

/* The enclave is the only producer and Host is the only consumer. A batch is
 * immutable after producer is release-published. Host release-publishes each
 * completion before advancing completion_count. */
struct group_pmp_sqlite_vfs_ring_header {
  uint64_t magic;
  uint64_t version;
  uint64_t generation;
  uint64_t producer;
  uint64_t consumer;
  uint64_t completion_count;
  uint64_t flags;
  /* Host rdtime at completion publication, written before completion_count.
   * Diagnostic only: never used to authorize buffer or task reuse. */
  uint64_t completed_time_ticks;
  /* Host-owned diagnostic stamps, sampled once after the validated ACK.
   * Written before resume, never after the worker can reuse the ring. */
  uint64_t host_received_ticks;
  uint64_t host_ack_ticks;
  uint64_t host_resume_request_ticks;
  uint64_t wait_host_received_ticks;
  uint64_t wait_host_ack_ticks;
  uint64_t wait_host_resume_request_ticks;
  uint64_t reserved[2];
};

struct group_pmp_sqlite_vfs_ring_doorbell {
  uint64_t magic;
  uint64_t version;
  uint64_t generation;
  uint64_t producer;
  uint64_t count;
  uint64_t flags;
  uint64_t ring_slot;
  uint64_t batch_request_id;
};

struct group_pmp_sqlite_vfs_ring_ack {
  uint64_t magic;
  uint64_t version;
  uint64_t generation;
  uint64_t accepted;
  int64_t status;
  uint64_t consumer;
  uint64_t ring_slot;
  uint64_t batch_request_id;
};

/* One OCALL publishes two independently owned request/completion rings. */
struct group_pmp_sqlite_vfs_ring_pair_doorbell {
  struct group_pmp_sqlite_vfs_ring_doorbell rings[2];
};

struct group_pmp_sqlite_vfs_ring_pair_ack {
  struct group_pmp_sqlite_vfs_ring_ack rings[2];
};

struct group_pmp_sqlite_vfs_batch_ack {
  uint64_t magic;
  uint64_t version;
  uint64_t count;
  int64_t status;
  uint64_t request_id[GROUP_PMP_SQLITE_VFS_LEGACY_BATCH_MAX];
};

struct group_pmp_sqlite_vfs_status {
  uint64_t magic;
  uint64_t version;
  uint64_t request_id;
  uint64_t state;
  int64_t result;
  uint64_t length;
  uint64_t sequence;
  uint8_t tag[16];
};

struct group_pmp_sqlite_vfs_config {
  uint64_t run_id;
  uint64_t worker_index;
  uint64_t worker_count;
  uint64_t workload;
  uint64_t logical_base;
  uint64_t file_base;
  uint64_t direct_layout;
  uint8_t aes128_key[16];
  uint64_t cipher_algorithm;
};

static inline uint64_t group_pmp_sqlite_io_chunk(uint64_t workload,
                                               uint64_t direct_layout) {
  if (workload == GROUP_PMP_SQLITE_READRAND100K)
    return GROUP_PMP_SQLITE_LARGE_VALUE_BYTES;
  if (group_pmp_sqlite_is_random(workload))
    return GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES;
  return direct_layout ?
      (GROUP_PMP_SQLITE_VFS_BUFFER_BYTES & ~UINT64_C(4095)) :
      GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
}

static inline int group_pmp_sqlite_page_random(uint64_t workload) {
  return group_pmp_sqlite_is_random(workload) &&
      workload != GROUP_PMP_SQLITE_READRAND100K;
}

/* Random 4 KB payloads retain page-aligned slots with one short tail at the
 * end. UTM capacity does not determine file padding in any mode. */
static inline uint64_t group_pmp_sqlite_file_span(uint64_t workload,
    uint64_t task_bytes, uint64_t direct_layout) {
  uint64_t span = task_bytes;
  if (!group_pmp_sqlite_valid_workload(workload) || !task_bytes ||
      (task_bytes & UINT64_C(15)) || direct_layout > 1) return 0;
  if (!direct_layout && !group_pmp_sqlite_page_random(workload)) return span;
  if (direct_layout && group_pmp_sqlite_is_random(workload)) {
    const uint64_t chunk = group_pmp_sqlite_io_chunk(workload, direct_layout);
    if (span > UINT64_MAX - (chunk - 1)) return 0;
    span = ((span + chunk - 1) / chunk) * chunk;
  }
  if (span > UINT64_MAX - UINT64_C(4095)) return 0;
  return (span + UINT64_C(4095)) & ~UINT64_C(4095);
}

struct group_pmp_sqlite_vfs_stats {
  uint64_t submit_count;
  uint64_t wait_count;
  uint64_t yield_count;
  uint64_t read_bytes;
  uint64_t write_bytes;
  uint64_t encrypt_cycles;
  uint64_t decrypt_cycles;
  uint64_t encrypt_time_ticks;
  uint64_t decrypt_time_ticks;
  uint64_t ocall_ticks;
  uint64_t wait_ticks;
  uint64_t batch_submit_count;
  uint64_t blocked_completion_count;
  uint64_t queue_depth_peak;
  uint64_t ring_doorbell_count;
  uint64_t ring_request_count;
  uint64_t completion_batch_count;
  uint64_t crypto_io_sample_ticks;
  uint64_t crypto_io_overlap_ticks;
  uint64_t both_buffers_wait_ticks;
  uint64_t completion_local_reaps;
  uint64_t buffer_reuses;
  uint64_t crypto_elapsed_ticks;
  struct group_pmp_sqlite_pipeline_timing pipeline;
};

#if defined(__cplusplus)
static_assert(sizeof(struct group_pmp_sqlite_io_intent) == 16 &&
                  sizeof(struct group_pmp_sqlite_intent_plan) == 112 &&
                  sizeof(struct group_pmp_sqlite_intent_ack) == 40 &&
                  GROUP_PMP_SQLITE_INTENT_MAX * 16 <= GROUP_PMP_SQLITE_VFS_BUFFER_BYTES,
              "SQLite intent control ABI or scratch bound mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_request) == 176,
              "SQLite async VFS request ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_ack) == 32,
              "SQLite async VFS ack ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_wait) == 56,
              "SQLite async VFS wait ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_wait_any) == 112,
              "SQLite async VFS wait-any ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_batch) == 384,
               "SQLite async VFS batch ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_indirect_batch) == 48,
              "SQLite indirect VFS batch ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_ring_header) == 128,
              "SQLite ring header ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_ring_doorbell) == 64,
              "SQLite ring doorbell ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_ring_ack) == 64,
              "SQLite ring ack ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_ring_pair_doorbell) == 128,
              "SQLite ring pair doorbell ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_ring_pair_ack) == 128,
              "SQLite ring pair ack ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_batch_ack) == 1056,
              "SQLite async VFS batch ack ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_status) == 72,
              "SQLite async VFS status ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_config) == 80,
              "SQLite async VFS config ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_vfs_stats) == 464,
              "SQLite async VFS stats ABI mismatch");
static_assert((GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET & UINT64_C(63)) == 0 &&
                  (GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET & UINT64_C(63)) == 0 &&
                  (GROUP_PMP_SQLITE_VFS_RING_OFFSET & UINT64_C(63)) == 0,
              "SQLite direct UTM regions must remain cache-line aligned");
static_assert((GROUP_PMP_SQLITE_VFS_UTM_BYTES & UINT64_C(4095)) == 0,
              "SQLite direct UTM allocation must remain page aligned");
static_assert(GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT == 488 || GROUP_PMP_SQLITE_VFS_UTM_BYTES <=
                  GROUP_PMP_SQLITE_VFS_BUDDY_LIMIT_BYTES,
              "SQLite worker UTM must fit in the 4 MiB buddy allocation");
static_assert(GROUP_PMP_SQLITE_VFS_STATUS_OFFSET +
                      GROUP_PMP_SQLITE_VFS_LEGACY_STATUS_COUNT *
                          sizeof(struct group_pmp_sqlite_vfs_status) <=
                  GROUP_PMP_SQLITE_VFS_CONTROL_BYTES,
              "SQLite batch completion table must fit in control page");
static_assert(GROUP_PMP_SQLITE_VFS_DESCRIPTOR_BYTES ==
                  GROUP_PMP_SQLITE_VFS_BATCH_MAX *
                      sizeof(struct group_pmp_sqlite_vfs_request),
              "SQLite descriptor table size mismatch");
static_assert(GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET_FOR_SLOT(0) +
                      GROUP_PMP_SQLITE_VFS_BATCH_MAX *
                          sizeof(struct group_pmp_sqlite_vfs_status) <=
                  GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(0) +
                      GROUP_PMP_SQLITE_VFS_RING_SLOT_BYTES &&
                  GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET_FOR_SLOT(1) +
                      GROUP_PMP_SQLITE_VFS_BATCH_MAX *
                          sizeof(struct group_pmp_sqlite_vfs_status) <=
                  GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(1) +
                      GROUP_PMP_SQLITE_VFS_RING_SLOT_BYTES,
              "SQLite request/completion rings must fit in UTM metadata");
#else
_Static_assert(sizeof(struct group_pmp_sqlite_io_intent) == 16 &&
                   sizeof(struct group_pmp_sqlite_intent_plan) == 112 &&
                   sizeof(struct group_pmp_sqlite_intent_ack) == 40 &&
                   GROUP_PMP_SQLITE_INTENT_MAX * 16 <= GROUP_PMP_SQLITE_VFS_BUFFER_BYTES,
               "SQLite intent control ABI or scratch bound mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_request) == 176,
               "SQLite async VFS request ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_ack) == 32,
               "SQLite async VFS ack ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_wait) == 56,
               "SQLite async VFS wait ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_wait_any) == 112,
               "SQLite async VFS wait-any ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_batch) == 384,
               "SQLite async VFS batch ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_indirect_batch) == 48,
               "SQLite indirect VFS batch ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_ring_header) == 128,
               "SQLite ring header ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_ring_doorbell) == 64,
               "SQLite ring doorbell ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_ring_ack) == 64,
               "SQLite ring ack ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_ring_pair_doorbell) == 128,
               "SQLite ring pair doorbell ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_ring_pair_ack) == 128,
               "SQLite ring pair ack ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_batch_ack) == 1056,
               "SQLite async VFS batch ack ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_status) == 72,
               "SQLite async VFS status ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_config) == 80,
               "SQLite async VFS config ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_vfs_stats) == 464,
               "SQLite async VFS stats ABI mismatch");
_Static_assert((GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET & UINT64_C(63)) == 0 &&
                   (GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET & UINT64_C(63)) == 0 &&
                   (GROUP_PMP_SQLITE_VFS_RING_OFFSET & UINT64_C(63)) == 0,
               "SQLite direct UTM regions must remain cache-line aligned");
_Static_assert((GROUP_PMP_SQLITE_VFS_UTM_BYTES & UINT64_C(4095)) == 0,
               "SQLite direct UTM allocation must remain page aligned");
_Static_assert(GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT == 488 || GROUP_PMP_SQLITE_VFS_UTM_BYTES <=
                   GROUP_PMP_SQLITE_VFS_BUDDY_LIMIT_BYTES,
               "SQLite worker UTM must fit in the 4 MiB buddy allocation");
_Static_assert(GROUP_PMP_SQLITE_VFS_STATUS_OFFSET +
                       GROUP_PMP_SQLITE_VFS_LEGACY_STATUS_COUNT *
                           sizeof(struct group_pmp_sqlite_vfs_status) <=
                   GROUP_PMP_SQLITE_VFS_CONTROL_BYTES,
               "SQLite batch completion table must fit in control page");
_Static_assert(GROUP_PMP_SQLITE_VFS_DESCRIPTOR_BYTES ==
                   GROUP_PMP_SQLITE_VFS_BATCH_MAX *
                       sizeof(struct group_pmp_sqlite_vfs_request),
               "SQLite descriptor table size mismatch");
_Static_assert(GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET_FOR_SLOT(0) +
                       GROUP_PMP_SQLITE_VFS_BATCH_MAX *
                           sizeof(struct group_pmp_sqlite_vfs_status) <=
                   GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(0) +
                       GROUP_PMP_SQLITE_VFS_RING_SLOT_BYTES &&
                   GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET_FOR_SLOT(1) +
                       GROUP_PMP_SQLITE_VFS_BATCH_MAX *
                           sizeof(struct group_pmp_sqlite_vfs_status) <=
                   GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(1) +
                       GROUP_PMP_SQLITE_VFS_RING_SLOT_BYTES,
               "SQLite request/completion rings must fit in UTM metadata");
#endif

#endif
