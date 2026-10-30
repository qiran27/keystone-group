#ifndef GROUP_PMP_SQLITE_SHARED_H
#define GROUP_PMP_SQLITE_SHARED_H

#include <stdint.h>

#define GROUP_PMP_SQLITE_ARTIFACT_MARKER "keystone-sqlite-host-engine-v1"
#define GROUP_PMP_SQLITE_FULL_FLOW_BASELINE_MARKER \
  "keystone-sqlite-full-flow-baseline-v1"
#define GROUP_PMP_SQLITE_CONFIGURABLE_TOTAL_MARKER \
  "keystone-sqlite-configurable-total-v1"
#define GROUP_PMP_SQLITE_DEFAULT_TOTAL_BYTES \
  (UINT64_C(512) * UINT64_C(1000000))
#define GROUP_PMP_SQLITE_PACKET_MAGIC UINT64_C(0x53514c4954455958)
#define GROUP_PMP_SQLITE_PACKET_VERSION UINT64_C(4)
#define GROUP_PMP_SQLITE_RESIDENT_BYTES (UINT64_C(4) * UINT64_C(1000000))
#define GROUP_PMP_SQLITE_NORMAL_VALUE_BYTES UINT64_C(240)
#define GROUP_PMP_SQLITE_LARGE_VALUE_BYTES UINT64_C(100000)
/* config.diagnostic_flags: Host enables only for adaptive READSEQ. */
#define GROUP_PMP_SQLITE_PAIRED_READS UINT64_C(2)
/* Shared by all I/O modes; unrelated to Adaptive's paired-read option. */
#define GROUP_PMP_SQLITE_DIRECT_LAYOUT UINT64_C(4)
/* Adaptive-only admission planning, independent of the two data buffers. */
#define GROUP_PMP_SQLITE_INTENT_LOOKAHEAD UINT64_C(8)
/* Address generation is shared by all modes; bit 16 is retired. */
/* #define GROUP_PMP_SQLITE_SEEDED_PAGE_PERMUTATION UINT64_C(16) */

enum group_pmp_sqlite_workload {
  GROUP_PMP_SQLITE_NONE = 0,
  GROUP_PMP_SQLITE_FILLSEQ = 1,
  GROUP_PMP_SQLITE_FILLSEQBATCH = 2,
  GROUP_PMP_SQLITE_FILLRANDOM = 3,
  GROUP_PMP_SQLITE_FILLRANDOMBATCH = 4,
  GROUP_PMP_SQLITE_OVERWRITE = 5,
  GROUP_PMP_SQLITE_READSEQ = 6,
  GROUP_PMP_SQLITE_READRANDOM = 7,
  GROUP_PMP_SQLITE_READRAND100K = 8,
  GROUP_PMP_SQLITE_WORKLOAD_COUNT = 8
};

struct group_pmp_sqlite_packet_header {
  uint64_t magic;
  uint64_t version;
  uint64_t workload;
  uint64_t worker_index;
  uint64_t batch_id;
  uint64_t first_record;
  uint64_t record_count;
  uint64_t value_size;
  uint64_t logical_bytes;
  uint64_t sequence;
  uint64_t payload_digest;
  uint64_t reserved[5];
};

struct group_pmp_sqlite_record_header {
  uint64_t key;
  uint64_t value_size;
};

#if defined(__cplusplus)
static_assert(sizeof(struct group_pmp_sqlite_packet_header) == 128,
              "SQLite YXSTM packet header ABI mismatch");
static_assert(sizeof(struct group_pmp_sqlite_record_header) == 16,
              "SQLite YXSTM record header ABI mismatch");
#else
_Static_assert(sizeof(struct group_pmp_sqlite_packet_header) == 128,
               "SQLite YXSTM packet header ABI mismatch");
_Static_assert(sizeof(struct group_pmp_sqlite_record_header) == 16,
               "SQLite YXSTM record header ABI mismatch");
#endif

static inline int
group_pmp_sqlite_valid_workload(uint64_t workload) {
  return workload >= GROUP_PMP_SQLITE_FILLSEQ &&
      workload <= GROUP_PMP_SQLITE_READRAND100K;
}

static inline int
group_pmp_sqlite_is_read(uint64_t workload) {
  return workload == GROUP_PMP_SQLITE_READSEQ ||
      workload == GROUP_PMP_SQLITE_READRANDOM ||
      workload == GROUP_PMP_SQLITE_READRAND100K;
}

static inline int
group_pmp_sqlite_is_random(uint64_t workload) {
  return workload == GROUP_PMP_SQLITE_FILLRANDOM ||
      workload == GROUP_PMP_SQLITE_FILLRANDOMBATCH ||
      workload == GROUP_PMP_SQLITE_OVERWRITE ||
      workload == GROUP_PMP_SQLITE_READRANDOM ||
      workload == GROUP_PMP_SQLITE_READRAND100K;
}

static inline int
group_pmp_sqlite_is_batch(uint64_t workload) {
  return workload == GROUP_PMP_SQLITE_FILLSEQBATCH ||
      workload == GROUP_PMP_SQLITE_FILLRANDOMBATCH;
}

static inline uint64_t
group_pmp_sqlite_value_size(uint64_t workload) {
  return workload == GROUP_PMP_SQLITE_READRAND100K ?
      GROUP_PMP_SQLITE_LARGE_VALUE_BYTES :
      GROUP_PMP_SQLITE_NORMAL_VALUE_BYTES;
}

static inline uint64_t
group_pmp_sqlite_record_size(uint64_t workload) {
  return sizeof(struct group_pmp_sqlite_record_header) +
      group_pmp_sqlite_value_size(workload);
}

static inline uint64_t
group_pmp_sqlite_records_per_packet(uint64_t workload,
                                    uint64_t slot_capacity) {
  uint64_t record_size = group_pmp_sqlite_record_size(workload);
  return slot_capacity > sizeof(struct group_pmp_sqlite_packet_header) ?
      (slot_capacity - sizeof(struct group_pmp_sqlite_packet_header)) /
          record_size : 0;
}

static inline uint64_t
group_pmp_sqlite_logical_capacity(uint64_t workload,
                                  uint64_t slot_capacity) {
  return group_pmp_sqlite_records_per_packet(workload, slot_capacity) *
      group_pmp_sqlite_value_size(workload);
}

/* Descriptor-only YXSTM transport. The host SQLite database stores encrypted
 * extents; no SQLite page or plaintext record is carried in YXSTM. */
static inline uint64_t
group_pmp_sqlite_task_chunk_bytes(uint64_t workload, uint64_t task_bytes) {
  uint64_t value_size = group_pmp_sqlite_value_size(workload);

  if (!group_pmp_sqlite_valid_workload(workload) || !value_size ||
      !task_bytes || task_bytes % value_size != 0)
    return 0;
  return task_bytes;
}

static inline uint64_t
group_pmp_sqlite_task_batch_count(uint64_t workload, uint64_t task_bytes) {
  uint64_t chunk = group_pmp_sqlite_task_chunk_bytes(workload, task_bytes);
  return chunk ? (task_bytes + chunk - UINT64_C(1)) / chunk : 0;
}

static inline uint64_t
group_pmp_sqlite_packet_size(uint64_t workload, uint64_t record_count) {
  return sizeof(struct group_pmp_sqlite_packet_header) +
      record_count * group_pmp_sqlite_record_size(workload);
}

static inline uint64_t
group_pmp_sqlite_prng(uint64_t value) {
  value ^= value >> 12;
  value ^= value << 25;
  value ^= value >> 27;
  return value * UINT64_C(2685821657736338717);
}

static inline uint64_t
group_pmp_sqlite_resident_records(uint64_t workload) {
  uint64_t value_size = group_pmp_sqlite_value_size(workload);
  uint64_t records = GROUP_PMP_SQLITE_RESIDENT_BYTES / value_size;
  return records ? records : 1;
}

static inline uint64_t
group_pmp_sqlite_key(uint64_t workload, uint64_t worker_index,
                     uint64_t record_index) {
  uint64_t lane_rank = worker_index / UINT64_C(3);
  uint64_t key = record_index + lane_rank * UINT64_C(104729);
  if (group_pmp_sqlite_is_random(workload))
    key = group_pmp_sqlite_prng(key ^ (workload << 48));
  return key;
}

static inline uint8_t
group_pmp_sqlite_value_byte(uint64_t key, uint64_t offset) {
  uint64_t value = group_pmp_sqlite_prng(
      key ^ (offset >> 3) ^ UINT64_C(0x53514c495445));
  return (uint8_t)(value >> ((offset & 7) * 8));
}

#endif
