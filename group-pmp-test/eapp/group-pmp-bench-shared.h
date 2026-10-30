#ifndef GROUP_PMP_BENCH_SHARED_H
#define GROUP_PMP_BENCH_SHARED_H

#include <stdint.h>

#define GROUP_PMP_BENCH_MAGIC UINT64_C(0x47504d5042454e43)
#define GROUP_PMP_BENCH_VERSION UINT64_C(3)
#define GROUP_PMP_BENCH_AES_ENCRYPT UINT64_C(1)
#define GROUP_PMP_BENCH_AES_DECRYPT UINT64_C(2)
#define GROUP_PMP_BENCH_STOP UINT64_C(3)
#define GROUP_PMP_BENCH_BATCH_BYTES (UINT64_C(24) * UINT64_C(1000000))
#define GROUP_PMP_BENCH_INPUT_OFFSET UINT64_C(4096)
#define GROUP_PMP_BENCH_EXPECTED_OFFSET (UINT64_C(28) * UINT64_C(1000000))
#define GROUP_PMP_BENCH_EXPECTED_MAGIC UINT64_C(0x47504d5045585043)
#define GROUP_PMP_BENCH_EXPECTED_MAX_RECORDS UINT64_C(16)
#define GROUP_PMP_BENCH_COMPUTE_SERVICE_BYTES (UINT64_C(256) * 1024)
#define GROUP_PMP_SCALE_MAGIC UINT64_C(0x47504d505343414c)
#define GROUP_PMP_SCALE_VERSION UINT64_C(2)
#define GROUP_PMP_SCALE_CONFIG_OFFSET UINT64_C(4096)
#define GROUP_PMP_SCALE_RESULT_OFFSET UINT64_C(8192)
#define GROUP_PMP_SCALE_MIN_WORKERS UINT64_C(1)
#define GROUP_PMP_SCALE_MAX_WORKERS UINT64_C(10)
#define GROUP_PMP_SCALE_LANES UINT64_C(3)
#define GROUP_PMP_SCALE_TOTAL_BYTES GROUP_PMP_BENCH_BATCH_BYTES
#define GROUP_PMP_SCALE_STATE_EMPTY UINT64_C(0)
#define GROUP_PMP_SCALE_STATE_STARTED UINT64_C(1)
#define GROUP_PMP_SCALE_STATE_COMPLETED UINT64_C(2)
/* VisionFive2/JH7110 exposes a 4 MHz timebase: 120M ticks is 30 seconds. */
#define GROUP_PMP_BENCH_PROTOCOL_TIMEOUT_TICKS UINT64_C(120000000)
#ifndef GROUP_PMP_AES_COOPERATIVE_SERVICE
#define GROUP_PMP_AES_COOPERATIVE_SERVICE 0
#endif

struct group_pmp_bench_header {
  uint64_t magic;
  uint64_t version;
  uint64_t operation;
  uint64_t worker_count;
  uint64_t round;
  uint64_t sequence;
  uint64_t global_offset;
  uint64_t data_length;
  uint64_t observed_payload_va;
  uint64_t worker_cycles;
  uint64_t checksum;
  uint64_t reserved;
};

struct group_pmp_bench_expected_record {
  uint64_t operation;
  uint64_t worker_count;
  uint64_t round;
  uint64_t slice_id;
  uint64_t global_offset;
  uint64_t data_length;
  uint64_t checksum;
};

struct group_pmp_bench_expected_table {
  uint64_t magic;
  uint64_t version;
  uint64_t operation;
  uint64_t record_count;
  struct group_pmp_bench_expected_record
      records[GROUP_PMP_BENCH_EXPECTED_MAX_RECORDS];
};

/*
 * P10 scaling is intentionally independent from the Spark-style task layer.
 * Each worker receives one fixed AES share through its own UTM, computes only
 * in private EPM, and returns a compact result. Equal lane work keeps the
 * three-hart saturation point comparable for worker counts 3..10.
 */
struct group_pmp_scale_config {
  uint64_t magic;
  uint64_t version;
  uint64_t worker_index;
  uint64_t worker_count;
  uint64_t lane_id;
  uint64_t lane_rank;
  uint64_t lane_depth;
  uint64_t assigned_bytes;
  uint64_t seed;
  uint64_t reserved[3];
};

struct group_pmp_scale_result {
  uint64_t magic;
  uint64_t version;
  uint64_t status;
  uint64_t worker_index;
  uint64_t worker_count;
  uint64_t lane_id;
  uint64_t assigned_bytes;
  uint64_t start_cycle;
  uint64_t end_cycle;
  uint64_t compute_cycles;
  uint64_t digest;
  uint64_t known_answer_ok;
};

#endif
