#ifndef GROUP_PMP_AES_BASELINE_SHARED_H
#define GROUP_PMP_AES_BASELINE_SHARED_H

#include <stdint.h>

#define GROUP_PMP_AES_BASELINE_MAGIC UINT64_C(0x4750414553424153)
#define GROUP_PMP_AES_BASELINE_VERSION UINT64_C(4)
#define GROUP_PMP_AES_BASELINE_RESULT_OFFSET UINT64_C(4096)
#define GROUP_PMP_AES_BASELINE_BYTES (UINT64_C(8) * UINT64_C(1000000))
#define GROUP_PMP_AES_BASELINE_SAMPLES UINT64_C(15)
#define GROUP_PMP_AES_BASELINE_WARMUP UINT64_C(2)
#define GROUP_PMP_AES_BASELINE_PAGE_SIZE UINT64_C(4096)
#define GROUP_PMP_AES_BUILD_TAG UINT64_C(0x4145534f33525647)

struct group_pmp_aes_baseline_result {
  uint64_t magic;
  uint64_t version;
  uint64_t status;
  uint64_t bytes;
  uint64_t samples;
  uint64_t warmup;
  uint64_t known_answer_ok;
  uint64_t checksum;
  uint64_t build_tag;
  uint64_t sample_cycles[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t sample_time_ticks[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t hot_block_cycles[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t hot_block_time_ticks[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t epm_read_cycles[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t epm_read_time_ticks[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t epm_write_cycles[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t epm_write_time_ticks[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t epm_copy_cycles[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t epm_copy_time_ticks[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t epm_page_stride_cycles[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t epm_page_stride_time_ticks[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t digest_cycles[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t digest_time_ticks[GROUP_PMP_AES_BASELINE_SAMPLES];
  uint64_t epm_read_sink;
  uint64_t epm_stride_sink;
  uint64_t epm_page_stride_accesses;
  uint64_t input_alignment;
  uint64_t output_alignment;
  uint64_t hidden_copy_bytes;
  uint64_t reserved[4];
};

#endif
