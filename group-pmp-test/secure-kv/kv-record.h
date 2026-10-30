#ifndef GROUP_PMP_KV_RECORD_H
#define GROUP_PMP_KV_RECORD_H
#include <stddef.h>
#include <stdint.h>
#define KV_BENCH_MARKER "keystone-enclave-kv-pipeline-v1"
#define KV_RESULT_OFFSET UINT64_C(2048)
#define KV_RESULT_MAGIC UINT64_C(0x4b56504950453031)
#define KV_RECORD_HEADER_BYTES 16u
/* Fixed-key-space KV prototype. This record check is NOT authentication. */
struct kv_bench_stats {
  uint64_t magic, version, workload, bytes, puts, gets, validated_gets;
};
#ifdef __cplusplus
extern "C" {
#endif
int kv_record_make(uint8_t* output, size_t length, uint64_t key,
                   uint32_t owner, uint32_t version);
int kv_record_check(const uint8_t* input, size_t length, uint64_t key,
                    uint32_t owner, uint32_t version, uint64_t* digest);
#ifdef __cplusplus
}
#endif
#endif
