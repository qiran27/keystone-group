#ifndef KEYSTONE_RV8_KERNELS_H
#define KEYSTONE_RV8_KERNELS_H
#include <stddef.h>
#include <stdint.h>
#define RV8_BENCH_MARKER "keystone-rv8-enclave-compute-v2"
#define RV8_RESULT_OFFSET UINT64_C(2048)
#define RV8_RESULT_MAGIC UINT64_C(0x5256384350553031)
#define RV8_KERNEL_BLOCK_BYTES 65536u
/* A separate control record; no existing SQLite result ABI is changed. */
struct rv8_kernel_stats {
  uint64_t magic, version, profile, bytes, blocks, cpu_ticks, elapsed_ticks;
  uint64_t digest, validated;
};
#ifdef __cplusplus
extern "C" {
#endif
int rv8_kernel_init(void);
int rv8_kernel_process(const uint8_t* input, size_t length);
void rv8_kernel_account(uint64_t cpu_ticks, uint64_t elapsed_ticks);
void rv8_kernel_get_stats(struct rv8_kernel_stats* stats);
#ifdef __cplusplus
}
#endif
#endif
