#ifndef GROUP_PMP_CRYPTO_COMPUTE_H
#define GROUP_PMP_CRYPTO_COMPUTE_H
#include <stdint.h>

#define CRYPTO_COMPUTE_MARKER "keystone-single-worker-crypto-compute-v1"
#define CRYPTO_COMPUTE_STARTUP_MARKER "keystone-crypto-compute-startup-v2"
#define CRYPTO_COMPUTE_MAGIC UINT64_C(0x43525950544f4331)
#define CRYPTO_COMPUTE_VERSION UINT64_C(1)
#define CRYPTO_COMPUTE_CONFIG_OFFSET 4096
#define CRYPTO_COMPUTE_RESULT_OFFSET 8192
#define CRYPTO_COMPUTE_BLOCK_BYTES UINT64_C(2000000)
/* The SDK reserves ELF file bytes, not BSS; include all three private arrays. */
#define CRYPTO_COMPUTE_FREE_BYTES \
  (3 * ((CRYPTO_COMPUTE_BLOCK_BYTES + 4095) & ~UINT64_C(4095)) + UINT64_C(4) * 1024 * 1024)

struct crypto_compute_config {
  uint64_t magic, version, algorithm, operation, total_bytes, sample;
};
struct crypto_compute_stamp {
  uint64_t wall_ticks, cpu_ticks, cycles;
};
struct crypto_compute_result {
  uint64_t magic, version, algorithm, operation, total_bytes, sample;
  uint64_t processed_bytes, blocks, wall_ticks, cpu_ticks, cycles;
  uint64_t validated, error_code;
};
typedef int (*crypto_compute_clock)(struct crypto_compute_stamp*);
#ifdef __cplusplus
extern "C" {
#endif
/* Bounded EPM streaming; only transform calls lie between clock samples. */
int crypto_compute_run(const struct crypto_compute_config*,
                       crypto_compute_clock, struct crypto_compute_result*);
#ifdef __cplusplus
}
#endif
#endif
