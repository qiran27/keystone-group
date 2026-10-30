#ifndef GROUP_PMP_BENCHMARK_CIPHER_H
#define GROUP_PMP_BENCHMARK_CIPHER_H
#include <stddef.h>
#include <stdint.h>

#define BENCHMARK_CIPHER_MARKER "keystone-benchmark-cipher-v1"
#define BENCHMARK_CIPHER_FLAG_SHIFT 20
#define BENCHMARK_CIPHER_FLAG_MASK (UINT64_C(3) << BENCHMARK_CIPHER_FLAG_SHIFT)
enum benchmark_cipher {
  BENCHMARK_AES_ECB = 0, BENCHMARK_AES_GCM = 1, BENCHMARK_CHACHA_POLY = 2
};
static inline const char* benchmark_cipher_name(unsigned cipher) {
  return cipher == BENCHMARK_AES_ECB ? "aes-ecb-128" :
      cipher == BENCHMARK_AES_GCM ? "aes-gcm-128" :
      cipher == BENCHMARK_CHACHA_POLY ? "chacha20-poly1305" : "invalid";
}

/* Expected identity comes from private request state. Stored sequence is
 * authenticated on reads, but this does not establish storage freshness. */
struct benchmark_aead_identity {
  uint64_t run_id, worker, workload, file_offset, logical_size;
  uint64_t logical_offset, length, sequence;
};
#ifdef __cplusplus
extern "C" {
#endif
int benchmark_aead_init(unsigned cipher, const uint8_t key[32]);
void benchmark_aead_free(void);
int benchmark_aead_seal(const struct benchmark_aead_identity* id,
                        const uint8_t* plain, uint8_t* cipher, uint8_t tag[16]);
/* cipher must be a private EPM snapshot; output is zeroed on auth failure. */
int benchmark_aead_open(const struct benchmark_aead_identity* id,
                        const uint8_t* cipher, const uint8_t tag[16], uint8_t* plain);
#ifdef __cplusplus
}
#endif
#endif
