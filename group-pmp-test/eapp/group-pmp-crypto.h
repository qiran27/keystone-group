#ifndef GROUP_PMP_CRYPTO_H
#define GROUP_PMP_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define GROUP_PMP_CRYPTO_INTERFACE_MARKER "keystone-crypto-interface-v1"
#define GROUP_PMP_CRYPTO_ONLY_MARKER "keystone-crypto-only-v1"

enum group_pmp_crypto_algorithm {
  GROUP_PMP_CRYPTO_AES_128_ECB = 1,
};

enum group_pmp_crypto_direction {
  GROUP_PMP_CRYPTO_ENCRYPT = 1,
  GROUP_PMP_CRYPTO_DECRYPT = 2,
};

struct group_pmp_crypto_context {
  uint32_t algorithm;
  uint32_t block_size;
  void* encrypt_context;
  void* decrypt_context;
};

int group_pmp_crypto_init(struct group_pmp_crypto_context* context,
                          uint32_t algorithm, const uint8_t* key,
                          size_t key_size);
int group_pmp_crypto_transform(struct group_pmp_crypto_context* context,
                               uint32_t direction, const uint8_t* input,
                               uint8_t* output, size_t length);
int group_pmp_crypto_self_test(struct group_pmp_crypto_context* context);
void group_pmp_crypto_deinit(struct group_pmp_crypto_context* context);
const char* group_pmp_crypto_name(uint32_t algorithm);

#endif
