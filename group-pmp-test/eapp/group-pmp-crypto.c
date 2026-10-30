#include "group-pmp-crypto.h"

#include <string.h>

#include "aes_core.h"

static const volatile char crypto_interface_marker[] __attribute__((used)) =
    GROUP_PMP_CRYPTO_INTERFACE_MARKER;
static const volatile char crypto_only_marker[] __attribute__((used)) =
    GROUP_PMP_CRYPTO_ONLY_MARKER;
static const volatile char crypto_bulk_marker[] __attribute__((used)) =
    "keystone-aes-bulk4-v1";

int group_pmp_crypto_init(struct group_pmp_crypto_context* context,
                          uint32_t algorithm, const uint8_t* key,
                          size_t key_size) {
  if (!context || !key)
    return -1;
  memset(context, 0, sizeof(*context));
  if (algorithm != GROUP_PMP_CRYPTO_AES_128_ECB || key_size != 16)
    return -1;
  context->algorithm = algorithm;
  context->block_size = 16;
  context->encrypt_context = aes_encrypt_init(key, key_size);
  context->decrypt_context = aes_decrypt_init(key, key_size);
  if (!context->encrypt_context || !context->decrypt_context) {
    group_pmp_crypto_deinit(context);
    return -1;
  }
  return 0;
}

int group_pmp_crypto_transform(struct group_pmp_crypto_context* context,
                               uint32_t direction, const uint8_t* input,
                               uint8_t* output, size_t length) {
  if (crypto_bulk_marker[0] != 'k' || !context || !input || !output ||
      !context->block_size ||
      length % context->block_size != 0 ||
      context->algorithm != GROUP_PMP_CRYPTO_AES_128_ECB)
    return -1;
  if (direction == GROUP_PMP_CRYPTO_ENCRYPT) {
    aes_encrypt_blocks(context->encrypt_context, input, output,
                       length / context->block_size);
    return 0;
  }
  if (direction == GROUP_PMP_CRYPTO_DECRYPT) {
    aes_decrypt_blocks(context->decrypt_context, input, output,
                       length / context->block_size);
    return 0;
  }
  return -1;
}

int group_pmp_crypto_self_test(struct group_pmp_crypto_context* context) {
  uint8_t plain[16];
  uint8_t cipher[16];
  uint8_t recovered[16];
  size_t index;

  for (index = 0; index < sizeof(plain); ++index)
    plain[index] = (uint8_t)(index * 17U + 3U);
  if (group_pmp_crypto_transform(context, GROUP_PMP_CRYPTO_ENCRYPT,
                                 plain, cipher, sizeof(plain)) != 0 ||
      group_pmp_crypto_transform(context, GROUP_PMP_CRYPTO_DECRYPT,
                                 cipher, recovered, sizeof(recovered)) != 0)
    return -1;
  return memcmp(plain, recovered, sizeof(plain)) == 0 ? 0 : -1;
}

void group_pmp_crypto_deinit(struct group_pmp_crypto_context* context) {
  if (!context)
    return;
  if (context->encrypt_context)
    aes_encrypt_deinit(context->encrypt_context);
  if (context->decrypt_context)
    aes_decrypt_deinit(context->decrypt_context);
  memset(context, 0, sizeof(*context));
}

const char* group_pmp_crypto_name(uint32_t algorithm) {
  return algorithm == GROUP_PMP_CRYPTO_AES_128_ECB ? "aes-128-ecb" :
                                                     "unsupported";
}
