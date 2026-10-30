#include "security-aead.h"
#include "mbedtls/gcm.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/platform_util.h"
#include <string.h>
int security_aead_encrypt(unsigned algorithm, const uint8_t* key,
                          const uint8_t* plain, struct security_aead_packet* p) {
  int rc = -1;
  if (algorithm == SECURITY_AEAD_GCM) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (!rc) rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
        SECURITY_AEAD_BYTES, p->nonce, sizeof(p->nonce), p->aad, sizeof(p->aad),
        plain, p->ciphertext, sizeof(p->tag), p->tag);
    mbedtls_gcm_free(&ctx);
  } else if (algorithm == SECURITY_AEAD_CHACHA) {
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, key);
    if (!rc) rc = mbedtls_chachapoly_encrypt_and_tag(&ctx, SECURITY_AEAD_BYTES,
        p->nonce, p->aad, sizeof(p->aad), plain, p->ciphertext, p->tag);
    mbedtls_chachapoly_free(&ctx);
  }
  return rc;
}
int security_aead_open(unsigned algorithm, const uint8_t* key,
                      const struct security_aead_packet* p,
                      const uint8_t expected_aad[40], uint8_t output[SECURITY_AEAD_BYTES]) {
  uint8_t verified[SECURITY_AEAD_BYTES];
  int rc = -1;
  // Object/range identity comes from trusted enclave task metadata, not UTM.
  if (memcmp(p->aad, expected_aad, 40)) return -1;
  if (algorithm == SECURITY_AEAD_GCM) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (!rc) rc = mbedtls_gcm_auth_decrypt(&ctx, SECURITY_AEAD_BYTES,
        p->nonce, sizeof(p->nonce), p->aad, sizeof(p->aad), p->tag, sizeof(p->tag),
        p->ciphertext, verified);
    mbedtls_gcm_free(&ctx);
  } else if (algorithm == SECURITY_AEAD_CHACHA) {
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, key);
    if (!rc) rc = mbedtls_chachapoly_auth_decrypt(&ctx, SECURITY_AEAD_BYTES,
        p->nonce, p->aad, sizeof(p->aad), p->tag, p->ciphertext, verified);
    mbedtls_chachapoly_free(&ctx);
  }
  if (!rc) memcpy(output, verified, sizeof(verified));
  mbedtls_platform_zeroize(verified, sizeof(verified));
  return rc;
}
int security_aead_self_test_algorithm(unsigned algorithm) {
  if (algorithm == SECURITY_AEAD_GCM) return mbedtls_gcm_self_test(0) ? -1 : 0;
  if (algorithm == SECURITY_AEAD_CHACHA) return mbedtls_chachapoly_self_test(0) ? -1 : 0;
  return -1;
}
int security_aead_self_test(void) {
  return security_aead_self_test_algorithm(SECURITY_AEAD_GCM) ||
         security_aead_self_test_algorithm(SECURITY_AEAD_CHACHA) ? -1 : 0;
}
