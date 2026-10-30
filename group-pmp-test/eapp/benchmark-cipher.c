#include "benchmark-cipher.h"
#include "mbedtls/gcm.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/platform_util.h"

/* One worker per enclave; these contexts and keys never enter UTM. */
static mbedtls_gcm_context gcm;
static mbedtls_chachapoly_context chacha;
static unsigned algorithm;
static uint64_t sealed_sequence;

static void encode64(uint8_t* out, uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) out[i] = (uint8_t)(value >> (i * 8));
}
static int identity(const struct benchmark_aead_identity* id,
                    uint8_t nonce[12], uint8_t aad[72]) {
  if (!id || !id->sequence || !id->length || id->length > 2000000 ||
      id->worker > UINT32_MAX || !id->run_id || !algorithm) return -1;
  for (unsigned i = 0; i < 4; ++i) nonce[i] = (uint8_t)(id->worker >> (i * 8));
  encode64(nonce + 4, id->sequence);
  encode64(aad, algorithm);
  encode64(aad + 8, id->run_id);
  encode64(aad + 16, id->worker);
  encode64(aad + 24, id->workload);
  encode64(aad + 32, id->file_offset);
  encode64(aad + 40, id->logical_size);
  encode64(aad + 48, id->logical_offset);
  encode64(aad + 56, id->length);
  encode64(aad + 64, id->sequence);
  return 0;
}
void benchmark_aead_free(void) {
  mbedtls_gcm_free(&gcm);
  mbedtls_chachapoly_free(&chacha);
  algorithm = 0;
  sealed_sequence = 0;
}
int benchmark_aead_init(unsigned cipher, const uint8_t key[32]) {
  int rc = -1;
  benchmark_aead_free();
  mbedtls_gcm_init(&gcm);
  mbedtls_chachapoly_init(&chacha);
  if (!key) return -1;
  if ((cipher == BENCHMARK_AES_GCM && mbedtls_gcm_self_test(0)) ||
      (cipher == BENCHMARK_CHACHA_POLY && mbedtls_chachapoly_self_test(0)))
    return -1;
  if (cipher == BENCHMARK_AES_GCM)
    rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
  else if (cipher == BENCHMARK_CHACHA_POLY)
    rc = mbedtls_chachapoly_setkey(&chacha, key);
  if (!rc) algorithm = cipher;
  else benchmark_aead_free();
  return rc;
}
int benchmark_aead_seal(const struct benchmark_aead_identity* id,
                        const uint8_t* plain, uint8_t* cipher, uint8_t tag[16]) {
  uint8_t nonce[12], aad[72];
  if (!plain || !cipher || !tag || identity(id, nonce, aad) ||
      id->sequence <= sealed_sequence) return -1;
  /* Consume nonce even on failure; prefill/measurement do not reset it. */
  sealed_sequence = id->sequence;
  if (algorithm == BENCHMARK_AES_GCM)
    return mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, id->length,
        nonce, sizeof(nonce), aad, sizeof(aad), plain, cipher, 16, tag);
  return mbedtls_chachapoly_encrypt_and_tag(&chacha, id->length, nonce,
      aad, sizeof(aad), plain, cipher, tag);
}
int benchmark_aead_open(const struct benchmark_aead_identity* id,
                        const uint8_t* cipher, const uint8_t tag[16], uint8_t* plain) {
  uint8_t nonce[12], aad[72];
  int rc;
  if (!plain || !cipher || !tag || identity(id, nonce, aad)) return -1;
  if (algorithm == BENCHMARK_AES_GCM)
    rc = mbedtls_gcm_auth_decrypt(&gcm, id->length, nonce, sizeof(nonce),
        aad, sizeof(aad), tag, 16, cipher, plain);
  else
    rc = mbedtls_chachapoly_auth_decrypt(&chacha, id->length, nonce,
        aad, sizeof(aad), tag, cipher, plain);
  if (rc) mbedtls_platform_zeroize(plain, id->length);
  return rc;
}
