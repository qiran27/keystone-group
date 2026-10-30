#include "sm2_bench.h"

#include <limits.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

#include <stdio.h>
#include <stdlib.h>

#include "sm2.h"

struct sm2_bench_key {
  EC_KEY* key;
};

static void sm2_bench_report_error(const char* operation)
{
  unsigned long code = ERR_peek_last_error();
  char message[256];

  if (code == 0) {
    fprintf(stderr, "[CRYPTO-NATIVE][sm2] %s failed\n", operation);
    return;
  }
  ERR_error_string_n(code, message, sizeof(message));
  fprintf(stderr, "[CRYPTO-NATIVE][sm2] %s failed: %s\n", operation,
          message);
}

struct sm2_bench_key* sm2_bench_key_create(void)
{
  struct sm2_bench_key* result;
  EC_KEY* key;

  ERR_clear_error();
#if defined(NID_sm2)
  key = EC_KEY_new_by_curve_name(NID_sm2);
#elif defined(NID_sm2p256v1)
  key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
#else
#error "The selected OpenSSL headers do not define the SM2 curve"
#endif
  if (key == NULL || EC_KEY_generate_key(key) != 1) {
    sm2_bench_report_error("key-create");
    EC_KEY_free(key);
    return NULL;
  }
  result = (struct sm2_bench_key*)calloc(1, sizeof(*result));
  if (result == NULL) {
    EC_KEY_free(key);
    return NULL;
  }
  result->key = key;
  return result;
}

void sm2_bench_key_destroy(struct sm2_bench_key* key)
{
  if (key == NULL) {
    return;
  }
  EC_KEY_free(key->key);
  free(key);
}

int sm2_bench_sign(struct sm2_bench_key* key, const uint8_t digest[32],
                   uint8_t* signature, size_t* signature_size)
{
  unsigned int encoded_size;

  if (key == NULL || digest == NULL || signature == NULL ||
      signature_size == NULL || *signature_size > UINT_MAX) {
    return -1;
  }
  encoded_size = (unsigned int)*signature_size;
  ERR_clear_error();
  if (SM2_sign(0, digest, 32, signature, &encoded_size, key->key) != 1) {
    sm2_bench_report_error("sign");
    return -1;
  }
  *signature_size = encoded_size;
  return 0;
}

int sm2_bench_verify(struct sm2_bench_key* key, const uint8_t digest[32],
                     const uint8_t* signature, size_t signature_size)
{
  int result;

  if (key == NULL || digest == NULL || signature == NULL ||
      signature_size > INT_MAX) {
    return -1;
  }
  ERR_clear_error();
  result = SM2_verify(0, digest, 32, signature, (int)signature_size,
                      key->key);
  if (result != 1) {
    sm2_bench_report_error("verify");
    return -1;
  }
  return 0;
}
