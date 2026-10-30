#include "rsa2048_bench.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <stdlib.h>

struct rsa2048_bench_key {
  EVP_PKEY* key;
};

static EVP_PKEY_CTX* rsa2048_operation_context(EVP_PKEY* key, int sign)
{
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new(key, NULL);

  if (context == NULL) {
    return NULL;
  }
  if ((sign ? EVP_PKEY_sign_init(context) : EVP_PKEY_verify_init(context)) <=
      0) {
    EVP_PKEY_CTX_free(context);
    return NULL;
  }
  if (EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_signature_md(context, EVP_sha256()) <= 0 ||
      EVP_PKEY_CTX_set_rsa_pss_saltlen(context,
                                       RSA_PSS_SALTLEN_DIGEST) <= 0) {
    EVP_PKEY_CTX_free(context);
    return NULL;
  }
  return context;
}

struct rsa2048_bench_key* rsa2048_bench_key_create(void)
{
  struct rsa2048_bench_key* result = NULL;
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY* key = NULL;

  if (context == NULL || EVP_PKEY_keygen_init(context) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) <= 0 ||
      EVP_PKEY_keygen(context, &key) <= 0) {
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    return NULL;
  }
  EVP_PKEY_CTX_free(context);

  result = (struct rsa2048_bench_key*)calloc(1, sizeof(*result));
  if (result == NULL) {
    EVP_PKEY_free(key);
    return NULL;
  }
  result->key = key;
  return result;
}

void rsa2048_bench_key_destroy(struct rsa2048_bench_key* key)
{
  if (key == NULL) {
    return;
  }
  EVP_PKEY_free(key->key);
  free(key);
}

int rsa2048_bench_sign(struct rsa2048_bench_key* key,
                       const uint8_t digest[32], uint8_t* signature,
                       size_t* signature_size)
{
  EVP_PKEY_CTX* context;
  int result;

  if (key == NULL || digest == NULL || signature_size == NULL) {
    return -1;
  }
  context = rsa2048_operation_context(key->key, 1);
  if (context == NULL) {
    return -1;
  }
  result = EVP_PKEY_sign(context, signature, signature_size, digest, 32);
  EVP_PKEY_CTX_free(context);
  return result > 0 ? 0 : -1;
}

int rsa2048_bench_verify(struct rsa2048_bench_key* key,
                         const uint8_t digest[32], const uint8_t* signature,
                         size_t signature_size)
{
  EVP_PKEY_CTX* context;
  int result;

  if (key == NULL || digest == NULL || signature == NULL) {
    return -1;
  }
  context = rsa2048_operation_context(key->key, 0);
  if (context == NULL) {
    return -1;
  }
  result = EVP_PKEY_verify(context, signature, signature_size, digest, 32);
  EVP_PKEY_CTX_free(context);
  return result == 1 ? 0 : -1;
}
