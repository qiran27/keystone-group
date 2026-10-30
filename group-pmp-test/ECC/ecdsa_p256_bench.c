#include "ecdsa_p256_bench.h"

#include "uECC.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#define ECDSA_P256_PRIVATE_KEY_SIZE 32U
#define ECDSA_P256_PUBLIC_KEY_SIZE 64U
#define ECDSA_P256_SIGNATURE_SIZE 64U

struct ecdsa_p256_bench_key {
  uint8_t private_key[ECDSA_P256_PRIVATE_KEY_SIZE];
  uint8_t public_key[ECDSA_P256_PUBLIC_KEY_SIZE];
  uECC_Curve curve;
};

static int ecdsa_p256_random(uint8_t* destination, unsigned int size)
{
  int descriptor;
  unsigned int offset = 0;

  descriptor = open("/dev/urandom", O_RDONLY);
  if (descriptor < 0) {
    return 0;
  }
  while (offset < size) {
    ssize_t length = read(descriptor, destination + offset, size - offset);
    if (length <= 0) {
      close(descriptor);
      return 0;
    }
    offset += (unsigned int)length;
  }
  close(descriptor);
  return 1;
}

struct ecdsa_p256_bench_key* ecdsa_p256_bench_key_create(void)
{
  struct ecdsa_p256_bench_key* key;

  key = (struct ecdsa_p256_bench_key*)calloc(1, sizeof(*key));
  if (key == NULL) {
    return NULL;
  }
  key->curve = uECC_secp256r1();
  uECC_set_rng(ecdsa_p256_random);
  if (key->curve == NULL ||
      !uECC_make_key(key->public_key, key->private_key, key->curve)) {
    free(key);
    return NULL;
  }
  return key;
}

void ecdsa_p256_bench_key_destroy(struct ecdsa_p256_bench_key* key)
{
  if (key == NULL) {
    return;
  }
  {
    volatile uint8_t* bytes = (volatile uint8_t*)key;
    size_t index;
    for (index = 0; index < sizeof(*key); ++index) {
      bytes[index] = 0;
    }
  }
  free(key);
}

int ecdsa_p256_bench_sign(struct ecdsa_p256_bench_key* key,
                          const uint8_t digest[32], uint8_t* signature,
                          size_t* signature_size)
{
  if (key == NULL || digest == NULL || signature == NULL ||
      signature_size == NULL ||
      *signature_size < ECDSA_P256_SIGNATURE_SIZE) {
    return -1;
  }
  if (!uECC_sign(key->private_key, digest, 32, signature, key->curve)) {
    return -1;
  }
  *signature_size = ECDSA_P256_SIGNATURE_SIZE;
  return 0;
}

int ecdsa_p256_bench_verify(struct ecdsa_p256_bench_key* key,
                            const uint8_t digest[32],
                            const uint8_t* signature,
                            size_t signature_size)
{
  if (key == NULL || digest == NULL || signature == NULL ||
      signature_size != ECDSA_P256_SIGNATURE_SIZE) {
    return -1;
  }
  return uECC_verify(key->public_key, digest, 32, signature, key->curve) ?
      0 : -1;
}
