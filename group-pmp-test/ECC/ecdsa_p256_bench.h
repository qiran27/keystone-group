#ifndef GROUP_PMP_ECDSA_P256_BENCH_H
#define GROUP_PMP_ECDSA_P256_BENCH_H

#include <stddef.h>
#include <stdint.h>

struct ecdsa_p256_bench_key;

struct ecdsa_p256_bench_key* ecdsa_p256_bench_key_create(void);
void ecdsa_p256_bench_key_destroy(struct ecdsa_p256_bench_key* key);

int ecdsa_p256_bench_sign(struct ecdsa_p256_bench_key* key,
                          const uint8_t digest[32], uint8_t* signature,
                          size_t* signature_size);
int ecdsa_p256_bench_verify(struct ecdsa_p256_bench_key* key,
                            const uint8_t digest[32],
                            const uint8_t* signature,
                            size_t signature_size);

#endif
