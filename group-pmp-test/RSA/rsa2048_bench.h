#ifndef GROUP_PMP_RSA2048_BENCH_H
#define GROUP_PMP_RSA2048_BENCH_H

#include <stddef.h>
#include <stdint.h>

struct rsa2048_bench_key;

struct rsa2048_bench_key* rsa2048_bench_key_create(void);
void rsa2048_bench_key_destroy(struct rsa2048_bench_key* key);

int rsa2048_bench_sign(struct rsa2048_bench_key* key,
                       const uint8_t digest[32], uint8_t* signature,
                       size_t* signature_size);
int rsa2048_bench_verify(struct rsa2048_bench_key* key,
                         const uint8_t digest[32], const uint8_t* signature,
                         size_t signature_size);

#endif
