#ifndef GROUP_PMP_SM2_BENCH_H
#define GROUP_PMP_SM2_BENCH_H

#include <stddef.h>
#include <stdint.h>

struct sm2_bench_key;

struct sm2_bench_key* sm2_bench_key_create(void);
void sm2_bench_key_destroy(struct sm2_bench_key* key);

int sm2_bench_sign(struct sm2_bench_key* key, const uint8_t digest[32],
                   uint8_t* signature, size_t* signature_size);
int sm2_bench_verify(struct sm2_bench_key* key, const uint8_t digest[32],
                     const uint8_t* signature, size_t signature_size);

#endif
