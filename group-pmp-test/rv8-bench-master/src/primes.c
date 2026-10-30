#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#ifdef RV8_BENCH_LIBRARY
#include <string.h>
/* Upstream bitmap sieve, with initialized storage and defined 64-bit shifts. */
int rv8_primes_run(uint64_t* bitmap, size_t bytes, uint64_t* result) {
    if (!bitmap || bytes < 16 || bytes > 65536 || (bytes & 7)) return -1;
    uint64_t limit = bytes * 8 - 1;
    memset(bitmap, 0, bytes);
    for (uint64_t p = 2; p <= limit / p; ++p) {
        if (bitmap[p >> 6] & (UINT64_C(1) << (p & 63))) continue;
        for (uint64_t n = 2 * p; n <= limit; n += p)
            bitmap[n >> 6] |= UINT64_C(1) << (n & 63);
    }
    uint64_t last = limit;
    while (last > 1 && (bitmap[last >> 6] & (UINT64_C(1) << (last & 63)))) --last;
    if (last < 2) return -1;
    for (uint64_t p = 2; p <= last / p; ++p) if (last % p == 0) return -1;
    *result = last;
    return 0;
}
#else

#define test(p) (primes[p >> 6] & 1 << (p & 0x3f))
#define set(p) (primes[p >> 6] |= 1 << (p & 0x3f))
#define is_prime(p) !test(p)

int main()
{
	int limit = 33333333;
	size_t primes_size = ((limit >> 6) + 1) * sizeof(uint64_t);
	uint64_t *primes = (uint64_t*)malloc(primes_size);
	int64_t p = 2, sqrt_limit = (int64_t)sqrt(limit);
	while (p <= limit >> 1) {
		for (int64_t n = 2 * p; n <= limit; n += p) if (!test(n)) set(n);
		while (++p <= sqrt_limit && test(p));
	}
	for (int i = limit; i > 0; i--) {
		if (is_prime(i)) {
			printf("%d\n", i);
			return 0;
		}
	}
};
#endif
