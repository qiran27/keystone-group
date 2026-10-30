#include "rv8-kernels.h"
#include <string.h>

#ifndef RV8_PROFILE
#error RV8_PROFILE must identify the enclave workload (1..8)
#endif
#if RV8_PROFILE < 1 || RV8_PROFILE > 8
#error Invalid RV8_PROFILE
#endif
static const volatile char marker[] __attribute__((used)) = RV8_BENCH_MARKER;
static struct rv8_kernel_stats stats;
static uint8_t output[RV8_KERNEL_BLOCK_BYTES + 4096] __attribute__((aligned(64), unused));
#if RV8_PROFILE >= 2 && RV8_PROFILE <= 4
static uint8_t restored[RV8_KERNEL_BLOCK_BYTES] __attribute__((aligned(64)));
#endif
/* Upstream AES/miniz use a bounded private arena, not the SDK's unmapped heap. */
static uint8_t arena[1048576] __attribute__((aligned(64)));
static size_t arena_used;
struct allocation { size_t size; size_t reserved; };
void* rv8_bench_workspace_alloc(size_t size) {
  const size_t header = sizeof(struct allocation);
  size_t amount;
  struct allocation* block;
  if (size > sizeof(arena) - header - 15) return NULL;
  amount = (size + header + 15) & ~(size_t)15;
  if (amount > sizeof(arena) - arena_used) return NULL;
  block = (struct allocation*)(void*)(arena + arena_used);
  block->size = size;
  arena_used += amount;
  return block + 1;
}
void rv8_bench_workspace_free(void* ptr) { (void)ptr; }
void* rv8_bench_workspace_realloc(void* ptr, size_t size) {
  void* next;
  size_t old;
  if (!ptr) return rv8_bench_workspace_alloc(size);
  if (!size) return NULL;
  old = ((struct allocation*)ptr)[-1].size;
  next = rv8_bench_workspace_alloc(size);
  if (next) memcpy(next, ptr, old < size ? old : size);
  return next;
}

void* rv8_aes_encrypt_init(const uint8_t*, size_t);
void* rv8_aes_decrypt_init(const uint8_t*, size_t);
void rv8_aes_encrypt(void*, const uint8_t*, uint8_t*);
void rv8_aes_decrypt(void*, const uint8_t*, uint8_t*);
void rv8_cf_norx32_encrypt(const uint8_t*, const uint8_t*, const uint8_t*, size_t,
    const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, uint8_t*);
int rv8_cf_norx32_decrypt(const uint8_t*, const uint8_t*, const uint8_t*, size_t,
    const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, uint8_t*);
void rv8_qsort(void*, size_t, size_t, int (*)(const void*, const void*));
struct sha512_ctx_t { uint64_t chain[8]; uint8_t block[128]; uint64_t nbytes; };
void rv8_sha512_init(struct sha512_ctx_t*);
void rv8_sha512_update(struct sha512_ctx_t*, const unsigned char*, uint64_t);
void rv8_sha512_final(struct sha512_ctx_t*, uint8_t*);
int mz_compress(unsigned char*, unsigned long*, const unsigned char*, unsigned long);
int mz_uncompress(unsigned char*, unsigned long*, const unsigned char*, unsigned long);
int rv8_bigint_run(size_t, uint64_t*);
int rv8_dhrystone_run(unsigned int);
int rv8_primes_run(uint64_t*, size_t, uint64_t*);

#if RV8_PROFILE == 3 || RV8_PROFILE == 4
static const uint8_t key[16] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
#endif
#if RV8_PROFILE == 5
static int compare_u32(const void* left, const void* right) {
  uint32_t a, b;
  memcpy(&a, left, sizeof(a)); memcpy(&b, right, sizeof(b));
  return (a > b) - (a < b);
}
#endif
static uint64_t __attribute__((unused)) checksum(const uint8_t* data, size_t length) {
  uint64_t value = UINT64_C(1469598103934665603);
  for (size_t i = 0; i < length; ++i)
    value = (value ^ data[i]) * UINT64_C(1099511628211);
  return value;
}

/* The caller's plaintext is unchanged. Validation is part of kernel cost. */
int rv8_kernel_process(const uint8_t* input, size_t length) {
  if (marker[0] != 'k' || !input || !length || (length & 15)) return -1;
  for (size_t done = 0; done < length;) {
    size_t n = length - done;
    const uint8_t* source = input + done;
    uint64_t digest;
    if (n > RV8_KERNEL_BLOCK_BYTES) n = RV8_KERNEL_BLOCK_BYTES;
    arena_used = 0;
#if RV8_PROFILE == 1
    (void)source;
    if (rv8_bigint_run(n, &digest)) return -1;
#elif RV8_PROFILE == 2
    unsigned long compressed = sizeof(output), recovered = n;
    if (mz_compress(output, &compressed, source, n) ||
        mz_uncompress(restored, &recovered, output, compressed) ||
        recovered != n || memcmp(restored, source, n)) return -1;
    digest = checksum(output, compressed);
#elif RV8_PROFILE == 3
    uint8_t nonce[8], tag[16];
    const uint64_t sequence = stats.blocks + 1;
    memcpy(nonce, &sequence, sizeof(nonce));
    rv8_cf_norx32_encrypt(key, nonce, NULL, 0, source, n, NULL, 0, output, tag);
    if (rv8_cf_norx32_decrypt(key, nonce, NULL, 0, output, n, NULL, 0, tag,
                            restored) || memcmp(restored, source, n)) return -1;
    digest = checksum(tag, sizeof(tag));
#elif RV8_PROFILE == 4
    void* enc = rv8_aes_encrypt_init(key, sizeof(key));
    void* dec = rv8_aes_decrypt_init(key, sizeof(key));
    if (!enc || !dec) return -1;
    for (size_t i = 0; i < n; i += 16) rv8_aes_encrypt(enc, source + i, output + i);
    for (size_t i = 0; i < n; i += 16) rv8_aes_decrypt(dec, output + i, restored + i);
    if (memcmp(restored, source, n)) return -1;
    digest = checksum(output, n);
#elif RV8_PROFILE == 5
    uint32_t* words = (uint32_t*)(void*)output;
    uint64_t before_sum = 0, after_sum = 0;
    uint32_t before_xor = 0, after_xor = 0;
    memcpy(output, source, n);
    for (size_t i = 0; i < n / 4; ++i) { before_sum += words[i]; before_xor ^= words[i]; }
    rv8_qsort(words, n / 4, 4, compare_u32);
    for (size_t i = 0; i < n / 4; ++i) {
      if (i && words[i-1] > words[i]) return -1;
      after_sum += words[i]; after_xor ^= words[i];
    }
    if (before_sum != after_sum || before_xor != after_xor) return -1;
    digest = checksum(output, n);
#elif RV8_PROFILE == 6
    struct sha512_ctx_t ctx;
    rv8_sha512_init(&ctx); rv8_sha512_update(&ctx, source, n);
    rv8_sha512_final(&ctx, output);
    digest = checksum(output, 64);
#elif RV8_PROFILE == 7
    (void)source;
    if (rv8_dhrystone_run((unsigned)n)) return -1;
    digest = n;
#elif RV8_PROFILE == 8
    (void)source;
    if (rv8_primes_run((uint64_t*)(void*)output, n, &digest)) return -1;
#endif
    stats.digest = (stats.digest ^ digest) * UINT64_C(1099511628211);
    stats.bytes += n; ++stats.blocks; done += n;
  }
  return 0;
}

int rv8_kernel_init(void) {
#if RV8_PROFILE == 4
  static const uint8_t aes_plain[16] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
  };
  static const uint8_t aes_cipher[16] = {
    0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
    0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
  };
#endif
#if RV8_PROFILE == 6
  static const uint8_t sha_empty[64] = {
    0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,
    0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,
    0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,
    0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e
  };
#endif
  uint8_t sample[64];
  memset(&stats, 0, sizeof(stats));
  for (size_t i = 0; i < sizeof(sample); ++i) sample[i] = (uint8_t)(i * 37);
#if RV8_PROFILE == 4
  arena_used = 0;
  void* enc = rv8_aes_encrypt_init(key, sizeof(key));
  if (!enc) return -1;
  rv8_aes_encrypt(enc, aes_plain, output);
  if (memcmp(output, aes_cipher, 16)) return -1;
#elif RV8_PROFILE == 6
  struct sha512_ctx_t ctx;
  rv8_sha512_init(&ctx); rv8_sha512_final(&ctx, output);
  if (memcmp(output, sha_empty, 64)) return -1;
#elif RV8_PROFILE == 3
  uint8_t nonce[8] = {0}, tag[16];
  rv8_cf_norx32_encrypt(key, nonce, NULL, 0, sample, sizeof(sample), NULL, 0, output, tag);
  tag[0] ^= 1;
  if (!rv8_cf_norx32_decrypt(key, nonce, NULL, 0, output, sizeof(sample), NULL, 0, tag,
                           restored)) return -1;
#endif
  if (rv8_kernel_process(sample, sizeof(sample))) return -1;
  memset(&stats, 0, sizeof(stats));
  stats.magic = RV8_RESULT_MAGIC; stats.version = 2; stats.profile = RV8_PROFILE;
  stats.digest = UINT64_C(1469598103934665603); stats.validated = 1;
  return 0;
}
void rv8_kernel_account(uint64_t cpu_ticks, uint64_t elapsed_ticks) {
  stats.cpu_ticks += cpu_ticks; stats.elapsed_ticks += elapsed_ticks;
}
void rv8_kernel_get_stats(struct rv8_kernel_stats* result) { *result = stats; }
