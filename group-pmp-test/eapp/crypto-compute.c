#include "crypto-compute.h"
#include "benchmark-cipher.h"
#include "group-pmp-crypto.h"
#include <stddef.h>
#include <string.h>

static uint8_t plain[CRYPTO_COMPUTE_BLOCK_BYTES] __attribute__((aligned(4096)));
static uint8_t cipher[CRYPTO_COMPUTE_BLOCK_BYTES] __attribute__((aligned(4096)));
static uint8_t output[CRYPTO_COMPUTE_BLOCK_BYTES] __attribute__((aligned(4096)));

static void wipe(uint8_t* p, size_t n) {
  volatile uint8_t* v = p;
  while (n--) *v++ = 0;
}

int crypto_compute_run(const struct crypto_compute_config* cfg,
                       crypto_compute_clock clock, struct crypto_compute_result* r) {
  struct group_pmp_crypto_context ecb;
  struct benchmark_aead_identity id;
  struct crypto_compute_stamp before, after;
  uint8_t key[32], tag[16];
  uint64_t done = 0, sequence = 1;
  int initialized = 0, rc = -1;
  if (!r) return -1;
  memset(r, 0, sizeof(*r));
  memset(&ecb, 0, sizeof(ecb));
  memset(&id, 0, sizeof(id));
  r->magic = CRYPTO_COMPUTE_MAGIC;
  r->version = CRYPTO_COMPUTE_VERSION;
  r->error_code = 1;
  if (!cfg || !clock || cfg->magic != CRYPTO_COMPUTE_MAGIC ||
      cfg->version != CRYPTO_COMPUTE_VERSION || cfg->algorithm > BENCHMARK_CHACHA_POLY ||
      (cfg->operation != GROUP_PMP_CRYPTO_ENCRYPT && cfg->operation != GROUP_PMP_CRYPTO_DECRYPT) ||
      !cfg->total_bytes || cfg->total_bytes > UINT64_C(500000000) ||
      cfg->total_bytes % 16 || !cfg->sample) return -1;
  r->algorithm = cfg->algorithm; r->operation = cfg->operation;
  r->total_bytes = cfg->total_bytes; r->sample = cfg->sample;
  for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)i;
  for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)(i * 131U + 0x5aU);
  r->error_code = 2;
  if (cfg->algorithm == BENCHMARK_AES_ECB) {
    static const uint8_t known_plain[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    static const uint8_t known_cipher[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    if (group_pmp_crypto_init(&ecb, GROUP_PMP_CRYPTO_AES_128_ECB, key, 16)) goto finish;
    initialized = 1;
    if (group_pmp_crypto_self_test(&ecb) ||
        group_pmp_crypto_transform(&ecb, GROUP_PMP_CRYPTO_ENCRYPT, known_plain, cipher, 16) ||
        memcmp(cipher, known_cipher, 16)) goto finish;
  } else {
    if (benchmark_aead_init((unsigned)cfg->algorithm, key)) goto finish;
    initialized = 1;
  }
  id.run_id = cfg->sample; id.worker = 0; id.workload = 1;
  id.logical_size = cfg->total_bytes;
  /* Warm up one complete encrypt/decrypt pair outside the measured intervals. */
  id.length = cfg->total_bytes < sizeof(plain) ? cfg->total_bytes : sizeof(plain);
  id.sequence = sequence++;
  if (cfg->algorithm == BENCHMARK_AES_ECB) {
    if (group_pmp_crypto_transform(&ecb, GROUP_PMP_CRYPTO_ENCRYPT, plain, cipher, (size_t)id.length) ||
        group_pmp_crypto_transform(&ecb, GROUP_PMP_CRYPTO_DECRYPT, cipher, output, (size_t)id.length)) goto finish;
  } else if (benchmark_aead_seal(&id, plain, cipher, tag) ||
             benchmark_aead_open(&id, cipher, tag, output)) goto finish;
  if (memcmp(plain, output, (size_t)id.length)) goto finish;
  while (done < cfg->total_bytes) {
    const size_t length = (size_t)(cfg->total_bytes - done < sizeof(plain) ? cfg->total_bytes - done : sizeof(plain));
    id.length = length; id.logical_offset = done; id.file_offset = done;
    id.sequence = sequence++;
    r->error_code = 3;
    /* Decryption input generation is never charged to decryption throughput. */
    if (cfg->operation == GROUP_PMP_CRYPTO_DECRYPT) {
      if (cfg->algorithm == BENCHMARK_AES_ECB) {
        if (group_pmp_crypto_transform(&ecb, GROUP_PMP_CRYPTO_ENCRYPT, plain, cipher, length)) goto finish;
      } else if (benchmark_aead_seal(&id, plain, cipher, tag)) goto finish;
    }
    r->error_code = 4;
    if (clock(&before)) goto finish;
    if (cfg->algorithm == BENCHMARK_AES_ECB) {
      rc = group_pmp_crypto_transform(&ecb, (uint32_t)cfg->operation,
          cfg->operation == GROUP_PMP_CRYPTO_ENCRYPT ? plain : cipher,
          cfg->operation == GROUP_PMP_CRYPTO_ENCRYPT ? cipher : output, length);
    } else if (cfg->operation == GROUP_PMP_CRYPTO_ENCRYPT) {
      rc = benchmark_aead_seal(&id, plain, cipher, tag);
    } else {
      rc = benchmark_aead_open(&id, cipher, tag, output);
    }
    if (clock(&after) || rc || after.wall_ticks <= before.wall_ticks ||
        after.cpu_ticks <= before.cpu_ticks || after.cycles < before.cycles ||
        after.cpu_ticks - before.cpu_ticks > after.wall_ticks - before.wall_ticks) goto finish;
    r->wall_ticks += after.wall_ticks - before.wall_ticks;
    r->cpu_ticks += after.cpu_ticks - before.cpu_ticks;
    r->cycles += after.cycles - before.cycles;
    r->error_code = 5;
    if (cfg->operation == GROUP_PMP_CRYPTO_ENCRYPT) {
      if (cfg->algorithm == BENCHMARK_AES_ECB) {
        if (group_pmp_crypto_transform(&ecb, GROUP_PMP_CRYPTO_DECRYPT, cipher, output, length)) goto finish;
      } else if (benchmark_aead_open(&id, cipher, tag, output)) goto finish;
    }
    if (memcmp(plain, output, length)) goto finish;
    done += length; r->processed_bytes = done; r->blocks++;
  }
  r->validated = 1; r->error_code = 0;
finish:
  if (initialized) {
    if (cfg->algorithm == BENCHMARK_AES_ECB) group_pmp_crypto_deinit(&ecb);
    else benchmark_aead_free();
  }
  wipe(key, sizeof(key)); wipe(tag, sizeof(tag));
  wipe(plain, sizeof(plain)); wipe(cipher, sizeof(cipher)); wipe(output, sizeof(output));
  return r->validated ? 0 : -1;
}
