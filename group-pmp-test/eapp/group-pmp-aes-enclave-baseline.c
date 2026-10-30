#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aes_core.h"
#include "group-pmp-aes-baseline-shared.h"
#include "group-pmp-common.h"

static uint8_t g_input[GROUP_PMP_AES_BASELINE_BYTES]
    __attribute__((aligned(GROUP_PMP_AES_BASELINE_PAGE_SIZE)));
static uint8_t g_output[GROUP_PMP_AES_BASELINE_BYTES]
    __attribute__((aligned(GROUP_PMP_AES_BASELINE_PAGE_SIZE)));

static const uint8_t kAes128Key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t kKnownPlaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static const uint8_t kKnownCiphertext[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
};

static void
fill_plaintext(uint8_t* data, size_t length) {
  for (size_t index = 0; index < length; ++index)
    data[index] = (uint8_t)(((uint64_t)index * UINT64_C(131) +
                            UINT64_C(0x5a)) & UINT64_C(0xff));
}

static uint64_t
checksum64(const uint8_t* data, size_t length) {
  uint64_t value = UINT64_C(1469598103934665603);

  for (size_t index = 0; index < length; ++index) {
    value ^= data[index];
    value *= UINT64_C(1099511628211);
  }
  return value;
}

static uint64_t
sequential_read64(const uint8_t* data, size_t length) {
  const volatile uint64_t* words =
      (const volatile uint64_t*)(const void*)data;
  uint64_t value = 0;
  size_t index;

  for (index = 0; index < length / sizeof(*words); ++index)
    value += words[index] ^ (uint64_t)index;
  return value;
}

static void
sequential_write64(uint8_t* data, size_t length, uint64_t seed) {
  volatile uint64_t* words = (volatile uint64_t*)(void*)data;
  size_t index;

  for (index = 0; index < length / sizeof(*words); ++index)
    words[index] = seed ^ (uint64_t)index * UINT64_C(0x9e3779b97f4a7c15);
}

static void
sequential_copy64(uint8_t* output, const uint8_t* input, size_t length) {
  volatile uint64_t* destination = (volatile uint64_t*)(void*)output;
  const volatile uint64_t* source =
      (const volatile uint64_t*)(const void*)input;
  size_t index;

  for (index = 0; index < length / sizeof(*source); ++index)
    destination[index] = source[index];
}

static uint64_t
page_stride_read(const uint8_t* data, size_t length, uint64_t* accesses) {
  const volatile uint8_t* bytes = (const volatile uint8_t*)data;
  uint64_t value = 0;
  uint64_t count = 0;
  uint64_t pass;
  size_t offset;

  for (pass = 0; pass < 64; ++pass) {
    for (offset = 0; offset < length;
         offset += GROUP_PMP_AES_BASELINE_PAGE_SIZE) {
      value += bytes[offset] + pass;
      count++;
    }
  }
  *accesses = count;
  return value;
}

int
main(void) {
  struct group_pmp_aes_baseline_result result;
  uint8_t known_ciphertext[sizeof(kKnownCiphertext)];
  uint8_t hot_block[sizeof(kKnownPlaintext)];
  void* aes;

  memset(&result, 0, sizeof(result));
  fill_plaintext(g_input, sizeof(g_input));
  aes = aes_encrypt_init(kAes128Key, sizeof(kAes128Key));
  if (aes == NULL)
    return 1;

  aes_encrypt(aes, kKnownPlaintext, known_ciphertext);
  result.known_answer_ok =
      memcmp(known_ciphertext, kKnownCiphertext,
             sizeof(kKnownCiphertext)) == 0;
  if (!result.known_answer_ok) {
    aes_encrypt_deinit(aes);
    return 2;
  }

  for (uint64_t warmup = 0; warmup < GROUP_PMP_AES_BASELINE_WARMUP;
       ++warmup)
    aes_encrypt_blocks(aes, g_input, g_output,
                       GROUP_PMP_AES_BASELINE_BYTES / 16);

  for (uint64_t sample = 0; sample < GROUP_PMP_AES_BASELINE_SAMPLES;
       ++sample) {
    uint64_t start_time = group_pmp_rdtime();
    uint64_t start = group_pmp_rdcycle();
    aes_encrypt_blocks(aes, g_input, g_output,
                       GROUP_PMP_AES_BASELINE_BYTES / 16);
    result.sample_cycles[sample] = group_pmp_rdcycle() - start;
    result.sample_time_ticks[sample] = group_pmp_rdtime() - start_time;
  }

  memcpy(hot_block, kKnownPlaintext, sizeof(hot_block));
  for (uint64_t sample = 0; sample < GROUP_PMP_AES_BASELINE_SAMPLES;
       ++sample) {
    uint64_t start_time = group_pmp_rdtime();
    uint64_t start = group_pmp_rdcycle();

    for (uint64_t block = 0;
         block < GROUP_PMP_AES_BASELINE_BYTES / sizeof(hot_block); ++block)
      aes_encrypt(aes, hot_block, hot_block);
    result.hot_block_cycles[sample] = group_pmp_rdcycle() - start;
    result.hot_block_time_ticks[sample] = group_pmp_rdtime() - start_time;
  }

  /*
   * Memory-path diagnostics run after the fair AES samples, so they cannot
   * warm or evict data used by the native/enclave AES comparison.
   */
  for (uint64_t sample = 0; sample < GROUP_PMP_AES_BASELINE_SAMPLES;
       ++sample) {
    uint64_t accesses = 0;
    uint64_t start_time;
    uint64_t start;

    __sync_synchronize();
    start_time = group_pmp_rdtime();
    start = group_pmp_rdcycle();
    result.epm_read_sink ^= sequential_read64(g_input, sizeof(g_input));
    result.epm_read_cycles[sample] = group_pmp_rdcycle() - start;
    result.epm_read_time_ticks[sample] = group_pmp_rdtime() - start_time;

    __sync_synchronize();
    start_time = group_pmp_rdtime();
    start = group_pmp_rdcycle();
    sequential_write64(g_output, sizeof(g_output),
                       UINT64_C(0x454e434c41564500) ^ sample);
    result.epm_write_cycles[sample] = group_pmp_rdcycle() - start;
    result.epm_write_time_ticks[sample] = group_pmp_rdtime() - start_time;

    __sync_synchronize();
    start_time = group_pmp_rdtime();
    start = group_pmp_rdcycle();
    sequential_copy64(g_output, g_input, sizeof(g_input));
    result.epm_copy_cycles[sample] = group_pmp_rdcycle() - start;
    result.epm_copy_time_ticks[sample] = group_pmp_rdtime() - start_time;

    __sync_synchronize();
    start_time = group_pmp_rdtime();
    start = group_pmp_rdcycle();
    result.epm_stride_sink ^=
        page_stride_read(g_input, sizeof(g_input), &accesses);
    result.epm_page_stride_cycles[sample] = group_pmp_rdcycle() - start;
    result.epm_page_stride_time_ticks[sample] =
        group_pmp_rdtime() - start_time;
    result.epm_page_stride_accesses = accesses;

    __sync_synchronize();
    start_time = group_pmp_rdtime();
    start = group_pmp_rdcycle();
    result.checksum ^= checksum64(g_input, sizeof(g_input));
    result.digest_cycles[sample] = group_pmp_rdcycle() - start;
    result.digest_time_ticks[sample] = group_pmp_rdtime() - start_time;
  }

  /* Restore the canonical AES output after write/copy diagnostics. */
  aes_encrypt_blocks(aes, g_input, g_output,
                     GROUP_PMP_AES_BASELINE_BYTES / 16);
  result.magic = GROUP_PMP_AES_BASELINE_MAGIC;
  result.version = GROUP_PMP_AES_BASELINE_VERSION;
  result.status = 1;
  result.bytes = GROUP_PMP_AES_BASELINE_BYTES;
  result.samples = GROUP_PMP_AES_BASELINE_SAMPLES;
  result.warmup = GROUP_PMP_AES_BASELINE_WARMUP;
  result.checksum = checksum64(g_output, sizeof(g_output));
  result.epm_read_sink ^= hot_block[0];
  result.build_tag = GROUP_PMP_AES_BUILD_TAG;
  result.input_alignment =
      (uintptr_t)g_input & (GROUP_PMP_AES_BASELINE_PAGE_SIZE - 1);
  result.output_alignment =
      (uintptr_t)g_output & (GROUP_PMP_AES_BASELINE_PAGE_SIZE - 1);
  result.hidden_copy_bytes = 0;
  aes_encrypt_deinit(aes);

  __sync_synchronize();
  if (copy_to_shared_utm(GROUP_PMP_AES_BASELINE_RESULT_OFFSET,
                         &result, sizeof(result)) != 0)
    return 3;
  return 0;
}
