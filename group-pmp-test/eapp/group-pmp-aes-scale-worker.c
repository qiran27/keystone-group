#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aes_core.h"
#include "group-pmp-common.h"

#define SCALE_BUFFER_BYTES (64 * 1024)

static uint8_t g_scale_buffer[SCALE_BUFFER_BYTES];

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

static uint64_t
digest_buffer(const uint8_t* buffer, uint64_t length) {
  uint64_t digest = UINT64_C(0xcbf29ce484222325);

  for (uint64_t i = 0; i < length; ++i) {
    digest ^= buffer[i];
    digest *= UINT64_C(0x100000001b3);
  }
  return digest;
}

static int
publish_result(struct group_pmp_scale_result* result, uint64_t state) {
  uint64_t published_state = state;

  /* Publish the state word last so the host never accepts a partial record. */
  result->status = GROUP_PMP_SCALE_STATE_EMPTY;
  if (copy_to_shared_utm(GROUP_PMP_SCALE_RESULT_OFFSET, result,
                         sizeof(*result)) != 0)
    return -1;
  __sync_synchronize();
  result->status = state;
  return copy_to_shared_utm(
      GROUP_PMP_SCALE_RESULT_OFFSET +
          offsetof(struct group_pmp_scale_result, status),
      &published_state, sizeof(published_state));
}

int
main(void) {
  struct group_pmp_scale_config config;
  struct group_pmp_scale_result result;
  uint8_t known_ciphertext[16];
  uint64_t remaining;
  void* aes;

  memset(&config, 0, sizeof(config));
  memset(&result, 0, sizeof(result));
  if (copy_from_shared(&config, GROUP_PMP_SCALE_CONFIG_OFFSET,
                       sizeof(config)) != 0)
    return 1;
  if (config.magic != GROUP_PMP_SCALE_MAGIC ||
      config.version != GROUP_PMP_SCALE_VERSION ||
      config.worker_count < GROUP_PMP_SCALE_MIN_WORKERS ||
      config.worker_count > GROUP_PMP_SCALE_MAX_WORKERS ||
      config.worker_index >= config.worker_count ||
      config.lane_id >= GROUP_PMP_SCALE_LANES ||
      config.lane_depth == 0 || config.lane_rank >= config.lane_depth ||
      config.assigned_bytes == 0 || (config.assigned_bytes & UINT64_C(15)))
    return 2;

  aes = aes_encrypt_init(kAes128Key, sizeof(kAes128Key));
  if (aes == NULL)
    return 3;
  aes_encrypt(aes, kKnownPlaintext, known_ciphertext);
  result.known_answer_ok =
      memcmp(known_ciphertext, kKnownCiphertext, sizeof(known_ciphertext)) == 0;
  if (!result.known_answer_ok) {
    aes_encrypt_deinit(aes);
    return 4;
  }

  for (uint64_t i = 0; i < sizeof(g_scale_buffer); ++i)
    g_scale_buffer[i] = (uint8_t)(
        (i * UINT64_C(131) + config.seed + config.worker_index) & 0xff);

  result.magic = GROUP_PMP_SCALE_MAGIC;
  result.version = GROUP_PMP_SCALE_VERSION;
  result.worker_index = config.worker_index;
  result.worker_count = config.worker_count;
  result.lane_id = config.lane_id;
  result.assigned_bytes = config.assigned_bytes;
  if (publish_result(&result, GROUP_PMP_SCALE_STATE_STARTED) != 0) {
    aes_encrypt_deinit(aes);
    return 5;
  }

  remaining = config.assigned_bytes;
  result.start_cycle = group_pmp_rdcycle();
  while (remaining != 0) {
    uint64_t chunk = remaining > sizeof(g_scale_buffer) ?
        sizeof(g_scale_buffer) : remaining;

    for (uint64_t offset = 0; offset < chunk; offset += 16)
      aes_encrypt(aes, &g_scale_buffer[offset], &g_scale_buffer[offset]);
    remaining -= chunk;
  }
  result.end_cycle = group_pmp_rdcycle();

  result.compute_cycles = result.end_cycle - result.start_cycle;
  result.digest = digest_buffer(g_scale_buffer, sizeof(g_scale_buffer));
  aes_encrypt_deinit(aes);

  if (publish_result(&result, GROUP_PMP_SCALE_STATE_COMPLETED) != 0)
    return 6;
  return 0;
}
