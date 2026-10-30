#include "media-io.h"
#include "group-pmp-crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int round_trip(struct group_pmp_crypto_context* crypto, size_t length) {
  struct group_pmp_media_frame frame = {0};
  uint8_t* plain = malloc(length);
  uint8_t* cipher = malloc(length + 16);
  uint8_t* recovered = malloc(length);
  size_t cipher_bytes;
  size_t i;
  int result = -1;
  if (!plain || !cipher || !recovered ||
      group_pmp_media_cipher_bytes(length, &cipher_bytes) != 0)
    goto done;
  for (i = 0; i < length; ++i)
    plain[i] = (uint8_t)(i * 37U + 11U);
  memset(cipher, 0xa5, length + 16);
  memset(recovered, 0, length);
  frame.magic = GROUP_PMP_MEDIA_FRAME_MAGIC;
  frame.version = GROUP_PMP_MEDIA_FRAME_VERSION;
  frame.codec = GROUP_PMP_MEDIA_JP2_ENCODE;
  frame.task_id = 7;
  frame.sequence = 3;
  frame.frame_bytes = length;
  frame.plain_bytes = length;
  frame.cipher_bytes = cipher_bytes;
  frame.key_epoch = 1;
  frame.final_chunk = 1;
  if (group_pmp_media_encrypt_chunk(crypto, &frame, plain, cipher,
                                    cipher_bytes) != 0 ||
      group_pmp_media_decrypt_chunk(crypto, &frame, cipher, cipher_bytes,
                                    recovered,
                                    length) != 0 ||
      memcmp(plain, recovered, length) != 0)
    goto done;
  if (group_pmp_media_decrypt_chunk(crypto, &frame, cipher,
                                    cipher_bytes - 1, recovered, length) == 0)
    goto done;
  frame.plain_bytes = length + 1;
  if (group_pmp_media_decrypt_chunk(crypto, &frame, cipher, cipher_bytes,
                                    recovered,
                                    length) == 0)
    goto done;
  result = 0;
done:
  free(plain);
  free(cipher);
  free(recovered);
  return result;
}

struct transport_test {
  struct group_pmp_media_frame frames[4];
  uint8_t* cipher[4];
  size_t count;
  size_t next;
};

static int publish(void* opaque, const struct group_pmp_media_frame* frame,
                   const uint8_t* cipher) {
  struct transport_test* state = opaque;
  size_t index = state->count;
  if (index == 4) return -1;
  state->cipher[index] = malloc((size_t)frame->cipher_bytes);
  if (!state->cipher[index]) return -1;
  memcpy(state->cipher[index], cipher, (size_t)frame->cipher_bytes);
  state->frames[index] = *frame;
  ++state->count;
  return 0;
}

static int receive(void* opaque, struct group_pmp_media_frame* frame,
                   uint8_t* cipher, size_t capacity) {
  struct transport_test* state = opaque;
  size_t index = state->next;
  if (index >= state->count || state->frames[index].cipher_bytes > capacity)
    return -1;
  *frame = state->frames[index];
  memcpy(cipher, state->cipher[index], (size_t)frame->cipher_bytes);
  ++state->next;
  return 0;
}

static int stream_round_trip(struct group_pmp_crypto_context* crypto) {
  const size_t length = GROUP_PMP_MEDIA_DATA_BUFFER_BYTES + 17;
  struct transport_test state = {0};
  uint8_t* plain = malloc(length);
  uint8_t* decoded = malloc(length);
  uint8_t* utm = malloc(GROUP_PMP_MEDIA_DATA_BUFFER_BYTES);
  size_t recovered = 0;
  size_t i;
  int result = -1;
  if (!plain || !decoded || !utm) goto done;
  for (i = 0; i < length; ++i) plain[i] = (uint8_t)(i * 13U);
  if (group_pmp_media_write_stream(crypto, GROUP_PMP_MEDIA_JP2_ENCODE,
                                    9, 100, 1, plain, length, utm,
                                    GROUP_PMP_MEDIA_DATA_BUFFER_BYTES,
                                    publish, &state) != 0 ||
      state.count != 2 || state.frames[0].final_chunk ||
      !state.frames[1].final_chunk ||
      group_pmp_media_read_stream(crypto, GROUP_PMP_MEDIA_JP2_ENCODE,
                                   9, 100, 1, decoded, length, &recovered,
                                   utm, GROUP_PMP_MEDIA_DATA_BUFFER_BYTES,
                                   receive, &state) != 0 ||
      recovered != length || memcmp(plain, decoded, length))
    goto done;
  state.next = 0;
  ++state.frames[1].chunk_index;
  if (group_pmp_media_read_stream(crypto, GROUP_PMP_MEDIA_JP2_ENCODE,
                                   9, 100, 1, decoded, length, &recovered,
                                   utm, GROUP_PMP_MEDIA_DATA_BUFFER_BYTES,
                                   receive, &state) == 0 || recovered != 0 ||
      decoded[0] != 0 || decoded[GROUP_PMP_MEDIA_DATA_BUFFER_BYTES - 1] != 0)
    goto done;
  result = 0;
done:
  for (i = 0; i < state.count; ++i) free(state.cipher[i]);
  free(utm);
  free(decoded);
  free(plain);
  return result;
}

int main(void) {
  struct group_pmp_crypto_context crypto;
  const uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8,
                           9, 10, 11, 12, 13, 14, 15, 16};
  const size_t sizes[] = {1, 15, 16, 17, 4096,
                          GROUP_PMP_MEDIA_DATA_BUFFER_BYTES - 1,
                          GROUP_PMP_MEDIA_DATA_BUFFER_BYTES};
  size_t i;
  if (group_pmp_crypto_init(&crypto, GROUP_PMP_CRYPTO_AES_128_ECB,
                            key, sizeof(key)) != 0)
    return 1;
  for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
    if (round_trip(&crypto, sizes[i]) != 0) {
      fprintf(stderr, "media I/O round trip failed: %zu\n", sizes[i]);
      group_pmp_crypto_deinit(&crypto);
      return 1;
    }
  if (stream_round_trip(&crypto) != 0) {
    fprintf(stderr, "media I/O streaming round trip failed\n");
    group_pmp_crypto_deinit(&crypto);
    return 1;
  }
  group_pmp_crypto_deinit(&crypto);
  puts("media I/O frame tests PASS");
  return 0;
}
