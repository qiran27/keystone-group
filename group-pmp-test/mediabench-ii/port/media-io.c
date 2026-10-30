#include "media-io.h"
#include "group-pmp-crypto.h"

#include <string.h>

int group_pmp_media_frame_valid(const struct group_pmp_media_frame* frame) {
  size_t expected;
  if (!frame || frame->magic != GROUP_PMP_MEDIA_FRAME_MAGIC ||
      frame->version != GROUP_PMP_MEDIA_FRAME_VERSION ||
      frame->codec < GROUP_PMP_MEDIA_MPEG4_ENCODE ||
      frame->codec > GROUP_PMP_MEDIA_H264_DECODE ||
      !frame->task_id || !frame->sequence || !frame->key_epoch ||
      !frame->plain_bytes || frame->plain_bytes > SIZE_MAX ||
      frame->cipher_bytes > GROUP_PMP_MEDIA_DATA_BUFFER_BYTES ||
      frame->chunk_offset > frame->frame_bytes ||
      frame->plain_bytes > frame->frame_bytes - frame->chunk_offset ||
      frame->final_chunk > 1 ||
      (frame->final_chunk != 0) !=
          (frame->plain_bytes == frame->frame_bytes - frame->chunk_offset) ||
      group_pmp_media_cipher_bytes((size_t)frame->plain_bytes, &expected) != 0 ||
      frame->cipher_bytes != expected)
    return 0;
  return 1;
}

int group_pmp_media_cipher_bytes(size_t plain_bytes, size_t* cipher_bytes) {
  if (!cipher_bytes || !plain_bytes ||
      plain_bytes > GROUP_PMP_MEDIA_DATA_BUFFER_BYTES ||
      plain_bytes > SIZE_MAX - 15)
    return -1;
  *cipher_bytes = (plain_bytes + 15) & ~(size_t)15;
  return *cipher_bytes <= GROUP_PMP_MEDIA_DATA_BUFFER_BYTES ? 0 : -1;
}

int group_pmp_media_encrypt_chunk(
    struct group_pmp_crypto_context* crypto,
    const struct group_pmp_media_frame* metadata,
    const uint8_t* private_plain, uint8_t* utm_cipher,
    size_t utm_capacity) {
  size_t whole;
  if (!crypto || !group_pmp_media_frame_valid(metadata) || !private_plain || !utm_cipher ||
      metadata->cipher_bytes > utm_capacity)
    return -1;
  whole = (size_t)metadata->plain_bytes & ~(size_t)15;
  if (whole && group_pmp_crypto_transform(crypto, GROUP_PMP_CRYPTO_ENCRYPT,
                                          private_plain, utm_cipher, whole) != 0)
    return -1;
  if (whole != metadata->plain_bytes) {
    uint8_t padded[16] = {0};
    memcpy(padded, private_plain + whole,
           (size_t)metadata->plain_bytes - whole);
    if (group_pmp_crypto_transform(crypto, GROUP_PMP_CRYPTO_ENCRYPT,
                                   padded, utm_cipher + whole, 16) != 0) {
      memset(padded, 0, sizeof(padded));
      return -1;
    }
    memset(padded, 0, sizeof(padded));
  }
  return 0;
}

int group_pmp_media_decrypt_chunk(
    struct group_pmp_crypto_context* crypto,
    const struct group_pmp_media_frame* metadata,
    const uint8_t* utm_cipher, size_t utm_capacity,
    uint8_t* private_plain,
    size_t private_capacity) {
  size_t whole;
  if (!crypto || !group_pmp_media_frame_valid(metadata) || !utm_cipher || !private_plain ||
      metadata->cipher_bytes > utm_capacity ||
      metadata->plain_bytes > private_capacity)
    return -1;
  whole = (size_t)metadata->plain_bytes & ~(size_t)15;
  if (whole && group_pmp_crypto_transform(crypto, GROUP_PMP_CRYPTO_DECRYPT,
                                          utm_cipher, private_plain, whole) != 0)
    return -1;
  if (whole != metadata->plain_bytes) {
    uint8_t padded[16] = {0};
    size_t index;
    if (group_pmp_crypto_transform(crypto, GROUP_PMP_CRYPTO_DECRYPT,
                                   utm_cipher + whole, padded, 16) != 0)
      return -1;
    for (index = (size_t)metadata->plain_bytes - whole; index < 16; ++index)
      if (padded[index] != 0) {
        memset(padded, 0, sizeof(padded));
        return -1;
      }
    memcpy(private_plain + whole, padded,
           (size_t)metadata->plain_bytes - whole);
    memset(padded, 0, sizeof(padded));
  }
  return 0;
}

int group_pmp_media_write_stream(
    struct group_pmp_crypto_context* crypto, uint64_t codec,
    uint64_t task_id, uint64_t first_sequence, uint64_t key_epoch,
    const uint8_t* private_output, size_t output_bytes,
    uint8_t* utm_cipher, size_t utm_capacity,
    group_pmp_media_publish_fn publish, void* opaque) {
  size_t offset = 0;
  uint64_t index = 0;
  if (!crypto || !private_output || !output_bytes || !utm_cipher ||
      !publish || utm_capacity < 16 || !first_sequence || !task_id ||
      !key_epoch || codec < GROUP_PMP_MEDIA_MPEG4_ENCODE ||
      codec > GROUP_PMP_MEDIA_H264_DECODE)
    return -1;
  while (offset < output_bytes) {
    struct group_pmp_media_frame frame = {0};
    size_t bytes = output_bytes - offset;
    size_t limit = utm_capacity < GROUP_PMP_MEDIA_DATA_BUFFER_BYTES ?
        utm_capacity : GROUP_PMP_MEDIA_DATA_BUFFER_BYTES;
    limit &= ~(size_t)15;
    if (!limit || index == UINT64_MAX || first_sequence > UINT64_MAX - index)
      return -1;
    if (bytes > limit) bytes = limit;
    frame.magic = GROUP_PMP_MEDIA_FRAME_MAGIC;
    frame.version = GROUP_PMP_MEDIA_FRAME_VERSION;
    frame.codec = codec;
    frame.task_id = task_id;
    frame.sequence = first_sequence + index;
    frame.chunk_index = index;
    frame.frame_bytes = output_bytes;
    frame.chunk_offset = offset;
    frame.plain_bytes = bytes;
    frame.key_epoch = key_epoch;
    frame.final_chunk = bytes == output_bytes - offset;
    if (group_pmp_media_cipher_bytes(bytes, &limit) != 0)
      return -1;
    frame.cipher_bytes = limit;
    if (group_pmp_media_encrypt_chunk(crypto, &frame,
                                      private_output + offset,
                                      utm_cipher, utm_capacity) != 0 ||
        publish(opaque, &frame, utm_cipher) != 0)
      return -1;
    offset += bytes;
    ++index;
  }
  return 0;
}

int group_pmp_media_read_stream(
    struct group_pmp_crypto_context* crypto, uint64_t codec,
    uint64_t task_id, uint64_t first_sequence, uint64_t key_epoch,
    uint8_t* private_input, size_t private_capacity,
    size_t* input_bytes, uint8_t* utm_cipher, size_t utm_capacity,
    group_pmp_media_receive_fn receive, void* opaque) {
  size_t offset = 0;
  size_t total = 0;
  uint64_t index = 0;
  if (!crypto || !private_input || !private_capacity || !input_bytes ||
      !utm_cipher || !receive || !first_sequence || !task_id || !key_epoch)
    return -1;
  *input_bytes = 0;
  for (;;) {
    struct group_pmp_media_frame frame = {0};
    if (index == UINT64_MAX || first_sequence > UINT64_MAX - index ||
        receive(opaque, &frame, utm_cipher, utm_capacity) != 0 ||
        !group_pmp_media_frame_valid(&frame) || frame.codec != codec ||
        frame.task_id != task_id || frame.key_epoch != key_epoch ||
        frame.sequence != first_sequence + index ||
        frame.chunk_index != index || frame.chunk_offset != offset ||
        frame.cipher_bytes > utm_capacity ||
        frame.frame_bytes > private_capacity ||
        (index && frame.frame_bytes != total))
      goto fail;
    if (!index) total = (size_t)frame.frame_bytes;
    if (group_pmp_media_decrypt_chunk(crypto, &frame, utm_cipher, utm_capacity,
                                      private_input + offset,
                                      private_capacity - offset) != 0) {
      memset(private_input + offset, 0, (size_t)frame.plain_bytes);
      goto fail;
    }
    offset += (size_t)frame.plain_bytes;
    ++index;
    if (frame.final_chunk) {
      *input_bytes = offset;
      return 0;
    }
  }
fail:
  memset(private_input, 0, offset);
  return -1;
}
