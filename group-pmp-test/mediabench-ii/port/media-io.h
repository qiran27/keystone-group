#ifndef GROUP_PMP_MEDIABENCH_MEDIA_IO_H
#define GROUP_PMP_MEDIABENCH_MEDIA_IO_H

#include <stddef.h>
#include <stdint.h>

struct group_pmp_crypto_context;

#define GROUP_PMP_MEDIA_FRAME_MAGIC UINT64_C(0x4d42494943495048)
#define GROUP_PMP_MEDIA_FRAME_VERSION UINT64_C(1)
#define GROUP_PMP_MEDIA_DATA_BUFFER_BYTES (2U * 1024U * 1024U)
#define GROUP_PMP_MEDIA_MAX_PLAIN_CHUNK GROUP_PMP_MEDIA_DATA_BUFFER_BYTES

enum group_pmp_media_codec {
  GROUP_PMP_MEDIA_MPEG4_ENCODE = 1,
  GROUP_PMP_MEDIA_MPEG4_DECODE = 2,
  GROUP_PMP_MEDIA_JP2_ENCODE = 3,
  GROUP_PMP_MEDIA_JP2_DECODE = 4,
  GROUP_PMP_MEDIA_H264_ENCODE = 5,
  GROUP_PMP_MEDIA_H264_DECODE = 6
};

/* Public metadata; payload ciphertext is stored separately in the UTM slot.
 * frame_bytes and chunk_offset describe unpadded codec output bytes. */
struct group_pmp_media_frame {
  uint64_t magic;
  uint64_t version;
  uint64_t codec;
  uint64_t task_id;
  uint64_t sequence;
  uint64_t chunk_index;
  uint64_t frame_bytes;
  uint64_t chunk_offset;
  uint64_t plain_bytes;
  uint64_t cipher_bytes;
  uint64_t key_epoch;
  uint64_t final_chunk;
};

int group_pmp_media_cipher_bytes(size_t plain_bytes, size_t* cipher_bytes);
int group_pmp_media_frame_valid(const struct group_pmp_media_frame* frame);
int group_pmp_media_encrypt_chunk(
    struct group_pmp_crypto_context* crypto,
    const struct group_pmp_media_frame* metadata,
    const uint8_t* private_plain, uint8_t* utm_cipher,
    size_t utm_capacity);
int group_pmp_media_decrypt_chunk(
    struct group_pmp_crypto_context* crypto,
    const struct group_pmp_media_frame* metadata,
    const uint8_t* utm_cipher, size_t utm_capacity,
    uint8_t* private_plain,
    size_t private_capacity);

typedef int (*group_pmp_media_publish_fn)(
    void* opaque, const struct group_pmp_media_frame* frame,
    const uint8_t* utm_cipher);
typedef int (*group_pmp_media_receive_fn)(
    void* opaque, struct group_pmp_media_frame* frame,
    uint8_t* utm_cipher, size_t utm_capacity);

/* The callbacks publish/receive ciphertext and public frame metadata only.
 * They must complete ownership transfer before the UTM slot is reused. */
int group_pmp_media_write_stream(
    struct group_pmp_crypto_context* crypto, uint64_t codec,
    uint64_t task_id, uint64_t first_sequence, uint64_t key_epoch,
    const uint8_t* private_output, size_t output_bytes,
    uint8_t* utm_cipher, size_t utm_capacity,
    group_pmp_media_publish_fn publish, void* opaque);
int group_pmp_media_read_stream(
    struct group_pmp_crypto_context* crypto, uint64_t codec,
    uint64_t task_id, uint64_t first_sequence, uint64_t key_epoch,
    uint8_t* private_input, size_t private_capacity,
    size_t* input_bytes, uint8_t* utm_cipher, size_t utm_capacity,
    group_pmp_media_receive_fn receive, void* opaque);

#endif
