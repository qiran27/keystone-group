#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "app/syscall.h"
#include "group-pmp-crypto.h"
#include "media-board-files.h"
#include "media-source.h"

#if defined(GROUP_PMP_MEDIA_BOARD_MPEG4)
#include "mpeg4-memory.h"
#elif defined(GROUP_PMP_MEDIA_BOARD_JP2)
#include "jp2-memory.h"
#else
#include "h264-memory.h"
#endif

static const uint8_t media_key[16] = {
  0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
  0x11, 0x33, 0x55, 0x77, 0x99, 0xbb, 0xdd, 0xff
};

struct media_context {
  uint64_t codec;
  uint64_t file_id;
  uint8_t* utm;
  struct group_pmp_crypto_context crypto;
};

static int board_call(struct group_pmp_media_board_request* request,
                      struct group_pmp_media_board_reply* reply) {
  request->magic = GROUP_PMP_MEDIA_BOARD_MAGIC;
  request->version = GROUP_PMP_MEDIA_BOARD_VERSION;
  request->utm_offset = GROUP_PMP_MEDIA_BOARD_UTM_DATA_OFFSET;
  memset(reply, 0, sizeof(*reply));
  return ocall(GROUP_PMP_MEDIA_BOARD_OCALL_ID, request, sizeof(*request),
               reply, sizeof(*reply)) == 0 && reply->status == 0 ? 0 : -1;
}

static int read_cipher(void* opaque, struct group_pmp_media_frame* frame,
                       uint8_t* utm, size_t capacity) {
  struct media_context* context = opaque;
  struct group_pmp_media_board_request request = {0};
  struct group_pmp_media_board_reply reply;
  if (utm != context->utm || capacity < GROUP_PMP_MEDIA_DATA_BUFFER_BYTES)
    return -1;
  request.operation = GROUP_PMP_MEDIA_BOARD_READ;
  request.codec = context->codec;
  request.file_id = context->file_id;
  request.task_id = context->file_id + 1;
  if (board_call(&request, &reply) != 0) return -1;
  *frame = reply.frame;
  return 0;
}

static int write_cipher(void* opaque,
    const struct group_pmp_media_frame* frame, const uint8_t* utm) {
  struct media_context* context = opaque;
  struct group_pmp_media_board_request request = {0};
  struct group_pmp_media_board_reply reply;
  if (utm != context->utm || !group_pmp_media_frame_valid(frame))
    return -1;
  request.operation = GROUP_PMP_MEDIA_BOARD_WRITE;
  request.codec = context->codec;
  request.file_id = context->file_id;
  request.task_id = context->file_id + 1;
  request.frame = *frame;
  return board_call(&request, &reply);
}

static int receive_file(struct media_context* context, uint64_t file_id,
                        uint8_t* data, size_t capacity, size_t* bytes) {
  context->file_id = file_id;
  return group_pmp_media_read_stream(&context->crypto, context->codec,
      file_id + 1, 1, 1, data, capacity, bytes, context->utm,
      GROUP_PMP_MEDIA_DATA_BUFFER_BYTES, read_cipher, context);
}

static int publish_file(struct media_context* context, uint64_t file_id,
                        const uint8_t* data, size_t bytes) {
  context->file_id = file_id;
  return group_pmp_media_write_stream(&context->crypto, context->codec,
      file_id + 1, 1, 1, data, bytes, context->utm,
      GROUP_PMP_MEDIA_DATA_BUFFER_BYTES, write_cipher, context);
}

int main(void) {
  struct group_pmp_media_board_request request = {0};
  struct group_pmp_media_board_reply reply;
  struct keystone_utm_direct_info direct = {0};
  struct media_context context = {0};
  const struct group_pmp_media_board_file* specs;
  uint8_t* data[GROUP_PMP_MEDIA_BOARD_MAX_FILES] = {0};
  size_t bytes[GROUP_PMP_MEDIA_BOARD_MAX_FILES] = {0};
  size_t count = 0;
  size_t index;
  uint64_t output_total = 0;
  int status = 1;

  request.operation = GROUP_PMP_MEDIA_BOARD_CONFIG;
  if (board_call(&request, &reply) != 0) return 1;
  context.codec = reply.codec;
#if defined(GROUP_PMP_MEDIA_BOARD_MPEG4)
  if (context.codec != GROUP_PMP_MEDIA_MPEG4_ENCODE &&
      context.codec != GROUP_PMP_MEDIA_MPEG4_DECODE) return 2;
#elif defined(GROUP_PMP_MEDIA_BOARD_JP2)
  if (context.codec != GROUP_PMP_MEDIA_JP2_ENCODE &&
      context.codec != GROUP_PMP_MEDIA_JP2_DECODE) return 2;
#elif defined(GROUP_PMP_MEDIA_BOARD_H264_ENC)
  if (context.codec != GROUP_PMP_MEDIA_H264_ENCODE) return 2;
#else
  if (context.codec != GROUP_PMP_MEDIA_H264_DECODE) return 2;
#endif
  specs = group_pmp_media_board_files(context.codec, &count);
  if (!specs || !count || count > GROUP_PMP_MEDIA_BOARD_MAX_FILES ||
      utm_query_direct(&direct, sizeof(direct)) != 0 ||
      direct.abi_version != KEYSTONE_UTM_DIRECT_ABI_VERSION ||
      direct.data_utm_offset != GROUP_PMP_MEDIA_BOARD_UTM_DATA_OFFSET ||
      direct.data_size < GROUP_PMP_MEDIA_DATA_BUFFER_BYTES ||
      !(direct.flags & KEYSTONE_UTM_DIRECT_FLAG_READ) ||
      !(direct.flags & KEYSTONE_UTM_DIRECT_FLAG_WRITE) ||
      !(direct.flags & KEYSTONE_UTM_DIRECT_FLAG_NX) ||
      group_pmp_crypto_init(&context.crypto, GROUP_PMP_CRYPTO_AES_128_ECB,
                            media_key, sizeof(media_key)) != 0)
    return 3;
  context.utm = (uint8_t*)(uintptr_t)direct.data_va;
  for (index = 0; index < count; ++index) {
    data[index] = malloc(specs[index].capacity);
    if (!data[index]) goto done;
    if (!specs[index].writable &&
        receive_file(&context, index, data[index], specs[index].capacity,
                     &bytes[index]) != 0)
      goto done;
  }
#if defined(GROUP_PMP_MEDIA_BOARD_MPEG4)
  if (context.codec == GROUP_PMP_MEDIA_MPEG4_ENCODE) {
    unsigned width = 0, height = 0;
    size_t produced = 0;
    size_t yuv_capacity = 2U << 20;
    uint8_t* yuv = malloc(yuv_capacity);
    if (!yuv) goto done;
    if (group_pmp_media_ppm_to_yuv420(data[0], bytes[0], yuv,
                                      yuv_capacity, &width, &height) != 0 ||
        group_pmp_mpeg4_encode_yuv420(yuv, (size_t)width * height * 3 / 2,
                                      width, height, data[1],
                                      specs[1].capacity, &produced) != 0) {
      memset(yuv, 0, yuv_capacity); free(yuv); goto done;
    }
    memset(yuv, 0, yuv_capacity); free(yuv);
    bytes[1] = produced;
  } else {
    const uint8_t* packet = 0;
    size_t packet_bytes = 0, produced = 0;
    unsigned width = 0, height = 0;
    if (group_pmp_media_avi_first_mpeg4(data[0], bytes[0], &packet,
                                         &packet_bytes, &width, &height) != 0 ||
        group_pmp_mpeg4_decode_yuv420(packet, packet_bytes, width, height,
                                      data[1], specs[1].capacity,
                                      &produced) != 0)
      goto done;
    bytes[1] = produced;
  }
#elif defined(GROUP_PMP_MEDIA_BOARD_JP2)
  if (context.codec == GROUP_PMP_MEDIA_JP2_ENCODE) {
    if (group_pmp_jp2_encode_ppm(data[0], bytes[0], data[1],
                                  specs[1].capacity, &bytes[1]) != 0)
      goto done;
  } else if (group_pmp_jp2_decode_ppm(data[0], bytes[0], data[1],
                                       specs[1].capacity, &bytes[1]) != 0)
    goto done;
#else
  {
    struct group_pmp_h264_file files[GROUP_PMP_MEDIA_BOARD_MAX_FILES] = {{0}};
    for (index = 0; index < count; ++index) {
      files[index].name = specs[index].name;
      files[index].private_data = data[index];
      files[index].bytes = bytes[index];
      files[index].capacity = specs[index].capacity;
      files[index].writable = specs[index].writable;
    }
    if (group_pmp_h264_run_memory(specs[0].name, files, count) != 0)
      goto done;
    for (index = 0; index < count; ++index)
      bytes[index] = files[index].bytes;
  }
#endif
  for (index = 0; index < count; ++index)
    if (specs[index].writable && bytes[index]) {
      if (publish_file(&context, index, data[index], bytes[index]) != 0)
        goto done;
      output_total += bytes[index];
    }
  if (!output_total) goto done;
  request.operation = GROUP_PMP_MEDIA_BOARD_DONE;
  request.codec = context.codec;
  request.output_bytes = output_total;
  if (board_call(&request, &reply) != 0) goto done;
  status = 0;
done:
  for (index = 0; index < count; ++index)
    if (data[index]) {
      memset(data[index], 0, specs[index].capacity);
      free(data[index]);
    }
  group_pmp_crypto_deinit(&context.crypto);
  return status;
}
