#include "mpeg4-memory.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "libavcodec/avcodec.h"

static int frame_bytes(unsigned width, unsigned height, size_t* bytes) {
  size_t pixels;
  if (!width || !height || (width & 1U) || (height & 1U) ||
      width > INT_MAX || height > INT_MAX ||
      (size_t)width > SIZE_MAX / height)
    return -1;
  pixels = (size_t)width * height;
  if (pixels > SIZE_MAX / 3 * 2)
    return -1;
  *bytes = pixels + pixels / 2;
  return 0;
}

int group_pmp_mpeg4_encode_yuv420(const uint8_t* yuv, size_t yuv_bytes,
                                   unsigned width, unsigned height,
                                   uint8_t* bitstream, size_t capacity,
                                   size_t* produced) {
  AVCodecContext* context = NULL;
  AVFrame* frame = NULL;
  AVCodec* codec;
  size_t required;
  size_t pixels;
  int opened = 0;
  int encoded;
  int rc = -1;
  if (!yuv || !bitstream || !produced ||
      frame_bytes(width, height, &required) != 0 ||
      yuv_bytes != required || !capacity || capacity > INT_MAX)
    return -1;
  *produced = 0;
  avcodec_register_all();
  codec = avcodec_find_encoder(CODEC_ID_MPEG4);
  context = avcodec_alloc_context();
  frame = avcodec_alloc_frame();
  if (!codec || !context || !frame)
    goto done;
  context->width = (int)width;
  context->height = (int)height;
  context->time_base.num = 1;
  context->time_base.den = 25;
  context->bit_rate = 400000;
  context->gop_size = 1;
  context->max_b_frames = 0;
  context->pix_fmt = PIX_FMT_YUV420P;
  if (avcodec_open(context, codec) < 0)
    goto done;
  opened = 1;
  pixels = (size_t)width * height;
  frame->data[0] = (uint8_t*)yuv;
  frame->data[1] = (uint8_t*)yuv + pixels;
  frame->data[2] = (uint8_t*)yuv + pixels + pixels / 4;
  frame->linesize[0] = (int)width;
  frame->linesize[1] = (int)width / 2;
  frame->linesize[2] = (int)width / 2;
  encoded = avcodec_encode_video(context, bitstream, (int)capacity, frame);
  if (encoded <= 0 || (size_t)encoded > capacity)
    goto done;
  *produced = (size_t)encoded;
  rc = 0;
done:
  if (opened) avcodec_close(context);
  if (frame) av_free(frame);
  if (context) av_free(context);
  return rc;
}

int group_pmp_mpeg4_decode_yuv420(const uint8_t* bitstream, size_t input_bytes,
                                   unsigned width, unsigned height,
                                   uint8_t* yuv, size_t capacity,
                                   size_t* produced) {
  AVCodecContext* context = NULL;
  AVFrame* frame = NULL;
  AVCodec* codec;
  uint8_t* padded = NULL;
  size_t required;
  size_t pixels;
  int opened = 0;
  int got = 0;
  int consumed;
  int rc = -1;
  unsigned plane;
  if (!bitstream || !input_bytes || input_bytes > INT_MAX ||
      input_bytes > SIZE_MAX - FF_INPUT_BUFFER_PADDING_SIZE || !yuv ||
      !produced || frame_bytes(width, height, &required) != 0 ||
      capacity < required)
    return -1;
  *produced = 0;
  padded = malloc(input_bytes + FF_INPUT_BUFFER_PADDING_SIZE);
  if (!padded) return -1;
  memcpy(padded, bitstream, input_bytes);
  memset(padded + input_bytes, 0, FF_INPUT_BUFFER_PADDING_SIZE);
  avcodec_register_all();
  codec = avcodec_find_decoder(CODEC_ID_MPEG4);
  context = avcodec_alloc_context();
  frame = avcodec_alloc_frame();
  if (!codec || !context || !frame)
    goto done;
  context->width = (int)width;
  context->height = (int)height;
  context->pix_fmt = PIX_FMT_YUV420P;
  if (avcodec_open(context, codec) < 0)
    goto done;
  opened = 1;
  consumed = avcodec_decode_video(context, frame, &got,
                                   padded, (int)input_bytes);
  if (consumed < 0 || !got || context->width != (int)width ||
      context->height != (int)height || context->pix_fmt != PIX_FMT_YUV420P)
    goto done;
  pixels = (size_t)width * height;
  for (plane = 0; plane < 3; ++plane) {
    const unsigned rows = plane == 0 ? height : height / 2;
    const unsigned row_bytes = plane == 0 ? width : width / 2;
    uint8_t* output = yuv + (plane == 0 ? 0 :
        plane == 1 ? pixels : pixels + pixels / 4);
    unsigned row;
    if (!frame->data[plane] || frame->linesize[plane] < (int)row_bytes)
      goto done;
    for (row = 0; row < rows; ++row)
      memcpy(output + (size_t)row * row_bytes,
             frame->data[plane] + (size_t)row * frame->linesize[plane],
             row_bytes);
  }
  *produced = required;
  rc = 0;
done:
  if (opened) avcodec_close(context);
  if (frame) av_free(frame);
  if (context) av_free(context);
  free(padded);
  return rc;
}
