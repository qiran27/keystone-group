#include "media-board-files.h"

static const struct group_pmp_media_board_file mpeg4_encode[] = {
  {"input_base_4CIF_000.ppm", 4U << 20, 0},
  {"output_base_4CIF_000.m4v", 4U << 20, 1}
};
static const struct group_pmp_media_board_file mpeg4_decode[] = {
  {"input_base_4CIF_96bps.avi", 8U << 20, 0},
  {"output_base_4CIF_000.yuv", 4U << 20, 1}
};
static const struct group_pmp_media_board_file jp2_encode[] = {
  {"input_base_4CIF.ppm", 4U << 20, 0},
  {"output_base_4CIF.jp2", 4U << 20, 1}
};
static const struct group_pmp_media_board_file jp2_decode[] = {
  {"input_base_4CIF_96bps.jp2", 4U << 20, 0},
  {"output_base_4CIF.ppm", 8U << 20, 1}
};
static const struct group_pmp_media_board_file h264_encode[] = {
  {"input_base_4CIF_96bps_encoder.cfg", 1U << 20, 0},
  {"input_base_4CIF_0to8.yuv", 8U << 20, 0},
  {"input_base_4CIF_96bps_leakybucketrate.cfg", 1U << 20, 0},
  {"output_base_4CIF_96bps_rec.yuv", 8U << 20, 1},
  {"output_base_4CIF_96bps.264", 4U << 20, 1},
  {"leakybucketparam.cfg", 1U << 20, 1},
  {"stats.dat", 1U << 20, 1},
  {"log.dat", 1U << 20, 1},
  {"data.txt", 1U << 20, 1},
  {"stat_frame.dat", 1U << 20, 1},
  {"output_base_4CIF_96bps_enc.txt", 1U << 20, 1}
};
static const struct group_pmp_media_board_file h264_decode[] = {
  {"input_base_4CIF_96bps_decoder.cfg", 1U << 20, 0},
  {"input_base_4CIF_96bps.264", 4U << 20, 0},
  {"input_base_4CIF_96bps_rec.yuv", 8U << 20, 0},
  {"input_base_4CIF_96bps_leakybucketparam.cfg", 1U << 20, 0},
  {"output_base_4CIF_96bps_dec.yuv", 8U << 20, 1},
  {"log.dec", 1U << 20, 1},
  {"dataDec.txt", 1U << 20, 1}
};

const struct group_pmp_media_board_file* group_pmp_media_board_files(
    uint64_t codec, size_t* count) {
  const struct group_pmp_media_board_file* files = 0;
  size_t length = 0;
  switch (codec) {
    case GROUP_PMP_MEDIA_MPEG4_ENCODE:
      files = mpeg4_encode; length = sizeof(mpeg4_encode) / sizeof(*files); break;
    case GROUP_PMP_MEDIA_MPEG4_DECODE:
      files = mpeg4_decode; length = sizeof(mpeg4_decode) / sizeof(*files); break;
    case GROUP_PMP_MEDIA_JP2_ENCODE:
      files = jp2_encode; length = sizeof(jp2_encode) / sizeof(*files); break;
    case GROUP_PMP_MEDIA_JP2_DECODE:
      files = jp2_decode; length = sizeof(jp2_decode) / sizeof(*files); break;
    case GROUP_PMP_MEDIA_H264_ENCODE:
      files = h264_encode; length = sizeof(h264_encode) / sizeof(*files); break;
    case GROUP_PMP_MEDIA_H264_DECODE:
      files = h264_decode; length = sizeof(h264_decode) / sizeof(*files); break;
    default: break;
  }
  if (count) *count = length;
  return files;
}
