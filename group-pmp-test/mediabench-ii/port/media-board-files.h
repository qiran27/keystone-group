#ifndef GROUP_PMP_MEDIA_BOARD_FILES_H
#define GROUP_PMP_MEDIA_BOARD_FILES_H

#include <stddef.h>
#include <stdint.h>

#include "media-io.h"

#define GROUP_PMP_MEDIA_BOARD_OCALL_ID 3
#define GROUP_PMP_MEDIA_BOARD_MAGIC UINT64_C(0x4d4242494f415244)
#define GROUP_PMP_MEDIA_BOARD_VERSION UINT64_C(1)
#define GROUP_PMP_MEDIA_BOARD_UTM_DATA_OFFSET 4096U
#define GROUP_PMP_MEDIA_BOARD_UTM_BYTES \
  (GROUP_PMP_MEDIA_BOARD_UTM_DATA_OFFSET + GROUP_PMP_MEDIA_DATA_BUFFER_BYTES)
#define GROUP_PMP_MEDIA_BOARD_MAX_FILES 12U

enum group_pmp_media_board_operation {
  GROUP_PMP_MEDIA_BOARD_CONFIG = 1,
  GROUP_PMP_MEDIA_BOARD_READ = 2,
  GROUP_PMP_MEDIA_BOARD_WRITE = 3,
  GROUP_PMP_MEDIA_BOARD_DONE = 4
};

struct group_pmp_media_board_file {
  const char* name;
  size_t capacity;
  int writable;
};

struct group_pmp_media_board_request {
  uint64_t magic;
  uint64_t version;
  uint64_t operation;
  uint64_t codec;
  uint64_t file_id;
  uint64_t task_id;
  uint64_t utm_offset;
  uint64_t output_bytes;
  struct group_pmp_media_frame frame;
};

struct group_pmp_media_board_reply {
  int64_t status;
  uint64_t codec;
  uint64_t width;
  uint64_t height;
  struct group_pmp_media_frame frame;
};

const struct group_pmp_media_board_file* group_pmp_media_board_files(
    uint64_t codec, size_t* count);

#endif
