#ifndef GROUP_PMP_MEDIABENCH_H264_MEMORY_H
#define GROUP_PMP_MEDIABENCH_H264_MEMORY_H

#include <stddef.h>
#include <stdint.h>

struct group_pmp_h264_file {
  const char* name;
  uint8_t* private_data;
  size_t bytes;
  size_t capacity;
  int writable;
};

/* Build encoder and decoder as separate binaries. The caller registers every
 * JM input, config and output. None of these pointers may refer to UTM. */
int group_pmp_h264_run_memory(const char* config_name,
                              struct group_pmp_h264_file* files,
                              size_t file_count);

#endif
