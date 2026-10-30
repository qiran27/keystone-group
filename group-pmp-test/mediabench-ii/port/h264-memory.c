#include "h264-memory.h"
#include "jm-memory-vfs.h"

#include <string.h>

#ifdef GROUP_PMP_H264_ENCODER
extern int group_pmp_jm_encoder_main(int argc, char** argv);
#else
extern int group_pmp_jm_decoder_main(int argc, char** argv);
#endif

int group_pmp_h264_run_memory(const char* config_name,
                              struct group_pmp_h264_file* files,
                              size_t file_count) {
  size_t i;
  int found_config = 0;
  int result;
  if (!config_name || !*config_name || !files || !file_count ||
      file_count > 24) return -1;
  group_pmp_jm_memory_reset();
  for (i = 0; i < file_count; ++i) {
    struct group_pmp_h264_file* file = &files[i];
    if (!file->name || !file->private_data || !file->capacity ||
        file->bytes > file->capacity ||
        (file->writable && file->bytes)) return -1;
    if (strcmp(file->name, config_name) == 0 && !file->writable)
      found_config = 1;
    if ((file->writable ?
         group_pmp_jm_memory_output(file->name, file->private_data,
                                     file->capacity) :
         group_pmp_jm_memory_input(file->name, file->private_data,
                                    file->bytes)) != 0)
      return -1;
  }
  if (!found_config) return -1;
#ifdef GROUP_PMP_H264_ENCODER
  {
    char* argv[] = {(char*)"jm-encoder", (char*)"-d",
                    (char*)config_name};
    result = group_pmp_jm_encoder_main(3, argv);
  }
#else
  {
    char* argv[] = {(char*)"jm-decoder", (char*)config_name};
    result = group_pmp_jm_decoder_main(2, argv);
  }
#endif
  if (result != 0) return -1;
  for (i = 0; i < file_count; ++i)
    if (files[i].writable &&
        group_pmp_jm_memory_size(files[i].name, &files[i].bytes) != 0)
      return -1;
  return 0;
}
