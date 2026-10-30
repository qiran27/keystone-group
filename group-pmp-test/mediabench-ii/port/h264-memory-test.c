#include "h264-memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The native harness loads MediaBench inputs; JM itself receives only the
 * registered private buffers. */
#undef main
#undef fopen
#undef open
#undef read
#undef write
#undef lseek
#undef close

static int load(const char* directory, const char* name,
                struct group_pmp_h264_file* file) {
  char path[1024];
  FILE* source;
  long length;
  if (snprintf(path, sizeof(path), "%s/%s", directory, name) >=
      (int)sizeof(path)) return -1;
  source = fopen(path, "rb");
  if (!source) return -1;
  if (fseek(source, 0, SEEK_END) || (length = ftell(source)) < 0 ||
      fseek(source, 0, SEEK_SET)) { fclose(source); return -1; }
  file->name = name;
  file->bytes = (size_t)length;
  file->capacity = file->bytes ? file->bytes : 1;
  file->private_data = malloc(file->capacity);
  file->writable = 0;
  if (!file->private_data ||
      fread(file->private_data, 1, file->bytes, source) != file->bytes) {
    fclose(source);
    return -1;
  }
  fclose(source);
  return 0;
}

static int output(const char* name, size_t capacity,
                  struct group_pmp_h264_file* file) {
  file->name = name;
  file->private_data = calloc(1, capacity);
  file->bytes = 0;
  file->capacity = capacity;
  file->writable = 1;
  return file->private_data ? 0 : -1;
}

int main(int argc, char** argv) {
  struct group_pmp_h264_file files[12] = {{0}};
  size_t count = 0;
  size_t i;
  const char* config;
  int rc = 1;
  if (argc != 2) return 2;
#ifdef GROUP_PMP_H264_ENCODER
  config = "input_base_4CIF_96bps_encoder.cfg";
  if (load(argv[1], config, &files[count++]) ||
      load(argv[1], "input_base_4CIF_0to8.yuv", &files[count++]) ||
      load(argv[1], "input_base_4CIF_96bps_leakybucketrate.cfg",
           &files[count++]) ||
      output("output_base_4CIF_96bps_rec.yuv", 8U << 20, &files[count++]) ||
      output("output_base_4CIF_96bps.264", 4U << 20, &files[count++]) ||
      output("leakybucketparam.cfg", 1U << 20, &files[count++]) ||
      output("stats.dat", 1U << 20, &files[count++]) ||
      output("log.dat", 1U << 20, &files[count++]) ||
      output("data.txt", 1U << 20, &files[count++]) ||
      output("stat_frame.dat", 1U << 20, &files[count++]) ||
      output("output_base_4CIF_96bps_enc.txt", 1U << 20, &files[count++]))
    goto done;
#else
  config = "input_base_4CIF_96bps_decoder.cfg";
  if (load(argv[1], config, &files[count++]) ||
      load(argv[1], "input_base_4CIF_96bps.264", &files[count++]) ||
      load(argv[1], "input_base_4CIF_96bps_rec.yuv", &files[count++]) ||
      load(argv[1], "input_base_4CIF_96bps_leakybucketparam.cfg",
           &files[count++]) ||
      output("output_base_4CIF_96bps_dec.yuv", 8U << 20, &files[count++]) ||
      output("log.dec", 1U << 20, &files[count++]) ||
      output("dataDec.txt", 1U << 20, &files[count++]))
    goto done;
#endif
  if (group_pmp_h264_run_memory(config, files, count) != 0)
    goto done;
#ifdef GROUP_PMP_H264_ENCODER
  printf("JM H.264 encode private-memory output=%zu\n", files[4].bytes);
  if (files[4].bytes == 0) goto done;
#else
  printf("JM H.264 decode private-memory output=%zu\n", files[4].bytes);
  if (files[4].bytes == 0) goto done;
#endif
  rc = 0;
done:
  for (i = 0; i < count; ++i) free(files[i].private_data);
  return rc;
}
