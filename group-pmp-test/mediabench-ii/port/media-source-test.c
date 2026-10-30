#include "media-source.h"

#include <stdio.h>
#include <stdlib.h>

static int read_file(const char* path, unsigned char** data, size_t* bytes) {
  FILE* file = fopen(path, "rb");
  long length;
  if (!file || fseek(file, 0, SEEK_END) != 0 ||
      (length = ftell(file)) <= 0 || fseek(file, 0, SEEK_SET) != 0) {
    if (file) fclose(file);
    return -1;
  }
  *data = malloc((size_t)length);
  if (!*data || fread(*data, 1, (size_t)length, file) != (size_t)length) {
    free(*data);
    fclose(file);
    return -1;
  }
  fclose(file);
  *bytes = (size_t)length;
  return 0;
}

int main(int argc, char** argv) {
  unsigned char* ppm = NULL;
  unsigned char* avi = NULL;
  unsigned char* yuv = NULL;
  const unsigned char* packet = NULL;
  size_t ppm_bytes = 0, avi_bytes = 0, packet_bytes = 0;
  unsigned width = 0, height = 0;
  int result = 1;
  if (argc != 3 || read_file(argv[1], &ppm, &ppm_bytes) != 0 ||
      read_file(argv[2], &avi, &avi_bytes) != 0) goto done;
  yuv = malloc(2U << 20);
  if (!yuv || group_pmp_media_ppm_to_yuv420(ppm, ppm_bytes, yuv,
      2U << 20, &width, &height) != 0) goto done;
  printf("PPM: %ux%u YUV bytes=%zu\n", width, height,
         (size_t)width * height * 3 / 2);
  if (group_pmp_media_avi_first_mpeg4(avi, avi_bytes, &packet,
      &packet_bytes, &width, &height) != 0) goto done;
  printf("AVI: %ux%u first compressed packet=%zu bytes\n",
         width, height, packet_bytes);
  result = packet_bytes > 0 ? 0 : 1;
done:
  free(yuv);
  free(ppm);
  free(avi);
  return result;
}
