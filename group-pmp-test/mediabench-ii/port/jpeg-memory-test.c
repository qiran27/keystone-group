#include "jpeg-memory.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t* read_file(const char* path, size_t* length) {
  FILE* stream = fopen(path, "rb");
  uint8_t* bytes;
  long size;
  if (!stream || fseek(stream, 0, SEEK_END) != 0 ||
      (size = ftell(stream)) < 0 || fseek(stream, 0, SEEK_SET) != 0) {
    if (stream) fclose(stream);
    return NULL;
  }
  bytes = (uint8_t*)malloc((size_t)size);
  if (!bytes || fread(bytes, 1, (size_t)size, stream) != (size_t)size) {
    free(bytes);
    fclose(stream);
    return NULL;
  }
  fclose(stream);
  *length = (size_t)size;
  return bytes;
}

int main(int argc, char** argv) {
  size_t ppm_bytes = 0, jpeg_bytes = 0, encoded_bytes = 0, decoded_bytes = 0;
  uint8_t* ppm = NULL;
  uint8_t* jpeg = NULL;
  uint8_t* encoded = NULL;
  uint8_t* decoded = NULL;
  unsigned width = 704, height = 576, decoded_width = 0, decoded_height = 0;
  const size_t pixels = (size_t)width * height * 3;
  int rc = 1;

  if (argc != 3) return 2;
  ppm = read_file(argv[1], &ppm_bytes);
  jpeg = read_file(argv[2], &jpeg_bytes);
  encoded = (uint8_t*)malloc(pixels);
  decoded = (uint8_t*)malloc(pixels);
  if (!ppm || !jpeg || !encoded || !decoded || ppm_bytes != pixels + 15 ||
      memcmp(ppm, "P6\n704 576\n255\n", 15) != 0)
    goto out;
  if (group_pmp_jpeg_encode_rgb(ppm + 15, pixels, width, height, 75,
                                encoded, pixels, &encoded_bytes) != 0 ||
      encoded_bytes < 100 || encoded_bytes >= pixels ||
      group_pmp_jpeg_encode_rgb(ppm + 15, pixels, width, height, 75,
                                encoded, 16, &decoded_bytes) == 0 ||
      group_pmp_jpeg_decode_rgb(jpeg, jpeg_bytes / 2, decoded, pixels,
                                &decoded_width, &decoded_height,
                                &decoded_bytes) == 0 ||
      group_pmp_jpeg_decode_rgb(jpeg, jpeg_bytes, decoded, pixels,
                                &decoded_width, &decoded_height,
                                &decoded_bytes) != 0 ||
      decoded_width != width || decoded_height != height ||
      decoded_bytes != pixels)
    goto out;
  printf("jpeg_memory_test=PASS encoded_bytes=%zu decoded_bytes=%zu\n",
         encoded_bytes, decoded_bytes);
  rc = 0;
out:
  if (rc != 0) fprintf(stderr, "jpeg_memory_test=FAIL\n");
  free(ppm);
  free(jpeg);
  free(encoded);
  free(decoded);
  return rc;
}
