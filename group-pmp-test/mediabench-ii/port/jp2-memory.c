#include "jp2-memory.h"

#include <limits.h>

#include <jasper/jasper.h>

static int initialized;

static int convert(const uint8_t* input, size_t input_bytes,
                   uint8_t* output, size_t capacity, size_t* produced,
                   const char* output_format) {
  jas_stream_t* source = NULL;
  jas_stream_t* destination = NULL;
  jas_image_t* image = NULL;
  long position;
  int format;
  int rc = -1;
  if (!input || !input_bytes || input_bytes > INT_MAX ||
      !output || !capacity || capacity > INT_MAX || !produced)
    return -1;
  *produced = 0;
  if (!initialized) {
    if (jas_init() != 0) return -1;
    initialized = 1;
  }
  format = jas_image_strtofmt((char*)output_format);
  if (format < 0) return -1;
  source = jas_stream_memopen((char*)input, (int)input_bytes);
  destination = jas_stream_memopen((char*)output, (int)capacity);
  if (!source || !destination) goto done;
  image = jas_image_decode(source, -1, NULL);
  if (!image || jas_image_encode(image, destination, format, NULL) != 0 ||
      jas_stream_flush(destination) != 0)
    goto done;
  position = jas_stream_tell(destination);
  if (position <= 0 || (size_t)position > capacity) goto done;
  *produced = (size_t)position;
  rc = 0;
done:
  if (image) jas_image_destroy(image);
  if (destination) jas_stream_close(destination);
  if (source) jas_stream_close(source);
  return rc;
}

int group_pmp_jp2_encode_ppm(const uint8_t* ppm, size_t ppm_bytes,
                             uint8_t* jp2, size_t capacity,
                             size_t* produced) {
  return convert(ppm, ppm_bytes, jp2, capacity, produced, "jp2");
}

int group_pmp_jp2_decode_ppm(const uint8_t* jp2, size_t jp2_bytes,
                             uint8_t* ppm, size_t capacity,
                             size_t* produced) {
  return convert(jp2, jp2_bytes, ppm, capacity, produced, "pnm");
}
