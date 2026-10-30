#include "jpeg-memory.h"

#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include "jpeglib.h"
#include "jerror.h"

struct jpeg_failure_context {
  struct jpeg_error_mgr pub;
  jmp_buf jump;
};

struct memory_source {
  struct jpeg_source_mgr pub;
  const JOCTET* data;
  size_t length;
};

struct memory_destination {
  struct jpeg_destination_mgr pub;
  JOCTET* data;
  size_t capacity;
  size_t written;
};

static void jpeg_failure(j_common_ptr common) {
  struct jpeg_failure_context* failure =
      (struct jpeg_failure_context*)common->err;
  longjmp(failure->jump, 1);
}

static void source_init(j_decompress_ptr decompressor) {
  struct memory_source* source = (struct memory_source*)decompressor->src;
  source->pub.next_input_byte = source->data;
  source->pub.bytes_in_buffer = source->length;
}

static boolean source_refill(j_decompress_ptr decompressor) {
  ERREXIT(decompressor, JERR_INPUT_EOF);
  return FALSE;
}

static void source_skip(j_decompress_ptr decompressor, long bytes) {
  struct jpeg_source_mgr* source = decompressor->src;
  if (bytes <= 0) return;
  if ((unsigned long)bytes > source->bytes_in_buffer)
    ERREXIT(decompressor, JERR_INPUT_EOF);
  source->next_input_byte += (size_t)bytes;
  source->bytes_in_buffer -= (size_t)bytes;
}

static void source_term(j_decompress_ptr decompressor) {
  (void)decompressor;
}

static void set_memory_source(j_decompress_ptr decompressor,
                              struct memory_source* source,
                              const uint8_t* data, size_t length) {
  memset(source, 0, sizeof(*source));
  source->data = data;
  source->length = length;
  source->pub.init_source = source_init;
  source->pub.fill_input_buffer = source_refill;
  source->pub.skip_input_data = source_skip;
  source->pub.resync_to_restart = jpeg_resync_to_restart;
  source->pub.term_source = source_term;
  decompressor->src = &source->pub;
}

static void destination_init(j_compress_ptr compressor) {
  struct memory_destination* destination =
      (struct memory_destination*)compressor->dest;
  destination->written = 0;
  destination->pub.next_output_byte = destination->data;
  destination->pub.free_in_buffer = destination->capacity;
}

static boolean destination_full(j_compress_ptr compressor) {
  ERREXIT(compressor, JERR_BUFFER_SIZE);
  return FALSE;
}

static void destination_term(j_compress_ptr compressor) {
  struct memory_destination* destination =
      (struct memory_destination*)compressor->dest;
  destination->written = destination->capacity -
      destination->pub.free_in_buffer;
}

static void set_memory_destination(j_compress_ptr compressor,
                                   struct memory_destination* destination,
                                   uint8_t* data, size_t capacity) {
  memset(destination, 0, sizeof(*destination));
  destination->data = data;
  destination->capacity = capacity;
  destination->pub.init_destination = destination_init;
  destination->pub.empty_output_buffer = destination_full;
  destination->pub.term_destination = destination_term;
  compressor->dest = &destination->pub;
}

int group_pmp_jpeg_encode_rgb(const uint8_t* rgb, size_t rgb_bytes,
                              unsigned width, unsigned height, int quality,
                              uint8_t* output, size_t output_capacity,
                              size_t* output_bytes) {
  struct jpeg_compress_struct compressor;
  struct jpeg_failure_context failure;
  struct memory_destination destination;
  volatile int created = 0;
  size_t row_bytes;

  if (!rgb || !output || !output_bytes || !width || !height ||
      quality < 1 || quality > 100 ||
      output_capacity < 2)
    return -1;
  row_bytes = (size_t)width * 3;
  if (row_bytes / 3 != width || height > SIZE_MAX / row_bytes ||
      rgb_bytes < row_bytes * height)
    return -1;
  *output_bytes = 0;
  memset(&compressor, 0, sizeof(compressor));
  compressor.err = jpeg_std_error(&failure.pub);
  failure.pub.error_exit = jpeg_failure;
  if (setjmp(failure.jump)) {
    if (created) jpeg_destroy_compress(&compressor);
    return -1;
  }
  jpeg_create_compress(&compressor);
  created = 1;
  set_memory_destination(&compressor, &destination, output,
                         output_capacity);
  compressor.image_width = width;
  compressor.image_height = height;
  compressor.input_components = 3;
  compressor.in_color_space = JCS_RGB;
  jpeg_set_defaults(&compressor);
  jpeg_set_quality(&compressor, quality, TRUE);
  jpeg_start_compress(&compressor, TRUE);
  while (compressor.next_scanline < compressor.image_height) {
    JSAMPROW row = (JSAMPROW)(rgb +
        (size_t)compressor.next_scanline * row_bytes);
    if (jpeg_write_scanlines(&compressor, &row, 1) != 1) {
      jpeg_destroy_compress(&compressor);
      return -1;
    }
  }
  jpeg_finish_compress(&compressor);
  *output_bytes = destination.written;
  jpeg_destroy_compress(&compressor);
  return 0;
}

int group_pmp_jpeg_decode_rgb(const uint8_t* jpeg, size_t jpeg_bytes,
                              uint8_t* output, size_t output_capacity,
                              unsigned* width, unsigned* height,
                              size_t* output_bytes) {
  struct jpeg_decompress_struct decompressor;
  struct jpeg_failure_context failure;
  struct memory_source source;
  volatile int created = 0;
  size_t row_bytes;

  if (!jpeg || jpeg_bytes < 2 || !output || !width || !height ||
      !output_bytes)
    return -1;
  *output_bytes = 0;
  memset(&decompressor, 0, sizeof(decompressor));
  decompressor.err = jpeg_std_error(&failure.pub);
  failure.pub.error_exit = jpeg_failure;
  if (setjmp(failure.jump)) {
    if (created) jpeg_destroy_decompress(&decompressor);
    return -1;
  }
  jpeg_create_decompress(&decompressor);
  created = 1;
  set_memory_source(&decompressor, &source, jpeg, jpeg_bytes);
  jpeg_read_header(&decompressor, TRUE);
  decompressor.out_color_space = JCS_RGB;
  jpeg_start_decompress(&decompressor);
  if (!decompressor.output_width || !decompressor.output_height ||
      decompressor.output_components != 3) {
    jpeg_destroy_decompress(&decompressor);
    return -1;
  }
  row_bytes = (size_t)decompressor.output_width * 3;
  if (row_bytes / 3 != decompressor.output_width ||
      decompressor.output_height > SIZE_MAX / row_bytes ||
      row_bytes * decompressor.output_height > output_capacity) {
    jpeg_destroy_decompress(&decompressor);
    return -1;
  }
  while (decompressor.output_scanline < decompressor.output_height) {
    JSAMPROW row = (JSAMPROW)(output +
        (size_t)decompressor.output_scanline * row_bytes);
    if (jpeg_read_scanlines(&decompressor, &row, 1) != 1) {
      jpeg_destroy_decompress(&decompressor);
      return -1;
    }
  }
  if (!jpeg_finish_decompress(&decompressor)) {
    jpeg_destroy_decompress(&decompressor);
    return -1;
  }
  *width = decompressor.output_width;
  *height = decompressor.output_height;
  *output_bytes = row_bytes * decompressor.output_height;
  jpeg_destroy_decompress(&decompressor);
  return 0;
}
