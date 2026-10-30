#ifndef GROUP_PMP_MEDIABENCH_JPEG_MEMORY_H
#define GROUP_PMP_MEDIABENCH_JPEG_MEMORY_H

#include <stddef.h>
#include <stdint.h>

int group_pmp_jpeg_encode_rgb(const uint8_t* rgb, size_t rgb_bytes,
                              unsigned width, unsigned height, int quality,
                              uint8_t* output, size_t output_capacity,
                              size_t* output_bytes);

int group_pmp_jpeg_decode_rgb(const uint8_t* jpeg, size_t jpeg_bytes,
                              uint8_t* output, size_t output_capacity,
                              unsigned* width, unsigned* height,
                              size_t* output_bytes);

#endif
