#ifndef GROUP_PMP_MEDIABENCH_MPEG4_MEMORY_H
#define GROUP_PMP_MEDIABENCH_MPEG4_MEMORY_H

#include <stddef.h>
#include <stdint.h>

/* Both sides are enclave-private buffers. Input/output file I/O is external
 * to this adapter and must use the encrypted media frame protocol. */
int group_pmp_mpeg4_encode_yuv420(const uint8_t* yuv, size_t yuv_bytes,
                                   unsigned width, unsigned height,
                                   uint8_t* bitstream, size_t capacity,
                                   size_t* produced);
int group_pmp_mpeg4_decode_yuv420(const uint8_t* bitstream, size_t input_bytes,
                                   unsigned width, unsigned height,
                                   uint8_t* yuv, size_t capacity,
                                   size_t* produced);

#endif
