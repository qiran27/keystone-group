#ifndef GROUP_PMP_MEDIABENCH_JP2_MEMORY_H
#define GROUP_PMP_MEDIABENCH_JP2_MEMORY_H

#include <stddef.h>
#include <stdint.h>

/* PPM/JP2 bytes remain in enclave-private memory throughout the codec call. */
int group_pmp_jp2_encode_ppm(const uint8_t* ppm, size_t ppm_bytes,
                             uint8_t* jp2, size_t capacity,
                             size_t* produced);
int group_pmp_jp2_decode_ppm(const uint8_t* jp2, size_t jp2_bytes,
                             uint8_t* ppm, size_t capacity,
                             size_t* produced);

#endif
