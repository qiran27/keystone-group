#ifndef GROUP_PMP_MEDIA_SOURCE_H
#define GROUP_PMP_MEDIA_SOURCE_H

#include <stddef.h>
#include <stdint.h>

int group_pmp_media_ppm_to_yuv420(const uint8_t* ppm, size_t ppm_bytes,
    uint8_t* yuv, size_t yuv_capacity, unsigned* width, unsigned* height);
int group_pmp_media_avi_first_mpeg4(const uint8_t* avi, size_t avi_bytes,
    const uint8_t** packet, size_t* packet_bytes,
    unsigned* width, unsigned* height);

#endif
