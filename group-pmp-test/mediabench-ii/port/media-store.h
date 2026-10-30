#ifndef GROUP_PMP_MEDIABENCH_MEDIA_STORE_H
#define GROUP_PMP_MEDIABENCH_MEDIA_STORE_H

#include <stdio.h>
#include "media-io.h"

struct group_pmp_media_host_file {
  FILE* file;
};

int group_pmp_media_host_open(struct group_pmp_media_host_file* host,
                              const char* path, int writing);
int group_pmp_media_host_close(struct group_pmp_media_host_file* host);
int group_pmp_media_host_publish(void* opaque,
    const struct group_pmp_media_frame* frame, const uint8_t* utm_cipher);
int group_pmp_media_host_receive(void* opaque,
    struct group_pmp_media_frame* frame, uint8_t* utm_cipher,
    size_t utm_capacity);

#endif
