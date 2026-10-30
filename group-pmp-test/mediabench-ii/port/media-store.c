#define _POSIX_C_SOURCE 200809L
#include "media-store.h"

#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

int group_pmp_media_host_open(struct group_pmp_media_host_file* host,
                              const char* path, int writing) {
  int fd;
  if (!host || !path || !*path || host->file) return -1;
  fd = open(path, writing ?
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW :
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) return -1;
  host->file = fdopen(fd, writing ? "wb" : "rb");
  if (!host->file) { close(fd); return -1; }
  return 0;
}

int group_pmp_media_host_close(struct group_pmp_media_host_file* host) {
  int rc;
  if (!host || !host->file) return -1;
  rc = fclose(host->file);
  host->file = NULL;
  return rc == 0 ? 0 : -1;
}

int group_pmp_media_host_publish(void* opaque,
    const struct group_pmp_media_frame* frame, const uint8_t* utm_cipher) {
  struct group_pmp_media_host_file* host = opaque;
  if (!host || !host->file || !utm_cipher ||
      !group_pmp_media_frame_valid(frame) ||
      fwrite(frame, sizeof(*frame), 1, host->file) != 1 ||
      fwrite(utm_cipher, 1, (size_t)frame->cipher_bytes, host->file) !=
          frame->cipher_bytes)
    return -1;
  return 0;
}

int group_pmp_media_host_receive(void* opaque,
    struct group_pmp_media_frame* frame, uint8_t* utm_cipher,
    size_t utm_capacity) {
  struct group_pmp_media_host_file* host = opaque;
  if (!host || !host->file || !frame || !utm_cipher ||
      fread(frame, sizeof(*frame), 1, host->file) != 1 ||
      !group_pmp_media_frame_valid(frame) ||
      frame->cipher_bytes > utm_capacity ||
      fread(utm_cipher, 1, (size_t)frame->cipher_bytes, host->file) !=
          frame->cipher_bytes)
    return -1;
  return 0;
}
