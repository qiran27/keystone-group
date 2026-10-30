#define _POSIX_C_SOURCE 200809L
#include "media-store.h"
#include "group-pmp-crypto.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
  const uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8,
                           9, 10, 11, 12, 13, 14, 15, 16};
  const size_t bytes = GROUP_PMP_MEDIA_DATA_BUFFER_BYTES + 17;
  struct group_pmp_crypto_context crypto;
  struct group_pmp_media_host_file host = {0};
  char path[] = "/tmp/group-pmp-media-XXXXXX";
  uint8_t* plain = NULL;
  uint8_t* recovered = NULL;
  uint8_t* utm = NULL;
  uint8_t first_cipher[16];
  size_t recovered_bytes = 0;
  size_t i;
  int fd = -1;
  int rc = 1;
  fd = mkstemp(path);
  if (fd < 0) return 1;
  close(fd);
  plain = malloc(bytes);
  recovered = malloc(bytes);
  utm = malloc(GROUP_PMP_MEDIA_DATA_BUFFER_BYTES);
  if (!plain || !recovered || !utm ||
      group_pmp_crypto_init(&crypto, GROUP_PMP_CRYPTO_AES_128_ECB,
                            key, sizeof(key)) != 0)
    goto done;
  for (i = 0; i < bytes; ++i) plain[i] = (uint8_t)(i * 29U + 5U);
  if (group_pmp_media_host_open(&host, path, 1) != 0 ||
      group_pmp_media_write_stream(&crypto, GROUP_PMP_MEDIA_H264_ENCODE,
                                    7, 100, 1, plain, bytes, utm,
                                    GROUP_PMP_MEDIA_DATA_BUFFER_BYTES,
                                    group_pmp_media_host_publish, &host) != 0 ||
      group_pmp_media_host_close(&host) != 0)
    goto crypto_done;
  {
    FILE* check = fopen(path, "rb");
    if (!check || fseek(check, sizeof(struct group_pmp_media_frame),
                        SEEK_SET) != 0 ||
        fread(first_cipher, 1, sizeof(first_cipher), check) !=
            sizeof(first_cipher) ||
        memcmp(first_cipher, plain, sizeof(first_cipher)) == 0) {
      if (check) fclose(check);
      goto crypto_done;
    }
    fclose(check);
  }
  if (group_pmp_media_host_open(&host, path, 0) != 0 ||
      group_pmp_media_read_stream(&crypto, GROUP_PMP_MEDIA_H264_ENCODE,
                                   7, 100, 1, recovered, bytes,
                                   &recovered_bytes, utm,
                                   GROUP_PMP_MEDIA_DATA_BUFFER_BYTES,
                                   group_pmp_media_host_receive, &host) != 0 ||
      recovered_bytes != bytes || memcmp(plain, recovered, bytes) != 0 ||
      group_pmp_media_host_close(&host) != 0)
    goto crypto_done;
  rc = 0;
crypto_done:
  if (host.file) group_pmp_media_host_close(&host);
  group_pmp_crypto_deinit(&crypto);
done:
  unlink(path);
  free(utm);
  free(recovered);
  free(plain);
  return rc;
}
