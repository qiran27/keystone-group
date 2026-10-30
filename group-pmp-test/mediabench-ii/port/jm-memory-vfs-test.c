#include "jm-memory-vfs.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

FILE* group_pmp_jm_fopen(const char*, const char*);
int group_pmp_jm_open(const char*, int, ...);
ssize_t group_pmp_jm_read(int, void*, size_t);
ssize_t group_pmp_jm_write(int, const void*, size_t);
off_t group_pmp_jm_lseek(int, off_t, int);
int group_pmp_jm_close(int);

int main(void) {
  const uint8_t input[] = {1, 2, 3, 4};
  uint8_t output[16] = {0};
  uint8_t fetched[4] = {0};
  size_t length;
  FILE* stream;
  int fd;
  group_pmp_jm_memory_reset();
  if (group_pmp_jm_memory_input("input.yuv", input, sizeof(input)) != 0 ||
      group_pmp_jm_memory_output("output.264", output, sizeof(output)) != 0 ||
      group_pmp_jm_open("not-registered", O_RDONLY) != -1)
    return 1;
  fd = group_pmp_jm_open("input.yuv", O_RDONLY);
  if (fd < 0 || group_pmp_jm_read(fd, fetched, 4) != 4 ||
      memcmp(input, fetched, 4) || group_pmp_jm_close(fd))
    return 2;
  fd = group_pmp_jm_open("output.264", O_WRONLY | O_TRUNC);
  if (fd < 0 || group_pmp_jm_write(fd, input, 4) != 4 ||
      group_pmp_jm_lseek(fd, 8, SEEK_SET) != 8 ||
      group_pmp_jm_write(fd, input, 4) != 4 ||
      group_pmp_jm_write(fd, input, 8) != -1 ||
      group_pmp_jm_close(fd) ||
      group_pmp_jm_memory_size("output.264", &length) != 0 ||
      length != 12 || output[4] != 0 || output[7] != 0)
    return 3;
  stream = group_pmp_jm_fopen("output.264", "ab");
  if (!stream || fwrite(input, 1, 4, stream) != 4 || fclose(stream) != 0 ||
      group_pmp_jm_memory_size("output.264", &length) != 0 || length != 16)
    return 4;
  stream = group_pmp_jm_fopen("input.yuv", "rb");
  if (!stream || fseek(stream, 2, SEEK_SET) != 0 ||
      fread(fetched, 1, 2, stream) != 2 || fetched[0] != 3 ||
      fclose(stream) != 0)
    return 5;
  puts("JM private memory VFS PASS");
  return 0;
}
