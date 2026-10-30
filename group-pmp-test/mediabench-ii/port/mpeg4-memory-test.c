#include "mpeg4-memory.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  uint8_t input[16 * 16 * 3 / 2];
  uint8_t output[sizeof(input)];
  uint8_t bitstream[128 * 1024];
  size_t encoded = 0;
  size_t decoded = 0;
  size_t i;
  for (i = 0; i < sizeof(input); ++i)
    input[i] = (uint8_t)(i * 7U + 31U);
  memset(output, 0, sizeof(output));
  if (group_pmp_mpeg4_encode_yuv420(input, sizeof(input), 16, 16,
                                     bitstream, sizeof(bitstream),
                                     &encoded) != 0 ||
      group_pmp_mpeg4_decode_yuv420(bitstream, encoded, 16, 16,
                                     output, sizeof(output), &decoded) != 0 ||
      !encoded || decoded != sizeof(input)) {
    fputs("MPEG-4 memory adapter failed\n", stderr);
    return 1;
  }
  printf("MPEG-4 memory adapter PASS: compressed=%zu decoded=%zu\n",
         encoded, decoded);
  return 0;
}
