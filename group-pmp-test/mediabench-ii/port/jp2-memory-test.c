#include "jp2-memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
  FILE* input;
  uint8_t* ppm = NULL;
  uint8_t* jp2 = NULL;
  uint8_t* recovered = NULL;
  size_t source_bytes;
  size_t encoded = 0;
  size_t decoded = 0;
  int rc = 1;
  long length;
  if (argc != 2 || !(input = fopen(argv[1], "rb"))) return 2;
  if (fseek(input, 0, SEEK_END) != 0 || (length = ftell(input)) <= 0 ||
      fseek(input, 0, SEEK_SET) != 0) goto done;
  source_bytes = (size_t)length;
  ppm = malloc(source_bytes);
  jp2 = malloc(source_bytes * 2);
  recovered = malloc(source_bytes * 2);
  if (!ppm || !jp2 || !recovered ||
      fread(ppm, 1, source_bytes, input) != source_bytes ||
      group_pmp_jp2_encode_ppm(ppm, source_bytes, jp2,
                                source_bytes * 2, &encoded) != 0 ||
      group_pmp_jp2_decode_ppm(jp2, encoded, recovered,
                                source_bytes * 2, &decoded) != 0 ||
      encoded == 0 || decoded == 0 || decoded > source_bytes * 2)
    goto done;
  printf("JP2 memory adapter PASS: input=%zu compressed=%zu decoded=%zu\n",
         source_bytes, encoded, decoded);
  rc = 0;
done:
  fclose(input);
  free(ppm);
  free(jp2);
  free(recovered);
  return rc;
}
