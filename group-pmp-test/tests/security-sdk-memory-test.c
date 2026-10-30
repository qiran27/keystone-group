#include "../security/security-aead.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* The real SDK allocator starts at this linker-defined EPM-like arena. */
union {
  max_align_t alignment;
  unsigned char bytes[65536];
} security_sdk_heap;

int main(void) {
  for (unsigned i = 0; i < 32; ++i) {
    unsigned char* scratch = calloc(1, 280);
    if (!scratch) return 2;
    for (unsigned j = 0; j < 280; ++j) {
      if (scratch[j] != 0) return 3;
      scratch[j] = (unsigned char)j;
    }
    free(scratch);
    if (security_aead_self_test()) {
      fprintf(stderr, "AEAD KAT with SDK memory functions failed at %u\n", i);
      return 1;
    }
  }
  puts("AEAD KAT with real SDK allocator/string functions PASS");
  return 0;
}
