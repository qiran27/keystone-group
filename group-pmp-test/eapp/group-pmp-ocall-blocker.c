#include <stdint.h>

#include "syscall.h"

int
main(void) {
  uint64_t payload = UINT64_C(0x4f43414c4c424c4b);
  uint64_t ack = 0;
  int ret;

  ret = ocall(1, &payload, sizeof(payload), &ack, sizeof(ack));
  if (ret != 0) {
    return ret;
  }

  return ack == UINT64_C(0x47504d504f43414c) ? 0 : 31;
}
