#ifndef GROUP_PMP_SECURITY_SENTINEL_H
#define GROUP_PMP_SECURITY_SENTINEL_H
#include <stddef.h>
#include <stdint.h>
#define GROUP_PMP_SECURITY_SENTINEL_BYTES 64
#define GROUP_PMP_SECURITY_SENTINEL_FLAG UINT64_C(32)
#define GROUP_PMP_SECURITY_INPUT_BYTES UINT64_C(1000000)
#define GROUP_PMP_SECURITY_BATCH_REQUESTS UINT64_C(8)
#define GROUP_PMP_SECURITY_PROBE_MAGIC UINT64_C(0x53454350524f4245)
#define GROUP_PMP_SECURITY_PROBE_OFFSET 3072
struct group_pmp_security_probe {
  uint64_t magic, operation, target, permission_state, attempted;
};
#define GROUP_PMP_SECURITY_PHASE_MAGIC UINT64_C(0x5345435048415331)
enum group_pmp_security_phase {
  SECURITY_PHASE_ENCRYPTED = 1, SECURITY_PHASE_INFLIGHT = 2,
  SECURITY_PHASE_DECRYPTED = 3, SECURITY_PHASE_REUSE = 4,
  SECURITY_PHASE_EXIT = 5
};
struct group_pmp_security_phase_state { uint64_t magic, phase, seen, sequence; };
/* Diagnostic identifier, not a cryptographic PRNG. Generate the complete
 * marker only inside EPM and the separate scanner process. */
static inline void group_pmp_security_sentinel(uint64_t nonce, uint8_t* out) {
  uint64_t state = nonce ^ UINT64_C(0x67d184aec759f302);
  size_t i;
  for (i = 0; i < GROUP_PMP_SECURITY_SENTINEL_BYTES; ++i) {
    uint64_t z;
    state += UINT64_C(0x9e3779b97f4a7c15);
    z = state;
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    out[i] = (uint8_t)(z ^ (z >> 31));
  }
}
#endif
