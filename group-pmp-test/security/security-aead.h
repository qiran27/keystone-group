#ifndef GROUP_PMP_SECURITY_AEAD_H
#define GROUP_PMP_SECURITY_AEAD_H
#include <stddef.h>
#include <stdint.h>
#define SECURITY_AEAD_BYTES 256
#define SECURITY_AEAD_UTM_OFFSET 4096
/* Security-only slot; must fit the SDK edge dispatch table (slots 0..9). */
#define SECURITY_AEAD_OCALL 9
#define SECURITY_AEAD_GCM 1
#define SECURITY_AEAD_CHACHA 2
#define SECURITY_AEAD_SCENARIOS 9
#define SECURITY_AEAD_PROGRESS_OFFSET 2048
#define SECURITY_AEAD_PROGRESS_MAGIC UINT64_C(0x4145414450524736)
enum security_aead_stage {
  SECURITY_AEAD_CONFIG_SENT = 1,
  SECURITY_AEAD_CONFIG_RETURNED,
  SECURITY_AEAD_KAT_STARTED,
  SECURITY_AEAD_KAT_FINISHED,
  SECURITY_AEAD_SCENARIO_STARTED,
  SECURITY_AEAD_SNAPSHOT_READY,
  SECURITY_AEAD_MUTATION_RETURNED,
  SECURITY_AEAD_OPEN_FINISHED,
  SECURITY_AEAD_REPORT_RETURNED,
  SECURITY_AEAD_WORKER_FINISHED
};
/* Diagnostic metadata only; never key material, plaintext or a PASS criterion. */
struct security_aead_progress {
  uint64_t magic, algorithm, iteration, scenario, stage;
};
struct security_aead_packet {
  uint8_t ciphertext[SECURITY_AEAD_BYTES], tag[16], nonce[12], aad[40];
};
struct security_aead_call {
  uint64_t phase, algorithm, scenario, iteration, accepted, output_changed;
  uint64_t consumed_verified_snapshot, valid_result, expected_accept;
};
struct security_aead_reply { uint64_t algorithm, repetitions, nonce; int64_t status; };
int security_aead_encrypt(unsigned algorithm, const uint8_t* key,
                          const uint8_t* plain, struct security_aead_packet* packet);
/* Output remains untouched on all failures; verification and consumption
 * operate on the same EPM snapshot, never on a second UTM read. */
int security_aead_open(unsigned algorithm, const uint8_t* key,
                      const struct security_aead_packet* epm_snapshot,
                      const uint8_t expected_aad[40], uint8_t output[SECURITY_AEAD_BYTES]);
int security_aead_self_test(void);
int security_aead_self_test_algorithm(unsigned algorithm);
#endif
