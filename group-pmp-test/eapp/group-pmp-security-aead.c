#include "group-pmp-common.h"
#include "../security/security-aead.h"
#include "../security/security-sentinel.h"

static int exchange(struct security_aead_call* call, struct security_aead_reply* reply) {
  memset(reply, 0, sizeof(*reply));
  return ocall(SECURITY_AEAD_OCALL, call, sizeof(*call), reply, sizeof(*reply)) ||
         reply->status ? -1 : 0;
}
static int progress(unsigned algorithm, uint64_t iteration, uint64_t scenario,
                    enum security_aead_stage stage) {
  const struct security_aead_progress record = {
      SECURITY_AEAD_PROGRESS_MAGIC, algorithm, iteration, scenario, stage};
  return copy_to_shared_utm(SECURITY_AEAD_PROGRESS_OFFSET, &record, sizeof(record));
}
int main(void) {
  struct security_aead_call call = {0};
  struct security_aead_reply reply;
  uint8_t key[32], plain[SECURITY_AEAD_BYTES];
  // Announce entry before KATs so a failed/blocked fixture has a visible stage.
  if (progress(0, 0, 0, SECURITY_AEAD_CONFIG_SENT) || exchange(&call, &reply)) return 90;
  const unsigned algorithm = (unsigned)reply.algorithm;
  const uint64_t repetitions = reply.repetitions, session = reply.nonce;
  if (progress(algorithm, 0, 0, SECURITY_AEAD_CONFIG_RETURNED)) return 98;
  if (!session || !repetitions || repetitions > 1000 ||
      (algorithm != SECURITY_AEAD_GCM && algorithm != SECURITY_AEAD_CHACHA)) return 91;
  if (progress(algorithm, 0, 0, SECURITY_AEAD_KAT_STARTED)) return 98;
  if (security_aead_self_test_algorithm(algorithm)) return 90;
  if (progress(algorithm, 0, 0, SECURITY_AEAD_KAT_FINISHED)) return 98;
  // Public test key. This fixture is not key establishment or production storage.
  for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(i * 7 + algorithm);
  group_pmp_security_sentinel(session, plain);
  memset(plain + GROUP_PMP_SECURITY_SENTINEL_BYTES, 0x3a,
         sizeof(plain) - GROUP_PMP_SECURITY_SENTINEL_BYTES);
  for (uint64_t iteration = 0; iteration < repetitions; ++iteration) {
    for (uint64_t scenario = 0; scenario < SECURITY_AEAD_SCENARIOS; ++scenario) {
      if (progress(algorithm, iteration, scenario, SECURITY_AEAD_SCENARIO_STARTED)) return 98;
      struct security_aead_packet original = {0}, other, snapshot;
      uint8_t output[SECURITY_AEAD_BYTES], expected[40];
      const uint64_t counter = iteration * SECURITY_AEAD_SCENARIOS * 2 + scenario * 2;
      memcpy(original.nonce, &session, 4);
      memcpy(original.nonce + 4, &counter, 8);
      uint64_t metadata[5] = {1, 1, 4096, sizeof(plain), iteration + 1};
      memcpy(original.aad, metadata, sizeof(metadata));
      memcpy(expected, original.aad, sizeof(expected));
      if (security_aead_encrypt(algorithm, key, plain, &original)) return 92;
      other = original;
      uint64_t next = counter + 1;
      memcpy(other.nonce + 4, &next, 8);
      // Separate range/object encrypted under a different authenticated identity.
      metadata[scenario == 6 ? 0 : 2] += 1;
      memcpy(other.aad, metadata, sizeof(metadata));
      if (security_aead_encrypt(algorithm, key, plain, &other) ||
          copy_to_shared_utm(SECURITY_AEAD_UTM_OFFSET, &original, sizeof(original)) ||
          copy_to_shared_utm(SECURITY_AEAD_UTM_OFFSET + sizeof(original), &other, sizeof(other))) return 93;
      memset(&call, 0, sizeof(call));
      call.algorithm = algorithm; call.scenario = scenario; call.iteration = iteration;
      call.phase = 1;
      if (exchange(&call, &reply) ||
          copy_from_shared(&snapshot, SECURITY_AEAD_UTM_OFFSET, sizeof(snapshot))) return 94;
      if (progress(algorithm, iteration, scenario, SECURITY_AEAD_SNAPSHOT_READY)) return 98;
      call.phase = 2; /* Host may now mutate UTM, but cannot mutate the snapshot. */
      if (exchange(&call, &reply)) return 95;
      if (progress(algorithm, iteration, scenario, SECURITY_AEAD_MUTATION_RETURNED)) return 98;
      memset(output, 0xa5, sizeof(output));
      call.accepted = security_aead_open(algorithm, key, &snapshot, expected, output) == 0;
      if (progress(algorithm, iteration, scenario, SECURITY_AEAD_OPEN_FINISHED)) return 98;
      call.expected_accept = scenario == 0 || scenario == 8;
      call.output_changed = 0;
      for (size_t i = 0; i < sizeof(output); ++i)
        if (output[i] != 0xa5) call.output_changed = 1;
      call.consumed_verified_snapshot = call.accepted && !memcmp(output, plain, sizeof(plain));
      call.valid_result = call.consumed_verified_snapshot;
      call.phase = 3;
      const int valid = call.accepted == call.expected_accept &&
          (call.accepted ? call.consumed_verified_snapshot : !call.output_changed && !call.valid_result);
      if (exchange(&call, &reply) || !valid) return 96;
      if (progress(algorithm, iteration, scenario, SECURITY_AEAD_REPORT_RETURNED)) return 98;
      memset(output, 0, sizeof(output));
      memset(&snapshot, 0, sizeof(snapshot));
    }
  }
  memset(key, 0, sizeof(key)); memset(plain, 0, sizeof(plain));
  if (progress(algorithm, repetitions, 0, SECURITY_AEAD_WORKER_FINISHED)) return 98;
  return 0;
}
