#include "../security/security-aead.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int security_fixture_main(void);
static uint8_t utm[8192];
static unsigned algorithm, phase, reports;
static unsigned progress_writes;
static int fail_progress;
int copy_to_shared_utm(uintptr_t offset, const void* source, size_t size) {
  assert(offset <= sizeof(utm) && size <= sizeof(utm) - offset);
  if (offset == SECURITY_AEAD_PROGRESS_OFFSET) {
    assert(size == sizeof(struct security_aead_progress));
    if (fail_progress) return -1;
    const struct security_aead_progress* record = source;
    assert(record->magic == SECURITY_AEAD_PROGRESS_MAGIC);
    assert(record->stage >= SECURITY_AEAD_CONFIG_SENT && record->stage <= SECURITY_AEAD_WORKER_FINISHED);
    ++progress_writes;
  }
  memcpy(utm + offset, source, size);
  return 0;
}
int copy_from_shared(void* output, uintptr_t offset, size_t size) {
  assert(offset <= sizeof(utm) && size <= sizeof(utm) - offset);
  memcpy(output, utm + offset, size);
  return 0;
}
int ocall(unsigned long id, void* input, size_t size, void* output, size_t output_size) {
  assert(id == SECURITY_AEAD_OCALL && size == sizeof(struct security_aead_call));
  assert(output_size == sizeof(struct security_aead_reply));
  const struct security_aead_call* call = input;
  struct security_aead_reply* reply = output;
  reply->algorithm = algorithm; reply->repetitions = 3; reply->nonce = 739501;
  reply->status = 0;
  struct security_aead_progress progress;
  memcpy(&progress, utm + SECURITY_AEAD_PROGRESS_OFFSET, sizeof(progress));
  if (!call->phase) {
    assert(!reports && !phase && progress.stage == SECURITY_AEAD_CONFIG_SENT);
    return 0;
  }
  assert(progress.algorithm == algorithm && progress.iteration == call->iteration &&
         progress.scenario == call->scenario);
  assert(progress.stage == (call->phase == 1 ? SECURITY_AEAD_SCENARIO_STARTED :
                            call->phase == 2 ? SECURITY_AEAD_SNAPSHOT_READY : SECURITY_AEAD_OPEN_FINISHED));
  assert(call->phase == phase + 1 && call->algorithm == algorithm);
  assert(call->iteration == reports / 9 && call->scenario == reports % 9);
  struct security_aead_packet* packet = (void*)(utm + SECURITY_AEAD_UTM_OFFSET);
  if (call->phase == 1) {
    switch (call->scenario) {
      case 1: packet->ciphertext[13] ^= 1; break;
      case 2: packet->tag[7] ^= 1; break;
      case 3: packet->nonce[3] ^= 1; break;
      case 4: packet->aad[9] ^= 1; break;
      case 5: case 6: memcpy(packet, packet + 1, sizeof(*packet)); break;
      case 7: packet->ciphertext[127] ^= 1; break;
    }
  }
  if (call->phase == 2 && call->scenario == 8) packet->ciphertext[31] ^= 1;
  phase = call->phase;
  if (phase == 3) {
    const unsigned expected = call->scenario == 0 || call->scenario == 8;
    assert(call->expected_accept == expected && call->accepted == expected);
    assert(call->valid_result == expected && call->consumed_verified_snapshot == expected);
    assert(expected || !call->output_changed);
    ++reports;
    phase = 0;
  }
  return 0;
}
int main(void) {
  for (algorithm = 1; algorithm <= 2; ++algorithm) {
    phase = reports = progress_writes = 0;
    memset(utm, 0, sizeof(utm));
    assert(security_fixture_main() == 0 && reports == 27 && phase == 0);
    struct security_aead_progress progress;
    memcpy(&progress, utm + SECURITY_AEAD_PROGRESS_OFFSET, sizeof(progress));
    assert(progress.stage == SECURITY_AEAD_WORKER_FINISHED && progress.algorithm == algorithm &&
           progress.iteration == 3 && progress_writes == 4 + 27 * 5 + 1);
  }
  phase = reports = progress_writes = 0;
  fail_progress = 1;
  assert(security_fixture_main() == 90 && reports == 0 && progress_writes == 0);
  puts("Production AEAD eapp: two algorithms, all nine transport scenarios, phase/result gating PASS (mock boundary)");
  return 0;
}
