#define main previous_store_main
#include "sqlite-store-pipeline-test.c"
#undef main

int main(void) {
  const uint64_t workloads[] = {GROUP_PMP_SQLITE_FILLSEQ, GROUP_PMP_SQLITE_FILLSEQBATCH,
    GROUP_PMP_SQLITE_FILLRANDOM, GROUP_PMP_SQLITE_FILLRANDOMBATCH, GROUP_PMP_SQLITE_OVERWRITE,
    GROUP_PMP_SQLITE_READSEQ, GROUP_PMP_SQLITE_READRANDOM, GROUP_PMP_SQLITE_READRAND100K};
  test_exec_clock();
  assert(keystone_enclave_store_set_exec_clock(&test_clock) == 0);
  for (test_cipher = 1; test_cipher <= 2; ++test_cipher) {
    for (unsigned w = 0; w < 8; ++w) for (unsigned mode = 0; mode <= 4; ++mode) {
      uint64_t digest = 0;
      const uint64_t length = 4000080;
      configure_case(workloads[w], length, mode, -1);
      assert(transfer_range(0, length, 0, GROUP_PMP_SQLITE_STORE_PREFILL, &digest) == 0);
      const uint64_t prefill_sequence = next_sequence;
      assert(keystone_enclave_store_begin_measurement() == 0);
      assert(next_sequence == prefill_sequence);
      assert(transfer_range(0, length, 1, GROUP_PMP_SQLITE_STORE_MEASURED, &digest) == 0);
      assert(store_stats.read_bytes == length);
      assert(transfer_range(0, length, 0, GROUP_PMP_SQLITE_STORE_MEASURED, &digest) == 0);
      assert(next_sequence > prefill_sequence);
      assert(transfer_range(0, length, 1, GROUP_PMP_SQLITE_STORE_MEASURED, &digest) == 0);
      assert(store_stats.read_bytes == 2 * length);
      check_utm();
      keystone_enclave_store_destroy();
    }
    for (corrupt_aead = 1; corrupt_aead <= 3; ++corrupt_aead) {
      uint64_t digest = 0;
      configure_case(GROUP_PMP_SQLITE_READRANDOM, 4096, 0, -1);
      assert(transfer_range(0, 4096, 0, GROUP_PMP_SQLITE_STORE_PREFILL, &digest) == 0);
      assert(keystone_enclave_store_begin_measurement() == 0);
      assert(transfer_range(0, 4096, 1, GROUP_PMP_SQLITE_STORE_MEASURED, &digest) != 0);
      assert(store_stats.read_bytes == 0);
      for (size_t i = 0; i < 4096; ++i) assert(plain_scratch[i] == 0);
      keystone_enclave_store_destroy();
    }
    corrupt_aead = 0;
  }
  puts("AEAD production store: eight workloads, short tails, completion orders, prefill/overwrite nonce continuity and fail-closed reads PASS");
}
