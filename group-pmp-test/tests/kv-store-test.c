#define main sqlite_store_regression_main
#include "sqlite-store-pipeline-test.c"
#undef main
int main(void) {
  const uint64_t bytes[] = {16, 4096, 4000000, 4000080};
  const uint64_t workloads[] = {GROUP_PMP_SQLITE_FILLRANDOM,
      GROUP_PMP_SQLITE_READRANDOM, GROUP_PMP_SQLITE_OVERWRITE};
  struct kv_bench_stats stats;
  test_exec_clock();
  assert(keystone_enclave_store_set_exec_clock(&test_clock) == 0);
  for (test_cipher = 0; test_cipher <= 2; ++test_cipher)
  for (unsigned mode = 0; mode <= 4; ++mode) {
    for (size_t w = 0; w < 3; ++w) for (size_t b = 0; b < 4; ++b) {
      uint64_t digest = 0;
      configure_case(workloads[w], bytes[b], mode, -1);
      memset(kv_mock_disk, 0, sizeof(kv_mock_disk));
      if (workloads[w] != GROUP_PMP_SQLITE_FILLRANDOM)
        assert(transfer_range(0, bytes[b], 0, GROUP_PMP_SQLITE_STORE_PREFILL, &digest) == 0);
      assert(keystone_enclave_store_begin_measurement() == 0);
      assert(transfer_range(0, bytes[b], workloads[w] == GROUP_PMP_SQLITE_READRANDOM,
                            GROUP_PMP_SQLITE_STORE_MEASURED, &digest) == 0);
      keystone_enclave_store_get_kv_stats(&stats);
      const uint64_t count = (bytes[b] + 4095) / 4096;
      assert(stats.magic == KV_RESULT_MAGIC && stats.workload == workloads[w]);
      assert(stats.bytes == bytes[b] && stats.puts + stats.gets == count);
      assert(stats.gets == stats.validated_gets);
      assert(store_stats.ring_request_count == count);
      assert(!pending[0] && !pending[1]);
      if (workloads[w] != GROUP_PMP_SQLITE_READRANDOM) {
        /* Verify actual persisted ciphertext, not a synthesized GET fixture. */
        for (uint64_t offset = 0; offset < bytes[b]; offset += 4096) {
          size_t length = bytes[b] - offset < 4096 ? bytes[b] - offset : 4096;
          if (test_cipher) {
            const uint64_t index = offset / chunk_bytes();
            const struct benchmark_aead_identity id = {store_config.run_id,
              store_config.worker_index, store_config.workload, extent_file_offset(offset),
              bytes[b], offset, length, aead_sequences[index]};
            assert(benchmark_aead_open(&id, aead_disk + extent_file_offset(offset),
                aead_tags[index], host_plain) == 0);
          } else {
            assert(group_pmp_crypto_transform(&crypto_context, GROUP_PMP_CRYPTO_DECRYPT,
                kv_mock_disk + extent_file_offset(offset), host_plain, length) == 0);
          }
          assert(kv_record_check(host_plain, length, kv_key_for_offset(offset), 0,
              workloads[w] == GROUP_PMP_SQLITE_OVERWRITE ? 1 : 0, NULL) == 0);
        }
      }
      check_utm();
      keystone_enclave_store_destroy();
    }
  }
  uint8_t record[4096];
  assert(kv_record_make(record, sizeof(record), 99, 3, 7) == 0);
  assert(kv_record_check(record, sizeof(record), 99, 3, 7, NULL) == 0);
  assert(kv_record_check(record, sizeof(record), 98, 3, 7, NULL) != 0);
  assert(kv_record_check(record, sizeof(record), 99, 4, 7, NULL) != 0);
  assert(kv_record_check(record, sizeof(record), 99, 3, 6, NULL) != 0);
  record[1000] ^= 1;
  assert(kv_record_check(record, sizeof(record), 99, 3, 7, NULL) != 0);
  assert(kv_record_make(record, 15, 99, 3, 7) != 0);
  puts("KV persisted ciphertext PUT/GET/UPDATE, short tails, full record validation, independent completions PASS");
  return 0;
}
