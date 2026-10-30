#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <sys/vfs.h>
#include <vector>
extern "C" {
#include "edge/edge_call.h"
}
#include "../secure-kv/kv-record.h"
#include "../eapp/group-pmp-sqlite-shared.h"
#include "../host/sqlite-extent-io.hpp"
#include "../host/benchmark-cipher-config.hpp"
extern "C" int __real_register_call(unsigned long, edgecallwrapper);
static unsigned rejected_id, registrations, runs, fail_run, mode;
extern "C" int __wrap_register_call(unsigned long id, edgecallwrapper handler) {
  ++registrations;
  return id == rejected_id ? -1 : __real_register_call(id, handler);
}
static void group_pmp_ocall_ack(void* p) {
  static_cast<edge_call*>(p)->return_data.call_status = CALL_STATUS_OK;
}
static void group_pmp_sqlite_async_vfs(void* p) {
  static_cast<edge_call*>(p)->return_data.call_status = CALL_STATUS_OK;
}
static bool stop_requested;
constexpr uint64_t GROUP_PMP_MIXED_OCALL_PER_TASK = 1;
struct MixedWorkload { bool kv_enabled; uint64_t n, workload_id; };
struct MixedRunMetrics {
  uint64_t total_bytes, sqlite_logical_request_count, sqlite_physical_request_count,
    sqlite_io_uring_submissions, vfs_ring_doorbell_count, sqlite_completion_wakeup_count,
    sqlite_merged_io_count, sqlite_useful_io_bytes, sqlite_physical_io_bytes, sqlite_collect_ns,
    sqlite_sort_ns, sqlite_cluster_ns, sqlite_submit_ns, sqlite_disk_io_ns, sqlite_completion_wait_ns,
    sqlite_storage_sync_ns, sqlite_utm_copy_ns, sqlite_completion_publish_ns,
    sqlite_registered_buffer_operations, sqlite_fixed_buffer_operations, worker_aes_time_ticks;
  std::array<uint64_t, SQLITE_PIPELINE_METRICS> sqlite_io_pipeline;
  double seconds, mb_per_sec;
};
static uint64_t env_u64(const char* name, uint64_t fallback, uint64_t, uint64_t) {
  const char* value = std::getenv(name);
  return value ? std::strtoull(value, nullptr, 10) : fallback;
}
static const char* sqlite_benchmark_cache_mode_name() {
  const char* value = std::getenv("GROUP_PMP_SQLITE_CACHE_MODE");
  return value ? value : "hot";
}
static double riscv_timebase_hz() { return 4000000; }
static void sqlite_selected_io_cleanup_case(uint64_t, uint64_t) {}
static bool build_mixed_workload(uint64_t n, uint64_t, MixedWorkload* w, uint64_t id) {
  w->kv_enabled = false; w->n = n; w->workload_id = id; return true;
}
static bool run_mixed_scaling_case(const char*, const char* worker, const char*, const char*,
                                 const MixedWorkload& w, void*, MixedRunMetrics* m) {
  assert(w.kv_enabled && !std::strcmp(worker, "group-pmp-kv-worker.eapp_riscv"));
  edge_call ack{}, vfs{};
  ack.call_id = 1; vfs.call_id = GROUP_PMP_SQLITE_VFS_OCALL_ID;
  incoming_call_dispatch(&ack); incoming_call_dispatch(&vfs);
  assert(ack.return_data.call_status == CALL_STATUS_OK && vfs.return_data.call_status == CALL_STATUS_OK);
  ++runs;
  if (runs == fail_run) return false;
  *m = {};
  m->total_bytes = 60000000;
  m->seconds = 3.0 / w.n;
  m->mb_per_sec = 60 / m->seconds;
  m->sqlite_logical_request_count = 100;
  m->sqlite_physical_request_count = mode == 3 ? 75 : 100;
  return true;
}
static bool validate_mixed_sample(const MixedRunMetrics& m, const MixedRunMetrics& base,
                                 size_t, std::ostream*) {
  return m.total_bytes == base.total_bytes && m.sqlite_logical_request_count == base.sqlite_logical_request_count;
}
static double nearest_rank_percentile(std::vector<double> values, int p) {
  std::sort(values.begin(), values.end());
  return values[(values.size() * p + 99) / 100 - 1];
}
#include "../host/kv-scaling.hpp"
static unsigned rows(const std::string& path) {
  unsigned count = 0; std::ifstream file(path); std::string line;
  while (std::getline(file, line)) ++count;
  return count;
}
int main(int argc, char** argv) {
  if (argc != 2) return 2;
  const std::string prefix = std::string(argv[1]) + "/kv-phase";
  const char* keys[] = {"GROUP_PMP_KV_CSV", "GROUP_PMP_KV_SAMPLES_CSV", "GROUP_PMP_KV_IO_CSV"};
  std::string paths[] = {prefix + ".csv", prefix + "-samples.csv", prefix + "-io.csv"};
  for (unsigned i = 0; i < 3; ++i) setenv(keys[i], paths[i].c_str(), 1);
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", "/dev/shm", 1);
  setenv("GROUP_PMP_SQLITE_CACHE_MODE", "hot", 1);
  setenv("GROUP_PMP_SQLITE_TOTAL_BYTES", "60000000", 1);
  setenv("GROUP_PMP_KV_MAX_WORKERS", "2", 1);
  setenv("GROUP_PMP_KV_REPETITIONS", "3", 1);
  const char* profiles[] = {"put", "get", "update"};
  const char* modes[] = {"sync-no-extent", "async-no-extent", "adaptive-extent"};
  for (unsigned cipher = 0; cipher <= 2; ++cipher)
  for (const char* p : profiles) for (mode = 1; mode <= 3; ++mode) {
    setenv("GROUP_PMP_BENCH_CIPHER", benchmark_cipher_name(cipher), 1);
    setenv("GROUP_PMP_KV_PROFILE", p, 1);
    setenv("GROUP_PMP_SQLITE_IO_MODE", modes[mode - 1], 1);
    for (rejected_id = 0; rejected_id <= 2; ++rejected_id) {
      for (const auto& path : paths) std::remove(path.c_str());
      std::fill(edge_call_table, edge_call_table + MAX_EDGE_CALL, nullptr);
      registrations = runs = fail_run = 0;
      const bool ok = run_kv_scaling_phase("master", "runtime", "loader");
      assert(ok == (rejected_id == 0));
      if (!rejected_id) {
        assert(registrations == 2 && runs == 6);
        assert(rows(paths[0]) == 3 && rows(paths[1]) == 7 && rows(paths[2]) == 3);
        for (const auto& path : paths) {
          std::ifstream file(path); std::string line;
          assert(std::getline(file, line) && line.substr(line.rfind(',') + 1) == "cipher");
          while (std::getline(file, line))
            assert(line.substr(line.rfind(',') + 1) == benchmark_cipher_name(cipher));
        }
      } else {
        assert(registrations == rejected_id && runs == 0);
        for (const auto& path : paths) assert(!std::ifstream(path).good());
      }
    }
  }
  rejected_id = runs = 0; fail_run = 3;
  assert(!run_kv_scaling_phase("master", "runtime", "loader"));
  assert(rows(paths[1]) == 3 && rows(paths[0]) == 1);
  setenv("GROUP_PMP_SQLITE_CACHE_MODE", "invalid", 1);
  assert(!run_kv_scaling_phase("master", "runtime", "loader"));
  for (const auto& path : paths) std::remove(path.c_str());
  std::cout << "KV Host phase: three profiles/modes, real SDK dispatch, samples/summary and fail-fast PASS" << std::endl;
}
