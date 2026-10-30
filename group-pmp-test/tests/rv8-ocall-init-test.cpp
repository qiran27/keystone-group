#include <algorithm>
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
#include "../eapp/group-pmp-sqlite-vfs-shared.h"
#include "../rv8-bench-master/port/rv8-kernels.h"

extern "C" {
int __real_register_call(unsigned long id, edgecallwrapper handler);
}

static unsigned long rejected_id;
static unsigned registrations, runs, ack_calls, vfs_calls;
static bool dispatch_ok;
static uint64_t selected_mode;

extern "C" int __wrap_register_call(unsigned long id, edgecallwrapper handler) {
  ++registrations;
  if (id == rejected_id) return -1;
  return __real_register_call(id, handler);
}

static void group_pmp_ocall_ack(void* buffer) {
  ++ack_calls;
  static_cast<edge_call*>(buffer)->return_data.call_status = CALL_STATUS_OK;
}

static void group_pmp_sqlite_async_vfs(void* buffer) {
  ++vfs_calls;
  static_cast<edge_call*>(buffer)->return_data.call_status = CALL_STATUS_OK;
}

// The hardware boundary is stubbed; the RV8 entry and SDK dispatcher are real.
constexpr uint64_t SQLITE_BENCHMARK_IO_ADAPTIVE_EXTENT = 3;
constexpr uint64_t GROUP_PMP_MIXED_OCALL_PER_TASK = 1;
static bool stop_requested;
struct MixedWorkload { uint64_t rv8_profile = 0, total_bytes = 60000000; };
struct MixedRunMetrics {
  double seconds = 0, mb_per_sec = 0;
  uint64_t rv8_bytes = 0, rv8_cpu_ticks = 0, rv8_elapsed_ticks = 0,
      total_bytes = 0, worker_aes_time_ticks = 0,
      sqlite_logical_request_count = 0, sqlite_physical_request_count = 0,
      vfs_ring_doorbell_count = 0, vfs_wait_count = 0, rv8_blocks = 0;
};
static uint64_t env_u64(const char* name, uint64_t fallback, uint64_t, uint64_t) {
  const char* value = std::getenv(name);
  return value ? std::strtoull(value, nullptr, 10) : fallback;
}
static uint64_t sqlite_benchmark_io_mode() { return selected_mode; }
static const char* sqlite_benchmark_io_mode_name() {
  return selected_mode == 1 ? "sync-no-extent" : "async-no-extent";
}
static double riscv_timebase_hz() { return 4000000; }
static void sqlite_selected_io_cleanup_case(uint64_t, uint64_t) {}
static bool build_mixed_workload(uint64_t, uint64_t, MixedWorkload*, uint64_t) {
  return true;
}
static bool validate_mixed_sample(const MixedRunMetrics&, const MixedRunMetrics&,
                                 size_t, std::ostream*) { return false; }
static double nearest_rank_percentile(const std::vector<double>& values, int) {
  return values.front();
}
static bool run_mixed_scaling_case(const char*, const char*, const char*,
    const char*, const MixedWorkload&, void*, MixedRunMetrics*) {
  ++runs;
  edge_call ack{};
  ack.call_id = 1;
  incoming_call_dispatch(&ack);
  dispatch_ok = ack.return_data.call_status == CALL_STATUS_OK &&
      ack_calls == 1 && vfs_calls == 0 &&
      edge_call_table[GROUP_PMP_SQLITE_VFS_OCALL_ID] == nullptr;
  // Stop before enclave execution: this test does not measure performance.
  return false;
}

#include "../host/rv8-scaling.hpp"

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  const std::string summary = std::string(argv[1]) + "/ocall-summary.csv";
  const std::string samples = std::string(argv[1]) + "/ocall-samples.csv";
  setenv("GROUP_PMP_RV8_CSV", summary.c_str(), 1);
  setenv("GROUP_PMP_RV8_SAMPLES_CSV", samples.c_str(), 1);
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", "/dev/shm", 1);
  setenv("GROUP_PMP_RV8_MAX_WORKERS", "1", 1);
  setenv("GROUP_PMP_RV8_REPETITIONS", "1", 1);
  setenv("GROUP_PMP_SQLITE_TOTAL_BYTES", "60000000", 1);
  const char* kernels[] = {"bigint", "miniz", "norx", "aes", "qsort", "sha-512", "dhrystone", "primes"};
  for (const char* kernel : kernels) {
    setenv("GROUP_PMP_RV8_KERNEL", kernel, 1);
    for (selected_mode = 1; selected_mode <= 2; ++selected_mode) {
      for (rejected_id = 0; rejected_id <= 1; ++rejected_id) {
        std::fill(edge_call_table, edge_call_table + MAX_EDGE_CALL, nullptr);
        registrations = runs = ack_calls = vfs_calls = 0;
        dispatch_ok = false;
        std::remove(summary.c_str());
        std::remove(samples.c_str());
        const bool ok = run_rv8_scaling_phase("master", "runtime", "loader");
        const bool headers_exist = std::ifstream(summary).good() ||
            std::ifstream(samples).good();
        if (ok || (!rejected_id && (!dispatch_ok || runs != 1 || registrations != 1 ||
                edge_call_table[1] != group_pmp_ocall_ack ||
                edge_call_table[GROUP_PMP_SQLITE_VFS_OCALL_ID] != nullptr)) ||
            (rejected_id && (runs || headers_exist || registrations != rejected_id))) {
          std::cerr << "RV8 OCALL init FAIL kernel=" << kernel
                    << " mode=" << selected_mode << " reject=" << rejected_id
                    << " registrations=" << registrations << " runs=" << runs
                    << " dispatch_ok=" << dispatch_ok << std::endl;
          return 1;
        }
      }
    }
  }
  std::remove(summary.c_str());
  std::remove(samples.c_str());
  std::cout << "RV8 control-only init/dispatch and fail-fast: eight kernels, Sync/Async PASS"
            << std::endl;
  return 0;
}
