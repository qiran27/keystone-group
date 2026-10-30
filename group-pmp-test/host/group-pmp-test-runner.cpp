#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cmath>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include "../motivation/backend.hpp"
#include "../motivation/uring-io.hpp"
#include "motivation-system.hpp"
static const volatile char motivation_system_marker[] __attribute__((used))=MOT_SYSTEM_MARKER;
static const volatile char motivation_interface_marker[] __attribute__((used))=MOT_PRODUCTION_INTERFACE_MARKER;

#ifdef __linux__
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <sys/vfs.h>
#endif

#include "edge/edge_call.h"
#include "host/keystone.h"
#include "aes_core.h"
#include "group-pmp-aes-baseline-shared.h"
#include "group-pmp-bench-shared.h"
#include "group-pmp-mixed-shared.h"
#include "../eapp/group-pmp-sqlite-shared.h"
#include "../eapp/group-pmp-sqlite-vfs-shared.h"
#include "sqlite-extent-io.hpp"
#include "benchmark-cipher-config.hpp"
#include "sqlite-submission-timing.hpp"
#include "group-warmup-watchdog.hpp"
#include "../security/security-host-hooks.hpp"
#include "../security/security-aead.h"
static_assert(SECURITY_AEAD_OCALL < MAX_EDGE_CALL,
              "Security AEAD OCALL must fit the SDK dispatch table");
#include "sqlite-gantt-trace.hpp"
#include "sqlite-io-range-trace.hpp"
#include "../sqlite-bench-master/sqlite3.h"
#include "../rv8-bench-master/port/rv8-kernels.h"
#include "../secure-kv/kv-record.h"
#ifndef GROUP_PMP_ENABLE_SPARK_SCHEDULER
#define GROUP_PMP_ENABLE_SPARK_SCHEDULER 0
#endif
#ifndef GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS
#define GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS 0
#endif
#ifndef GROUP_PMP_AES_MARCH_STRING
#define GROUP_PMP_AES_MARCH_STRING "unknown"
#endif
#ifndef GROUP_PMP_AES_MABI_STRING
#define GROUP_PMP_AES_MABI_STRING "unknown"
#endif
#if GROUP_PMP_ENABLE_SPARK_SCHEDULER
#include "app/group_task.h"
#endif

using Keystone::Enclave;
using Keystone::Error;
using Keystone::Params;

namespace {

thread_local SqliteSubmissionTiming sqlite_submission_timing;
GroupWarmupDiagnostics group_warmup_diagnostics;

static const volatile char mixed_lane_dynamic_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_MIXED_ARTIFACT_MARKER;
static const volatile char mixed_terminal_ready_commit_artifact_marker[]
    __attribute__((used)) = "keystone-terminal-ready-commit-v1";
static const volatile char mixed_variable_sample_artifact_marker[]
    __attribute__((used)) = "keystone-variable-sample-aggregation-v2";
static const volatile char sqlite_descriptor_accounting_artifact_marker[]
    __attribute__((used)) = "keystone-sqlite-descriptor-accounting-v1";
static const volatile char sqlite_vfs_directional_accounting_marker[]
    __attribute__((used)) =
        "keystone-sqlite-vfs-directional-accounting-v1";
static const volatile char sqlite_vfs_authenticated_truncate_marker[]
    __attribute__((used)) =
        "keystone-sqlite-vfs-authenticated-truncate-v1";
static const volatile char mixed_ready_coalescing_artifact_marker[]
    __attribute__((used)) = "keystone-worker-ready-coalescing-v1";
static const volatile char mixed_warmup_monotonic_state_artifact_marker[]
    __attribute__((used)) = "keystone-mixed-warmup-monotonic-state-v1";
static const volatile char sqlite_yxstm_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_ARTIFACT_MARKER;
static const volatile char fio_profile_artifact_marker[]
    __attribute__((used)) = "keystone-fio-enclave-profile-v1";
static const volatile char sqlite_full_flow_baseline_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_FULL_FLOW_BASELINE_MARKER;
static const volatile char sqlite_no_extent_baseline_artifact_marker[]
    __attribute__((used)) = "keystone-sqlite-dynamic-no-extent-baseline-v4";
static const volatile char sqlite_double_buffer_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_DOUBLE_BUFFER_MARKER;
static const volatile char sqlite_completion_fastpath_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_COMPLETION_FASTPATH_MARKER;
static const volatile char group_batched_ocall_resume_artifact_marker[]
    __attribute__((used)) = "keystone-group-batched-ocall-resume-v1";
static const volatile char sqlite_utm_buddy_layout_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_UTM_BUDDY_LAYOUT_MARKER;
static const volatile char sqlite_csv_schema_artifact_marker[]
    __attribute__((used)) = "keystone-sqlite-csv-schema-v44";
static const volatile char sqlite_scale_matched_baseline_artifact_marker[]
    __attribute__((used)) = "keystone-sqlite-scale-matched-baseline-v1";
static const volatile char sqlite_submit_wait_accounting_artifact_marker[]
    __attribute__((used)) =
        "keystone-sqlite-submit-wait-ocall-accounting-v1";
static const volatile char sqlite_async_completion_accounting_marker[]
    __attribute__((used)) =
        "keystone-sqlite-async-completion-accounting-v2";
static const volatile char sqlite_worker_buffer_depth_artifact_marker[]
    __attribute__((used)) =
        "keystone-sqlite-worker-buffer-depth-accounting-v1";
static const volatile char sqlite_async_vfs_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_ASYNC_VFS_MARKER;
static const volatile char sqlite_central_io_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_CENTRAL_IO_MARKER;
static const volatile char sqlite_gantt_trace_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_GANTT_TRACE_MARKER;
static const volatile char sqlite_configurable_total_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_CONFIGURABLE_TOTAL_MARKER;
static const volatile char sqlite_warmup_ocall_artifact_marker[]
    __attribute__((used)) = "keystone-sqlite-warmup-ocall-v1";
static const volatile char sqlite_host_engine_artifact_marker[]
    __attribute__((used)) = "keystone-sqlite-wal-connection-pool-v1";
static const volatile char sqlite_lane_pool_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_LANE_POOL_MARKER;
static const volatile char sqlite_immediate_ocall_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_IMMEDIATE_OCALL_MARKER;
static const volatile char sqlite_batched_random_read_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_BATCHED_RANDOM_READ_MARKER;
static const volatile char sqlite_status_commit_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_STATUS_COMMIT_MARKER;
static const volatile char sqlite_crypto_timing_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_CRYPTO_TIMING_MARKER;
static const volatile char sqlite_blocking_pipeline_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_BLOCKING_PIPELINE_MARKER;
static const volatile char sqlite_batch_ocall_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_BATCH_OCALL_MARKER;
static const volatile char sqlite_control_abi_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_CONTROL_ABI_MARKER;
static const volatile char sqlite_independent_sync_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_INDEPENDENT_SYNC_MARKER;
static const volatile char sqlite_static_freemem_artifact_marker[]
    __attribute__((used)) = "keystone-sqlite-static-buffer-freemem-v1";
static const volatile char group_event_overflow_epoch_artifact_marker[]
    __attribute__((used)) = "keystone-group-event-overflow-epoch-v3";
static const volatile char lease_exit_cleanup_artifact_marker[]
    __attribute__((used)) = "keystone-worker-lease-exit-cleanup-v1";

volatile std::sig_atomic_t stop_requested = 0;

extern "C" void
request_stop(int) {
  stop_requested = 1;
}

constexpr uint64_t kYxstmSize = 64 * 1024 * 1024;
constexpr double kDecimalMbBytes = 1000000.0;
constexpr uint64_t kSqliteCsvSchemaVersion = UINT64_C(44);

static const volatile char benchmark_cipher_marker[] __attribute__((used)) = BENCHMARK_CIPHER_MARKER;
constexpr uint64_t kPerfYxstmSize = 64 * 1024 * 1024;
constexpr uint64_t kPerfYxstmSliceSize = 16 * 1024 * 1024;
static_assert(kPerfYxstmSize ==
                  KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT *
                      kPerfYxstmSliceSize,
              "P10 YXSTM must contain one bank of four aligned slices");
constexpr uint64_t kUtmSize = 64 * 1024;
constexpr uint64_t kSqliteWorkerUtmSize = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
constexpr uint64_t kPerfUtmSize = 32 * 1000000;
constexpr uint64_t kFreeMemSize = 1024 * 1024;
constexpr uint64_t kAesBaselineFreeMemSize = 24 * 1000000;
// The master is created first and therefore fixes the group EPM slice size.
// Workers need only AES scratch space; SQLite itself runs once on CPU0.
constexpr uint64_t kSqliteMasterFreeMemSize = 12 * 1000000;
/* Eyrie materializes the worker's three 2 MB ELF/BSS buffers from freemem at
 * first touch. Keep enough pages for those buffers plus runtime page tables
 * and stack; the resulting request still fits the 14 MiB group EPM slice. */
constexpr uint64_t kSqliteWorkerFreeMemSize = 12 * 1000000;
constexpr uint64_t kPerfBatchBytes = GROUP_PMP_BENCH_BATCH_BYTES;
constexpr size_t kPerfExpectedOffset = GROUP_PMP_BENCH_EXPECTED_OFFSET;
static_assert(GROUP_PMP_BENCH_INPUT_OFFSET + kPerfBatchBytes <=
                  kPerfExpectedOffset,
              "P10 input and expected digest table must not overlap");
static_assert(kPerfExpectedOffset +
                  sizeof(struct group_pmp_bench_expected_table) <=
                  kPerfUtmSize,
              "P10 expected digest table must fit in UTM");
constexpr uint64_t kPerfDefaultCycleHz = 1000000000ULL;
constexpr size_t kPerfUtmChunkBytes = 16 * 1024;
constexpr size_t kPerfUtmOffset = GROUP_PMP_BENCH_INPUT_OFFSET;
constexpr uint64_t kPerfAesEncrypt = GROUP_PMP_BENCH_AES_ENCRYPT;
constexpr uint64_t kPerfAesDecrypt = GROUP_PMP_BENCH_AES_DECRYPT;
constexpr uint64_t kScaleYxstmSize = 64 * 1024 * 1024;
constexpr uint64_t kScaleYxstmSliceSize = 16 * 1024 * 1024;
static_assert(kScaleYxstmSize ==
                  KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT *
                      kScaleYxstmSliceSize,
              "scale-test YXSTM layout must contain four slices");
static_assert(GROUP_PMP_SCALE_RESULT_OFFSET +
                  sizeof(struct group_pmp_scale_result) <= kUtmSize,
              "scale-test result must fit in the per-enclave UTM");
/* Aligned backing; each worker lane exposes exactly 12 MB of task capacity. */
constexpr uint64_t kMixedYxstmSize = 64 * 1024 * 1024;
constexpr uint64_t kMixedYxstmSliceSize = 16 * 1024 * 1024;
static_assert(KEYSTONE_YXSTM_WORKER_TOTAL_SIZE == 36 * 1000000,
              "mixed YXSTM must expose exactly three 12 MB worker lanes");
constexpr uint64_t kMixedYxstmBankStride =
    KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT * kMixedYxstmSliceSize;
static_assert(kMixedYxstmSize ==
                  GROUP_PMP_MIXED_BANK_COUNT * kMixedYxstmBankStride,
               "mixed-scale YXSTM must contain one four-slice bank");
static_assert(GROUP_PMP_MIXED_RESULT_OFFSET +
                  sizeof(struct group_pmp_mixed_worker_result) <= kUtmSize,
              "mixed-scale result must fit in UTM");
static_assert(GROUP_PMP_SQLITE_VFS_CONFIG_OFFSET +
                  sizeof(struct group_pmp_mixed_worker_config) <=
              GROUP_PMP_SQLITE_VFS_RESULT_OFFSET,
              "SQLite worker config must fit before the result");
static_assert(GROUP_PMP_SQLITE_VFS_RESULT_OFFSET +
                  sizeof(struct group_pmp_mixed_worker_result) <=
              GROUP_PMP_SQLITE_VFS_STATUS_OFFSET,
              "SQLite worker result must fit before async status slots");
static_assert(sizeof(struct edge_call) +
                  sizeof(struct group_pmp_sqlite_vfs_batch) <=
              GROUP_PMP_SQLITE_VFS_CONFIG_OFFSET,
              "SQLite inline batch must not overwrite worker config");
static_assert(sizeof(struct edge_call) +
                  sizeof(struct group_pmp_sqlite_vfs_indirect_batch) <=
              GROUP_PMP_SQLITE_VFS_CONFIG_OFFSET,
              "SQLite indirect batch must not overwrite worker config");
static_assert(GROUP_PMP_SQLITE_VFS_STATUS_OFFSET +
                  GROUP_PMP_SQLITE_VFS_LEGACY_STATUS_COUNT *
                      sizeof(struct group_pmp_sqlite_vfs_status) <=
              GROUP_PMP_SQLITE_VFS_CONTROL_BYTES,
              "SQLite legacy status metadata must fit in control page");
static_assert(GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET +
                  GROUP_PMP_SQLITE_VFS_BATCH_MAX *
                      sizeof(struct group_pmp_sqlite_vfs_status) <=
              GROUP_PMP_SQLITE_VFS_UTM_BYTES,
              "SQLite ring metadata must fit in direct UTM");
static_assert(GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT == 488 || kSqliteWorkerUtmSize <=
                  GROUP_PMP_SQLITE_VFS_BUDDY_LIMIT_BYTES,
              "SQLite worker UTM must stay on the buddy allocation path");
static_assert(KEYSTONE_YXSTM_SLOT_PROTOCOL_METADATA_SIZE == 0,
              "mixed protocol metadata must remain SM-private");
static_assert(GROUP_PMP_MIXED_MAX_WORKERS + UINT64_C(1) <=
                  KEYSTONE_GROUP_MEMBER_LIMIT,
              "mixed worker limit must leave one group member for master");
static_assert(GROUP_PMP_MIXED_MAX_LANE_DEPTH ==
                  (GROUP_PMP_MIXED_MAX_WORKERS +
                   GROUP_PMP_MIXED_LANES - UINT64_C(1)) /
                      GROUP_PMP_MIXED_LANES,
              "mixed lane depth must be derived from worker capacity");
static_assert(GROUP_PMP_AES_BASELINE_RESULT_OFFSET +
                  sizeof(struct group_pmp_aes_baseline_result) <= kUtmSize,
              "AES enclave baseline result must fit in UTM");
static_assert(kAesBaselineFreeMemSize >=
                  2 * GROUP_PMP_AES_BASELINE_BYTES + 4 * 1000000,
              "AES enclave baseline needs room for both EPM buffers");
const uint8_t kPerfAesKey[16] = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x11, 0x33, 0x55, 0x77, 0x99, 0xbb, 0xdd, 0xff,
};
constexpr uint64_t kPerfPayloadCapacity =
    (kPerfYxstmSliceSize - sizeof(struct keystone_yxstm_channel_header) -
     sizeof(struct group_pmp_bench_header)) & ~UINT64_C(15);
static_assert(kPerfPayloadCapacity != 0,
              "P10 YXSTM slice must have payload capacity");
constexpr uint64_t kDefaultGroupId = 1;
constexpr uint64_t kDefaultGroupCapacity = 12;
constexpr uint64_t kDefaultGroupHartCount = 4;
constexpr uint64_t kMaxEnabledGroups = 4;
constexpr uint64_t kHousekeepingCpu = KEYSTONE_VF2_HOUSEKEEPING_CPU;
constexpr uint64_t kHousekeepingHart = KEYSTONE_VF2_HOUSEKEEPING_HART;
constexpr uint64_t kCpuHartOffset = KEYSTONE_VF2_CPU_HART_OFFSET;
constexpr uint64_t kDefaultCoherenceBusyTimeoutMs = 5000;
constexpr uint64_t kCoherenceBusyBackoffUs = 100;
constexpr uint64_t kGroupPmpOcallPayload = 0x4f43414c4c424c4bULL;
constexpr uint64_t kGroupPmpTaskOcallPayload = 0x4f43414c4c544153ULL;
constexpr uint64_t kGroupPmpOcallAck = 0x47504d504f43414cULL;
constexpr size_t kSqliteAsyncQueueDepth = 32768;
constexpr char kLoaderAbiMarker[] = KEYSTONE_GROUP_ABI_MARKER;
uint64_t last_group_generation[kMaxEnabledGroups + 1] = {0};
struct keystone_group_topology configured_topologies[kMaxEnabledGroups + 1];
bool configured_topology_valid[kMaxEnabledGroups + 1] = {false};
bool lifecycle_freeze_checked = false;
std::mutex group_ocall_dispatch_mutex;

uint64_t sqlite_status_offset_for_request(
    const struct group_pmp_sqlite_vfs_request& request) {
  return (request.reserved[0] & GROUP_PMP_SQLITE_STORE_RING) ?
      GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET_FOR_SLOT(
          request.ring_slot) +
          request.descriptor_id *
              sizeof(struct group_pmp_sqlite_vfs_status) :
      GROUP_PMP_SQLITE_VFS_STATUS_OFFSET +
          request.buffer_id * sizeof(struct group_pmp_sqlite_vfs_status);
}

/* Independent legacy baseline: ciphertext remains in SQLite BLOB rows and
 * every request is serviced separately. No extent sorting, range merging,
 * collection window, readv/writev, or io_uring is used.
 * Deployment marker: keystone-sqlite-no-extent-io-v2 */
static const volatile char sqlite_no_extent_io_artifact_marker[]
    __attribute__((used)) = "keystone-sqlite-no-extent-io-v2";

struct SqliteAsyncTask {
  struct group_pmp_sqlite_vfs_request request;
  uint8_t* utm;
  size_t utm_size;
  std::shared_ptr<SqliteAsyncCompletion> completion;
  uint64_t enqueue_ns;
};

uint64_t sqlite_perf_now_ns() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
}

void sqlite_atomic_update_max(std::atomic<uint64_t>& target,
                              uint64_t value) {
  uint64_t observed = target.load(std::memory_order_relaxed);
  while (observed < value &&
         !target.compare_exchange_weak(observed, value,
                                       std::memory_order_relaxed)) {}
}

void sqlite_atomic_set_first(std::atomic<uint64_t>& target,
                             uint64_t value) {
  uint64_t expected = 0;
  (void)target.compare_exchange_strong(expected, value,
                                       std::memory_order_relaxed);
}

class SqliteAsyncIoService {
 public:
  explicit SqliteAsyncIoService(uint64_t lane_id, bool accepts_all_lanes)
      : lane_id_(lane_id), accepts_all_lanes_(accepts_all_lanes),
        stopping_(false), processing_task_(false), db_(nullptr),
        reset_statement_(nullptr), write_statement_(nullptr),
        read_statement_(nullptr), begin_statement_(nullptr),
        commit_statement_(nullptr), rollback_statement_(nullptr),
        transaction_open_(false), transaction_extent_count_(0),
        transaction_run_(0), transaction_workload_(0),
        task_count_(0), data_request_count_(0), data_request_bytes_(0),
        data_success_bytes_(0), batch_count_(0), queue_wait_ns_(0),
        writer_wait_ns_(0), read_service_ns_(0), write_service_ns_(0),
        control_service_ns_(0), commit_ns_(0), commit_count_(0),
        queue_depth_peak_(0),
        window_first_enqueue_ns_(0), window_last_completion_ns_(0),
        max_queue_wait_ns_(0), max_batch_service_ns_(0),
        max_completion_latency_ns_(0),
        worker_(&SqliteAsyncIoService::worker_loop, this) {}

  ~SqliteAsyncIoService() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopping_ = true;
    }
    condition_.notify_all();
    worker_.join();
    std::lock_guard<std::mutex> database_lock(database_mutex_);
    if (db_) {
      if (transaction_open_)
        (void)step_control_statement(commit_statement_);
      if (reset_statement_)
        sqlite3_finalize(reset_statement_);
      if (write_statement_)
        sqlite3_finalize(write_statement_);
      if (read_statement_)
        sqlite3_finalize(read_statement_);
      if (begin_statement_)
        sqlite3_finalize(begin_statement_);
      if (commit_statement_)
        sqlite3_finalize(commit_statement_);
      if (rollback_statement_)
        sqlite3_finalize(rollback_statement_);
      sqlite3_close(db_);
    }
  }

  bool submit(const struct group_pmp_sqlite_vfs_request& request,
               uint8_t* utm, size_t utm_size,
               const std::shared_ptr<SqliteAsyncCompletion>& completion) {
    return submitBatch(&request, 1, utm, utm_size, completion);
  }

  bool submitBatch(const struct group_pmp_sqlite_vfs_request* requests,
                   uint64_t count, uint8_t* utm, size_t utm_size,
                   const std::shared_ptr<SqliteAsyncCompletion>& completion) {
    std::array<SqliteAsyncTask, GROUP_PMP_SQLITE_VFS_BATCH_MAX> tasks;
    uint64_t now = sqlite_perf_now_ns();
    if (!requests || !count || count > GROUP_PMP_SQLITE_VFS_BATCH_MAX)
      return false;
    for (uint64_t index = 0; index < count; ++index) {
      const struct group_pmp_sqlite_vfs_request& request = requests[index];
      if (!utm ||
          sqlite_status_offset_for_request(request) > utm_size ||
          sizeof(struct group_pmp_sqlite_vfs_status) >
              utm_size - sqlite_status_offset_for_request(request) ||
          request.buffer_offset > utm_size ||
          request.length > utm_size - request.buffer_offset ||
          (!accepts_all_lanes_ &&
           request.worker_index % GROUP_PMP_MIXED_LANES != lane_id_))
        return false;
      tasks[index].request = request;
      tasks[index].utm = utm;
      tasks[index].utm_size = utm_size;
      tasks[index].completion = completion;
      tasks[index].enqueue_ns = now;
    }
    sqlite_atomic_set_first(window_first_enqueue_ns_, now);
    uint64_t depth = 0;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      condition_.wait(lock, [this, count] {
        return stopping_ ||
            queue_.size() <= kSqliteAsyncQueueDepth - count;
      });
      if (stopping_)
        return false;
      for (uint64_t index = 0; index < count; ++index)
        queue_.push_back(tasks[index]);
      depth = queue_.size();
      uint64_t observed = queue_depth_peak_.load(std::memory_order_relaxed);
      while (observed < depth &&
             !queue_depth_peak_.compare_exchange_weak(
                 observed, depth, std::memory_order_relaxed)) {}
    }
    for (uint64_t index = 0; index < count; ++index)
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_QUEUE_ENQUEUE, requests[index],
          completion ? completion->trace_id : 0, 0, depth, now);
    batch_count_.fetch_add(1, std::memory_order_relaxed);
    condition_.notify_all();
    return true;
  }

  SqliteIoPerfSnapshot snapshot() const {
    SqliteIoPerfSnapshot value;
    value.task_count = task_count_.load(std::memory_order_relaxed);
    value.batch_count = batch_count_.load(std::memory_order_relaxed);
    value.queue_wait_ns = queue_wait_ns_.load(std::memory_order_relaxed);
    value.writer_wait_ns = writer_wait_ns_.load(std::memory_order_relaxed);
    value.read_service_ns = read_service_ns_.load(std::memory_order_relaxed);
    value.write_service_ns = write_service_ns_.load(std::memory_order_relaxed);
    value.control_service_ns = control_service_ns_.load(std::memory_order_relaxed);
    value.commit_ns = commit_ns_.load(std::memory_order_relaxed);
    value.commit_count = commit_count_.load(std::memory_order_relaxed);
    value.queue_depth_peak = queue_depth_peak_.load(std::memory_order_relaxed);
    // One SQLite BLOB operation per data request. Control tasks are not data
    // I/O, and these are not SQLite's internal block-device request counts.
    value.logical_request_count = data_request_count_.load(std::memory_order_relaxed);
    value.physical_request_count = value.logical_request_count;
    value.sparse_io_count = value.logical_request_count;
    value.physical_io_bytes = data_request_bytes_.load(std::memory_order_relaxed);
    value.useful_io_bytes = data_success_bytes_.load(std::memory_order_relaxed);
    value.window_first_enqueue_ns =
        window_first_enqueue_ns_.load(std::memory_order_relaxed);
    value.window_last_completion_ns =
        window_last_completion_ns_.load(std::memory_order_relaxed);
    value.critical_path_ns = value.window_last_completion_ns >=
            value.window_first_enqueue_ns ?
        value.window_last_completion_ns - value.window_first_enqueue_ns : 0;
    value.max_queue_wait_ns =
        max_queue_wait_ns_.load(std::memory_order_relaxed);
    value.max_batch_service_ns =
        max_batch_service_ns_.load(std::memory_order_relaxed);
    value.max_completion_latency_ns =
        max_completion_latency_ns_.load(std::memory_order_relaxed);
    return value;
  }

  SqliteIoPerfSnapshot drainAndSnapshot() {
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [this] {
      return queue_.empty() && !processing_task_;
    });
    return snapshot();
  }

  bool resetPerf() {
    bool cache_ready = true;
#ifdef __linux__
    const char* cache_mode = std::getenv("GROUP_PMP_SQLITE_CACHE_MODE");
    if (cache_mode && (std::strcmp(cache_mode, "cold") == 0 ||
                       std::strcmp(cache_mode, "direct") == 0)) {
      {
        std::lock_guard<std::mutex> lock(database_mutex_);
        if (db_)
          (void)sqlite3_exec(db_, "PRAGMA shrink_memory", nullptr,
                             nullptr, nullptr);
      }
      const int fd = open(database_path().c_str(), O_RDONLY | O_CLOEXEC);
      if (fd >= 0) {
        if (fdatasync(fd) != 0 ||
            posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) != 0)
          cache_ready = false;
        close(fd);
      } else {
        cache_ready = false;
      }
    }
#endif
    task_count_.store(0, std::memory_order_relaxed);
    data_request_count_.store(0, std::memory_order_relaxed);
    data_request_bytes_.store(0, std::memory_order_relaxed);
    data_success_bytes_.store(0, std::memory_order_relaxed);
    batch_count_.store(0, std::memory_order_relaxed);
    queue_wait_ns_.store(0, std::memory_order_relaxed);
    writer_wait_ns_.store(0, std::memory_order_relaxed);
    read_service_ns_.store(0, std::memory_order_relaxed);
    write_service_ns_.store(0, std::memory_order_relaxed);
    control_service_ns_.store(0, std::memory_order_relaxed);
    commit_ns_.store(0, std::memory_order_relaxed);
    commit_count_.store(0, std::memory_order_relaxed);
    queue_depth_peak_.store(0, std::memory_order_relaxed);
    window_first_enqueue_ns_.store(0, std::memory_order_relaxed);
    window_last_completion_ns_.store(0, std::memory_order_relaxed);
    max_queue_wait_ns_.store(0, std::memory_order_relaxed);
    max_batch_service_ns_.store(0, std::memory_order_relaxed);
    max_completion_latency_ns_.store(0, std::memory_order_relaxed);
    return cache_ready;
  }

  void cleanup_case(uint64_t worker_count, uint64_t workload) {
    std::lock_guard<std::mutex> lock(database_mutex_);
    sqlite3_stmt* statement = nullptr;
    if (db_ && transaction_open_) {
      (void)step_control_statement(commit_statement_);
      transaction_open_ = false;
      transaction_extent_count_ = 0;
      transaction_finished_workers_.clear();
    }
    if (!ensure_database_locked() ||
        sqlite3_prepare_v2(db_,
            "DELETE FROM cipher_extents WHERE worker_count=?1 AND workload=?2",
            -1, &statement, nullptr) != SQLITE_OK)
      return;
    sqlite3_bind_int64(statement, 1, static_cast<sqlite3_int64>(worker_count));
    sqlite3_bind_int64(statement, 2, static_cast<sqlite3_int64>(workload));
    (void)sqlite3_step(statement);
    sqlite3_finalize(statement);
  }

 private:
  std::string database_path() const {
    const char* directory = std::getenv("GROUP_PMP_SQLITE_STORAGE_DIR");
    char name[320];
    if (!directory || !directory[0])
      directory = "/tmp";
    std::snprintf(name, sizeof(name), "%s/keystone-group-ciphertext.db",
                  directory);
    return name;
  }

  bool ensure_database_locked() {
    static std::mutex database_initialization_mutex;
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS cipher_extents("
        "run_id INTEGER NOT NULL, worker_index INTEGER NOT NULL,"
        "worker_count INTEGER NOT NULL, workload INTEGER NOT NULL,"
        "extent_id INTEGER NOT NULL, logical_offset INTEGER NOT NULL,"
        "logical_size INTEGER NOT NULL, sequence INTEGER NOT NULL,"
        "tag BLOB NOT NULL, ciphertext BLOB NOT NULL,"
        "PRIMARY KEY(run_id,worker_index,workload,logical_offset))";
    char* error = nullptr;
    if (db_)
      return reset_statement_ && write_statement_ && read_statement_ &&
          begin_statement_ && commit_statement_ && rollback_statement_;
    std::lock_guard<std::mutex> initialization_lock(
        database_initialization_mutex);
    if (sqlite3_open_v2(database_path().c_str(), &db_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                            SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK)
      return false;
    if (sqlite3_exec(db_,
                     "PRAGMA journal_mode=WAL;PRAGMA synchronous=NORMAL;"
                     "PRAGMA busy_timeout=5000;PRAGMA wal_autocheckpoint=4096;"
                     "PRAGMA temp_store=MEMORY;PRAGMA cache_size=-8192;",
                     nullptr, nullptr, &error) != SQLITE_OK ||
        sqlite3_exec(db_, schema, nullptr, nullptr, &error) != SQLITE_OK) {
      if (error)
        sqlite3_free(error);
      return false;
    }
    return sqlite3_prepare_v2(db_,
               "DELETE FROM cipher_extents WHERE run_id=?1 AND worker_index=?2 "
               "AND workload=?3", -1, &reset_statement_, nullptr) == SQLITE_OK &&
        sqlite3_prepare_v2(db_,
               "INSERT OR REPLACE INTO cipher_extents VALUES("
               "?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
               -1, &write_statement_, nullptr) == SQLITE_OK &&
        sqlite3_prepare_v2(db_,
               "SELECT sequence,tag,ciphertext FROM cipher_extents WHERE "
               "run_id=?1 AND worker_index=?2 AND workload=?3 AND "
               "logical_offset=?4", -1, &read_statement_, nullptr) ==
            SQLITE_OK &&
        sqlite3_prepare_v2(db_, "BEGIN IMMEDIATE", -1, &begin_statement_,
                           nullptr) == SQLITE_OK &&
        sqlite3_prepare_v2(db_, "COMMIT", -1, &commit_statement_, nullptr) ==
            SQLITE_OK &&
        sqlite3_prepare_v2(db_, "ROLLBACK", -1, &rollback_statement_,
                           nullptr) == SQLITE_OK;
  }

  static bool step_control_statement(sqlite3_stmt* statement) {
    if (!statement)
      return false;
    sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
    const int result = sqlite3_step(statement);
    sqlite3_reset(statement);
    return result == SQLITE_DONE;
  }

  int commit_locked() {
    uint64_t started = sqlite_perf_now_ns();
    int result = step_control_statement(commit_statement_) ?
        SQLITE_OK : SQLITE_ERROR;
    commit_ns_.fetch_add(sqlite_perf_now_ns() - started,
                         std::memory_order_relaxed);
    commit_count_.fetch_add(1, std::memory_order_relaxed);
    return result;
  }

  void publish(const SqliteAsyncTask& task, int64_t result,
               uint64_t length, uint64_t sequence,
               const uint8_t tag[16]) {
    struct group_pmp_sqlite_vfs_status status;
    const uint64_t final_state = result == 0 ?
        GROUP_PMP_SQLITE_VFS_STATE_DONE :
        GROUP_PMP_SQLITE_VFS_STATE_ERROR;
    const uint64_t offset = sqlite_status_offset_for_request(task.request);
    uint8_t* destination;
    if (offset > task.utm_size || sizeof(status) > task.utm_size - offset)
      return;
    destination = task.utm + offset;
    std::memset(&status, 0, sizeof(status));
    status.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    status.version = GROUP_PMP_SQLITE_VFS_VERSION;
    status.request_id = task.request.request_id;
    /* Publish all payload fields before the terminal state commit word. */
    status.state = GROUP_PMP_SQLITE_VFS_STATE_PENDING;
    status.result = result;
    status.length = length;
    status.sequence = sequence;
    if (tag)
      std::memcpy(status.tag, tag, sizeof(status.tag));
    std::memcpy(destination, &status, sizeof(status));
    __atomic_store_n(reinterpret_cast<uint64_t*>(
                         destination + offsetof(
                             struct group_pmp_sqlite_vfs_status, state)),
                      final_state, __ATOMIC_RELEASE);
    if ((task.request.reserved[0] & GROUP_PMP_SQLITE_STORE_RING) &&
        task.request.ring_slot < GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT) {
      const uint64_t ring_offset = GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(
          task.request.ring_slot);
      struct group_pmp_sqlite_vfs_ring_header* ring =
          reinterpret_cast<struct group_pmp_sqlite_vfs_ring_header*>(
              task.utm + ring_offset);
      if (ring_offset <= task.utm_size &&
          sizeof(*ring) <=
              task.utm_size - ring_offset &&
          ring->magic == GROUP_PMP_SQLITE_VFS_RING_MAGIC &&
          ring->version == GROUP_PMP_SQLITE_VFS_VERSION)
        sqlite_publish_ring_completion(ring, UINT64_C(1));
    }
    sqlite_gantt_trace().recordRequest(
        SQLITE_GANTT_REQUEST_COMPLETE, task.request,
        task.completion ? task.completion->trace_id : 0, result);
    if (task.completion)
      task.completion->completeOne();
  }

  static void report_io_error(
      const char* stage, const struct group_pmp_sqlite_vfs_request& request,
      int result) {
    const int error = result < 0 ? -result : result;
    std::fprintf(stderr,
        "[P10][sqlite-vfs] %s failed: worker=%llu workload=%llu request=%llu "
        "file=%016llx offset=%llu length=%llu result=%d errno=%d (%s) "
        "sqlite=%s\n",
        stage,
        static_cast<unsigned long long>(request.worker_index),
        static_cast<unsigned long long>(request.workload),
        static_cast<unsigned long long>(request.request_id),
        static_cast<unsigned long long>(request.file_id),
        static_cast<unsigned long long>(request.file_offset),
        static_cast<unsigned long long>(request.length), result, error,
        error ? std::strerror(error) : "none", sqlite3_errstr(error));
  }

  int process(const SqliteAsyncTask& task) {
    const struct group_pmp_sqlite_vfs_request& request = task.request;
    uint8_t* data = task.utm + request.buffer_offset;
    uint8_t zero_tag[16] = {0};
    std::lock_guard<std::mutex> database_lock(database_mutex_);
    sqlite3_stmt* statement = nullptr;
    int step;

    if (!ensure_database_locked()) {
      publish(task, -EIO, request.length, request.sequence, zero_tag);
      return -EIO;
    }

    if (request.operation == GROUP_PMP_SQLITE_VFS_OP_RESET) {
      if (transaction_open_) {
        if (commit_locked() != SQLITE_OK)
          goto sqlite_error_no_statement;
        transaction_open_ = false;
        transaction_extent_count_ = 0;
        transaction_finished_workers_.clear();
      }
      statement = reset_statement_;
      sqlite3_reset(statement);
      sqlite3_clear_bindings(statement);
      sqlite3_bind_int64(statement, 1, request.run_id);
      sqlite3_bind_int64(statement, 2, request.worker_index);
      sqlite3_bind_int64(statement, 3, request.workload);
      step = sqlite3_step(statement);
      sqlite3_reset(statement);
      statement = nullptr;
      if (step != SQLITE_DONE)
        goto sqlite_error_no_statement;
      publish(task, 0, request.length, request.sequence, zero_tag);
      return 0;
    }

    if (request.operation == GROUP_PMP_SQLITE_VFS_OP_SYNC) {
      /* The service queue is FIFO, so all requests submitted by this worker
       * before SYNC have already reached SQLite. A collective worker-count
       * barrier here deadlocks if any peer is delayed or cancelled. */
      if (transaction_open_) {
        if (commit_locked() != SQLITE_OK)
          goto sqlite_error_no_statement;
        transaction_open_ = false;
        transaction_extent_count_ = 0;
        transaction_finished_workers_.clear();
      }
      publish(task, 0, request.length, request.sequence, zero_tag);
      return 0;
    }

    if (request.operation == GROUP_PMP_SQLITE_VFS_OP_DELETE ||
        request.operation == GROUP_PMP_SQLITE_VFS_OP_TRUNCATE) {
      publish(task, 0, request.length, request.sequence, zero_tag);
      return 0;
    }

    if (request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE) {
      const uint64_t transaction_workers = request.worker_count;
      if (!transaction_workers)
        goto sqlite_error_no_statement;
      if (transaction_open_ &&
          (transaction_run_ != request.run_id ||
           transaction_workload_ != request.workload)) {
        if (commit_locked() != SQLITE_OK)
          goto sqlite_error_no_statement;
        transaction_open_ = false;
        transaction_extent_count_ = 0;
        transaction_finished_workers_.clear();
      }
      if (!transaction_open_) {
        const uint64_t writer_started = sqlite_perf_now_ns();
        const bool transaction_started =
            step_control_statement(begin_statement_);
        writer_wait_ns_.fetch_add(sqlite_perf_now_ns() - writer_started,
                                  std::memory_order_relaxed);
        if (!transaction_started)
          goto sqlite_error_no_statement;
        transaction_open_ = true;
        transaction_extent_count_ = 0;
        transaction_run_ = request.run_id;
        transaction_workload_ = request.workload;
      }
      statement = write_statement_;
      sqlite3_reset(statement);
      sqlite3_clear_bindings(statement);
      sqlite3_bind_int64(statement, 1, request.run_id);
      sqlite3_bind_int64(statement, 2, request.worker_index);
      sqlite3_bind_int64(statement, 3, request.worker_count);
      sqlite3_bind_int64(statement, 4, request.workload);
      sqlite3_bind_int64(statement, 5, request.file_id);
      sqlite3_bind_int64(statement, 6, request.file_offset);
      sqlite3_bind_int64(statement, 7, request.logical_size);
      sqlite3_bind_int64(statement, 8, request.sequence);
      sqlite3_bind_blob(statement, 9, request.tag, sizeof(request.tag),
                        SQLITE_TRANSIENT);
      sqlite3_bind_blob64(statement, 10, data, request.length,
                          SQLITE_TRANSIENT);
      step = sqlite3_step(statement);
      sqlite3_reset(statement);
      statement = nullptr;
      if (step != SQLITE_DONE)
        goto sqlite_error_no_statement;
      transaction_extent_count_++;
      if ((request.reserved[0] & GROUP_PMP_SQLITE_STORE_TXN_END) != 0)
        transaction_finished_workers_.insert(request.worker_index);
      if (transaction_extent_count_ >= GROUP_PMP_SQLITE_VFS_HOST_BATCH_EXTENTS ||
          transaction_finished_workers_.size() == transaction_workers) {
        const bool lane_finished =
            transaction_finished_workers_.size() == transaction_workers;
        if (commit_locked() != SQLITE_OK)
          goto sqlite_error_no_statement;
        transaction_open_ = false;
        transaction_extent_count_ = 0;
        if (lane_finished)
          transaction_finished_workers_.clear();
      }
      publish(task, 0, request.length, request.sequence, request.tag);
      return 0;
    }

    if (request.operation == GROUP_PMP_SQLITE_VFS_OP_READ) {
      statement = read_statement_;
      sqlite3_reset(statement);
      sqlite3_clear_bindings(statement);
      sqlite3_bind_int64(statement, 1, request.run_id);
      sqlite3_bind_int64(statement, 2, request.worker_index);
      sqlite3_bind_int64(statement, 3, request.workload);
      sqlite3_bind_int64(statement, 4, request.file_offset);
      step = sqlite3_step(statement);
      if (step != SQLITE_ROW || sqlite3_column_bytes(statement, 1) != 16 ||
          sqlite3_column_bytes(statement, 2) <= 0 ||
          static_cast<uint64_t>(sqlite3_column_bytes(statement, 2)) >
              GROUP_PMP_SQLITE_VFS_BUFFER_BYTES) {
        sqlite3_reset(statement);
        statement = nullptr;
        report_io_error("select", request, -ENOENT);
        publish(task, -ENOENT, request.length, request.sequence, zero_tag);
        return -ENOENT;
      }
      {
        const uint64_t sequence = static_cast<uint64_t>(
            sqlite3_column_int64(statement, 0));
        const uint8_t* tag = static_cast<const uint8_t*>(
            sqlite3_column_blob(statement, 1));
        const uint8_t* ciphertext = static_cast<const uint8_t*>(
            sqlite3_column_blob(statement, 2));
        const uint64_t length = static_cast<uint64_t>(
            sqlite3_column_bytes(statement, 2));
        uint8_t copied_tag[16];
        std::memcpy(copied_tag, tag, sizeof(copied_tag));
        std::memcpy(data, ciphertext, static_cast<size_t>(length));
        sqlite3_reset(statement);
        statement = nullptr;
        publish(task, 0, length, sequence, copied_tag);
      }
      return 0;
    }

    publish(task, -EINVAL, request.length, request.sequence, zero_tag);
    return -EINVAL;

sqlite_error_no_statement:
    if (transaction_open_) {
      (void)step_control_statement(rollback_statement_);
      transaction_open_ = false;
      transaction_extent_count_ = 0;
      transaction_finished_workers_.clear();
    }
    report_io_error("sqlite", request, -EIO);
    publish(task, -EIO, request.length, request.sequence, zero_tag);
    return -EIO;
  }

  void worker_loop() {
#if defined(__linux__)
    cpu_set_t housekeeping;
    CPU_ZERO(&housekeeping);
    CPU_SET(0, &housekeeping);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(housekeeping),
                                 &housekeeping);
#endif
    for (;;) {
      SqliteAsyncTask task;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this] {
          return stopping_ || !queue_.empty();
        });
        if (stopping_ && queue_.empty())
          return;
        task = queue_.front();
        queue_.pop_front();
        processing_task_ = true;
      }
      condition_.notify_all();
      uint64_t started = sqlite_perf_now_ns();
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_QUEUE_SERVICE_BEGIN, task.request,
          task.completion ? task.completion->trace_id : 0, 0, 1, started);
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_STORAGE_IO_BEGIN, task.request,
          task.completion ? task.completion->trace_id : 0, 0, 1, started);
      uint64_t queue_wait = started >= task.enqueue_ns ?
          started - task.enqueue_ns : 0;
      sqlite_atomic_update_max(max_queue_wait_ns_, queue_wait);
      queue_wait_ns_.fetch_add(queue_wait, std::memory_order_relaxed);
      const unsigned diagnostic_channel = accepts_all_lanes_ ?
          static_cast<unsigned>(GroupWarmupDiagnostics::WRITER) :
          GroupWarmupDiagnostics::READER0 + static_cast<unsigned>(lane_id_);
      group_warmup_diagnostics.mark(diagnostic_channel, "sqlite-process",
          task.request.worker_index, task.request.request_id);
      int process_result = process(task);
      group_warmup_diagnostics.mark(diagnostic_channel, "idle");
      sqlite_io_range_trace().recordNoExtent(task.request, process_result);
      uint64_t elapsed = sqlite_perf_now_ns() - started;
      const uint64_t finished = started + elapsed;
      sqlite_atomic_update_max(max_batch_service_ns_, elapsed);
      sqlite_atomic_update_max(
          max_completion_latency_ns_,
          finished >= task.enqueue_ns ? finished - task.enqueue_ns : 0);
      sqlite_atomic_update_max(window_last_completion_ns_, finished);
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_STORAGE_IO_END, task.request,
          task.completion ? task.completion->trace_id : 0, process_result);
      task_count_.fetch_add(1, std::memory_order_relaxed);
      if (task.request.operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
          task.request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE) {
        data_request_count_.fetch_add(1, std::memory_order_relaxed);
        // Host-requested BLOB bytes, not SQLite page/WAL/device traffic.
        data_request_bytes_.fetch_add(task.request.length, std::memory_order_relaxed);
        if (!process_result)
          data_success_bytes_.fetch_add(task.request.length, std::memory_order_relaxed);
      }
      if (task.request.operation == GROUP_PMP_SQLITE_VFS_OP_READ)
        read_service_ns_.fetch_add(elapsed, std::memory_order_relaxed);
      else if (task.request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE)
        write_service_ns_.fetch_add(elapsed, std::memory_order_relaxed);
      else
        control_service_ns_.fetch_add(elapsed, std::memory_order_relaxed);
      {
        std::lock_guard<std::mutex> lock(mutex_);
        processing_task_ = false;
      }
      condition_.notify_all();
    }
  }

  uint64_t lane_id_;
  bool accepts_all_lanes_;
  bool stopping_;
  bool processing_task_;
  std::mutex mutex_;
  std::condition_variable condition_;
  std::deque<SqliteAsyncTask> queue_;
  sqlite3* db_;
  sqlite3_stmt* reset_statement_;
  sqlite3_stmt* write_statement_;
  sqlite3_stmt* read_statement_;
  sqlite3_stmt* begin_statement_;
  sqlite3_stmt* commit_statement_;
  sqlite3_stmt* rollback_statement_;
  bool transaction_open_;
  uint64_t transaction_extent_count_;
  uint64_t transaction_run_;
  uint64_t transaction_workload_;
  std::set<uint64_t> transaction_finished_workers_;
  std::atomic<uint64_t> task_count_;
  std::atomic<uint64_t> data_request_count_;
  std::atomic<uint64_t> data_request_bytes_;
  std::atomic<uint64_t> data_success_bytes_;
  std::atomic<uint64_t> batch_count_;
  std::atomic<uint64_t> queue_wait_ns_;
  std::atomic<uint64_t> writer_wait_ns_;
  std::atomic<uint64_t> read_service_ns_;
  std::atomic<uint64_t> write_service_ns_;
  std::atomic<uint64_t> control_service_ns_;
  std::atomic<uint64_t> commit_ns_;
  std::atomic<uint64_t> commit_count_;
  std::atomic<uint64_t> queue_depth_peak_;
  std::atomic<uint64_t> window_first_enqueue_ns_;
  std::atomic<uint64_t> window_last_completion_ns_;
  std::atomic<uint64_t> max_queue_wait_ns_;
  std::atomic<uint64_t> max_batch_service_ns_;
  std::atomic<uint64_t> max_completion_latency_ns_;
  std::thread worker_;
  std::mutex database_mutex_;
};

class SqliteNoExtentIoService {
 public:
  SqliteNoExtentIoService()
      : writer_(new SqliteAsyncIoService(0, true)) {
    for (uint64_t lane = 0; lane < GROUP_PMP_MIXED_LANES; ++lane)
      readers_[lane].reset(new SqliteAsyncIoService(lane, false));
  }

  bool submit(const struct group_pmp_sqlite_vfs_request& request,
               uint8_t* utm, size_t utm_size,
               const std::shared_ptr<SqliteAsyncCompletion>& completion) {
    return submitBatch(&request, 1, utm, utm_size, completion);
  }

  bool submitBatch(const struct group_pmp_sqlite_vfs_request* requests,
                   uint64_t count, uint8_t* utm, size_t utm_size,
                   const std::shared_ptr<SqliteAsyncCompletion>& completion) {
    if (!requests || !count || count > GROUP_PMP_SQLITE_VFS_BATCH_MAX)
      return false;
    const bool read = requests[0].operation == GROUP_PMP_SQLITE_VFS_OP_READ;
    const uint64_t lane =
        requests[0].worker_index % GROUP_PMP_MIXED_LANES;
    for (uint64_t index = 1; index < count; ++index)
      if ((requests[index].operation == GROUP_PMP_SQLITE_VFS_OP_READ) != read ||
          requests[index].worker_index % GROUP_PMP_MIXED_LANES != lane)
        return false;
    if (!read)
      return writer_->submitBatch(
          requests, count, utm, utm_size, completion);
    return lane < readers_.size() && readers_[lane]->submitBatch(
        requests, count, utm, utm_size, completion);
  }

  SqliteIoPerfSnapshot snapshot() const {
    SqliteIoPerfSnapshot result = writer_->snapshot();
    for (size_t lane = 0; lane < readers_.size(); ++lane) {
      SqliteIoPerfSnapshot value = readers_[lane]->snapshot();
      result.task_count += value.task_count;
      result.batch_count += value.batch_count;
      result.queue_wait_ns += value.queue_wait_ns;
      result.writer_wait_ns += value.writer_wait_ns;
      result.read_service_ns += value.read_service_ns;
      result.write_service_ns += value.write_service_ns;
      result.control_service_ns += value.control_service_ns;
      result.commit_ns += value.commit_ns;
      result.commit_count += value.commit_count;
      result.queue_depth_peak = std::max(
          result.queue_depth_peak, value.queue_depth_peak);
      result.physical_request_count += value.physical_request_count;
      result.logical_request_count += value.logical_request_count;
      result.physical_io_bytes += value.physical_io_bytes;
      result.useful_io_bytes += value.useful_io_bytes;
      result.sparse_io_count += value.sparse_io_count;
      if (value.window_first_enqueue_ns &&
          (!result.window_first_enqueue_ns ||
           value.window_first_enqueue_ns < result.window_first_enqueue_ns))
        result.window_first_enqueue_ns = value.window_first_enqueue_ns;
      result.window_last_completion_ns = std::max(
          result.window_last_completion_ns, value.window_last_completion_ns);
      result.max_queue_wait_ns = std::max(
          result.max_queue_wait_ns, value.max_queue_wait_ns);
      result.max_batch_service_ns = std::max(
          result.max_batch_service_ns, value.max_batch_service_ns);
      result.max_completion_latency_ns = std::max(
          result.max_completion_latency_ns,
          value.max_completion_latency_ns);
    }
    result.critical_path_ns = result.window_last_completion_ns >=
            result.window_first_enqueue_ns ?
        result.window_last_completion_ns - result.window_first_enqueue_ns : 0;
    return result;
  }

  SqliteIoPerfSnapshot drainAndSnapshot() {
    // Terminal callers have stopped producers; drain every connection first.
    (void)writer_->drainAndSnapshot();
    for (const auto& reader : readers_)
      (void)reader->drainAndSnapshot();
    return snapshot();
  }

  bool resetPerf() {
    bool cache_ready = writer_->resetPerf();
    for (size_t lane = 0; lane < readers_.size(); ++lane)
      cache_ready = readers_[lane]->resetPerf() && cache_ready;
    return cache_ready;
  }

  void cleanup_case(uint64_t worker_count, uint64_t workload) {
    writer_->cleanup_case(worker_count, workload);
  }

 private:
  std::unique_ptr<SqliteAsyncIoService> writer_;
  std::array<std::unique_ptr<SqliteAsyncIoService>,
             GROUP_PMP_MIXED_LANES> readers_;
};

SqliteNoExtentIoService& sqlite_no_extent_io_service() {
  static SqliteNoExtentIoService service;
  return service;
}

enum SqliteBenchmarkIoMode {
  SQLITE_BENCHMARK_IO_ADAPTIVE_EXTENT = 0,
  SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT = 1,
  SQLITE_BENCHMARK_IO_ASYNC_NO_EXTENT = 2
};

struct SqliteDetachedCompletionKey {
  uint64_t run_id;
  uint64_t worker_index;
  uint64_t request_id;
  uint64_t buffer_id;

  bool operator<(const SqliteDetachedCompletionKey& other) const {
    if (run_id != other.run_id)
      return run_id < other.run_id;
    if (worker_index != other.worker_index)
      return worker_index < other.worker_index;
    if (request_id != other.request_id)
      return request_id < other.request_id;
    return buffer_id < other.buffer_id;
  }
};

std::mutex sqlite_detached_completion_mutex;
std::map<SqliteDetachedCompletionKey,
         std::shared_ptr<SqliteAsyncCompletion> >
    sqlite_detached_completions;
std::atomic<uint64_t> sqlite_completion_wait_ocalls(0);

bool sqlite_store_detached_completion(
    const struct group_pmp_sqlite_vfs_request& request,
    const std::shared_ptr<SqliteAsyncCompletion>& completion) {
  const SqliteDetachedCompletionKey key = {
      request.run_id, request.worker_index, request.request_id,
      request.buffer_id};
  std::lock_guard<std::mutex> lock(sqlite_detached_completion_mutex);
  for (std::map<SqliteDetachedCompletionKey,
                std::shared_ptr<SqliteAsyncCompletion> >::iterator it =
           sqlite_detached_completions.begin();
       it != sqlite_detached_completions.end();) {
    if (it->first.run_id == request.run_id &&
        it->first.worker_index == request.worker_index &&
        it->first.buffer_id == request.buffer_id && it->second &&
        it->second->isComplete()) {
      it = sqlite_detached_completions.erase(it);
    } else {
      ++it;
    }
  }
  return completion &&
      sqlite_detached_completions.emplace(key, completion).second;
}

bool sqlite_store_detached_read_pair(
    const std::array<SqliteDetachedCompletionKey, 2>& keys,
    const std::array<std::shared_ptr<SqliteAsyncCompletion>, 2>& completions) {
  if (!completions[0] || !completions[1] ||
      completions[0] == completions[1] ||
      keys[0].run_id != keys[1].run_id ||
      keys[0].worker_index != keys[1].worker_index ||
      keys[0].buffer_id == keys[1].buffer_id ||
      keys[0].buffer_id >= GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT ||
      keys[1].buffer_id >= GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT)
    return false;
  std::lock_guard<std::mutex> lock(sqlite_detached_completion_mutex);
  // A new pair owns both slots; never replace a still-pending generation.
  for (const auto& entry : sqlite_detached_completions)
    if (entry.first.run_id == keys[0].run_id &&
        entry.first.worker_index == keys[0].worker_index &&
        (!entry.second || !entry.second->isComplete()))
      return false;
  for (auto it = sqlite_detached_completions.begin();
       it != sqlite_detached_completions.end();) {
    if (it->first.run_id == keys[0].run_id &&
        it->first.worker_index == keys[0].worker_index)
      it = sqlite_detached_completions.erase(it);
    else
      ++it;
  }
  sqlite_detached_completions.emplace(keys[0], completions[0]);
  sqlite_detached_completions.emplace(keys[1], completions[1]);
  return true;
}

void sqlite_remove_detached_read_pair(
    const std::array<SqliteDetachedCompletionKey, 2>& keys,
    const std::array<std::shared_ptr<SqliteAsyncCompletion>, 2>& completions) {
  std::lock_guard<std::mutex> lock(sqlite_detached_completion_mutex);
  for (size_t index = 0; index < keys.size(); ++index) {
    const auto found = sqlite_detached_completions.find(keys[index]);
    if (found != sqlite_detached_completions.end() &&
        found->second == completions[index])
      sqlite_detached_completions.erase(found);
  }
}

std::shared_ptr<SqliteAsyncCompletion> sqlite_take_detached_completion(
    const struct group_pmp_sqlite_vfs_wait& wait) {
  const SqliteDetachedCompletionKey key = {
      wait.run_id, wait.worker_index, wait.request_id, wait.buffer_id};
  std::lock_guard<std::mutex> lock(sqlite_detached_completion_mutex);
  std::map<SqliteDetachedCompletionKey,
           std::shared_ptr<SqliteAsyncCompletion> >::iterator found =
      sqlite_detached_completions.find(key);
  if (found == sqlite_detached_completions.end())
    return std::shared_ptr<SqliteAsyncCompletion>();
  std::shared_ptr<SqliteAsyncCompletion> completion = found->second;
  sqlite_detached_completions.erase(found);
  return completion;
}

void sqlite_clear_detached_completions() {
  std::lock_guard<std::mutex> lock(sqlite_detached_completion_mutex);
  sqlite_detached_completions.clear();
}

std::shared_ptr<SqliteAsyncCompletion> sqlite_wait_any_completion(
    const group_pmp_sqlite_vfs_wait_any& wait) {
  std::array<std::shared_ptr<SqliteAsyncCompletion>, 2> children;
  {
    std::lock_guard<std::mutex> lock(sqlite_detached_completion_mutex);
    for (size_t i = 0; i < children.size(); ++i) {
      const auto& item = wait.buffers[i];
      if (item.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
          item.version != GROUP_PMP_SQLITE_VFS_VERSION || !item.run_id ||
          !item.request_id || item.flags ||
          item.buffer_id >= GROUP_PMP_SQLITE_VFS_BUFFER_COUNT ||
          item.run_id != wait.buffers[0].run_id ||
          item.worker_index != wait.buffers[0].worker_index)
        return {};
      const SqliteDetachedCompletionKey key = {
          item.run_id, item.worker_index, item.request_id, item.buffer_id};
      const auto found = sqlite_detached_completions.find(key);
      if (found == sqlite_detached_completions.end()) return {};
      children[i] = found->second;
    }
    if (wait.buffers[0].buffer_id == wait.buffers[1].buffer_id) return {};
  }
  // Keep both registrations: the losing ring is still pending and may be
  // waited on again. The next submission reclaims completed registrations.
  auto completion = std::make_shared<SqliteAsyncCompletion>(1);
  for (const auto& child : children) child->watchAny(completion);
  return completion;
}

SqliteBenchmarkIoMode sqlite_benchmark_io_mode() {
  const char* mode = std::getenv("GROUP_PMP_SQLITE_IO_MODE");
  if (mode && (std::strcmp(mode, "no-extent") == 0 ||
               std::strcmp(mode, "sync-no-extent") == 0))
    return SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT;
  if (mode && std::strcmp(mode, "async-no-extent") == 0)
    return SQLITE_BENCHMARK_IO_ASYNC_NO_EXTENT;
  return SQLITE_BENCHMARK_IO_ADAPTIVE_EXTENT;
}

const char* sqlite_benchmark_io_mode_name() {
  switch (sqlite_benchmark_io_mode()) {
    case SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT:
      return "sync-no-extent";
    case SQLITE_BENCHMARK_IO_ASYNC_NO_EXTENT:
      return "async-no-extent";
    default:
      return "adaptive-extent";
  }
}

const char* sqlite_address_mode_name() {
  return "locality-random-v1";
}

uint64_t sqlite_worker_diagnostic_flags(uint64_t workload, uint64_t flags) {
  if (workload == GROUP_PMP_SQLITE_READSEQ &&
      sqlite_benchmark_io_mode() != SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT)
    flags |= GROUP_PMP_SQLITE_PAIRED_READS;
  // Online planning never expands the benchmark's future address generator.
  flags &= ~GROUP_PMP_SQLITE_INTENT_LOOKAHEAD;
  return flags;
}

bool sqlite_ring_counts_valid(uint64_t workload, uint64_t doorbells,
                              uint64_t requests, uint64_t completions) {
  if (sqlite_worker_diagnostic_flags(workload, 0) & GROUP_PMP_SQLITE_PAIRED_READS)
    return completions == requests && completions >= doorbells &&
        completions - doorbells <= doorbells;
  return doorbells == completions && (!doorbells || requests >= doorbells);
}

uint64_t sqlite_expected_host_ocalls(uint64_t batches, const SqliteIoPerfSnapshot& perf) {
  // Intent planning is a control OCALL, not a data request or a ring doorbell.
  return batches + perf.completion_wait_ocall_count +
      perf.pipeline[SQLITE_PIPELINE_INTENT_WINDOWS];
}

const char* sqlite_benchmark_cache_mode_name() {
  const char* mode = std::getenv("GROUP_PMP_SQLITE_CACHE_MODE");
  if (mode && (std::strcmp(mode, "cold") == 0 ||
               std::strcmp(mode, "direct") == 0))
    return mode;
  return "hot";
}

bool sqlite_selected_io_submit(
    const struct group_pmp_sqlite_vfs_request& request,
    uint8_t* utm, size_t utm_size,
    const std::shared_ptr<SqliteAsyncCompletion>& completion) {
  if (sqlite_benchmark_io_mode() == SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT)
    return sqlite_no_extent_io_service().submit(
        request, utm, utm_size, completion);
  return sqlite_async_io_service().submit(request, utm, utm_size, completion);
}

bool sqlite_selected_io_submit_batch(
    const struct group_pmp_sqlite_vfs_request* requests, uint64_t count,
    uint8_t* utm, size_t utm_size,
    const std::shared_ptr<SqliteAsyncCompletion>& completion) {
  if (sqlite_benchmark_io_mode() == SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT)
    return sqlite_no_extent_io_service().submitBatch(
        requests, count, utm, utm_size, completion);
  return sqlite_async_io_service().submitBatch(
      requests, count, utm, utm_size, completion);
}

SqliteIoPerfSnapshot sqlite_selected_io_snapshot(bool drain = false) {
  SqliteIoPerfSnapshot value =
      sqlite_benchmark_io_mode() == SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT ?
          (drain ? sqlite_no_extent_io_service().drainAndSnapshot() :
                   sqlite_no_extent_io_service().snapshot()) :
          (drain ? sqlite_async_io_service().drainAndSnapshot() :
                   sqlite_async_io_service().snapshot());
  value.completion_wait_ocall_count =
      sqlite_completion_wait_ocalls.load(std::memory_order_acquire);
  return value;
}

bool sqlite_selected_io_reset_perf() {
  sqlite_completion_wait_ocalls.store(0, std::memory_order_release);
  if (sqlite_benchmark_io_mode() == SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT) {
    return sqlite_no_extent_io_service().resetPerf();
  }
  return sqlite_async_io_service().resetPerf();
}

void sqlite_selected_io_cleanup_case(uint64_t worker_count,
                                     uint64_t workload) {
  sqlite_clear_detached_completions();
  if (sqlite_benchmark_io_mode() == SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT)
    sqlite_no_extent_io_service().cleanup_case(worker_count, workload);
  else {
    /* io_uring holds long-term pins on every worker UTM payload buffer.
     * Release those pins before the enclosing case destroys its enclaves and
     * returns the UTM pages to the Keystone allocator. */
    sqlite_async_io_service().clearRegisteredUtmBuffers();
    sqlite_async_io_service().cleanup_case(worker_count, workload);
  }
}

bool sqlite_selected_io_prepare_case(uint64_t file_id,
                                     uint8_t* const* utms,
                                     const size_t* utm_sizes,
                                     size_t count) {
  if (sqlite_benchmark_io_mode() == SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT)
    return true;
  return sqlite_async_io_service().prepareCase(
      file_id, utms, utm_sizes, count);
}

void sqlite_selected_io_record_wakeup(uint64_t publish_ns,
                                      uint64_t eligible_ns,
                                      uint64_t wake_ns,
                                      uint64_t resume_ns) {
  if (sqlite_benchmark_io_mode() != SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT)
    sqlite_async_io_service().recordWakeupTimeline(
        publish_ns, eligible_ns, wake_ns, resume_ns);
}

thread_local std::shared_ptr<SqliteAsyncCompletion>
    sqlite_dispatched_completion;

size_t
process_vma_count() {
#ifdef __linux__
  std::ifstream maps("/proc/self/maps");
  std::string line;
  size_t count = 0;

  while (std::getline(maps, line))
    ++count;
  return maps.bad() ? 0 : count;
#else
  return 0;
#endif
}

struct EnclaveSpec {
  const char* name;
  const char* eapp;
  uint64_t group_id;
  uint64_t group_capacity;
  uint64_t yxstm_size;
  uint64_t yxstm_slice_size;
  uint64_t utm_size;
  uint64_t free_mem_size;
};

struct EnclaveInstance {
  EnclaveSpec spec;
  std::unique_ptr<Enclave> enclave;
};

struct ParallelRunResult {
  ParallelRunResult()
      : ok(false),
        err(Error::DeviceError),
        retval(0),
        event_eid(0),
        event(KEYSTONE_GROUP_EVENT_NONE),
        started(false),
        finished(false) {}

  bool ok;
  Error err;
  uintptr_t retval;
  uint64_t event_eid;
  uint64_t event;
  std::atomic<bool> started;
  std::atomic<bool> finished;
};

uint64_t
env_u64(const char* name, uint64_t fallback, uint64_t minimum,
        uint64_t maximum) {
  const char* value = std::getenv(name);
  if (!value || !*value)
    return fallback;
  char* end = nullptr;
  unsigned long long parsed = std::strtoull(value, &end, 10);
  if (!end || *end || parsed < minimum || parsed > maximum) {
    std::cerr << "[host] invalid " << name << "=" << value
              << " expected " << minimum << ".." << maximum << std::endl;
    return fallback;
  }
  return static_cast<uint64_t>(parsed);
}

uint64_t
riscv_timebase_hz() {
  const char* override_value = std::getenv("GROUP_PMP_TIMEBASE_HZ");
  if (override_value && *override_value) {
    char* end = nullptr;
    unsigned long long parsed =
        std::strtoull(override_value, &end, 10);
    if (end && !*end && parsed >= 1000)
      return static_cast<uint64_t>(parsed);
  }
#ifdef __linux__
  std::ifstream input("/proc/device-tree/cpus/timebase-frequency",
                      std::ios::in | std::ios::binary);
  if (input) {
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),
                               std::istreambuf_iterator<char>());
    if (bytes.size() == 4 || bytes.size() == 8) {
      uint64_t value = 0;
      for (size_t index = 0; index < bytes.size(); ++index)
        value = (value << 8) | bytes[index];
      if (value >= 1000)
        return value;
    }
  }
#endif
  std::cerr << "[AES-FAIR] warning: timebase-frequency unavailable; "
               "using JH7110 default 4000000 Hz"
            << std::endl;
  return UINT64_C(4000000);
}

uint64_t
host_rdcycle(void) {
#if defined(__riscv)
  uint64_t value;
  __asm__ volatile("fence rw, rw\n\trdcycle %0\n\tfence rw, rw"
                   : "=r"(value) : : "memory");
  return value;
#else
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
#endif
}

double
nearest_rank_percentile(std::vector<double> values, uint64_t percent) {
  if (values.empty() || percent > 100)
    return 0.0;
  std::sort(values.begin(), values.end());
  size_t rank =
      static_cast<size_t>((percent * values.size() + 99) / 100);
  if (rank == 0)
    rank = 1;
  if (rank > values.size())
    rank = values.size();
  return values[rank - 1];
}

uint64_t
monotonic_raw_ns() {
#ifdef __linux__
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0)
    return static_cast<uint64_t>(ts.tv_sec) * UINT64_C(1000000000) +
           static_cast<uint64_t>(ts.tv_nsec);
#endif
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
}

void
print_group_perf_summary(const struct keystone_group_perf_snapshot& snapshot,
                         uint64_t cycle_hz) {
  std::cout << "[P10][sm] cycle_source=" << snapshot.cycle_source
            << " cycle_hz=" << cycle_hz << std::endl;
  if (snapshot.acquire_count != 0) {
    std::cout << "[P10][sm] acquire count=" << snapshot.acquire_count
              << " avg_cycles="
              << (snapshot.acquire_cycles / snapshot.acquire_count)
              << std::endl;
  }
  if (snapshot.release_count != 0) {
    std::cout << "[P10][sm] release count=" << snapshot.release_count
              << " avg_cycles="
              << (snapshot.release_cycles / snapshot.release_count)
              << std::endl;
  }
  if (snapshot.pmp_update_count != 0) {
    std::cout << "[P10][sm] pmp_update count=" << snapshot.pmp_update_count
              << " avg_cycles="
              << (snapshot.pmp_update_cycles / snapshot.pmp_update_count)
              << std::endl;
  }
  std::cout << "[P10][sm] context_switch count="
            << snapshot.context_switch_count
            << " total_cycles=" << snapshot.context_switch_cycles
            << " avg_cycles="
            << (snapshot.context_switch_count ?
                snapshot.context_switch_cycles /
                    snapshot.context_switch_count : 0)
            << std::endl;
  std::cout << "[P10][sm] context_components gpr_cycles="
            << snapshot.context_gpr_cycles
            << " smode_csr_cycles=" << snapshot.context_smode_csr_cycles
            << " fp_cycles=" << snapshot.context_fp_cycles
            << " pmp_cycles=" << snapshot.context_pmp_cycles
            << " platform_cycles=" << snapshot.context_platform_cycles
            << " scheduler_lock_cycles="
            << snapshot.context_scheduler_lock_cycles
            << std::endl;
  std::cout << "[P10][sm] ocall_e2e count=" << snapshot.ocall_count
            << " total_cycles=" << snapshot.ocall_cycles
            << " avg_cycles="
            << (snapshot.ocall_count ?
                snapshot.ocall_cycles / snapshot.ocall_count : 0)
            << std::endl;
  std::cout << "[P10][sm] ocall_handler count="
            << snapshot.ocall_handler_count
            << " total_cycles=" << snapshot.ocall_handler_cycles
            << " avg_cycles="
            << (snapshot.ocall_handler_count ?
                snapshot.ocall_handler_cycles /
                    snapshot.ocall_handler_count : 0)
            << std::endl;
  std::cout << "[P10][sm] ocall_wait count="
            << snapshot.ocall_wait_count
            << " total_mtime_ticks=" << snapshot.ocall_wait_ticks
            << " avg_mtime_ticks="
            << (snapshot.ocall_wait_count ?
                snapshot.ocall_wait_ticks / snapshot.ocall_wait_count : 0)
            << std::endl;
  std::cout << "[P10][sm] lane_wait blocked="
            << snapshot.lane_wait_block_count
            << " woken=" << snapshot.lane_wait_wake_count
            << " total_mtime_ticks=" << snapshot.lane_wait_ticks
            << std::endl;
  std::cout << "[P10][sm] cfs_lite picks=" << snapshot.cfs_pick_count
            << " preemptions=" << snapshot.cfs_preempt_count
            << " runtime_mtime_ticks=" << snapshot.cfs_runtime_ticks
            << " vruntime_delta=" << snapshot.cfs_vruntime_delta
            << " scheduled_slice_ticks=" << snapshot.cfs_slice_ticks
            << " min_granularity_hits="
            << snapshot.cfs_min_granularity_count
            << std::endl;
  std::cout << "[P10][sm] heartbeat count=" << snapshot.heartbeat_count
            << " total_cycles=" << snapshot.heartbeat_cycles
            << " avg_cycles="
            << (snapshot.heartbeat_count ?
                snapshot.heartbeat_cycles / snapshot.heartbeat_count : 0)
            << std::endl;
  std::cout << "[P10][sm] timer_trap_exclusive count="
            << snapshot.timer_trap_count
            << " total_cycles=" << snapshot.timer_trap_cycles
            << " avg_cycles="
            << (snapshot.timer_trap_count ?
                snapshot.timer_trap_cycles / snapshot.timer_trap_count : 0)
            << std::endl;
  if (snapshot.ipi_shootdown_count != 0) {
    std::cout << "[P10][sm] ipi_shootdown count="
              << snapshot.ipi_shootdown_count
              << " avg_cycles="
              << (snapshot.ipi_shootdown_cycles /
                  snapshot.ipi_shootdown_count)
              << std::endl;
  }
  if (snapshot.host_service_count != 0) {
    std::cout << "[P10][sm] host_service count="
              << snapshot.host_service_count
              << " avg_cycles="
              << (snapshot.host_service_cycles /
                  snapshot.host_service_count)
              << " total_cycles=" << snapshot.host_service_cycles
              << std::endl;
  }
  if (snapshot.grant_suspend_restore_count != 0) {
    std::cout << "[P10][sm] grant_suspend_restore count="
              << snapshot.grant_suspend_restore_count
              << " avg_cycles="
              << (snapshot.grant_suspend_restore_cycles /
                  snapshot.grant_suspend_restore_count)
              << " total_cycles="
              << snapshot.grant_suspend_restore_cycles
              << std::endl;
  }
}

bool
take_resource_snapshot(uint64_t group_id,
                       struct keystone_group_test_snapshot* snapshot) {
  Keystone::KeystoneDevice device;
  Params params;
  std::memset(snapshot, 0, sizeof(*snapshot));
  if (!device.initDevice(params) ||
      device.groupTestSnapshot(group_id, snapshot) != Error::Success) {
    std::cerr << "[host] group resource snapshot failed" << std::endl;
    return false;
  }
  return true;
}

void
print_resource_snapshot(const char* label,
                        const struct keystone_group_test_snapshot& snapshot) {
  std::cerr << "[host] " << label
            << ": group_enclaves=" << snapshot.live_group_enclaves
            << " groups=" << snapshot.live_groups
            << " members=" << snapshot.live_members
            << " active_harts=" << snapshot.active_harts
            << " acquired_yxstm=" << snapshot.acquired_yxstm_harts
            << " runqueue=" << snapshot.runqueue_entries
            << " events=" << snapshot.event_queue_entries
            << " member_capacity=" << snapshot.member_capacity
            << " metadata_capacity=" << snapshot.member_metadata_capacity
            << " metadata_bytes=" << snapshot.metadata_bytes
            << " metadata_free=" << snapshot.metadata_free_bytes
            << " running_workers=" << snapshot.running_workers
            << " max_running_workers=" << snapshot.max_running_workers
            << " lane_switches=" << snapshot.lane_owner_switches
            << " lane_scrubs=" << snapshot.lane_scrubs
            << " master_non_boundary="
            << snapshot.master_non_boundary_entries
            << std::endl;
}

bool
group_resources_quiesced(
    const struct keystone_group_test_snapshot& snapshot) {
  return snapshot.live_group_enclaves == 0 &&
      snapshot.live_groups == 0 && snapshot.live_members == 0 &&
      snapshot.active_harts == 0 && snapshot.acquired_yxstm_harts == 0 &&
      snapshot.runqueue_entries == 0 && snapshot.event_queue_entries == 0;
}

bool
same_reclaimable_resources(const struct keystone_group_test_snapshot& before,
                           const struct keystone_group_test_snapshot& after,
                           const char* label) {
  bool same = before.live_enclaves == after.live_enclaves &&
      before.live_group_enclaves == after.live_group_enclaves &&
      before.live_groups == after.live_groups &&
      before.live_members == after.live_members &&
      before.pmp_regions == after.pmp_regions &&
      after.active_harts == 0 && after.acquired_yxstm_harts == 0 &&
      after.runqueue_entries == 0 && after.event_queue_entries == 0 &&
      before.event_queue_overflows == after.event_queue_overflows &&
      before.metadata_free_bytes == after.metadata_free_bytes;
  if (!same) {
    std::cerr << "[host] resource leak: " << label
              << " enclaves=" << before.live_enclaves << "->"
              << after.live_enclaves
              << " group_enclaves=" << before.live_group_enclaves << "->"
              << after.live_group_enclaves
              << " groups=" << before.live_groups << "->" << after.live_groups
              << " members=" << before.live_members << "->" << after.live_members
              << " pmp=" << before.pmp_regions << "->" << after.pmp_regions
              << " active=" << after.active_harts
              << " acquired=" << after.acquired_yxstm_harts
              << " runqueue=" << after.runqueue_entries
              << " events=" << after.event_queue_entries
              << " metadata_free=" << before.metadata_free_bytes << "->"
              << after.metadata_free_bytes << std::endl;
  }
  return same;
}

const char*
error_name(Error err) {
  switch (err) {
    case Error::Success:
      return "Success";
    case Error::FileInitFailure:
      return "FileInitFailure";
    case Error::DeviceInitFailure:
      return "DeviceInitFailure";
    case Error::DeviceError:
      return "DeviceError";
    case Error::IoctlErrorCreate:
      return "IoctlErrorCreate";
    case Error::IoctlErrorDestroy:
      return "IoctlErrorDestroy";
    case Error::IoctlErrorFinalize:
      return "IoctlErrorFinalize";
    case Error::IoctlErrorRun:
      return "IoctlErrorRun";
    case Error::IoctlErrorResume:
      return "IoctlErrorResume";
    case Error::IoctlErrorUTMInit:
      return "IoctlErrorUTMInit";
    case Error::IoctlErrorUTMShare:
      return "IoctlErrorUTMShare";
    case Error::DeviceMemoryMapError:
      return "DeviceMemoryMapError";
    case Error::ELFLoadFailure:
      return "ELFLoadFailure";
    case Error::InvalidEnclave:
      return "InvalidEnclave";
    case Error::VSpaceAllocationFailure:
      return "VSpaceAllocationFailure";
    case Error::PageAllocationFailure:
      return "PageAllocationFailure";
    case Error::EdgeCallHost:
      return "EdgeCallHost";
    case Error::EnclaveInterrupted:
      return "EnclaveInterrupted";
    case Error::EnclaveFatalFault:
      return "EnclaveFatalFault";
    case Error::GroupCoherenceBusy:
      return "GroupCoherenceBusy";
    case Error::GroupEventTimeout:
      return "GroupEventTimeout";
    case Error::GroupNotRunnable:
      return "GroupNotRunnable";
    case Error::GroupInvalidArgument:
      return "GroupInvalidArgument";
    case Error::GroupBusy:
      return "GroupBusy";
    case Error::GroupNoSpace:
      return "GroupNoSpace";
    case Error::GroupStale:
      return "GroupStale";
    case Error::GroupIOError:
      return "GroupIOError";
    case Error::GroupOcallTimeout:
      return "GroupOcallTimeout";
    case Error::GroupOcallCancelled:
      return "GroupOcallCancelled";
    case Error::GroupOcallAbandoned:
      return "GroupOcallAbandoned";
    case Error::GroupNotSupported:
      return "GroupNotSupported";
    case Error::GroupVectorUnsupported:
      return "GroupVectorUnsupported";
  }
  return "Unknown";
}

const char*
ocall_blocker_retval_name(uintptr_t retval) {
  if (retval == 0) {
    return "ok";
  }
  if (retval == 1) {
    return "legacy-ocall-error";
  }
  if (retval == 2) {
    return "ocall-buffer-overflow";
  }
  if (retval == 3) {
    return "edge-call-setup-call-failed";
  }
  if (retval >= 10 && retval < 20) {
    return "sbi-stop-enclave-returned-error";
  }
  if (retval >= 20 && retval < 30) {
    return "edge-call-status-not-ok";
  }
  if (retval == 30) {
    return "edge-call-return-pointer-invalid";
  }
  if (retval == 31) {
    return "ocall-ack-mismatch";
  }
  return "unknown";
}

void
group_pmp_ocall_ack(void* buffer) {
  struct edge_call* edge_call = static_cast<struct edge_call*>(buffer);
  uintptr_t args_ptr = 0;
  size_t args_size = 0;
  if (edge_call_args_ptr(edge_call, &args_ptr, &args_size) != 0 ||
      args_size != sizeof(kGroupPmpOcallPayload)) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  uint64_t payload = 0;
  std::memcpy(&payload, reinterpret_cast<void*>(args_ptr), sizeof(payload));
  if (payload != kGroupPmpOcallPayload &&
      payload != kGroupPmpTaskOcallPayload) {
    edge_call->return_data.call_status = CALL_STATUS_ERROR;
    return;
  }

  uintptr_t ret_ptr = edge_call_data_ptr();
  std::memcpy(
      reinterpret_cast<void*>(ret_ptr), &kGroupPmpOcallAck, sizeof(kGroupPmpOcallAck));
  if (edge_call_setup_ret(
          edge_call, reinterpret_cast<void*>(ret_ptr), sizeof(kGroupPmpOcallAck)) !=
      0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    return;
  }

  edge_call->return_data.call_status = CALL_STATUS_OK;
}

void
group_pmp_sqlite_async_vfs(void* buffer) {
  if (std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR") && _shared_start &&
      _shared_len >= GROUP_PMP_SECURITY_PROBE_OFFSET + sizeof(group_pmp_security_phase_state)) {
    group_pmp_security_phase_state phase, verify;
    std::memcpy(&phase, reinterpret_cast<void*>(_shared_start + GROUP_PMP_SECURITY_PROBE_OFFSET), sizeof(phase));
    __sync_synchronize();
    std::memcpy(&verify, reinterpret_cast<void*>(_shared_start + GROUP_PMP_SECURITY_PROBE_OFFSET), sizeof(verify));
    static std::mutex capture_mutex;
    std::lock_guard<std::mutex> capture_lock(capture_mutex);
    static std::map<uintptr_t, uint64_t> captured;
    if (phase.magic == GROUP_PMP_SECURITY_PHASE_MAGIC && !(phase.sequence & 1) &&
        !std::memcmp(&phase, &verify, sizeof(phase)) && phase.phase >= 1 && phase.phase <= 5 &&
        (captured[_shared_start] & phase.seen) != phase.seen) {
      uint64_t missed = phase.seen & ~captured[_shared_start] & ~(UINT64_C(1) << phase.phase);
      const char* dir = std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR");
      std::ofstream history(std::string(dir) + "/phase-history.csv", std::ios::app);
      history << _shared_start << ',' << phase.phase << ',' << phase.seen << ',' << missed << '\n';
      history.flush();
      if(!history) throw std::runtime_error("cannot record security phase history");
      captured[_shared_start] |= phase.seen;
      security_scan_checkpoint(("worker-milestone-" + std::to_string(phase.phase)).c_str());
    }
  }
  sqlite_submission_timing.begin(sqlite_io_time_ticks());
  struct edge_call* edge_call = static_cast<struct edge_call*>(buffer);
  uintptr_t args_ptr = 0;
  uintptr_t ret_ptr;
  size_t args_size = 0;
  std::shared_ptr<SqliteAsyncCompletion> completion;
  bool defer_current_ocall = false;

  if (edge_call_args_ptr(edge_call, &args_ptr, &args_size) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  uint64_t packet_magic = 0;
  if (args_size >= sizeof(packet_magic))
    std::memcpy(&packet_magic, reinterpret_cast<void*>(args_ptr), sizeof(packet_magic));
  if (args_size == sizeof(group_pmp_sqlite_intent_plan) &&
      packet_magic == GROUP_PMP_SQLITE_INTENT_MAGIC) {
    group_pmp_sqlite_intent_plan plan;
    std::memcpy(&plan, reinterpret_cast<void*>(args_ptr), sizeof(plan));
    group_pmp_sqlite_intent_ack ack = {};
    ack.magic = GROUP_PMP_SQLITE_INTENT_MAGIC;
    ack.version = GROUP_PMP_SQLITE_INTENT_VERSION;
    ack.request_id = plan.request_id;
    ack.count = plan.count;
    ack.status = sqlite_async_io_service().planIntents(plan,
        reinterpret_cast<uint8_t*>(_shared_start), _shared_len) ? 0 : -1;
    ret_ptr = edge_call_data_ptr();
    std::memcpy(reinterpret_cast<void*>(ret_ptr), &ack, sizeof(ack));
    edge_call->return_data.call_status = edge_call_setup_ret(edge_call,
        reinterpret_cast<void*>(ret_ptr), sizeof(ack)) == 0 ?
        CALL_STATUS_OK : CALL_STATUS_BAD_PTR;
    return;
  }
  if (args_size == sizeof(struct group_pmp_sqlite_vfs_wait) ||
      args_size == sizeof(struct group_pmp_sqlite_vfs_wait_any)) {
    struct group_pmp_sqlite_vfs_wait wait;
    struct group_pmp_sqlite_vfs_ack ack;
    std::memcpy(&wait, reinterpret_cast<void*>(args_ptr), sizeof(wait));
    std::memset(&ack, 0, sizeof(ack));
    if (wait.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
        wait.version != GROUP_PMP_SQLITE_VFS_VERSION || !wait.run_id ||
        !wait.request_id ||
        wait.buffer_id >= GROUP_PMP_SQLITE_VFS_BUFFER_COUNT || wait.flags) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    if (args_size == sizeof(struct group_pmp_sqlite_vfs_wait_any)) {
      group_pmp_sqlite_vfs_wait_any packet;
      std::memcpy(&packet, reinterpret_cast<void*>(args_ptr), sizeof(packet));
      completion = sqlite_wait_any_completion(packet);
    } else {
      completion = sqlite_take_detached_completion(wait);
    }
    if (!completion) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    const uint64_t offset = GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(wait.buffer_id);
    if (_shared_start && _shared_len <= UINTPTR_MAX - _shared_start &&
        offset <= _shared_len && sizeof(group_pmp_sqlite_vfs_ring_header) <=
            _shared_len - offset) {
      auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
          _shared_start + offset);
      if (ring->magic == GROUP_PMP_SQLITE_VFS_RING_MAGIC &&
          ring->version == GROUP_PMP_SQLITE_VFS_VERSION)
        sqlite_submission_timing.acceptWait(ring);
    }
    sqlite_completion_wait_ocalls.fetch_add(1, std::memory_order_relaxed);
    ack.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    ack.version = GROUP_PMP_SQLITE_VFS_VERSION;
    ack.request_id = wait.request_id;
    ack.status = 0;
    ret_ptr = edge_call_data_ptr();
    std::memcpy(reinterpret_cast<void*>(ret_ptr), &ack, sizeof(ack));
    if (edge_call_setup_ret(edge_call, reinterpret_cast<void*>(ret_ptr),
                            sizeof(ack)) != 0) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      return;
    }
    edge_call->return_data.call_status = CALL_STATUS_OK;
    /* A synchronous submit may already have consumed this object's wakeup.
     * A late WAIT still ACKs, but must not arm that one-shot callback twice. */
    if (!completion->isComplete())
      sqlite_dispatched_completion = completion;
    sqlite_submission_timing.publishAck(sqlite_io_time_ticks());
    return;
  }
  const uint64_t allowed_flags = GROUP_PMP_SQLITE_STORE_PREFILL |
      GROUP_PMP_SQLITE_STORE_MEASURED | GROUP_PMP_SQLITE_STORE_TXN_BEGIN |
      GROUP_PMP_SQLITE_STORE_TXN_END |
      GROUP_PMP_SQLITE_STORE_BLOCK_ON_COMPLETE |
      GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY |
      GROUP_PMP_SQLITE_STORE_RING | GROUP_PMP_SQLITE_READSEQ_DIAGNOSTICS;
  const auto valid_request = [allowed_flags](
      const struct group_pmp_sqlite_vfs_request& request) {
    const bool data_operation =
        request.operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
        request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE;
    const bool control_operation =
        request.operation == GROUP_PMP_SQLITE_VFS_OP_RESET ||
        request.operation == GROUP_PMP_SQLITE_VFS_OP_TRUNCATE ||
        request.operation == GROUP_PMP_SQLITE_VFS_OP_DELETE ||
        request.operation == GROUP_PMP_SQLITE_VFS_OP_SYNC;
    const uint64_t buffer0_end = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET +
        GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
    const uint64_t buffer1_end = GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET +
        GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
    const bool in_buffer0 =
        request.buffer_offset >= GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET &&
        request.buffer_offset <= buffer0_end &&
        request.length <= buffer0_end - request.buffer_offset;
    const bool in_buffer1 =
        request.buffer_offset >= GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET &&
        request.buffer_offset <= buffer1_end &&
        request.length <= buffer1_end - request.buffer_offset;
    const bool valid_buffer =
        request.buffer_id < GROUP_PMP_SQLITE_VFS_BUFFER_COUNT &&
        request.length <= GROUP_PMP_SQLITE_VFS_BUFFER_BYTES &&
        ((request.buffer_id == 0 && in_buffer0) ||
         (request.buffer_id == 1 && in_buffer1));
    const bool block_on_complete =
        (request.reserved[0] &
         GROUP_PMP_SQLITE_STORE_BLOCK_ON_COMPLETE) != 0;
    const bool submit_only =
        (request.reserved[0] & GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY) != 0;
    const bool ring_transport =
        (request.reserved[0] & GROUP_PMP_SQLITE_STORE_RING) != 0;
    return request.magic == GROUP_PMP_SQLITE_VFS_MAGIC &&
        request.version == GROUP_PMP_SQLITE_VFS_VERSION &&
        request.request_id && request.run_id && request.worker_count &&
        request.worker_index < request.worker_count &&
        request.workload >= GROUP_PMP_SQLITE_FILLSEQ &&
        request.workload <= GROUP_PMP_SQLITE_READRAND100K && valid_buffer &&
        (!data_operation ||
         (request.file_id && request.task_id &&
          request.file_offset <= UINT64_MAX - request.length)) &&
        ((data_operation && request.length) ||
         (control_operation && request.length == 0)) &&
        !(block_on_complete && submit_only) &&
        (!ring_transport ||
         (request.ring_slot < GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT &&
          request.descriptor_id < GROUP_PMP_SQLITE_VFS_BATCH_MAX)) &&
        (ring_transport ||
         request.buffer_id < GROUP_PMP_SQLITE_VFS_LEGACY_STATUS_COUNT) &&
        (!submit_only ||
         (data_operation &&
          request.buffer_id < GROUP_PMP_SQLITE_VFS_BUFFER_COUNT)) &&
        (request.reserved[0] & ~allowed_flags) == 0 &&
        (!(request.reserved[0] & GROUP_PMP_SQLITE_READSEQ_DIAGNOSTICS) ||
         (request.operation == GROUP_PMP_SQLITE_VFS_OP_READ &&
          request.workload == GROUP_PMP_SQLITE_READSEQ));
  };

  if (args_size == sizeof(struct group_pmp_sqlite_vfs_request)) {
    struct group_pmp_sqlite_vfs_request request;
    struct group_pmp_sqlite_vfs_ack ack;
    std::memcpy(&request, reinterpret_cast<void*>(args_ptr), sizeof(request));
    std::memset(&ack, 0, sizeof(ack));
    if (!valid_request(request)) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    const bool block_on_complete =
        (request.reserved[0] &
         GROUP_PMP_SQLITE_STORE_BLOCK_ON_COMPLETE) != 0;
    const bool submit_only =
        (request.reserved[0] & GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY) != 0;
    if (block_on_complete || submit_only)
      completion.reset(new SqliteAsyncCompletion(1));
    sqlite_gantt_trace().recordRequest(
        SQLITE_GANTT_REQUEST_SUBMIT, request,
        completion ? completion->trace_id : 0);
    if (!sqlite_selected_io_submit(
            request, reinterpret_cast<uint8_t*>(_shared_start), _shared_len,
            completion)) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    if (submit_only &&
        !sqlite_store_detached_completion(request, completion)) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    /* Keep the worker synchronous, not the Host event dispatcher. */
    defer_current_ocall = block_on_complete ||
        (submit_only && sqlite_benchmark_io_mode() ==
                            SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT);
    ack.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    ack.version = GROUP_PMP_SQLITE_VFS_VERSION;
    ack.request_id = request.request_id;
    ack.status = 0;
    ret_ptr = edge_call_data_ptr();
    std::memcpy(reinterpret_cast<void*>(ret_ptr), &ack, sizeof(ack));
    if (edge_call_setup_ret(edge_call, reinterpret_cast<void*>(ret_ptr),
                            sizeof(ack)) != 0) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      return;
    }
  } else if (args_size ==
                 sizeof(struct group_pmp_sqlite_vfs_ring_pair_doorbell)) {
    struct group_pmp_sqlite_vfs_ring_pair_doorbell pair;
    struct group_pmp_sqlite_vfs_ring_pair_ack ack = {};
    std::array<struct group_pmp_sqlite_vfs_ring_header*, 2> rings;
    std::array<struct group_pmp_sqlite_vfs_request, 2> requests;
    std::array<SqliteDetachedCompletionKey, 2> keys;
    std::array<std::shared_ptr<SqliteAsyncCompletion>, 2> completions;
    if (sqlite_benchmark_io_mode() == SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT ||
        !_shared_start || _shared_len > UINTPTR_MAX - _shared_start) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    std::memcpy(&pair, reinterpret_cast<const void*>(args_ptr), sizeof(pair));
    if (pair.rings[0].ring_slot == pair.rings[1].ring_slot) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    for (size_t index = 0; index < requests.size(); ++index) {
      const auto& doorbell = pair.rings[index];
      if (doorbell.ring_slot >= GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT ||
          GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(doorbell.ring_slot) >
              _shared_len ||
          GROUP_PMP_SQLITE_VFS_RING_SLOT_BYTES >
              _shared_len -
                  GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(doorbell.ring_slot) ||
          doorbell.magic != GROUP_PMP_SQLITE_VFS_RING_MAGIC ||
          doorbell.version != GROUP_PMP_SQLITE_VFS_VERSION ||
          !doorbell.generation || doorbell.count != 1 || doorbell.producer != 1 ||
          doorbell.flags != GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY ||
          !doorbell.batch_request_id) {
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
      }
      rings[index] = reinterpret_cast<struct group_pmp_sqlite_vfs_ring_header*>(
          _shared_start + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(doorbell.ring_slot));
      const auto* ring = rings[index];
      std::atomic_thread_fence(std::memory_order_acquire);
      if (ring->magic != GROUP_PMP_SQLITE_VFS_RING_MAGIC ||
          ring->version != GROUP_PMP_SQLITE_VFS_VERSION ||
          ring->generation != doorbell.generation ||
          __atomic_load_n(&ring->producer, __ATOMIC_ACQUIRE) != doorbell.producer ||
          ring->consumer || ring->completion_count || ring->flags ||
          ring->completed_time_ticks) {
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
      }
      std::memcpy(&requests[index], reinterpret_cast<const void*>(
          _shared_start + GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET_FOR_SLOT(
              doorbell.ring_slot)), sizeof(requests[index]));
      const auto& request = requests[index];
      if (!valid_request(request) ||
          request.operation != GROUP_PMP_SQLITE_VFS_OP_READ ||
          request.workload != GROUP_PMP_SQLITE_READSEQ ||
          !(request.reserved[0] & GROUP_PMP_SQLITE_STORE_RING) ||
          !(request.reserved[0] & GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY) ||
          (request.reserved[0] & GROUP_PMP_SQLITE_STORE_BLOCK_ON_COMPLETE) ||
          request.ring_slot != doorbell.ring_slot ||
          request.buffer_id != doorbell.ring_slot || request.descriptor_id != 0 ||
          request.buffer_offset > _shared_len ||
          request.length > _shared_len - request.buffer_offset ||
          request.sequence != request.task_id ||
          request.task_id !=
              request.reserved[1] / GROUP_PMP_SQLITE_VFS_BUFFER_BYTES + 1) {
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
      }
      keys[index] = SqliteDetachedCompletionKey{
          request.run_id, request.worker_index,
          doorbell.batch_request_id, doorbell.ring_slot};
      ack.rings[index].magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
      ack.rings[index].version = GROUP_PMP_SQLITE_VFS_VERSION;
      ack.rings[index].generation = doorbell.generation;
      ack.rings[index].accepted = 1;
      ack.rings[index].consumer = 1;
      ack.rings[index].ring_slot = doorbell.ring_slot;
      ack.rings[index].batch_request_id = doorbell.batch_request_id;
    }
    const auto& first = requests[0];
    const auto& second = requests[1];
    if (first.run_id != second.run_id ||
        first.worker_index != second.worker_index ||
        first.worker_count != second.worker_count || first.file_id != second.file_id ||
        first.request_id == second.request_id || first.sequence == second.sequence ||
        (first.buffer_offset < second.buffer_offset + second.length &&
         second.buffer_offset < first.buffer_offset + first.length)) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    // Validate the reply and reserve both wait keys before the service sees either read.
    ret_ptr = edge_call_data_ptr();
    if (edge_call_setup_ret(edge_call, reinterpret_cast<void*>(ret_ptr),
                            sizeof(ack)) != 0) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      return;
    }
    for (auto& read_completion : completions)
      read_completion.reset(new SqliteAsyncCompletion(1));
    if (!sqlite_store_detached_read_pair(keys, completions)) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    for (size_t index = 0; index < requests.size(); ++index)
      sqlite_gantt_trace().recordRequest(SQLITE_GANTT_REQUEST_SUBMIT,
          requests[index], completions[index]->trace_id);
    if (!sqlite_async_io_service().submitReadPair(requests.data(),
            reinterpret_cast<uint8_t*>(_shared_start), _shared_len,
            completions.data())) {
      sqlite_remove_detached_read_pair(keys, completions);
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    for (auto* ring : rings)
      __atomic_store_n(&ring->consumer, UINT64_C(1), __ATOMIC_RELEASE);
    for (auto* ring : rings)
      sqlite_submission_timing.accept(ring);
    std::memcpy(reinterpret_cast<void*>(ret_ptr), &ack, sizeof(ack));
  } else if (args_size ==
                 sizeof(struct group_pmp_sqlite_vfs_ring_doorbell)) {
    struct group_pmp_sqlite_vfs_ring_doorbell doorbell;
    struct group_pmp_sqlite_vfs_ring_ack ack;
    struct group_pmp_sqlite_vfs_ring_header* ring;
    struct group_pmp_sqlite_vfs_request batch_key;
    std::array<struct group_pmp_sqlite_vfs_request,
               GROUP_PMP_SQLITE_VFS_BATCH_MAX> requests;
    bool seen_descriptor[GROUP_PMP_SQLITE_VFS_BATCH_MAX] = {false};
    std::memcpy(&doorbell, reinterpret_cast<void*>(args_ptr),
                sizeof(doorbell));
    std::memset(&ack, 0, sizeof(ack));
    if (doorbell.ring_slot >= GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT ||
        GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(doorbell.ring_slot) >
            _shared_len ||
        GROUP_PMP_SQLITE_VFS_RING_SLOT_BYTES >
            _shared_len -
                GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(doorbell.ring_slot) ||
        doorbell.magic != GROUP_PMP_SQLITE_VFS_RING_MAGIC ||
        doorbell.version != GROUP_PMP_SQLITE_VFS_VERSION ||
        !doorbell.generation || !doorbell.count ||
        doorbell.count > GROUP_PMP_SQLITE_VFS_BATCH_MAX ||
        doorbell.producer != doorbell.count ||
        doorbell.flags != GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY ||
        !doorbell.batch_request_id) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    ring = reinterpret_cast<struct group_pmp_sqlite_vfs_ring_header*>(
        _shared_start +
            GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(doorbell.ring_slot));
    std::atomic_thread_fence(std::memory_order_acquire);
    if (ring->magic != GROUP_PMP_SQLITE_VFS_RING_MAGIC ||
        ring->version != GROUP_PMP_SQLITE_VFS_VERSION ||
        ring->generation != doorbell.generation ||
        __atomic_load_n(&ring->producer, __ATOMIC_ACQUIRE) !=
            doorbell.producer || ring->consumer || ring->completion_count ||
        ring->flags || ring->completed_time_ticks) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    std::memcpy(
        requests.data(),
        reinterpret_cast<const void*>(
            _shared_start +
                GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET_FOR_SLOT(
                    doorbell.ring_slot)),
        static_cast<size_t>(doorbell.count * sizeof(requests[0])));
    for (uint64_t index = 0; index < doorbell.count; ++index) {
      const struct group_pmp_sqlite_vfs_request& request = requests[index];
      if (!valid_request(request) ||
          !(request.reserved[0] & GROUP_PMP_SQLITE_STORE_RING) ||
          (request.reserved[0] &
            GROUP_PMP_SQLITE_STORE_BLOCK_ON_COMPLETE) ||
          !(request.reserved[0] & GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY) ||
          request.ring_slot != doorbell.ring_slot ||
          request.descriptor_id != index ||
          seen_descriptor[request.descriptor_id] ||
          (request.operation != GROUP_PMP_SQLITE_VFS_OP_READ &&
           request.operation != GROUP_PMP_SQLITE_VFS_OP_WRITE)) {
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
      }
      seen_descriptor[request.descriptor_id] = true;
    }
    if (!sqlite_submission_buffers_disjoint(requests.data(), doorbell.count)) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    completion.reset(new SqliteAsyncCompletion(doorbell.count));
    defer_current_ocall = false;
    for (uint64_t index = 0; index < doorbell.count; ++index)
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_REQUEST_SUBMIT, requests[index], completion->trace_id);
    if (!sqlite_selected_io_submit_batch(
            requests.data(), doorbell.count,
            reinterpret_cast<uint8_t*>(_shared_start), _shared_len,
            completion)) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    batch_key = requests[0];
    batch_key.request_id = doorbell.batch_request_id;
    batch_key.buffer_id = doorbell.ring_slot;
    if (!sqlite_store_detached_completion(batch_key, completion)) {
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    /* Resume the synchronous worker only on completion. Sleeping here would
     * hold the global edge dispatcher and prevent other lanes' events and
     * warmup timeout checks from being serviced. */
    defer_current_ocall = sqlite_benchmark_io_mode() ==
        SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT;
    __atomic_store_n(&ring->consumer, doorbell.count, __ATOMIC_RELEASE);
    sqlite_submission_timing.accept(ring);
    ack.magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
    ack.version = GROUP_PMP_SQLITE_VFS_VERSION;
    ack.generation = doorbell.generation;
    ack.accepted = doorbell.count;
    ack.status = 0;
    ack.consumer = doorbell.count;
    ack.ring_slot = doorbell.ring_slot;
    ack.batch_request_id = doorbell.batch_request_id;
    ret_ptr = edge_call_data_ptr();
    std::memcpy(reinterpret_cast<void*>(ret_ptr), &ack, sizeof(ack));
    if (edge_call_setup_ret(edge_call, reinterpret_cast<void*>(ret_ptr),
                            sizeof(ack)) != 0) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      return;
    }
  } else if (args_size == sizeof(struct group_pmp_sqlite_vfs_batch) ||
             args_size ==
                 sizeof(struct group_pmp_sqlite_vfs_indirect_batch)) {
    std::array<struct group_pmp_sqlite_vfs_request,
               GROUP_PMP_SQLITE_VFS_BATCH_MAX> requests;
    struct group_pmp_sqlite_vfs_batch_ack ack;
    bool seen_buffer[GROUP_PMP_SQLITE_VFS_BATCH_MAX] = {false};
    uint64_t count = 0;
    bool indirect_batch = false;
    std::memset(requests.data(), 0,
                requests.size() * sizeof(requests[0]));
    std::memset(&ack, 0, sizeof(ack));
    if (args_size == sizeof(struct group_pmp_sqlite_vfs_batch)) {
      struct group_pmp_sqlite_vfs_batch batch;
      std::memcpy(&batch, reinterpret_cast<void*>(args_ptr), sizeof(batch));
      if (batch.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
          batch.version != GROUP_PMP_SQLITE_VFS_VERSION ||
          batch.flags != 0 || !batch.count ||
          batch.count > GROUP_PMP_SQLITE_VFS_INLINE_BATCH_MAX) {
        std::fprintf(stderr,
                     "[P10][sqlite-ocall] reject inline batch header: "
                     "magic=0x%llx version=%llu flags=0x%llx count=%llu\n",
                     static_cast<unsigned long long>(batch.magic),
                     static_cast<unsigned long long>(batch.version),
                     static_cast<unsigned long long>(batch.flags),
                     static_cast<unsigned long long>(batch.count));
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
      }
      count = batch.count;
      for (uint64_t index = 0; index < count; ++index)
        requests[index] = batch.requests[index];
    } else {
      struct group_pmp_sqlite_vfs_indirect_batch batch;
      std::memcpy(&batch, reinterpret_cast<void*>(args_ptr), sizeof(batch));
      if (batch.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
          batch.version != GROUP_PMP_SQLITE_VFS_VERSION ||
          batch.flags != 0 ||
          batch.count <= GROUP_PMP_SQLITE_VFS_INLINE_BATCH_MAX ||
          batch.count > GROUP_PMP_SQLITE_VFS_LEGACY_BATCH_MAX ||
          batch.descriptor_offset !=
              GROUP_PMP_SQLITE_VFS_DESCRIPTOR_OFFSET ||
          batch.descriptor_bytes !=
              batch.count * sizeof(requests[0]) ||
          batch.descriptor_offset > _shared_len ||
          batch.descriptor_bytes >
              _shared_len - batch.descriptor_offset) {
        std::fprintf(stderr,
                     "[P10][sqlite-ocall] reject indirect batch header: "
                     "magic=0x%llx version=%llu flags=0x%llx count=%llu "
                     "descriptor=0x%llx/%llu utm=%zu\n",
                     static_cast<unsigned long long>(batch.magic),
                     static_cast<unsigned long long>(batch.version),
                     static_cast<unsigned long long>(batch.flags),
                     static_cast<unsigned long long>(batch.count),
                     static_cast<unsigned long long>(batch.descriptor_offset),
                     static_cast<unsigned long long>(batch.descriptor_bytes),
                     _shared_len);
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
      }
      count = batch.count;
      indirect_batch = true;
      std::memcpy(requests.data(),
                  reinterpret_cast<const void*>(
                      _shared_start + batch.descriptor_offset),
                  static_cast<size_t>(batch.descriptor_bytes));
    }
    for (uint64_t index = 0; index < count; ++index) {
      const struct group_pmp_sqlite_vfs_request& request =
          requests[index];
      if (!valid_request(request) || seen_buffer[request.buffer_id] ||
          (request.reserved[0] &
           GROUP_PMP_SQLITE_STORE_BLOCK_ON_COMPLETE) == 0 ||
           (request.operation != GROUP_PMP_SQLITE_VFS_OP_READ &&
            request.operation != GROUP_PMP_SQLITE_VFS_OP_WRITE)) {
        std::fprintf(stderr,
                     "[P10][sqlite-ocall] reject batch request: index=%llu "
                     "worker=%llu/%llu operation=%llu buffer=%llu "
                     "offset=0x%llx length=%llu flags=0x%llx\n",
                     static_cast<unsigned long long>(index),
                     static_cast<unsigned long long>(request.worker_index),
                     static_cast<unsigned long long>(request.worker_count),
                     static_cast<unsigned long long>(request.operation),
                     static_cast<unsigned long long>(request.buffer_id),
                     static_cast<unsigned long long>(request.buffer_offset),
                     static_cast<unsigned long long>(request.length),
                     static_cast<unsigned long long>(request.reserved[0]));
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
      }
      for (uint64_t previous = 0; previous < index; ++previous) {
        const struct group_pmp_sqlite_vfs_request& prior =
            requests[previous];
        const uint64_t request_end = request.buffer_offset + request.length;
        const uint64_t prior_end = prior.buffer_offset + prior.length;
        if (request.buffer_offset < prior_end &&
            prior.buffer_offset < request_end) {
          std::fprintf(stderr,
                       "[P10][sqlite-ocall] reject overlapping batch buffers: "
                       "index=%llu previous=%llu current=0x%llx/%llu "
                       "prior=0x%llx/%llu\n",
                       static_cast<unsigned long long>(index),
                       static_cast<unsigned long long>(previous),
                       static_cast<unsigned long long>(request.buffer_offset),
                       static_cast<unsigned long long>(request.length),
                       static_cast<unsigned long long>(prior.buffer_offset),
                       static_cast<unsigned long long>(prior.length));
          edge_call->return_data.call_status = CALL_STATUS_ERROR;
          return;
        }
      }
      if (indirect_batch) {
        const uint64_t request_end = request.buffer_offset + request.length;
        const uint64_t descriptor_end =
            GROUP_PMP_SQLITE_VFS_DESCRIPTOR_OFFSET +
            count * sizeof(requests[0]);
        if (request.buffer_offset < descriptor_end &&
            GROUP_PMP_SQLITE_VFS_DESCRIPTOR_OFFSET < request_end) {
          std::fprintf(stderr,
                       "[P10][sqlite-ocall] reject descriptor overlap: "
                       "index=%llu payload=0x%llx/%llu descriptor=0x%llx/%llu\n",
                       static_cast<unsigned long long>(index),
                       static_cast<unsigned long long>(request.buffer_offset),
                       static_cast<unsigned long long>(request.length),
                       static_cast<unsigned long long>(
                           GROUP_PMP_SQLITE_VFS_DESCRIPTOR_OFFSET),
                       static_cast<unsigned long long>(
                           count * sizeof(requests[0])));
          edge_call->return_data.call_status = CALL_STATUS_ERROR;
          return;
        }
      }
      seen_buffer[request.buffer_id] = true;
      ack.request_id[index] = request.request_id;
    }
    completion.reset(new SqliteAsyncCompletion(count));
    defer_current_ocall = true;
    for (uint64_t index = 0; index < count; ++index)
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_REQUEST_SUBMIT, requests[index],
          completion->trace_id);
    if (!sqlite_selected_io_submit_batch(
            requests.data(), count,
            reinterpret_cast<uint8_t*>(_shared_start), _shared_len,
            completion)) {
      std::fprintf(stderr,
                   "[P10][sqlite-ocall] batch service stopped or rejected: "
                   "count=%llu worker=%llu/%llu operation=%llu utm=%zu\n",
                   static_cast<unsigned long long>(count),
                   static_cast<unsigned long long>(requests[0].worker_index),
                   static_cast<unsigned long long>(requests[0].worker_count),
                   static_cast<unsigned long long>(requests[0].operation),
                   _shared_len);
      edge_call->return_data.call_status = CALL_STATUS_ERROR;
      return;
    }
    ack.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    ack.version = GROUP_PMP_SQLITE_VFS_VERSION;
    ack.count = count;
    ack.status = 0;
    ret_ptr = edge_call_data_ptr();
    std::memcpy(reinterpret_cast<void*>(ret_ptr), &ack, sizeof(ack));
    if (edge_call_setup_ret(edge_call, reinterpret_cast<void*>(ret_ptr),
                            sizeof(ack)) != 0) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      return;
    }
  } else {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  edge_call->return_data.call_status = CALL_STATUS_OK;
  if (defer_current_ocall)
    sqlite_dispatched_completion = completion;
  sqlite_submission_timing.publishAck(sqlite_io_time_ticks());
}

Params
make_group_params(uint64_t group_id, uint64_t group_capacity,
                  uint64_t yxstm_size, uint64_t yxstm_slice_size,
                  uint64_t utm_size,
                  uint64_t free_mem_size = kFreeMemSize) {
  Params params;
  params.setFreeMemSize(free_mem_size);
  params.setUntrustedSize(utm_size);
  uint64_t bank_size = yxstm_slice_size *
                       KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
  uint64_t bank_count = bank_size ? yxstm_size / bank_size : 0;
  if (!params.setYXSTMBankedLayout(
          yxstm_size, bank_count, yxstm_slice_size)) {
    std::cerr << "[host] invalid YXSTM layout: total=" << yxstm_size
              << " slice=" << yxstm_slice_size
              << " banks=" << bank_count
              << std::endl;
  }
  params.setYXms(group_capacity);
  params.setEngineID(group_id);
  return params;
}

bool
init_instance(EnclaveInstance& instance, const char* runtime, const char* loader) {
  Params params = make_group_params(
      instance.spec.group_id, instance.spec.group_capacity,
      instance.spec.yxstm_size, instance.spec.yxstm_slice_size,
      instance.spec.utm_size, instance.spec.free_mem_size);
  instance.enclave.reset(new Enclave());

  Error err = instance.enclave->initNoFinalize(
      instance.spec.eapp, runtime, loader, params);
  if (err != Error::Success) {
    std::cerr << "[host] init/load failed: " << instance.spec.name
              << " group=" << instance.spec.group_id
              << " capacity=" << instance.spec.group_capacity
              << " error=" << error_name(err) << std::endl;
    return false;
  }

  instance.enclave->registerOcallDispatch(incoming_call_dispatch);
  std::cout << "[host] init/load ok: " << instance.spec.name
            << " eid=" << instance.enclave->getEid()
            << " group=" << instance.spec.group_id
            << " capacity=" << instance.spec.group_capacity
            << " free_mem_mb="
            << (static_cast<double>(instance.spec.free_mem_size) /
                kDecimalMbBytes)
            << std::endl;
  return true;
}

bool
finalize_instance(EnclaveInstance& instance) {
  Error err = instance.enclave->finalize();
  if (err != Error::Success) {
    std::cerr << "[host] finalize failed: " << instance.spec.name
              << " error=" << error_name(err) << std::endl;
    return false;
  }

  // finalize() creates the Host UTM mapping; initNoFinalize() does not.
  if (security_scan_nonce()) {
    const uint8_t* base = static_cast<const uint8_t*>(instance.enclave->getOcallBuffer());
    const size_t bytes = instance.enclave->getOcallBufferSize();
    if (!base || !bytes) {
      std::cerr << "[security] finalized UTM mapping unavailable: " << instance.spec.name << std::endl;
      return false;
    }
    const size_t control = std::min<size_t>(bytes, GROUP_PMP_SQLITE_VFS_CONTROL_BYTES);
    security_region("add", "control-utm", base, control);
    if (bytes > control) security_region("add", "data-utm", base + control, bytes - control);
  }

  std::cout << "[host] finalize ok: " << instance.spec.name << std::endl;
  return true;
}

bool
run_instance(EnclaveInstance& instance, uintptr_t expected_ret) {
  uintptr_t retval = 0;
  std::cout << "[host] run: " << instance.spec.name << std::endl;

  edge_call_init_internals(
      reinterpret_cast<uintptr_t>(instance.enclave->getOcallBuffer()),
      instance.enclave->getOcallBufferSize());

  Error err = instance.enclave->run(&retval);
  if (err != Error::Success) {
    std::cerr << "[host] run failed: " << instance.spec.name
              << " error=" << error_name(err) << std::endl;
    return false;
  }

  if (retval != expected_ret) {
    std::cerr << "[host] unexpected return: " << instance.spec.name
              << " got=" << retval << " expected=" << expected_ret
              << std::endl;
    return false;
  }

  std::cout << "[host] run ok: " << instance.spec.name << std::endl;
  return true;
}

bool
run_instance_expect_failure(EnclaveInstance& instance) {
  uintptr_t retval = 0;
  const uintptr_t kRuntimeFaultRetval = static_cast<uintptr_t>(-1);
  std::cout << "[host] expect enclave fault: "
            << instance.spec.name << std::endl;

  edge_call_init_internals(
      reinterpret_cast<uintptr_t>(instance.enclave->getOcallBuffer()),
      instance.enclave->getOcallBufferSize());

  Error err = instance.enclave->run(&retval);
  if (err != Error::Success) {
    std::cout << "[host] run failed as expected: " << instance.spec.name
              << " error=" << error_name(err) << std::endl;
    return true;
  }

  if (retval == kRuntimeFaultRetval) {
    std::cout << "[host] page fault exit observed as expected: "
              << instance.spec.name << " retval=" << retval << std::endl;
    return true;
  }

  std::cerr << "[host] expected enclave fault but got normal return: "
            << instance.spec.name << " retval=" << retval << std::endl;
  return false;
}

bool
pin_current_thread_to_cpu(int cpu, const char* name) {
#ifdef __linux__
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);

  int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
  if (rc != 0) {
    std::cerr << "[host] failed to pin " << name << " to cpu=" << cpu
              << " error=" << std::strerror(rc) << std::endl;
    return false;
  }

  std::cout << "[host] pinned " << name << " to cpu=" << cpu << std::endl;
  return true;
#else
  std::cerr << "[host] CPU affinity is only supported on Linux: "
            << name << std::endl;
  return false;
#endif
}

Error
group_run_hart_until_guest_event(Keystone::KeystoneDevice& device,
    uint64_t group_id, uint64_t sm_hart_id, uint64_t* event_eid,
    uint64_t* event, uintptr_t* retval) {
  const std::chrono::milliseconds busy_timeout(env_u64(
      "GROUP_PMP_COHERENCE_BUSY_TIMEOUT_MS",
      kDefaultCoherenceBusyTimeoutMs, 1, 60000));
  std::chrono::steady_clock::time_point busy_since;
  bool busy = false;

  while (true) {
    if (event_eid)
      *event_eid = 0;
    if (event)
      *event = KEYSTONE_GROUP_EVENT_NONE;
    if (retval)
      *retval = 0;

    Error err = device.groupRunHart(
        group_id, sm_hart_id, event_eid, event, retval);
    if (err == Error::GroupCoherenceBusy) {
      const auto now = std::chrono::steady_clock::now();
      if (!busy) {
        busy = true;
        busy_since = now;
      } else if (now - busy_since >= busy_timeout) {
        std::cerr << "[host] group coherence remained busy: group="
                  << group_id << " sm_hart=" << sm_hart_id
                  << " timeout_ms=" << busy_timeout.count() << std::endl;
        return err;
      }
      std::this_thread::sleep_for(
          std::chrono::microseconds(kCoherenceBusyBackoffUs));
      continue;
    }

    if (err == Error::Success && event &&
        *event == KEYSTONE_GROUP_EVENT_HOST_INTERRUPT) {
      busy = false;
      /*
       * This event is a real CPU handoff. Yield before re-entering the SM so
       * Linux can run timer, RCU and per-CPU work instead of letting four
       * pinned runner threads immediately reclaim every CPU.
       */
      std::this_thread::yield();
      continue;
    }
    if (err == Error::EnclaveInterrupted && event &&
        *event == KEYSTONE_GROUP_EVENT_INTERRUPTED) {
      /* Explicit yield remains available for scheduler and debug fixtures. */
      busy = false;
      std::this_thread::yield();
      continue;
    }
    return err;
  }
}

Enclave*
find_group_enclave_by_eid(const std::vector<EnclaveInstance>* enclaves,
                          uint64_t eid) {
  if (!enclaves)
    return nullptr;

  for (size_t i = 0; i < enclaves->size(); ++i) {
    Enclave* candidate = (*enclaves)[i].enclave.get();
    if (candidate && static_cast<uint64_t>(candidate->getEid()) == eid)
      return candidate;
  }
  return nullptr;
}

struct DeferredGroupOcall {
  uint64_t group_id;
  uint64_t hart_id;
  uint64_t eid;
  uint64_t ocall_id;
  std::shared_ptr<SqliteAsyncCompletion> completion;
  SqliteSubmissionTiming submission_timing;
};

std::mutex deferred_group_ocall_mutex;
std::mutex deferred_group_ocall_flush_mutex;
std::vector<DeferredGroupOcall> deferred_group_ocalls;
std::vector<DeferredGroupOcall> completed_group_ocalls;
std::atomic<bool> deferred_group_ocall_failure(false);

bool
group_has_deferred_ocalls(uint64_t group_id) {
  std::lock_guard<std::mutex> lock(deferred_group_ocall_mutex);
  for (size_t index = 0; index < deferred_group_ocalls.size(); ++index)
    if (deferred_group_ocalls[index].group_id == group_id)
      return true;
  for (size_t index = 0; index < completed_group_ocalls.size(); ++index)
    if (completed_group_ocalls[index].group_id == group_id)
      return true;
  return false;
}

bool
flush_completed_group_ocalls(Keystone::KeystoneDevice& device,
                             uint64_t group_id, const char* label) {
  std::lock_guard<std::mutex> flush_lock(deferred_group_ocall_flush_mutex);
  std::vector<DeferredGroupOcall> ready;
  {
    std::lock_guard<std::mutex> lock(deferred_group_ocall_mutex);
    for (std::vector<DeferredGroupOcall>::iterator it =
             completed_group_ocalls.begin();
         it != completed_group_ocalls.end();) {
      if (it->group_id == group_id) {
        ready.push_back(*it);
        it = completed_group_ocalls.erase(it);
      } else {
        ++it;
      }
    }
  }

  for (size_t offset = 0; offset < ready.size();) {
    const size_t count = std::min<size_t>(
        KEYSTONE_GROUP_OCALL_RESUME_BATCH_MAX, ready.size() - offset);
    std::array<struct keystone_group_ocall_resume_entry,
               KEYSTONE_GROUP_OCALL_RESUME_BATCH_MAX> entries{};
    const uint64_t wake_ns = sqlite_gantt_now_ns();
    for (size_t index = 0; index < count; ++index) {
      DeferredGroupOcall& deferred = ready[offset + index];
      deferred.submission_timing.requestResume(sqlite_io_time_ticks());
      entries[index].hart_id = deferred.hart_id;
      entries[index].eid = deferred.eid;
      entries[index].ocall_id = deferred.ocall_id;
      entries[index].result = 0;
      sqlite_gantt_trace().recordOcall(
          SQLITE_GANTT_WAKEUP_REQUEST, group_id, deferred.hart_id,
          deferred.eid, deferred.ocall_id,
          deferred.completion ? deferred.completion->trace_id : 0,
          0, wake_ns);
    }

    uint64_t resumed = 0;
    group_warmup_diagnostics.mark(GroupWarmupDiagnostics::RESUME,
        "batch-resume-ioctl", entries[0].eid, entries[0].ocall_id);
    Error resume_error = device.groupResumeBlockedOcalls(
        group_id, entries.data(), count, &resumed);
    group_warmup_diagnostics.mark(GroupWarmupDiagnostics::RESUME, "idle");
    const uint64_t resume_ns = sqlite_gantt_now_ns();
    if (resumed > count)
      resumed = count;
    for (size_t index = 0; index < count; ++index) {
      const DeferredGroupOcall& deferred = ready[offset + index];
      const uint64_t completion_id = deferred.completion ?
          deferred.completion->trace_id : 0;
      const bool success = index < resumed;
      sqlite_gantt_trace().recordOcall(
          SQLITE_GANTT_WAKEUP_COMPLETE, group_id, deferred.hart_id,
          deferred.eid, deferred.ocall_id, completion_id,
          success ? 0 : -1, resume_ns);
      // ioctl return acknowledges the resume request, not execution on a hart.
      // Actual submission return is timestamped by the worker after its OCALL.
      if (success && deferred.completion)
        sqlite_selected_io_record_wakeup(
            deferred.completion->publishedAtNs(),
            deferred.completion->wakeupEligibleAtNs(), wake_ns, resume_ns);
    }

    if (resume_error != Error::Success || resumed != count) {
      for (size_t index = offset + resumed; index < ready.size(); ++index) {
        const DeferredGroupOcall& deferred = ready[index];
        (void)device.groupAbandonBlockedOcall(
            group_id, deferred.hart_id, deferred.eid,
            deferred.ocall_id, 0);
      }
      std::cerr << "[host] failed batched SQLite OCALL wakeup: group="
                << group_id << " resumed=" << resumed << "/" << count
                << " error=" << error_name(resume_error)
                << " label=" << label << std::endl;
      deferred_group_ocall_failure.store(true, std::memory_order_release);
      return false;
    }
    offset += count;
  }
  return true;
}

bool
resume_completed_group_ocalls(Keystone::KeystoneDevice& device,
                              uint64_t group_id, const char* label) {
  if (!flush_completed_group_ocalls(device, group_id, label))
    return false;
  if (!deferred_group_ocall_failure.load(std::memory_order_acquire))
    return true;
  std::cerr << "[host] asynchronous SQLite OCALL wakeup failed: label="
            << label << std::endl;
  return false;
}

void
clear_deferred_group_ocalls(uint64_t group_id) {
  std::lock_guard<std::mutex> lock(deferred_group_ocall_mutex);
  deferred_group_ocalls.erase(
      std::remove_if(deferred_group_ocalls.begin(),
                     deferred_group_ocalls.end(),
                     [group_id](const DeferredGroupOcall& ocall) {
                       return ocall.group_id == group_id;
                     }),
      deferred_group_ocalls.end());
  completed_group_ocalls.erase(
      std::remove_if(completed_group_ocalls.begin(),
                     completed_group_ocalls.end(),
                     [group_id](const DeferredGroupOcall& ocall) {
                       return ocall.group_id == group_id;
                     }),
      completed_group_ocalls.end());
}

bool
dispatch_and_resume_group_ocall(Keystone::KeystoneDevice& device,
    uint64_t group_id, uint64_t sm_hart_id, uint64_t event_eid,
    uint64_t ocall_id, const std::vector<EnclaveInstance>* enclaves,
    const char* label, bool quiet = false) {
  const uint64_t handler_begin_ns = sqlite_gantt_now_ns();
  Enclave* ocall_enclave = find_group_enclave_by_eid(enclaves, event_eid);
  sqlite_gantt_trace().recordOcall(
      SQLITE_GANTT_OCALL_HANDLER_BEGIN, group_id, sm_hart_id, event_eid,
      ocall_id, 0, 0, handler_begin_ns);
  if (!ocall_enclave || !ocall_enclave->getOcallBuffer() ||
      ocall_enclave->getOcallBufferSize() < sizeof(struct edge_call)) {
    Error abandon_error = device.groupAbandonBlockedOcall(
        group_id, sm_hart_id, event_eid, ocall_id, 0);
    std::cerr << "[host] invalid OCALL buffer for group event: group="
              << group_id << " sm_hart=" << sm_hart_id
              << " eid=" << event_eid << " ocall_id=" << ocall_id
              << " abandon=" << error_name(abandon_error)
              << " label=" << label << std::endl;
    return false;
  }

  uintptr_t call_status = CALL_STATUS_BAD_CALL_ID;
  std::shared_ptr<SqliteAsyncCompletion> deferred_completion;
  SqliteSubmissionTiming submission_timing;
  {
    std::lock_guard<std::mutex> lock(group_ocall_dispatch_mutex);
    struct edge_call* edge_call = static_cast<struct edge_call*>(
        ocall_enclave->getOcallBuffer());
    edge_call_init_internals(
        reinterpret_cast<uintptr_t>(ocall_enclave->getOcallBuffer()),
        ocall_enclave->getOcallBufferSize());
    sqlite_dispatched_completion.reset();
    sqlite_submission_timing.begin(0);
    group_warmup_diagnostics.mark(GroupWarmupDiagnostics::MAIN,
        "ocall-handler", event_eid, ocall_id);
    incoming_call_dispatch(ocall_enclave->getOcallBuffer());
    call_status = edge_call->return_data.call_status;
    deferred_completion = sqlite_dispatched_completion;
    submission_timing = sqlite_submission_timing;
    sqlite_dispatched_completion.reset();
  }
  const uint64_t completion_id = deferred_completion ?
      deferred_completion->trace_id : 0;
  sqlite_gantt_trace().recordOcall(
      SQLITE_GANTT_OCALL_HANDLER_END, group_id, sm_hart_id, event_eid,
      ocall_id, completion_id, static_cast<int64_t>(call_status));

  if (call_status != CALL_STATUS_OK) {
    Error abandon_error = device.groupAbandonBlockedOcall(
        group_id, sm_hart_id, event_eid, ocall_id, 0);
    std::cerr << "[host] group OCALL dispatch failed: group=" << group_id
              << " sm_hart=" << sm_hart_id << " eid=" << event_eid
              << " ocall_id=" << ocall_id << " status=" << call_status
              << " abandon=" << error_name(abandon_error)
              << " label=" << label << std::endl;
    return false;
  }

  if (deferred_completion) {
    group_warmup_diagnostics.mark(GroupWarmupDiagnostics::MAIN,
        "arm-completion", event_eid, ocall_id);
    sqlite_gantt_trace().recordOcall(
        SQLITE_GANTT_ENCLAVE_BLOCKED, group_id, sm_hart_id, event_eid,
        ocall_id, completion_id, 0, handler_begin_ns);
    DeferredGroupOcall deferred;
    deferred.group_id = group_id;
    deferred.hart_id = sm_hart_id;
    deferred.eid = event_eid;
    deferred.ocall_id = ocall_id;
    deferred.completion = deferred_completion;
    deferred.submission_timing = submission_timing;
    {
      std::lock_guard<std::mutex> lock(deferred_group_ocall_mutex);
      deferred_group_ocalls.push_back(deferred);
    }
    deferred_completion->arm(
        [&device, group_id, sm_hart_id, event_eid,
         ocall_id](bool defer_batch_flush) {
          DeferredGroupOcall completed;
          {
            std::lock_guard<std::mutex> lock(deferred_group_ocall_mutex);
            std::vector<DeferredGroupOcall>::iterator pending =
                std::find_if(
                    deferred_group_ocalls.begin(),
                    deferred_group_ocalls.end(),
                    [group_id, sm_hart_id, event_eid, ocall_id](
                        const DeferredGroupOcall& value) {
                      return value.group_id == group_id &&
                          value.hart_id == sm_hart_id &&
                          value.eid == event_eid &&
                          value.ocall_id == ocall_id;
                    });
            /* Claim the completion under the registry lock, then perform the
             * potentially slow SM ioctl without serializing unrelated lanes. */
            if (pending == deferred_group_ocalls.end())
              return;
            completed = *pending;
            deferred_group_ocalls.erase(pending);
            completed_group_ocalls.push_back(completed);
          }
          if (!defer_batch_flush)
            (void)flush_completed_group_ocalls(
                device, group_id, "sqlite-completion-batch");
        }, sm_hart_id);
    return true;
  }

  sqlite_gantt_trace().recordOcall(
      SQLITE_GANTT_ENCLAVE_BLOCKED, group_id, sm_hart_id, event_eid,
      ocall_id, 0, 0, handler_begin_ns);
  sqlite_gantt_trace().recordOcall(
      SQLITE_GANTT_WAKEUP_REQUEST, group_id, sm_hart_id, event_eid,
      ocall_id, 0);
  submission_timing.requestResume(sqlite_io_time_ticks());
  group_warmup_diagnostics.mark(GroupWarmupDiagnostics::MAIN,
      "single-resume-ioctl", event_eid, ocall_id);
  Error resume_error = device.groupResumeBlockedOcall(
      group_id, sm_hart_id, event_eid, ocall_id, 0);
  sqlite_gantt_trace().recordOcall(
      SQLITE_GANTT_WAKEUP_COMPLETE, group_id, sm_hart_id, event_eid,
      ocall_id, 0, resume_error == Error::Success ? 0 : -1);
  if (resume_error != Error::Success) {
    Error abandon_error = device.groupAbandonBlockedOcall(
        group_id, sm_hart_id, event_eid, ocall_id, 0);
    std::cerr << "[host] failed to resume group OCALL: group=" << group_id
              << " sm_hart=" << sm_hart_id << " eid=" << event_eid
              << " ocall_id=" << ocall_id
              << " resume=" << error_name(resume_error)
              << " abandon=" << error_name(abandon_error)
              << " label=" << label << std::endl;
    return false;
  }

  if (!quiet)
    std::cout << "[host] group OCALL completed: group=" << group_id
              << " sm_hart=" << sm_hart_id << " eid=" << event_eid
              << " ocall_id=" << ocall_id << " label=" << label
              << std::endl;
  return true;
}

void
group_run_hart_worker(uint64_t group_id, uint64_t sm_hart_id, int cpu,
    const std::vector<EnclaveInstance>* ocall_enclaves,
    ParallelRunResult* result) {
  uintptr_t retval = 0;
  uint64_t event_eid = 0;
  uint64_t event = KEYSTONE_GROUP_EVENT_NONE;
  Keystone::KeystoneDevice device;
  Params params;

  result->ok = false;
  result->err = Error::DeviceError;
  result->retval = 0;
  result->event_eid = 0;
  result->event = KEYSTONE_GROUP_EVENT_NONE;
  result->started.store(true, std::memory_order_release);
  result->finished.store(false, std::memory_order_release);

  if (!pin_current_thread_to_cpu(cpu, "group-run-hart")) {
    result->finished.store(true, std::memory_order_release);
    return;
  }

  if (!device.initDevice(params)) {
    std::cerr << "[host] failed to open keystone device for groupRunHart"
              << std::endl;
    result->finished.store(true, std::memory_order_release);
    return;
  }

  std::cout << "[host] group run hart start: group=" << group_id
            << " sm_hart=" << sm_hart_id << " cpu=" << cpu << std::endl;

  Error err = Error::DeviceError;
  while (true) {
    event_eid = 0;
    event = KEYSTONE_GROUP_EVENT_NONE;
    retval = 0;
    err = group_run_hart_until_guest_event(device,
        group_id, sm_hart_id, &event_eid, &event, &retval);
    result->err = err;
    result->retval = retval;
    result->event_eid = event_eid;
    result->event = event;

    if (err != Error::EdgeCallHost ||
        event != KEYSTONE_GROUP_EVENT_OCALL)
      break;

    if (!dispatch_and_resume_group_ocall(device, group_id, sm_hart_id,
            event_eid, retval, ocall_enclaves, "parallel-runner")) {
      err = Error::DeviceError;
      result->err = err;
      break;
    }
  }

  if (err != Error::Success) {
    std::cerr << "[host] group run hart failed: group=" << group_id
              << " sm_hart=" << sm_hart_id
              << " error=" << error_name(err)
              << " event=" << event << " eid=" << event_eid
              << " retval=" << retval << std::endl;
    result->finished.store(true, std::memory_order_release);
    return;
  }

  if (event != KEYSTONE_GROUP_EVENT_EXIT) {
    std::cerr << "[host] group run hart unexpected event: group=" << group_id
              << " sm_hart=" << sm_hart_id
              << " event=" << event << " eid=" << event_eid
              << " retval=" << retval << std::endl;
    result->finished.store(true, std::memory_order_release);
    return;
  }

  if (retval != 0) {
    std::cerr << "[host] group run hart unexpected return: group=" << group_id
              << " sm_hart=" << sm_hart_id
              << " got=" << retval << " expected=0" << std::endl;
    result->finished.store(true, std::memory_order_release);
    return;
  }

  std::cout << "[host] group run hart ok: group=" << group_id
            << " sm_hart=" << sm_hart_id
            << " event_eid=" << event_eid
            << " retval=" << retval << std::endl;
  result->ok = true;
  result->finished.store(true, std::memory_order_release);
}

bool
run_group_harts_parallel(uint64_t group_id, const std::vector<uint64_t>& sm_harts,
    const std::vector<int>& cpus, const char* label,
    const std::vector<EnclaveInstance>* ocall_enclaves = nullptr) {
  const std::chrono::seconds kParallelTimeout(
      env_u64("GROUP_PMP_GROUP_RUN_TIMEOUT_SEC", 15, 1, 3600));
  Keystone::KeystoneDevice topology_device;
  Params topology_params;
  struct keystone_group_topology topology;

  if (sm_harts.size() != cpus.size() || sm_harts.empty()) {
    std::cerr << "[host] invalid group hart selection: " << label
              << std::endl;
    return false;
  }
  std::memset(&topology, 0, sizeof(topology));
  if (!topology_device.initDevice(topology_params) ||
      topology_device.groupQueryTopology(group_id, &topology) !=
          Error::Success ||
      topology.execution_mode != GROUP_MODE_SATURATION_TEST) {
    std::cerr << "[host] legacy parallel runner requires "
              << "GROUP_MODE_SATURATION_TEST: " << label << std::endl;
    return false;
  }
  for (size_t i = 0; i < sm_harts.size(); ++i) {
    if (cpus[i] < 0 ||
        static_cast<uint64_t>(cpus[i]) + topology.cpu_hart_offset !=
            sm_harts[i] ||
        !(topology.configured_hart_mask &
          (UINT64_C(1) << sm_harts[i]))) {
      std::cerr << "[host] saturation CPU/hart mapping mismatch: "
                << label << " cpu=" << cpus[i]
                << " hart=" << sm_harts[i]
                << " offset=" << topology.cpu_hart_offset << std::endl;
      return false;
    }
  }

  std::unique_ptr<ParallelRunResult[]> results(
      new ParallelRunResult[sm_harts.size()]);
  std::vector<std::thread> threads(sm_harts.size());

  std::cout << "[host] group run harts start: " << label
            << " count=" << sm_harts.size() << std::endl;
  for (size_t i = 0; i < sm_harts.size(); ++i) {
    results[i].ok = false;
    results[i].err = Error::DeviceError;
    results[i].retval = 0;
    results[i].event_eid = 0;
    results[i].event = KEYSTONE_GROUP_EVENT_NONE;
    results[i].started.store(false, std::memory_order_release);
    results[i].finished.store(false, std::memory_order_release);
    threads[i] = std::thread(group_run_hart_worker,
        group_id, sm_harts[i], cpus[i], ocall_enclaves, &results[i]);
  }

  auto start = std::chrono::steady_clock::now();
  while (true) {
    bool all_finished = true;
    for (size_t i = 0; i < sm_harts.size(); ++i) {
      if (!results[i].finished.load(std::memory_order_acquire)) {
        all_finished = false;
        break;
      }
    }
    if (all_finished) {
      break;
    }
    if (std::chrono::steady_clock::now() - start > kParallelTimeout) {
      std::cerr << "[host] timeout in group run harts phase: "
                << label << std::endl;
      for (size_t i = 0; i < sm_harts.size(); ++i) {
        std::cerr << "[host]   group=" << group_id
                  << " sm_hart=" << sm_harts[i]
                  << " cpu=" << cpus[i]
                  << " started="
                  << results[i].started.load(std::memory_order_acquire)
                  << " finished="
                  << results[i].finished.load(std::memory_order_acquire)
                  << " error=" << error_name(results[i].err)
                  << " event=" << results[i].event
                  << " eid=" << results[i].event_eid
                  << " retval=" << results[i].retval << std::endl;
      }
      std::exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  for (size_t i = 0; i < threads.size(); ++i) {
    threads[i].join();
  }

  for (size_t i = 0; i < sm_harts.size(); ++i) {
    if (!results[i].ok) {
      std::cerr << "[host] group run harts failed: " << label
                << " sm_hart=" << sm_harts[i]
                << " error=" << error_name(results[i].err)
                << " event=" << results[i].event
                << " eid=" << results[i].event_eid
                << " retval=" << results[i].retval << std::endl;
      return false;
    }
  }

  std::cout << "[host] group run harts ok: " << label << std::endl;
  return true;
}

bool
is_worker_eid(const std::vector<EnclaveInstance>& enclaves, uint64_t eid) {
  for (size_t i = 1; i < enclaves.size(); ++i) {
    if (enclaves[i].enclave &&
        static_cast<uint64_t>(enclaves[i].enclave->getEid()) == eid)
      return true;
  }
  return false;
}

bool
run_group_3w1hm(uint64_t group_id,
                std::vector<EnclaveInstance>& enclaves,
                const char* label) {
  const uint64_t timeout_ms = env_u64(
      "GROUP_PMP_MASTER_WAIT_TIMEOUT_MS", 60000, 1, 3600000);
  const uint64_t event_mask =
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_WORKERS_READY) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_EXIT) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_OCALL) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_FAULT) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_WATCHDOG) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_HEARTBEAT);
  uint64_t lease_flags = KEYSTONE_GROUP_LEASE_FLAG_REQUIRE_ISOLATION |
      KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE |
      KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE;
  const char* fallback = std::getenv("GROUP_PMP_LEASE_TEST_FALLBACK");
  Keystone::KeystoneDevice device;
  Params params;
  struct keystone_group_topology topology;
  struct keystone_group_lease lease;
  std::vector<uint64_t> worker_exit_eids;
  uint64_t max_control_steps;
  bool master_exited = false;
  bool ok = true;

  if (fallback && std::strcmp(fallback, "1") == 0) {
    lease_flags &= ~(KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE |
                     KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE);
    lease_flags |= KEYSTONE_GROUP_LEASE_FLAG_TEST_FALLBACK |
                   KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT;
  }
  if (enclaves.size() < 2 || !pin_current_thread_to_cpu(
          static_cast<int>(kHousekeepingCpu), label) ||
      !device.initDevice(params)) {
    std::cerr << "[host] failed to initialize 3W_1HM control path: "
              << label << std::endl;
    return false;
  }
  std::memset(&topology, 0, sizeof(topology));
  if (device.groupQueryTopology(group_id, &topology) != Error::Success ||
      topology.execution_mode != GROUP_MODE_3W_1HM ||
      topology.housekeeping_cpu != kHousekeepingCpu ||
      topology.housekeeping_hart != kHousekeepingHart ||
      topology.master_hart != kHousekeepingHart ||
      topology.worker_hart_mask != KEYSTONE_VF2_WORKER_HART_MASK ||
      topology.worker_count != KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT - 1 ||
      enclaves.size() < 2) {
    std::cerr << "[host] invalid 3W_1HM topology for " << label << std::endl;
    return false;
  }
  max_control_steps = env_u64(
      "GROUP_PMP_MASTER_CONTROL_STEPS",
      std::max<uint64_t>(4096,
                         static_cast<uint64_t>(enclaves.size()) * 64),
      1, 1000000);

  std::memset(&lease, 0, sizeof(lease));
  Error lease_error = device.groupLeaseWorkers(
      group_id, lease_flags, &lease);
  if (lease_error != Error::Success) {
    std::cerr << "[host] worker lease failed: " << label
              << " error=" << error_name(lease_error)
              << " (verify CPU1-3 isolation and driver worker_isolation_ready)"
              << std::endl;
    return false;
  }

  std::cout << "[host] worker lease active: group=" << group_id
            << " mask=0x" << std::hex << lease.worker_hart_mask << std::dec
            << " epoch=" << lease.lease_epoch << std::endl;

  for (uint64_t step = 0;
       ok && !master_exited && step < max_control_steps; ++step) {
    uintptr_t retval = 0;
    uint64_t event_eid = 0;
    uint64_t event = KEYSTONE_GROUP_EVENT_NONE;
    uint64_t queue_overflows = 0;
    Error run_error = device.groupRunMaster(
        group_id, &event_eid, &event, &retval, nullptr, nullptr,
        &queue_overflows);

    if (queue_overflows) {
      std::cerr << "[host] master event queue overflow: " << label
                << " count=" << queue_overflows << std::endl;
      ok = false;
      break;
    }

    if (run_error == Error::EnclaveFatalFault ||
        event == KEYSTONE_GROUP_EVENT_FAULT ||
        event == KEYSTONE_GROUP_EVENT_WATCHDOG) {
      std::cerr << "[host] master fault: " << label
                << " event=" << event << " eid=" << event_eid
                << " value=" << retval << std::endl;
      ok = false;
      break;
    }
    if (event == KEYSTONE_GROUP_EVENT_OCALL) {
      if (run_error != Error::Success && run_error != Error::EdgeCallHost) {
        std::cerr << "[host] master OCALL was not dispatchable: " << label
                  << " error=" << error_name(run_error)
                  << " eid=" << event_eid << " ocall_id=" << retval
                  << std::endl;
        ok = false;
        break;
      }
      if (!dispatch_and_resume_group_ocall(device, group_id,
              topology.master_hart, event_eid, retval, &enclaves,
              "3W_1HM-master")) {
        ok = false;
        break;
      }
      continue;
    }
    if (event == KEYSTONE_GROUP_EVENT_EXIT) {
      uint64_t master_eid =
          static_cast<uint64_t>(enclaves[0].enclave->getEid());
      if (event_eid != master_eid || retval != 0) {
        std::cerr << "[host] unexpected master exit: eid=" << event_eid
                  << " expected=" << master_eid
                  << " value=" << retval << std::endl;
        ok = false;
      } else {
        master_exited = true;
      }
      break;
    }
    if (run_error != Error::EnclaveInterrupted &&
        run_error != Error::Success &&
        run_error != Error::GroupNotRunnable) {
      std::cerr << "[host] groupRunMaster failed: " << label
                << " error=" << error_name(run_error)
                << " event=" << event << std::endl;
      ok = false;
      break;
    }
    if (event == KEYSTONE_GROUP_EVENT_HOST_INTERRUPT)
      continue;

    struct keystone_group_wait_event ready;
    std::memset(&ready, 0, sizeof(ready));
    Error wait_error = device.groupWaitEvent(
        group_id, event_mask, timeout_ms, &ready);
    if (wait_error == Error::GroupEventTimeout) {
      std::cerr << "[host] timed out waiting for worker barrier: "
                << label << " step=" << step << std::endl;
      ok = false;
      break;
    }
    if (ready.queue_overflows) {
      std::cerr << "[host] worker event queue overflow: " << label
                << " count=" << ready.queue_overflows
                << " sequence=" << ready.event_sequence << std::endl;
      ok = false;
      break;
    }
    if (wait_error == Error::EnclaveFatalFault ||
        ready.event == KEYSTONE_GROUP_EVENT_FAULT ||
        ready.event == KEYSTONE_GROUP_EVENT_WATCHDOG) {
      std::cerr << "[host] worker fault: " << label
                << " event=" << ready.event << " eid=" << ready.eid
                << " error=" << ready.error << " value=" << ready.value
                << std::endl;
      ok = false;
      break;
    }
    if (wait_error == Error::GroupIOError ||
        ready.event == KEYSTONE_GROUP_EVENT_HEARTBEAT) {
      std::cerr << "[host] worker heartbeat failed: " << label
                << " hart=" << ready.hart_id << " eid=" << ready.eid
                << " error=" << ready.error << " value=" << ready.value
                << " sequence=" << ready.event_sequence << std::endl;
      ok = false;
      break;
    }
    if (wait_error != Error::Success) {
      std::cerr << "[host] groupWaitEvent failed: " << label
                << " error=" << error_name(wait_error)
                << " event=" << ready.event << " eid=" << ready.eid
                << std::endl;
      ok = false;
      break;
    }
    if (ready.event == KEYSTONE_GROUP_EVENT_OCALL) {
      if (!dispatch_and_resume_group_ocall(device, group_id, ready.hart_id,
              ready.eid, ready.value, &enclaves, "3W_1HM-worker")) {
        ok = false;
        break;
      }
      continue;
    }
    if (ready.event == KEYSTONE_GROUP_EVENT_EXIT) {
      if (!is_worker_eid(enclaves, ready.eid)) {
        std::cerr << "[host] unexpected exit while waiting for workers: eid="
                  << ready.eid << std::endl;
        ok = false;
        break;
      }
      if (std::find(worker_exit_eids.begin(), worker_exit_eids.end(),
                    ready.eid) == worker_exit_eids.end())
        worker_exit_eids.push_back(ready.eid);
      continue;
    }
    if (ready.event != KEYSTONE_GROUP_EVENT_WORKERS_READY) {
      std::cerr << "[host] unsupported 3W_1HM event: event="
                << ready.event << " eid=" << ready.eid << std::endl;
      ok = false;
      break;
    }
  }

  while (ok && master_exited &&
         worker_exit_eids.size() < enclaves.size() - 1) {
    struct keystone_group_wait_event event;
    std::memset(&event, 0, sizeof(event));
    Error wait_error = device.groupWaitEvent(
        group_id,
        KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_EXIT) |
            KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_OCALL) |
            KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_FAULT) |
            KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_WATCHDOG) |
            KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_HEARTBEAT),
        timeout_ms, &event);
    if (event.queue_overflows) {
      std::cerr << "[host] worker exit event queue overflow: " << label
                << " count=" << event.queue_overflows
                << " sequence=" << event.event_sequence << std::endl;
      ok = false;
      break;
    }
    if (wait_error == Error::EnclaveFatalFault ||
        event.event == KEYSTONE_GROUP_EVENT_FAULT ||
        event.event == KEYSTONE_GROUP_EVENT_WATCHDOG ||
        wait_error == Error::GroupIOError ||
        event.event == KEYSTONE_GROUP_EVENT_HEARTBEAT) {
      std::cerr << "[host] worker failed during exit drain: " << label
                << " error=" << error_name(wait_error)
                << " event=" << event.event << " hart=" << event.hart_id
                << " eid=" << event.eid << " value=" << event.value
                << std::endl;
      ok = false;
      break;
    }
    if (wait_error != Error::Success) {
      std::cerr << "[host] worker event failed during exit drain: " << label
                << " error=" << error_name(wait_error)
                << " event=" << event.event << " hart=" << event.hart_id
                << " eid=" << event.eid << " value=" << event.value
                << std::endl;
      ok = false;
      break;
    }
    if (event.event == KEYSTONE_GROUP_EVENT_OCALL) {
      if (!dispatch_and_resume_group_ocall(device, group_id, event.hart_id,
              event.eid, event.value, &enclaves,
              "3W_1HM-worker-exit-drain")) {
        ok = false;
        break;
      }
      continue;
    }
    if (event.event != KEYSTONE_GROUP_EVENT_EXIT ||
        !is_worker_eid(enclaves, event.eid) || event.value != 0) {
      std::cerr << "[host] worker did not exit cleanly: " << label
                << " error=" << error_name(wait_error)
                << " event=" << event.event << " eid=" << event.eid
                << " value=" << event.value << std::endl;
      ok = false;
      break;
    }
    if (std::find(worker_exit_eids.begin(), worker_exit_eids.end(),
                  event.eid) != worker_exit_eids.end()) {
      std::cerr << "[host] duplicate worker EXIT event: " << label
                << " eid=" << event.eid << std::endl;
      ok = false;
      break;
    }
    worker_exit_eids.push_back(event.eid);
  }

  Error release_error = device.groupReleaseWorkers(
      group_id, lease_flags, &lease);
  if (release_error != Error::Success) {
    std::cerr << "[host] worker lease release failed: " << label
              << " error=" << error_name(release_error) << std::endl;
    ok = false;
  }
  if (!master_exited) {
    std::cerr << "[host] master did not reach EXIT: " << label << std::endl;
    ok = false;
  }
  if (ok)
    std::cout << "[host] 3W_1HM run ok: " << label
              << " worker_exits=" << worker_exit_eids.size() << std::endl;
  return ok;
}

bool
run_group_hart_expect_fault(uint64_t group_id, uint64_t sm_hart_id, int cpu,
    const char* label, uint64_t expected_event_eid = 0) {
  uintptr_t retval = 0;
  uint64_t event_eid = 0;
  uint64_t event = KEYSTONE_GROUP_EVENT_NONE;
  Keystone::KeystoneDevice device;
  Params params;

  if (!pin_current_thread_to_cpu(cpu, label)) {
    return false;
  }
  if (!device.initDevice(params)) {
    std::cerr << "[host] failed to open keystone device for " << label
              << std::endl;
    return false;
  }

  Error err = group_run_hart_until_guest_event(device,
      group_id, sm_hart_id, &event_eid, &event, &retval);
  if (err == Error::EnclaveFatalFault &&
      event == KEYSTONE_GROUP_EVENT_FAULT &&
      event_eid != 0 &&
      (expected_event_eid == 0 || event_eid == expected_event_eid)) {
    std::cout << "[host] group run hart fault observed as expected: "
              << label << " eid=" << event_eid
              << " event=" << event
              << " retval=" << retval << std::endl;
    return true;
  }

  std::cerr << "[host] expected group hart fault: " << label
            << " error=" << error_name(err)
            << " event=" << event
            << " eid=" << event_eid
            << " expected_eid=" << expected_event_eid
            << " retval=" << retval << std::endl;
  return false;
}

bool
run_group_hart_expect_exit(uint64_t group_id, uint64_t sm_hart_id, int cpu,
    const char* label, uint64_t expected_event_eid) {
  uintptr_t retval = 0;
  uint64_t event_eid = 0;
  uint64_t event = KEYSTONE_GROUP_EVENT_NONE;
  Keystone::KeystoneDevice device;
  Params params;

  if (!pin_current_thread_to_cpu(cpu, label)) {
    return false;
  }
  if (!device.initDevice(params)) {
    std::cerr << "[host] failed to open keystone device for " << label
              << std::endl;
    return false;
  }

  Error err = group_run_hart_until_guest_event(device,
      group_id, sm_hart_id, &event_eid, &event, &retval);
  if (err == Error::Success &&
      event == KEYSTONE_GROUP_EVENT_EXIT &&
      event_eid == expected_event_eid &&
      retval == 0) {
    std::cout << "[host] group run hart exit observed: "
              << label << " eid=" << event_eid
              << " retval=" << retval << std::endl;
    return true;
  }

  std::cerr << "[host] expected group hart exit: " << label
            << " error=" << error_name(err)
            << " event=" << event
            << " eid=" << event_eid
            << " expected_eid=" << expected_event_eid
            << " retval=" << retval
            << " retval_reason=" << ocall_blocker_retval_name(retval)
            << std::endl;
  return false;
}

uint64_t
first_hart_in_mask(uint64_t mask) {
  for (uint64_t hart = 0; hart < 64; ++hart) {
    if (mask & (UINT64_C(1) << hart))
      return hart;
  }
  return UINT64_MAX;
}

bool
configure_groups(uint64_t group_count, const uint64_t* hart_counts,
                 const uint64_t* execution_modes) {
  Keystone::KeystoneDevice device;
  Params params;
  uint64_t hart_count = 0;
  uint64_t hart_mask = 0;
  uint64_t lifecycle_state = KEYSTONE_GROUP_STATE_FREE;
  uint64_t generation = 0;
  std::vector<uint64_t> created_groups;

  for (uint64_t group_id = 1; group_id <= kMaxEnabledGroups; ++group_id)
    configured_topology_valid[group_id] = false;

  if (!device.initDevice(params)) {
    std::cerr << "[host] failed to open keystone device for group config"
              << std::endl;
    return false;
  }

  if (device.groupSetCount(group_count) != Error::Success) {
    std::cerr << "[host] groupSetCount(" << group_count << ") failed"
              << std::endl;
    struct keystone_group_test_snapshot snapshot;
    if (take_resource_snapshot(0, &snapshot))
      print_resource_snapshot("group configuration blocked by residual state",
                              snapshot);
    return false;
  }

  for (uint64_t group_id = 1; group_id <= group_count; ++group_id) {
    if (device.groupCreate(group_id) != Error::Success) {
      std::cerr << "[host] groupCreate(group=" << group_id << ") failed"
                << std::endl;
      for (size_t i = created_groups.size(); i > 0; --i)
        device.groupDestroy(created_groups[i - 1]);
      return false;
    }
    created_groups.push_back(group_id);
    if (device.groupSetHartCount(group_id,
            hart_counts[group_id - 1]) != Error::Success) {
      std::cerr << "[host] groupSetHartCount(group=" << group_id
                << ",harts=" << hart_counts[group_id - 1] << ") failed"
                << std::endl;
      for (size_t i = created_groups.size(); i > 0; --i)
        device.groupDestroy(created_groups[i - 1]);
      return false;
    }

    uint64_t group_hart_count = 0;
    uint64_t group_hart_mask = 0;
    uint64_t group_generation = 0;
    if (device.groupQuery(group_id, nullptr, &group_hart_count,
            &group_hart_mask, nullptr, nullptr, nullptr,
            &group_generation) != Error::Success) {
      std::cerr << "[host] groupQuery before topology failed: group="
                << group_id << std::endl;
      for (size_t i = created_groups.size(); i > 0; --i)
        device.groupDestroy(created_groups[i - 1]);
      return false;
    }

    struct keystone_group_topology topology;
    std::memset(&topology, 0, sizeof(topology));
    KEYSTONE_ABI_INIT(&topology, KEYSTONE_GROUP_ABI_FEATURES);
    topology.group_id = group_id;
    topology.group_generation = group_generation;
    topology.execution_mode = execution_modes[group_id - 1];
    topology.configured_hart_mask = group_hart_mask;
    topology.cpu_hart_offset = kCpuHartOffset;
    topology.flags = KEYSTONE_GROUP_TOPOLOGY_FLAG_EXPLICIT_CPU_HART_MAP;
    if (topology.execution_mode == GROUP_MODE_3W_1HM) {
      topology.housekeeping_cpu = kHousekeepingCpu;
      topology.housekeeping_hart = kHousekeepingHart;
      topology.master_hart = kHousekeepingHart;
      topology.worker_hart_mask = KEYSTONE_VF2_WORKER_HART_MASK;
      topology.worker_count = 3;
      topology.flags |= KEYSTONE_GROUP_TOPOLOGY_FLAG_REQUIRE_ISOLATION;
    } else if (topology.execution_mode == GROUP_MODE_SATURATION_TEST) {
      topology.master_hart = first_hart_in_mask(group_hart_mask);
      if (topology.master_hart == UINT64_MAX ||
          topology.master_hart < topology.cpu_hart_offset) {
        std::cerr << "[host] invalid saturation topology mask: group="
                  << group_id << " mask=0x" << std::hex << group_hart_mask
                  << std::dec << std::endl;
        for (size_t i = created_groups.size(); i > 0; --i)
          device.groupDestroy(created_groups[i - 1]);
        return false;
      }
      topology.housekeeping_hart = topology.master_hart;
      topology.housekeeping_cpu =
          topology.housekeeping_hart - topology.cpu_hart_offset;
      topology.worker_hart_mask =
          group_hart_mask & ~(UINT64_C(1) << topology.master_hart);
      topology.worker_count = group_hart_count - 1;
    } else {
      std::cerr << "[host] unsupported execution mode: "
                << topology.execution_mode << std::endl;
      for (size_t i = created_groups.size(); i > 0; --i)
        device.groupDestroy(created_groups[i - 1]);
      return false;
    }

    if (device.groupConfigTopology(&topology) != Error::Success ||
        device.groupQueryTopology(group_id, &topology) != Error::Success ||
        topology.execution_mode != execution_modes[group_id - 1] ||
        topology.configured_hart_mask != group_hart_mask) {
      std::cerr << "[host] explicit topology configuration failed: group="
                << group_id << std::endl;
      for (size_t i = created_groups.size(); i > 0; --i)
        device.groupDestroy(created_groups[i - 1]);
      return false;
    }
    configured_topologies[group_id] = topology;
    configured_topology_valid[group_id] = true;
    std::cout << "[host] topology: group=" << group_id
              << " mode=" << topology.execution_mode
              << " housekeeping=cpu" << topology.housekeeping_cpu
              << "/hart" << topology.housekeeping_hart
              << " master_hart=" << topology.master_hart
              << " worker_harts=0x" << std::hex
              << topology.worker_hart_mask << std::dec
              << " worker_count=" << topology.worker_count
              << " cpu_hart_offset=" << topology.cpu_hart_offset
              << std::endl;
  }

  uint64_t queried_count = 0;
  if (device.groupQuery(kDefaultGroupId, &queried_count, &hart_count,
          &hart_mask, nullptr, nullptr, &lifecycle_state,
          &generation) != Error::Success) {
    std::cerr << "[host] groupQuery failed" << std::endl;
    for (size_t i = created_groups.size(); i > 0; --i)
      device.groupDestroy(created_groups[i - 1]);
    return false;
  }

  std::cout << "[host] group config: count=" << queried_count
            << " group=" << kDefaultGroupId
            << " hart_count=" << hart_count
            << " hart_mask=0x" << std::hex << hart_mask << std::dec
            << " state=" << lifecycle_state
            << " generation=" << generation
            << std::endl;

  if (queried_count != group_count || !generation ||
      lifecycle_state != KEYSTONE_GROUP_STATE_CONFIGURING) {
    for (size_t i = created_groups.size(); i > 0; --i)
      device.groupDestroy(created_groups[i - 1]);
    return false;
  }
  if (kDefaultGroupId <= kMaxEnabledGroups &&
      last_group_generation[kDefaultGroupId] == generation) {
    std::cerr << "[host] stale group generation reused: group="
              << kDefaultGroupId << " generation=" << generation << std::endl;
    for (size_t i = created_groups.size(); i > 0; --i)
      device.groupDestroy(created_groups[i - 1]);
    return false;
  }
  last_group_generation[kDefaultGroupId] = generation;
  return true;
}

bool
configure_groups(uint64_t group_count, const uint64_t* hart_counts) {
  uint64_t execution_modes[kMaxEnabledGroups] = {0};
  for (uint64_t i = 0; i < group_count; ++i)
    execution_modes[i] = GROUP_MODE_SATURATION_TEST;
  return configure_groups(group_count, hart_counts, execution_modes);
}

bool
configure_default_group() {
  uint64_t hart_counts[1] = {kDefaultGroupHartCount};
  uint64_t execution_modes[1] = {GROUP_MODE_3W_1HM};
  return configure_groups(1, hart_counts, execution_modes);
}

bool
configure_saturation_group() {
  uint64_t hart_counts[1] = {kDefaultGroupHartCount};
  uint64_t execution_modes[1] = {GROUP_MODE_SATURATION_TEST};
  return configure_groups(1, hart_counts, execution_modes);
}

void
destroy_instances(std::vector<EnclaveInstance>& enclaves) {
  if (security_scan_nonce() && !enclaves.empty()) security_scan_checkpoint();
  std::vector<uint64_t> groups;
  for (size_t i = 0; i < enclaves.size(); ++i) {
    uint64_t group_id = enclaves[i].spec.group_id;
    if (group_id && std::find(groups.begin(), groups.end(), group_id) == groups.end())
      groups.push_back(group_id);
  }
  Keystone::KeystoneDevice lifecycle_device;
  Params lifecycle_params;
  bool lifecycle_ready = lifecycle_device.initDevice(lifecycle_params);
  if (lifecycle_ready) {
    for (size_t i = 0; i < groups.size(); ++i) {
      Error err = lifecycle_device.groupDestroy(groups[i]);
      if (err != Error::Success)
        std::cerr << "[host] initial groupDestroy(group=" << groups[i]
                  << ") failed: " << error_name(err) << std::endl;
    }
  }
  for (size_t i = enclaves.size(); i > 0; --i) {
    if (i == enclaves.size() && std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR"))
      security_scan_checkpoint("quiesced-before-destroy");
    if (enclaves[i - 1].enclave) {
      if (security_scan_nonce()) {
        const uint8_t* base = static_cast<const uint8_t*>(enclaves[i - 1].enclave->getOcallBuffer());
        const size_t bytes = enclaves[i - 1].enclave->getOcallBufferSize();
        const size_t control = std::min<size_t>(bytes, GROUP_PMP_SQLITE_VFS_CONTROL_BYTES);
        if (base && control) security_region("remove", "control-utm", base, control);
        if (base && bytes > control) security_region("remove", "data-utm", base + control, bytes - control);
      }
      Error err = enclaves[i - 1].enclave->destroy();
      if (err != Error::Success)
        std::cerr << "[host] destroy failed: "
                  << enclaves[i - 1].spec.name << " error="
                  << error_name(err) << std::endl;
      enclaves[i - 1].enclave.reset();
    }
  }
  if (lifecycle_ready) {
    for (size_t i = 0; i < groups.size(); ++i) {
      Error err = lifecycle_device.groupDestroy(groups[i]);
      if (err != Error::Success)
        std::cerr << "[host] final groupDestroy(group=" << groups[i]
                  << ") failed: " << error_name(err) << std::endl;
    }
  }
  enclaves.clear();
  if (std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR")) security_scan_checkpoint("after-cleanup");
}

bool
init_all(std::vector<EnclaveInstance>& enclaves,
    const char* runtime, const char* loader) {
  for (size_t i = 0; i < enclaves.size(); ++i) {
    if (!init_instance(enclaves[i], runtime, loader)) {
      destroy_instances(enclaves);
      return false;
    }
  }
  return true;
}

bool
finalize_all(std::vector<EnclaveInstance>& enclaves) {
  for (size_t i = 0; i < enclaves.size(); ++i) {
    if (!finalize_instance(enclaves[i])) {
      destroy_instances(enclaves);
      return false;
    }
  }
  std::vector<uint64_t> groups;
  for (size_t i = 0; i < enclaves.size(); ++i) {
    uint64_t group_id = enclaves[i].spec.group_id;
    if (group_id && std::find(groups.begin(), groups.end(), group_id) == groups.end())
      groups.push_back(group_id);
  }
  Keystone::KeystoneDevice lifecycle_device;
  Params lifecycle_params;
  if (!lifecycle_device.initDevice(lifecycle_params)) {
    destroy_instances(enclaves);
    return false;
  }
  const char* test_mode = std::getenv("GROUP_PMP_TEST_MODE");
  const char* force_freeze_probe =
      std::getenv("GROUP_PMP_LIFECYCLE_FREEZE_PROBE");
  const bool throughput_mode = test_mode &&
      (std::strcmp(test_mode, "mixed-scale") == 0 ||
       std::strcmp(test_mode, "sqlite-bench") == 0);
  const bool run_freeze_probe = !throughput_mode ||
      (force_freeze_probe && std::strcmp(force_freeze_probe, "1") == 0);
  for (size_t i = 0; i < groups.size(); ++i) {
    if (lifecycle_device.groupActivate(groups[i]) != Error::Success) {
      std::cerr << "[host] groupActivate(group=" << groups[i] << ") failed"
                << std::endl;
      destroy_instances(enclaves);
      return false;
    }
    uint64_t state = KEYSTONE_GROUP_STATE_FREE;
    uint64_t generation = 0;
    if (lifecycle_device.groupQuery(groups[i], nullptr, nullptr, nullptr,
            nullptr, nullptr, &state, &generation) != Error::Success ||
        state != KEYSTONE_GROUP_STATE_ACTIVE || !generation) {
      std::cerr << "[host] lifecycle verification failed: group="
                << groups[i] << " state=" << state
                << " generation=" << generation << std::endl;
      destroy_instances(enclaves);
      return false;
    }
    if (!lifecycle_freeze_checked && run_freeze_probe) {
      uint64_t hart_count = 0;
      struct keystone_group_topology topology;
      std::memset(&topology, 0, sizeof(topology));
      lifecycle_device.groupQuery(groups[i], nullptr, &hart_count, nullptr);
      Error topology_query = lifecycle_device.groupQueryTopology(
          groups[i], &topology);
      Error create_error = lifecycle_device.groupCreate(groups[i]);
      Error hart_error = lifecycle_device.groupSetHartCount(
          groups[i], hart_count);
      Error topology_error = lifecycle_device.groupConfigTopology(&topology);
      if (create_error != Error::GroupBusy ||
          hart_error != Error::GroupBusy ||
          topology_query != Error::Success ||
          topology_error != Error::GroupBusy) {
        std::cerr << "[host] ACTIVE group error transport mismatch: create="
                  << error_name(create_error)
                  << " hart=" << error_name(hart_error)
                  << " query=" << error_name(topology_query)
                  << " topology=" << error_name(topology_error)
                  << std::endl;
        destroy_instances(enclaves);
        return false;
      }
      lifecycle_freeze_checked = true;
      std::cout << "[host] lifecycle freeze verified: group=" << groups[i]
                << " generation=" << generation << std::endl;
    }
  }
  return true;
}

bool
bind_and_enqueue(
    EnclaveInstance& instance, uint64_t hart_id,
    uint64_t priority = KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT,
    uint64_t quantum_ticks = KEYSTONE_GROUP_SCHED_QUANTUM_DEFAULT) {
  Keystone::KeystoneDevice device;
  Params params;

  if (!device.initDevice(params)) {
    std::cerr << "[host] failed to open keystone device for bind/enqueue"
              << std::endl;
    return false;
  }

  uint64_t eid = static_cast<uint64_t>(instance.enclave->getEid());
  if (device.groupBindEnclave(
          eid, hart_id, priority, quantum_ticks) != Error::Success) {
    std::cerr << "[host] groupBindEnclave failed: "
              << instance.spec.name << " eid=" << eid
               << " hart=" << hart_id
               << " priority=" << priority
               << " cfs_min_slice_multiplier=" << quantum_ticks << std::endl;
    return false;
  }
  if (device.groupEnqueueEnclave(eid) != Error::Success) {
    std::cerr << "[host] groupEnqueueEnclave failed: "
              << instance.spec.name << " eid=" << eid << std::endl;
    return false;
  }

  std::cout << "[host] bound/enqueued: " << instance.spec.name
            << " eid=" << eid << " hart=" << hart_id
            << " priority=" << priority
            << " scheduler=cfs-lite"
            << " cfs_min_slice_multiplier=" << quantum_ticks << std::endl;
  return true;
}

uint64_t
sm_hart_id_for_cpu(uint64_t cpu_index,
                   uint64_t group_id = kDefaultGroupId) {
  if (!group_id || group_id > kMaxEnabledGroups ||
      !configured_topology_valid[group_id]) {
    std::cerr << "[host] CPU/hart mapping requested before topology query: "
              << "group=" << group_id << " cpu=" << cpu_index << std::endl;
    return UINT64_MAX;
  }
  const struct keystone_group_topology& topology =
      configured_topologies[group_id];
  uint64_t hart = cpu_index + topology.cpu_hart_offset;
  if (!(topology.configured_hart_mask & (UINT64_C(1) << hart))) {
    std::cerr << "[host] CPU is outside configured topology: group="
              << group_id << " cpu=" << cpu_index << " hart=" << hart
              << " mask=0x" << std::hex << topology.configured_hart_mask
              << std::dec << std::endl;
    return UINT64_MAX;
  }
  return hart;
}

bool
expect_group_capacity_failure(
    const char* writer, const char* runtime, const char* loader,
    uint64_t group_id, uint64_t group_capacity, const char* label) {
  EnclaveInstance overflow = {
      {label, writer, group_id, group_capacity, kYxstmSize,
       kYxstmSize / KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT, kUtmSize,
       kFreeMemSize},
      nullptr};
  Params params = make_group_params(
      group_id, group_capacity, kYxstmSize,
      kYxstmSize / KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT, kUtmSize);
  overflow.enclave.reset(new Enclave());

  std::cout << "[host] expect failure: " << label << std::endl;
  Error err = overflow.enclave->initNoFinalize(writer, runtime, loader, params);
  if (err == Error::Success) {
    std::cerr << "[host] expected create failure unexpectedly initialized: "
              << label
              << std::endl;
    overflow.enclave->destroy();
    return false;
  }

  std::cout << "[host] create failed as expected: " << label << " "
            << error_name(err) << std::endl;
  return true;
}

void
add_instance(std::vector<EnclaveInstance>& enclaves,
    const char* name, const char* eapp,
    uint64_t group_id, uint64_t group_capacity,
    uint64_t yxstm_size = kYxstmSize, uint64_t utm_size = kUtmSize,
    uint64_t yxstm_slice_size = 0,
    uint64_t free_mem_size = kFreeMemSize) {
  if (yxstm_slice_size == 0)
    yxstm_slice_size =
        yxstm_size / KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
  EnclaveInstance instance = {
      {name, eapp, group_id, group_capacity, yxstm_size,
       yxstm_slice_size, utm_size, free_mem_size},
      std::unique_ptr<Enclave>()};
  enclaves.push_back(std::move(instance));
}

bool
run_scheduler_saturation_phase(const char* timeslice_a,
    const char* timeslice_b, const char* timeslice_check,
    const char* runtime, const char* loader) {
  std::cout << "[host] phase: scheduler 4-hart/8-enclave saturation"
            << std::endl;
  if (!configure_saturation_group()) {
    return false;
  }

  std::vector<EnclaveInstance> enclaves;
  const char* names_a[4] = {
      "timeslice-a-hart0", "timeslice-a-hart1",
      "timeslice-a-hart2", "timeslice-a-hart3"};
  const char* names_b[4] = {
      "timeslice-b-hart0", "timeslice-b-hart1",
      "timeslice-b-hart2", "timeslice-b-hart3"};
  for (uint64_t hart = 0; hart < 4; ++hart) {
    add_instance(enclaves, names_a[hart], timeslice_a,
        kDefaultGroupId, kDefaultGroupCapacity);
  }
  for (uint64_t hart = 0; hart < 4; ++hart) {
    add_instance(enclaves, names_b[hart], timeslice_b,
        kDefaultGroupId, kDefaultGroupCapacity);
  }
  const char* check_names[4] = {
      "timeslice-check-hart0", "timeslice-check-hart1",
      "timeslice-check-hart2", "timeslice-check-hart3"};
  for (uint64_t hart = 0; hart < 4; ++hart) {
    add_instance(enclaves, check_names[hart], timeslice_check,
        kDefaultGroupId, kDefaultGroupCapacity);
  }

  if (!init_instance(enclaves[0], runtime, loader)) {
    destroy_instances(enclaves);
    return false;
  }
  if (!expect_group_capacity_failure(
          timeslice_a, runtime, loader, kDefaultGroupId,
          kDefaultGroupCapacity + 1, "group 1 capacity mismatch")) {
    destroy_instances(enclaves);
    return false;
  }
  for (size_t i = 1; i < enclaves.size(); ++i) {
    if (!init_instance(enclaves[i], runtime, loader)) {
      destroy_instances(enclaves);
      return false;
    }
  }
  if (!expect_group_capacity_failure(
          timeslice_a, runtime, loader, kDefaultGroupId, kDefaultGroupCapacity,
          "group 1 capacity overflow")) {
    destroy_instances(enclaves);
    return false;
  }
  if (!finalize_all(enclaves)) {
    return false;
  }

  for (uint64_t hart = 0; hart < 4; ++hart) {
    uint64_t sm_hart = sm_hart_id_for_cpu(hart);
    if (!bind_and_enqueue(enclaves[hart], sm_hart,
                          KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT + 2, 2) ||
        !bind_and_enqueue(enclaves[4 + hart], sm_hart,
                          KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT, 1)) {
      destroy_instances(enclaves);
      return false;
    }
  }
  std::vector<uint64_t> sm_harts;
  std::vector<int> cpus;
  for (size_t hart = 0; hart < 4; ++hart) {
    sm_harts.push_back(sm_hart_id_for_cpu(hart));
    cpus.push_back(static_cast<int>(hart));
  }

  bool ok = run_group_harts_parallel(
      kDefaultGroupId, sm_harts, cpus, "timeslice saturation");
  std::vector<uint64_t> check_sm_harts;
  std::vector<int> check_cpus;
  for (size_t hart = 0; hart < 4; ++hart) {
    if (ok && !bind_and_enqueue(
                  enclaves[8 + hart], sm_hart_id_for_cpu(hart))) {
      ok = false;
      break;
    }
    check_sm_harts.push_back(sm_hart_id_for_cpu(hart));
    check_cpus.push_back(static_cast<int>(hart));
  }
  ok = ok && run_group_harts_parallel(
      kDefaultGroupId, check_sm_harts, check_cpus,
      "timeslice per-hart checks");
  destroy_instances(enclaves);
  struct keystone_group_test_snapshot cleanup;
  if (!take_resource_snapshot(0, &cleanup))
    return false;
  if (!group_resources_quiesced(cleanup)) {
    print_resource_snapshot("scheduler saturation cleanup incomplete", cleanup);
    return false;
  }
  return ok;
}

bool
run_production_lane_queue_phase(const char* master_eapp,
    const char* worker_eapp, const char* runtime, const char* loader) {
  constexpr uint64_t kWorkerMembers = 15;
  constexpr uint64_t kCapacity = 1 + kWorkerMembers;
  const char* worker_names[kWorkerMembers] = {
      "lane-worker-01", "lane-worker-02", "lane-worker-03",
      "lane-worker-04", "lane-worker-05", "lane-worker-06",
      "lane-worker-07", "lane-worker-08", "lane-worker-09",
      "lane-worker-10", "lane-worker-11", "lane-worker-12",
      "lane-worker-13", "lane-worker-14", "lane-worker-15"};

  std::cout << "[host] phase: 3W_1HM lane queue (five workers per lane)"
            << std::endl;
  if (!configure_default_group())
    return false;

  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, "lane-master", master_eapp,
      kDefaultGroupId, kCapacity);
  for (uint64_t worker = 0; worker < kWorkerMembers; ++worker) {
    add_instance(enclaves, worker_names[worker], worker_eapp,
        kDefaultGroupId, kCapacity);
  }

  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves))
    return false;

  bool ok = bind_and_enqueue(enclaves[0], sm_hart_id_for_cpu(0));
  for (size_t member = 1; ok && member < enclaves.size(); ++member) {
    uint64_t worker_cpu = 1 + ((member - 1) % 3);
    ok = bind_and_enqueue(enclaves[member],
                          sm_hart_id_for_cpu(worker_cpu));
  }
  if (ok)
    ok = run_group_3w1hm(kDefaultGroupId, enclaves,
                         "3W_1HM lane queue");

  if (ok) {
    struct keystone_group_test_snapshot snapshot;
    std::memset(&snapshot, 0, sizeof(snapshot));
    if (!take_resource_snapshot(kDefaultGroupId, &snapshot) ||
        snapshot.member_capacity != kCapacity ||
        snapshot.member_metadata_capacity != kCapacity ||
        snapshot.running_workers != 0 ||
        snapshot.max_running_workers > 3 ||
        snapshot.max_running_workers == 0 ||
        snapshot.master_non_boundary_entries != 0 ||
        snapshot.lane_owner_switches < kWorkerMembers - 3) {
      print_resource_snapshot("lane queue boundary verification failed",
                              snapshot);
      ok = false;
    } else {
      std::cout << "[P15][lane] capacity=" << snapshot.member_capacity
                << " max_running=" << snapshot.max_running_workers
                << " owner_switches=" << snapshot.lane_owner_switches
                << " scrubs=" << snapshot.lane_scrubs << std::endl;
    }
  }

  destroy_instances(enclaves);
  return ok;
}

bool
run_active_worker_lease_release_phase(const char* master_eapp,
    const char* worker_hold_eapp, const char* runtime, const char* loader) {
  constexpr uint64_t kCapacity = 4;
  const uint64_t observe_timeout_ms = env_u64(
      "GROUP_PMP_ACTIVE_RELEASE_OBSERVE_MS", 5000, 1, 60000);
  uint64_t lease_flags = KEYSTONE_GROUP_LEASE_FLAG_REQUIRE_ISOLATION |
      KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE |
      KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE;
  const char* fallback = std::getenv("GROUP_PMP_LEASE_TEST_FALLBACK");
  std::vector<EnclaveInstance> enclaves;
  Keystone::KeystoneDevice device;
  Params params;
  struct keystone_group_topology topology;
  struct keystone_group_lease lease;
  struct keystone_group_test_snapshot snapshot;
  bool leased = false;
  bool active_observed = false;
  bool ok = true;

  std::cout << "[host] phase: active worker lease release" << std::endl;
  if (!configure_default_group())
    return false;
  add_instance(enclaves, "lease-release-master", master_eapp,
      kDefaultGroupId, kCapacity);
  add_instance(enclaves, "lease-release-worker1", worker_hold_eapp,
      kDefaultGroupId, kCapacity);
  add_instance(enclaves, "lease-release-worker2", worker_hold_eapp,
      kDefaultGroupId, kCapacity);
  add_instance(enclaves, "lease-release-worker3", worker_hold_eapp,
      kDefaultGroupId, kCapacity);
  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves))
    return false;
  for (size_t member = 0; member < enclaves.size(); ++member) {
    if (!bind_and_enqueue(enclaves[member], sm_hart_id_for_cpu(member))) {
      destroy_instances(enclaves);
      return false;
    }
  }

  if (fallback && std::strcmp(fallback, "1") == 0) {
    lease_flags &= ~(KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE |
                     KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE);
    lease_flags |= KEYSTONE_GROUP_LEASE_FLAG_TEST_FALLBACK |
                   KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT;
  }
  std::memset(&topology, 0, sizeof(topology));
  std::memset(&lease, 0, sizeof(lease));
  if (!device.initDevice(params) ||
      device.groupQueryTopology(kDefaultGroupId, &topology) !=
          Error::Success ||
      device.groupLeaseWorkers(kDefaultGroupId, lease_flags, &lease) !=
          Error::Success) {
    std::cerr << "[host] could not start active lease release test"
              << std::endl;
    destroy_instances(enclaves);
    return false;
  }
  leased = true;

  const std::chrono::steady_clock::time_point observe_deadline =
      std::chrono::steady_clock::now() +
      std::chrono::milliseconds(observe_timeout_ms);
  do {
    if (!take_resource_snapshot(kDefaultGroupId, &snapshot)) {
      ok = false;
      break;
    }
    if (snapshot.active_harts >= topology.worker_count) {
      active_observed = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  } while (std::chrono::steady_clock::now() < observe_deadline);

  if (!active_observed) {
    std::cerr << "[host] worker harts never became active before lease release"
              << std::endl;
    ok = false;
  }

  const std::chrono::steady_clock::time_point release_start =
      std::chrono::steady_clock::now();
  Error release_error = device.groupReleaseWorkers(
      kDefaultGroupId, lease_flags, &lease);
  const uint64_t release_ms = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - release_start).count());
  if (release_error != Error::Success) {
    std::cerr << "[host] active worker lease release failed: error="
              << error_name(release_error)
              << " elapsed_ms=" << release_ms << std::endl;
    ok = false;
  } else {
    leased = false;
  }

  std::memset(&topology, 0, sizeof(topology));
  if (!leased &&
      (device.groupQueryTopology(kDefaultGroupId, &topology) !=
           Error::Success ||
       topology.lease_state != KEYSTONE_GROUP_LEASE_FREE ||
       !take_resource_snapshot(kDefaultGroupId, &snapshot) ||
       snapshot.active_harts != 0 ||
       snapshot.acquired_yxstm_harts != 0)) {
    std::cerr << "[host] active lease release left worker state installed"
              << std::endl;
    ok = false;
  }

  if (!leased) {
    for (size_t member = 0; member < enclaves.size(); ++member) {
      const uint64_t eid = static_cast<uint64_t>(
          enclaves[member].enclave->getEid());
      if (device.groupControlEnclave(
              eid, KEYSTONE_GROUP_CONTROL_CANCEL) != Error::Success) {
        std::cerr << "[host] failed to cancel lease-release member eid="
                  << eid << std::endl;
        ok = false;
      }
    }
  } else {
    (void)device.groupReleaseWorkers(kDefaultGroupId, lease_flags, &lease);
  }

  std::cout << "[host] active worker lease release "
            << (ok ? "ok" : "failed")
            << ": elapsed_ms=" << release_ms << std::endl;
  destroy_instances(enclaves);
  struct keystone_group_test_snapshot cleanup;
  std::memset(&cleanup, 0, sizeof(cleanup));
  if (!take_resource_snapshot(0, &cleanup) ||
      !group_resources_quiesced(cleanup)) {
    print_resource_snapshot("active lease release cleanup incomplete",
                            cleanup);
    ok = false;
  }
  return ok;
}

bool
run_private_epm_isolation_phase(const char* private_probe,
    const char* runtime, const char* loader) {
  std::cout << "[host] phase: private EPM slice isolation" << std::endl;
  if (!configure_default_group()) {
    return false;
  }

  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, "private-epm-probe", private_probe,
      kDefaultGroupId, 1);

  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    return false;
  }

  bool ok = pin_current_thread_to_cpu(0, "private-epm-probe") &&
      run_instance_expect_failure(enclaves[0]);
  destroy_instances(enclaves);
  return ok;
}

bool
run_cross_group_phase(const char* master_dispatch, const char* master_miss,
    const char* runtime, const char* loader) {
  std::cout << "[host] phase: cross-group resource isolation" << std::endl;
  uint64_t hart_counts[2] = {2, 2};
  if (!configure_groups(2, hart_counts)) {
    return false;
  }

  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, "g1-master-dispatch", master_dispatch, 1, 1);
  add_instance(enclaves, "g2-master-miss", master_miss, 2, 1);

  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    return false;
  }

  bool ok = true;
  ok = ok && pin_current_thread_to_cpu(0, "cross-group-g1");
  ok = ok && run_instance(enclaves[0], 0);
  ok = ok && pin_current_thread_to_cpu(2, "cross-group-g2");
  ok = ok && run_instance(enclaves[1], 0);
  destroy_instances(enclaves);
  return ok;
}

bool
run_yxstm_cross_schedule_phase(const char* hold_yield,
    const char* inherit_probe, const char* runtime, const char* loader) {
  std::cout << "[host] phase: YXSTM revoke across schedule-out" << std::endl;
  if (!configure_saturation_group()) {
    return false;
  }

  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, "yxstm-hold-yield", hold_yield,
      kDefaultGroupId, 2);
  add_instance(enclaves, "yxstm-inherit-probe", inherit_probe,
      kDefaultGroupId, 2);

  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    return false;
  }
  if (!bind_and_enqueue(enclaves[0], sm_hart_id_for_cpu(0)) ||
      !bind_and_enqueue(enclaves[1], sm_hart_id_for_cpu(0))) {
    destroy_instances(enclaves);
    return false;
  }

  bool ok = run_group_hart_expect_fault(kDefaultGroupId,
      sm_hart_id_for_cpu(0), 0, "yxstm-cross-schedule",
      static_cast<uint64_t>(enclaves[1].enclave->getEid()));
  destroy_instances(enclaves);
  return ok;
}

bool
run_ocall_block_phase(const char* ocall_blocker,
    const char* worker_placeholder, const char* master_peer,
    const char* runtime, const char* loader) {
  std::cout << "[host] phase: OCALL blocked member poll" << std::endl;
  if (!configure_saturation_group()) {
    return false;
  }

  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, "ocall-blocker-resume", ocall_blocker,
      kDefaultGroupId, 6);
  add_instance(enclaves, "ocall-worker1-placeholder", worker_placeholder,
      kDefaultGroupId, 6);
  add_instance(enclaves, "ocall-worker2-placeholder", worker_placeholder,
      kDefaultGroupId, 6);
  add_instance(enclaves, "ocall-worker3-placeholder", worker_placeholder,
      kDefaultGroupId, 6);
  add_instance(enclaves, "ocall-peer", master_peer,
      kDefaultGroupId, 6);
  add_instance(enclaves, "ocall-blocker-abandon", ocall_blocker,
      kDefaultGroupId, 6);

  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    return false;
  }
  if (!bind_and_enqueue(enclaves[0], sm_hart_id_for_cpu(0)) ||
      !bind_and_enqueue(enclaves[4], sm_hart_id_for_cpu(0)) ||
      !bind_and_enqueue(enclaves[5], sm_hart_id_for_cpu(0))) {
    destroy_instances(enclaves);
    return false;
  }

  Keystone::KeystoneDevice device;
  Params params;
  uint64_t pending_eid = 0;
  uint64_t pending_count = 0;
  uint64_t pending_ocall_id = 0;
  uint64_t pending_host_cookie = 0;
  uint64_t resumed_eid = 0;
  uint64_t abandoned_eid = 0;
  uint64_t resume_blocker_eid =
      static_cast<uint64_t>(enclaves[0].enclave->getEid());
  uint64_t abandon_blocker_eid =
      static_cast<uint64_t>(enclaves[5].enclave->getEid());
  uint64_t peer_eid = static_cast<uint64_t>(enclaves[4].enclave->getEid());

  bool ok = pin_current_thread_to_cpu(0, "ocall-blocked-lifecycle") &&
      device.initDevice(params);
  bool saw_resume_ocall = false;
  bool saw_abandon_ocall = false;
  bool saw_peer_exit = false;

  /*
   * The per-hart scheduler does not promise which runnable member produces
   * the first host-visible event.  Observe both sides of the lifecycle rather
   * than assuming that the blocker has issued its OCALL before peer EXIT.
   */
  for (unsigned int attempt = 0;
       ok && attempt < 8 &&
           (!saw_resume_ocall || !saw_abandon_ocall || !saw_peer_exit);
       ++attempt) {
    uintptr_t retval = 0;
    uint64_t event_eid = 0;
    uint64_t event = KEYSTONE_GROUP_EVENT_NONE;
    Error err = group_run_hart_until_guest_event(device,
        kDefaultGroupId, sm_hart_id_for_cpu(0),
        &event_eid, &event, &retval);

    if (err == Error::EdgeCallHost &&
        event == KEYSTONE_GROUP_EVENT_OCALL &&
        (event_eid == resume_blocker_eid ||
         event_eid == abandon_blocker_eid)) {
      if (event_eid == resume_blocker_eid)
        saw_resume_ocall = true;
      else
        saw_abandon_ocall = true;
      std::cout << "[host] group OCALL observed: blocker eid="
                << event_eid << std::endl;
      continue;
    }
    if (err == Error::Success &&
        event == KEYSTONE_GROUP_EVENT_EXIT &&
        event_eid == peer_eid && retval == 0) {
      saw_peer_exit = true;
      std::cout << "[host] group run hart exit observed: "
                << "ocall-peer-continues eid=" << event_eid
                << " retval=" << retval << std::endl;
      continue;
    }

    std::cerr << "[host] unexpected OCALL lifecycle event: error="
              << error_name(err) << " event=" << event
              << " eid=" << event_eid << " retval=" << retval
              << " saw_resume_ocall=" << saw_resume_ocall
              << " saw_abandon_ocall=" << saw_abandon_ocall
              << " saw_peer_exit=" << saw_peer_exit << std::endl;
    ok = false;
  }
  if (ok && (!saw_resume_ocall || !saw_abandon_ocall || !saw_peer_exit)) {
    std::cerr << "[host] incomplete OCALL lifecycle: saw_resume_ocall="
              << saw_resume_ocall
              << " saw_abandon_ocall=" << saw_abandon_ocall
              << " saw_peer_exit=" << saw_peer_exit << std::endl;
    ok = false;
  }

  if (ok && device.groupPollBlockedOcall(kDefaultGroupId,
          KEYSTONE_GROUP_OCALL_ANY_HART, &pending_eid,
          &pending_count, &pending_ocall_id, nullptr,
          &pending_host_cookie) == Error::Success) {
    std::cout << "[host] blocked ocall poll: eid=" << pending_eid
              << " count=" << pending_count
              << " ocall_id=" << pending_ocall_id << std::endl;
    ok = pending_count == 2 &&
         (pending_eid == resume_blocker_eid ||
          pending_eid == abandon_blocker_eid) &&
         pending_ocall_id != 0 && pending_host_cookie != 0;
  } else {
    ok = false;
  }

  if (ok) {
    if (register_call(1, group_pmp_ocall_ack) != 0) {
      std::cerr << "[host] failed to register OCALL ack handler" << std::endl;
      ok = false;
    }
  }

  if (ok) {
    const size_t resume_index =
        pending_eid == resume_blocker_eid ? 0 : 5;
    struct edge_call* edge_call =
        static_cast<struct edge_call*>(
            enclaves[resume_index].enclave->getOcallBuffer());
    edge_call_init_internals(
        reinterpret_cast<uintptr_t>(
            enclaves[resume_index].enclave->getOcallBuffer()),
        enclaves[resume_index].enclave->getOcallBufferSize());
    incoming_call_dispatch(enclaves[resume_index].enclave->getOcallBuffer());
    if (edge_call->return_data.call_status != CALL_STATUS_OK) {
      std::cerr << "[host] OCALL dispatch failed: status="
                << edge_call->return_data.call_status << std::endl;
      ok = false;
    }
  }

  if (ok) {
    resumed_eid = pending_eid;
    if (device.groupResumeBlockedOcall(kDefaultGroupId,
            sm_hart_id_for_cpu(0), resumed_eid,
            pending_ocall_id) != Error::Success) {
      std::cerr << "[host] groupResumeBlockedOcall failed: eid="
                << resumed_eid << std::endl;
      ok = false;
    }
  }

  pending_eid = 0;
  pending_count = 0;
  pending_ocall_id = 0;
  pending_host_cookie = 0;
  if (ok && device.groupPollBlockedOcall(kDefaultGroupId,
          KEYSTONE_GROUP_OCALL_ANY_HART, &pending_eid,
          &pending_count, &pending_ocall_id, nullptr,
          &pending_host_cookie) == Error::Success) {
    std::cout << "[host] blocked ocall after resume: eid=" << pending_eid
              << " count=" << pending_count << std::endl;
    abandoned_eid = pending_eid;
    ok = pending_count == 1 && abandoned_eid != resumed_eid &&
         (abandoned_eid == resume_blocker_eid ||
          abandoned_eid == abandon_blocker_eid) &&
         pending_ocall_id != 0 && pending_host_cookie != 0;
  } else if (ok) {
    ok = false;
  }

  if (ok && device.groupAbandonBlockedOcall(
          kDefaultGroupId, sm_hart_id_for_cpu(0), abandoned_eid,
          pending_ocall_id, pending_host_cookie) != Error::Success) {
    std::cerr << "[host] groupAbandonBlockedOcall failed: eid="
              << abandoned_eid << std::endl;
    ok = false;
  }

  pending_eid = 0;
  pending_count = 0;
  if (ok && device.groupPollBlockedOcall(kDefaultGroupId,
          KEYSTONE_GROUP_OCALL_ANY_HART, &pending_eid,
          &pending_count) == Error::Success) {
    std::cout << "[host] blocked ocall after abandon: eid=" << pending_eid
              << " count=" << pending_count << std::endl;
    ok = pending_count == 0;
  } else if (ok) {
    ok = false;
  }

  bool saw_resumed_exit = false;
  bool saw_abandoned_event = false;
  for (unsigned int attempt = 0;
       ok && attempt < 4 && (!saw_resumed_exit || !saw_abandoned_event);
       ++attempt) {
    uintptr_t retval = 0;
    uint64_t event_eid = 0;
    uint64_t event = KEYSTONE_GROUP_EVENT_NONE;
    Error err = group_run_hart_until_guest_event(
        device, kDefaultGroupId, sm_hart_id_for_cpu(0),
        &event_eid, &event, &retval);

    if (err == Error::GroupOcallAbandoned &&
        event == KEYSTONE_GROUP_EVENT_OCALL_ABANDONED &&
        event_eid == abandoned_eid) {
      saw_abandoned_event = true;
      continue;
    }
    if (err == Error::Success && event == KEYSTONE_GROUP_EVENT_EXIT &&
        event_eid == resumed_eid && retval == 0) {
      saw_resumed_exit = true;
      continue;
    }
    std::cerr << "[host] unexpected OCALL completion event: error="
              << error_name(err) << " event=" << event
              << " eid=" << event_eid << " retval=" << retval
              << std::endl;
    ok = false;
  }
  if (ok && (!saw_resumed_exit || !saw_abandoned_event)) {
    std::cerr << "[host] incomplete OCALL completion: resumed_exit="
              << saw_resumed_exit
              << " abandoned_event=" << saw_abandoned_event << std::endl;
    ok = false;
  }

  destroy_instances(enclaves);
  return ok;
}

bool
run_master_worker_pipeline_phase(const char* master_dispatch,
    const char* worker, const char* master_aggregate,
    const char* runtime, const char* loader,
    uint64_t injection_operation = KEYSTONE_GROUP_TEST_INJECT_NONE) {
  std::cout << "[host] phase: master-worker YXSTM pipeline" << std::endl;
  if (!configure_default_group()) {
    return false;
  }

  std::vector<EnclaveInstance> enclaves;
  (void)master_aggregate;
  add_instance(enclaves, "mw-master", master_dispatch,
      kDefaultGroupId, 4);
  add_instance(enclaves, "mw-worker1", worker,
      kDefaultGroupId, 4);
  add_instance(enclaves, "mw-worker2", worker,
      kDefaultGroupId, 4);
  add_instance(enclaves, "mw-worker3", worker,
      kDefaultGroupId, 4);

  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    return false;
  }

  bool ok = true;
  for (size_t i = 0; i < enclaves.size(); ++i) {
    uint64_t sm_hart = sm_hart_id_for_cpu(i);
    if (!bind_and_enqueue(enclaves[i], sm_hart)) {
      ok = false;
      break;
    }
  }
  if (ok && injection_operation != KEYSTONE_GROUP_TEST_INJECT_NONE) {
    Keystone::KeystoneDevice injection_device;
    Params injection_params;
    uint64_t injection_hart = injection_operation ==
        KEYSTONE_GROUP_TEST_INJECT_DROP_NEXT_IPI ? (uint64_t)-1 : 0;
    ok = injection_device.initDevice(injection_params) &&
        injection_device.groupTestInject(injection_operation,
            kDefaultGroupId, injection_hart, 1) == Error::Success;
  }
  if (ok)
    ok = run_group_3w1hm(
        kDefaultGroupId, enclaves, "master-worker protocol");

  destroy_instances(enclaves);
  return ok;
}

bool
run_worker_missing_injection_phase(const char* master_dispatch,
    const char* worker, const char* runtime, const char* loader) {
  std::vector<EnclaveInstance> enclaves;
  struct keystone_group_test_snapshot after;

  std::cout << "[host] phase: missing worker rollback injection"
            << std::endl;
  if (!configure_default_group())
    return false;
  add_instance(enclaves, "missing-master", master_dispatch,
      kDefaultGroupId, 4);
  add_instance(enclaves, "missing-worker1", worker,
      kDefaultGroupId, 4);
  add_instance(enclaves, "missing-worker2", worker,
      kDefaultGroupId, 4);
  add_instance(enclaves, "missing-worker3-not-enqueued", worker,
      kDefaultGroupId, 4);
  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    destroy_instances(enclaves);
    return false;
  }
  if (!bind_and_enqueue(enclaves[0], sm_hart_id_for_cpu(0)) ||
      !bind_and_enqueue(enclaves[1], sm_hart_id_for_cpu(1)) ||
      !bind_and_enqueue(enclaves[2], sm_hart_id_for_cpu(2))) {
    destroy_instances(enclaves);
    return false;
  }

  /* The master requests all three worker bits; lane3 is deliberately absent. */
  bool failed_as_expected = !run_group_3w1hm(
      kDefaultGroupId, enclaves, "missing-worker-injection");
  destroy_instances(enclaves);
  std::memset(&after, 0, sizeof(after));
  if (!failed_as_expected || !take_resource_snapshot(0, &after) ||
      !group_resources_quiesced(after)) {
    print_resource_snapshot("missing worker cleanup failed", after);
    return false;
  }
  std::cout << "[P15][fault] missing worker rejected and resources revoked"
            << std::endl;
  return true;
}

bool
run_single_worker_negative_phase(const char* master_dummy,
    const char* worker_probe, const char* runtime, const char* loader,
    const char* label, bool expect_fault) {
  std::cout << "[host] phase: " << label << std::endl;
  if (!configure_default_group()) {
    return false;
  }

  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, "negative-master-dummy", master_dummy,
      kDefaultGroupId, 2);
  add_instance(enclaves, label, worker_probe, kDefaultGroupId, 2);

  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    return false;
  }

  bool ok = pin_current_thread_to_cpu(1, label);
  if (ok) {
    ok = expect_fault ? run_instance_expect_failure(enclaves[1]) :
                        run_instance(enclaves[1], 0);
  }

  destroy_instances(enclaves);
  return ok;
}

bool
run_single_master_negative_phase(const char* master_probe,
    const char* runtime, const char* loader, const char* label,
    bool expect_fault) {
  std::cout << "[host] phase: " << label << std::endl;
  if (!configure_default_group()) {
    return false;
  }

  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, label, master_probe, kDefaultGroupId, 1);

  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    return false;
  }

  bool ok = pin_current_thread_to_cpu(0, label);
  if (ok) {
    ok = expect_fault ? run_instance_expect_failure(enclaves[0]) :
                        run_instance(enclaves[0], 0);
  }

  destroy_instances(enclaves);
  return ok;
}

bool
run_master_worker_schedule_revoke_phase(const char* master_dummy,
    const char* worker_dummy, const char* hold_yield,
    const char* inherit_fault, const char* runtime, const char* loader) {
  std::cout << "[host] phase: master-worker schedule-out revoke"
            << std::endl;
  if (!configure_saturation_group()) {
    return false;
  }

  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, "mw-sched-master0", master_dummy,
      kDefaultGroupId, 6);
  add_instance(enclaves, "mw-hold-yield", hold_yield,
      kDefaultGroupId, 6);
  add_instance(enclaves, "mw-worker2-dummy", worker_dummy,
      kDefaultGroupId, 6);
  add_instance(enclaves, "mw-worker3-dummy", worker_dummy,
      kDefaultGroupId, 6);
  add_instance(enclaves, "mw-sched-master1", master_dummy,
      kDefaultGroupId, 6);
  add_instance(enclaves, "mw-inherit-fault", inherit_fault,
      kDefaultGroupId, 6);

  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    return false;
  }

  if (!bind_and_enqueue(enclaves[1], sm_hart_id_for_cpu(1)) ||
      !bind_and_enqueue(enclaves[5], sm_hart_id_for_cpu(1))) {
    destroy_instances(enclaves);
    return false;
  }

  bool ok = run_group_hart_expect_fault(kDefaultGroupId,
      sm_hart_id_for_cpu(1), 1, "mw-schedule-out-revoke",
      static_cast<uint64_t>(enclaves[5].enclave->getEid()));
  destroy_instances(enclaves);
  return ok;
}

bool
run_master_worker_denied_fault_phase(const char* master_dispatch,
    const char* worker, const char* worker_dispatch_rw_denied,
    const char* worker_cross_slice_fault,
    const char* worker_slice0_fault,
    const char* master_aggregate_rw_denied,
    const char* no_acquire_fault,
    const char* release_fault,
    const char* hold_yield,
    const char* inherit_fault,
    const char* exec_fault,
    const char* runtime, const char* loader) {
  bool ok = true;

  ok = ok && run_single_worker_negative_phase(master_dispatch,
      worker_dispatch_rw_denied, runtime, loader,
      "worker dispatch RW denied", false);
  ok = ok && run_single_worker_negative_phase(master_dispatch,
      worker_cross_slice_fault, runtime, loader,
      "worker cross-slice fault", true);
  ok = ok && run_single_worker_negative_phase(master_dispatch,
      worker_slice0_fault, runtime, loader,
      "worker slice0 fault", true);
  ok = ok && run_single_master_negative_phase(master_aggregate_rw_denied,
      runtime, loader, "master aggregate RW denied", false);
  ok = ok && run_single_worker_negative_phase(master_dispatch,
      no_acquire_fault, runtime, loader, "access without acquire", true);

  /* These are retained as build artifacts for dedicated protocol fixtures. */
  (void)release_fault;
  (void)hold_yield;
  (void)inherit_fault;
  (void)exec_fault;
  (void)worker;

  return ok;
}

bool
run_non_old_semantics_regression_phase(const char* timeslice_a,
    const char* timeslice_b, const char* timeslice_check,
    const char* private_probe,
    const char* master_dispatch, const char* master_miss,
    const char* ocall_blocker, const char* worker_placeholder,
    const char* master_peer,
    const char* runtime, const char* loader) {
  bool ok = true;

  ok = ok && run_production_lane_queue_phase(
      timeslice_check, timeslice_b, runtime, loader);
  ok = ok && run_scheduler_saturation_phase(timeslice_a, timeslice_b,
      timeslice_check, runtime, loader);
  ok = ok && run_private_epm_isolation_phase(private_probe, runtime, loader);
  ok = ok && run_cross_group_phase(master_dispatch, master_miss,
      runtime, loader);
  ok = ok && run_ocall_block_phase(ocall_blocker, worker_placeholder,
      master_peer, runtime, loader);

  return ok;
}

bool
run_lifecycle_leak_stress(const char* eapp, const char* runtime,
                          const char* loader, uint64_t iterations) {
  struct keystone_group_test_snapshot baseline;
  struct keystone_group_test_snapshot after;
  const size_t baseline_vmas = process_vma_count();
  constexpr size_t kVmaGrowthTolerance = 16;
  std::cout << "[host] stress: lifecycle iterations=" << iterations
            << " baseline_vmas=" << baseline_vmas << std::endl;
  if (!take_resource_snapshot(0, &baseline))
    return false;

  for (uint64_t i = 0; i < iterations; ++i) {
    if (!configure_default_group())
      return false;
    std::vector<EnclaveInstance> enclaves;
    add_instance(enclaves, "lifecycle-stress", eapp,
                 kDefaultGroupId, 1);
    if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves))
      return false;
    if (!pin_current_thread_to_cpu(0, "lifecycle-stress") ||
        !run_instance(enclaves[0], 0)) {
      destroy_instances(enclaves);
      return false;
    }
    destroy_instances(enclaves);
    if (!take_resource_snapshot(0, &after) ||
        !same_reclaimable_resources(baseline, after, "lifecycle-stress"))
      return false;
    const size_t current_vmas = process_vma_count();
    if (baseline_vmas && current_vmas &&
        current_vmas > baseline_vmas + kVmaGrowthTolerance) {
      std::cerr << "[host] lifecycle userspace VMA leak: iteration="
                << (i + 1) << " baseline=" << baseline_vmas
                << " current=" << current_vmas << std::endl;
      return false;
    }
    if ((i + 1) % 100 == 0 || i + 1 == iterations)
      std::cout << "[host] lifecycle stress progress=" << (i + 1)
                << "/" << iterations << " vmas=" << current_vmas
                << std::endl;
  }
  return true;
}

bool
run_two_group_concurrency_stress(const char* eapp, const char* runtime,
                                 const char* loader, uint64_t rounds) {
  std::cout << "[host] stress: two-group concurrency rounds=" << rounds
            << std::endl;
  for (uint64_t round = 0; round < rounds; ++round) {
    struct keystone_group_test_snapshot baseline;
    struct keystone_group_test_snapshot after;
    if (!take_resource_snapshot(0, &baseline))
      return false;
    uint64_t hart_counts[2] = {2, 2};
    if (!configure_groups(2, hart_counts))
      return false;
    std::vector<EnclaveInstance> enclaves;
    add_instance(enclaves, "g1-concurrent-master", eapp, 1, 2);
    add_instance(enclaves, "g1-concurrent-worker", eapp, 1, 2);
    add_instance(enclaves, "g2-concurrent-master", eapp, 2, 2);
    add_instance(enclaves, "g2-concurrent-worker", eapp, 2, 2);
    if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves))
      return false;
    for (size_t i = 0; i < enclaves.size(); ++i) {
      if (!bind_and_enqueue(enclaves[i],
              sm_hart_id_for_cpu(i, enclaves[i].spec.group_id))) {
        destroy_instances(enclaves);
        return false;
      }
    }

    std::atomic<bool> g1_ok(false);
    std::atomic<bool> g2_ok(false);
    std::thread g1([&]() {
      g1_ok.store(run_group_harts_parallel(1, {sm_hart_id_for_cpu(0, 1),
          sm_hart_id_for_cpu(1, 1)}, {0, 1}, "two-group-g1"));
    });
    std::thread g2([&]() {
      g2_ok.store(run_group_harts_parallel(2, {sm_hart_id_for_cpu(2, 2),
          sm_hart_id_for_cpu(3, 2)}, {2, 3}, "two-group-g2"));
    });
    g1.join();
    g2.join();
    bool ok = g1_ok.load() && g2_ok.load();
    destroy_instances(enclaves);
    if (!ok || !take_resource_snapshot(0, &after) ||
        !same_reclaimable_resources(baseline, after, "two-group-stress"))
      return false;
  }
  return true;
}

bool
run_scheduler_long_stress(const char* timeslice_a, const char* timeslice_b,
                          const char* timeslice_check, const char* runtime,
                          const char* loader, uint64_t rounds) {
  std::cout << "[host] stress: 4-hart/8-enclave rounds=" << rounds
            << std::endl;
  for (uint64_t round = 0; round < rounds; ++round) {
    if (!run_scheduler_saturation_phase(timeslice_a, timeslice_b,
                                        timeslice_check, runtime, loader))
      return false;
  }
  return true;
}

bool
run_fault_cleanup_phase(const char* master_fault, const char* worker_fault,
                        const char* master_dummy, const char* runtime,
                        const char* loader) {
  struct keystone_group_test_snapshot baseline;
  struct keystone_group_test_snapshot after;
  if (!take_resource_snapshot(0, &baseline))
    return false;
  bool ok = run_single_master_negative_phase(master_fault, runtime, loader,
                                              "master fault cleanup", true);
  ok = ok && run_single_worker_negative_phase(master_dummy, worker_fault,
      runtime, loader, "worker fault cleanup", true);
  return ok && take_resource_snapshot(0, &after) &&
      same_reclaimable_resources(baseline, after, "fault-cleanup");
}

bool
run_yxstm_execute_fault_phase(const char* exec_fault, const char* worker,
                              const char* master_aggregate,
                              const char* runtime, const char* loader) {
  std::cout << "[host] phase: YXSTM NX execute fault" << std::endl;
  bool pipeline_failed = !run_master_worker_pipeline_phase(
      exec_fault, worker, master_aggregate, runtime, loader);
  if (!pipeline_failed)
    std::cerr << "[host] executable YXSTM was not rejected" << std::endl;
  return pipeline_failed;
}

bool
run_yxstm_release_fault_phase(const char* release_fault, const char* worker,
                              const char* master_aggregate,
                              const char* runtime, const char* loader) {
  std::cout << "[host] phase: YXSTM release revocation fault" << std::endl;
  bool pipeline_failed = !run_master_worker_pipeline_phase(
      release_fault, worker, master_aggregate, runtime, loader);
  if (!pipeline_failed)
    std::cerr << "[host] released YXSTM remained accessible" << std::endl;
  return pipeline_failed;
}

bool
run_ipi_injection_control_phase(const char* master_dispatch,
                                const char* worker,
                                const char* master_aggregate,
                                const char* runtime,
                                const char* loader) {
  const char* required = std::getenv("GROUP_PMP_REQUIRE_FAULT_INJECTION");
  Keystone::KeystoneDevice device;
  Params params;
  struct keystone_group_test_snapshot before;
  struct keystone_group_test_snapshot after;
  if (!required || std::strcmp(required, "1") != 0) {
    std::cout << "[host] SKIP IPI injection: set "
              << "GROUP_PMP_REQUIRE_FAULT_INJECTION=1 and build SM with "
              << "KEYSTONE_GROUP_TESTING=1" << std::endl;
    return true;
  }
  if (!device.initDevice(params) || !take_resource_snapshot(0, &before))
    return false;
  bool forced_timeout_failed = !run_master_worker_pipeline_phase(
      master_dispatch, worker, master_aggregate, runtime, loader,
      KEYSTONE_GROUP_TEST_INJECT_FORCE_IPI_TIMEOUT);
  if (device.groupTestInject(KEYSTONE_GROUP_TEST_INJECT_CLEAR,
          0, 0, 0) != Error::Success)
    return false;

  bool dropped_ack_failed = !run_master_worker_pipeline_phase(
      master_dispatch, worker, master_aggregate, runtime, loader,
      KEYSTONE_GROUP_TEST_INJECT_DROP_NEXT_IPI);
  if (device.groupTestInject(KEYSTONE_GROUP_TEST_INJECT_CLEAR,
          0, 0, 0) != Error::Success)
    return false;
  if (!take_resource_snapshot(0, &after))
    return false;
  if (!forced_timeout_failed || !dropped_ack_failed ||
      after.ipi_timeouts < before.ipi_timeouts + 2) {
    std::cerr << "[host] IPI fault injection was not observed: forced="
              << forced_timeout_failed << " dropped=" << dropped_ack_failed
              << " timeouts=" << before.ipi_timeouts << "->"
              << after.ipi_timeouts << std::endl;
    return false;
  }
  std::cout << "[host] IPI timeout/drop injection observed" << std::endl;
  return true;
}

bool
run_host_yxstm_access_denial(const char* eapp, const char* runtime,
                             const char* loader) {
  std::cout << "[host] kernel nofault probe of protected YXSTM"
            << std::endl;
  struct keystone_group_test_snapshot preflight;
  if (!take_resource_snapshot(0, &preflight))
    return false;
  if (!group_resources_quiesced(preflight)) {
    print_resource_snapshot("host-access probe refused residual group state",
                            preflight);
    std::cerr << "[host] host-access probe requires an isolated clean state"
              << std::endl;
    return false;
  }
  if (!configure_default_group())
    return false;
  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, "host-yxstm-probe", eapp, kDefaultGroupId, 1);
  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves))
    return false;
  if (!pin_current_thread_to_cpu(0, "host-yxstm-probe")) {
    destroy_instances(enclaves);
    return false;
  }
  uintptr_t retval = 0;
  Error err = enclaves[0].enclave->test_os_access_stm_run(&retval);
  bool denied = err == Error::Success &&
      retval == KEYSTONE_OS_ACCESS_RESULT_ALL_DENIED;
  if (denied) {
    std::cout << "[host] host YXSTM access denied: read=EFAULT write=EFAULT"
              << std::endl;
  } else {
    std::cerr << "[host] host YXSTM denial probe failed: error="
              << error_name(err) << " result=0x" << std::hex << retval
              << std::dec << " expected=0x" << std::hex
              << KEYSTONE_OS_ACCESS_RESULT_ALL_DENIED << std::dec
              << std::endl;
  }
  destroy_instances(enclaves);
  return denied;
}

struct SecurityAeadHost {
  uint8_t* utm = nullptr;
  size_t size = 0;
  uint64_t algorithm = 0, repetitions = 0, nonce = 0, phase = 0, reports = 0;
  bool configured = false, failed = false;
} security_aead_host;

void security_aead_ocall(void* buffer) {
  auto* edge = static_cast<struct edge_call*>(buffer);
  uintptr_t args = 0;
  size_t size = 0;
  struct security_aead_call call;
  struct security_aead_reply reply = {};
  reply.status = -1;
  if (edge_call_args_ptr(edge, &args, &size) || size != sizeof(call)) {
    edge->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  std::memcpy(&call, reinterpret_cast<const void*>(args), sizeof(call));
  SecurityAeadHost& host = security_aead_host;
  reply.algorithm = host.algorithm; reply.repetitions = host.repetitions; reply.nonce = host.nonce;
  if (!call.phase && !host.configured) {
    host.configured = true;
    reply.status = 0;
    std::cout << "[security-aead] stage=worker-entered algorithm=" << host.algorithm
              << " ocall=" << SECURITY_AEAD_OCALL << " attempts=" << host.repetitions
              << "; running enclave KATs then tamper scenarios" << std::endl;
  } else if (host.configured && call.algorithm == host.algorithm &&
             call.iteration == host.reports / SECURITY_AEAD_SCENARIOS &&
             call.scenario == host.reports % SECURITY_AEAD_SCENARIOS &&
             host.reports < host.repetitions * SECURITY_AEAD_SCENARIOS &&
             call.phase == host.phase + 1 &&
             host.size >= SECURITY_AEAD_UTM_OFFSET + 2 * sizeof(security_aead_packet)) {
    auto* packet = reinterpret_cast<security_aead_packet*>(host.utm + SECURITY_AEAD_UTM_OFFSET);
    if (call.phase == 1) {
      switch (call.scenario) {
        case 1: packet->ciphertext[13] ^= 1; break;
        case 2: packet->tag[7] ^= 1; break;
        case 3: packet->nonce[3] ^= 1; break;
        case 4: packet->aad[9] ^= 1; break;
        case 5: case 6: std::memcpy(packet, packet + 1, sizeof(*packet)); break;
        case 7: packet->ciphertext[127] ^= 1; break;
        default: break;
      }
    }
    if (call.phase == 2 && call.scenario == 8) packet->ciphertext[31] ^= 1;
    if (call.phase == 3) {
      const char* names[] = {"unaltered-control", "ciphertext-flip", "tag-flip",
          "nonce-flip", "aad-flip", "range-swap", "object-swap",
          "utm-before-snapshot", "utm-after-snapshot"};
      const bool expected = call.scenario == 0 || call.scenario == 8;
      const bool valid = call.expected_accept == expected && call.accepted == expected &&
          (expected ? call.valid_result == 1 && call.consumed_verified_snapshot == 1 :
                      call.output_changed == 0 && call.valid_result == 0);
      host.failed = host.failed || !valid;
      std::cout << "[security-aead] algorithm=" << host.algorithm
                << " scenario=" << names[call.scenario] << " attempt=" << call.iteration+1
                << " expected_accept=" << expected << " accepted=" << call.accepted
                << " output_changed=" << call.output_changed
                << " consumed_verified_snapshot=" << call.consumed_verified_snapshot
                << " valid_result=" << call.valid_result << " tsr_plaintext_result=not-exported"
                << " result=" << (valid ? "PASS" : "FAIL") << std::endl;
      ++host.reports;
      host.phase = 0;
    } else host.phase = call.phase;
    reply.status = 0;
  }
  uintptr_t ret = edge_call_data_ptr();
  std::memcpy(reinterpret_cast<void*>(ret), &reply, sizeof(reply));
  edge->return_data.call_status = edge_call_setup_ret(edge, reinterpret_cast<void*>(ret), sizeof(reply)) ?
      CALL_STATUS_BAD_PTR : CALL_STATUS_OK;
}

bool run_security_authorized_control(const char* master, const char* worker,
                                     const char* runtime, const char* loader);

struct SecurityGuestEvent {
  Error error = Error::DeviceError;
  uint64_t eid = 0;
  uint64_t event = KEYSTONE_GROUP_EVENT_NONE;
  uintptr_t retval = 0;
};

bool security_access_denied(const group_pmp_security_probe& record,
                            uint64_t operation, uint64_t state,
                            uint64_t expected_eid, const SecurityGuestEvent& terminal) {
  return record.magic == GROUP_PMP_SECURITY_PROBE_MAGIC && record.attempted == 1 &&
      record.target && record.operation == operation && record.permission_state == state &&
      terminal.eid == expected_eid &&
      ((terminal.error == Error::EnclaveFatalFault && terminal.event == KEYSTONE_GROUP_EVENT_FAULT) ||
       (terminal.error == Error::Success && terminal.event == KEYSTONE_GROUP_EVENT_EXIT &&
        terminal.retval == uintptr_t(-1)));
}

SecurityGuestEvent run_security_guest(std::vector<EnclaveInstance>& enclaves, size_t index) {
  SecurityGuestEvent terminal;
  Keystone::KeystoneDevice device;
  Params params;
  const uint64_t hart = sm_hart_id_for_cpu(index);
  if (!device.initDevice(params) || !bind_and_enqueue(enclaves[index], hart)) return terminal;
  const uint64_t expected_eid = enclaves[index].enclave->getEid();
  // Group events retain the guest EXIT value and UTM evidence. Enclave::run()
  // loses the group EXIT value and destroys the mapping on a fatal fault.
  do {
    terminal.error = group_run_hart_until_guest_event(device, kDefaultGroupId,
        hart, &terminal.eid, &terminal.event, &terminal.retval);
    if (terminal.eid != expected_eid) break;
    if (terminal.error != Error::EdgeCallHost || terminal.event != KEYSTONE_GROUP_EVENT_OCALL) break;
    if (!dispatch_and_resume_group_ocall(device, kDefaultGroupId, hart,
        terminal.eid, terminal.retval, &enclaves, "security-guest", true)) {
      terminal.error = Error::DeviceError;
      break;
    }
  } while (true);
  std::cout << "[security-event] eid=" << terminal.eid << " expected_eid=" << expected_eid
            << " event=" << terminal.event << " error=" << error_name(terminal.error)
            << " retval=" << terminal.retval << std::endl;
  return terminal;
}

bool security_aead_progress_snapshot(const void* buffer, size_t size,
                                    struct security_aead_progress* result) {
  if (!buffer || !result || size < SECURITY_AEAD_PROGRESS_OFFSET + sizeof(*result))
    return false;
  const uint8_t* source = static_cast<const uint8_t*>(buffer) + SECURITY_AEAD_PROGRESS_OFFSET;
  struct security_aead_progress first, second;
  // A live UTM snapshot is diagnostic only, never authentication evidence.
  for (unsigned attempt = 0; attempt < 3; ++attempt) {
    std::memcpy(&first, source, sizeof(first));
    std::atomic_thread_fence(std::memory_order_acquire);
    std::memcpy(&second, source, sizeof(second));
    if (std::memcmp(&first, &second, sizeof(first))) continue;
    if (first.magic != SECURITY_AEAD_PROGRESS_MAGIC ||
        first.stage < SECURITY_AEAD_CONFIG_SENT ||
        first.stage > SECURITY_AEAD_WORKER_FINISHED) return false;
    *result = first;
    return true;
  }
  return false;
}

const char* security_aead_stage_name(uint64_t stage) {
  switch (stage) {
    case SECURITY_AEAD_CONFIG_SENT: return "config-sent";
    case SECURITY_AEAD_CONFIG_RETURNED: return "config-returned";
    case SECURITY_AEAD_KAT_STARTED: return "kat-started";
    case SECURITY_AEAD_KAT_FINISHED: return "kat-finished";
    case SECURITY_AEAD_SCENARIO_STARTED: return "scenario-started";
    case SECURITY_AEAD_SNAPSHOT_READY: return "snapshot-ready";
    case SECURITY_AEAD_MUTATION_RETURNED: return "mutation-returned";
    case SECURITY_AEAD_OPEN_FINISHED: return "open-finished";
    case SECURITY_AEAD_REPORT_RETURNED: return "report-returned";
    case SECURITY_AEAD_WORKER_FINISHED: return "worker-finished";
    default: return "unavailable";
  }
}

bool security_aead_ocall_identity_valid(uint64_t resume_token,
                                        const void* buffer, size_t size) {
  if (!resume_token || !buffer || size < sizeof(struct edge_call)) return false;
  struct edge_call header;
  std::memcpy(&header, buffer, sizeof(header));
  // Group event.value is an opaque SM transaction token, not edge.call_id.
  // Only the UTM edge header selects the SDK handler; resume keeps the token.
  return header.call_id == SECURITY_AEAD_OCALL;
}

SecurityGuestEvent run_security_aead_worker(std::vector<EnclaveInstance>& enclaves,
                                           size_t index) {
  SecurityGuestEvent terminal;
  Keystone::KeystoneDevice device;
  Params params;
  const uint64_t hart = sm_hart_id_for_cpu(index);
  if (!pin_current_thread_to_cpu(kHousekeepingCpu, "security-aead-host") ||
      !device.initDevice(params) || !bind_and_enqueue(enclaves[index], hart))
    return terminal;
  const uint64_t expected_eid = enclaves[index].enclave->getEid();
  const uint64_t flags = KEYSTONE_GROUP_LEASE_FLAG_REQUIRE_ISOLATION |
      KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE | KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE;
  struct keystone_group_lease lease = {};
  Error lease_error = device.groupLeaseWorkers(kDefaultGroupId, flags, &lease);
  if (lease_error != Error::Success) {
    std::cerr << "[security-aead] lease failed: " << error_name(lease_error) << std::endl;
    return terminal;
  }
  std::cout << "[security-aead] stage=lease-active host_cpu=0 worker_hart=" << hart
            << " eid=" << expected_eid << " timeout_seconds=120" << std::endl;
  const uint64_t mask = KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_OCALL) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_EXIT) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_FAULT) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_WATCHDOG) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_HEARTBEAT);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
  // Long crypto fixtures must not occupy an online Linux CPU in groupRunHart.
  // The production lease runs the worker remotely; CPU0 only handles events.
  try {
    while (!stop_requested && std::chrono::steady_clock::now() < deadline) {
      struct keystone_group_wait_event event = {};
      const Error error = device.groupWaitEvent(kDefaultGroupId, mask, 1000, &event);
      if (error == Error::GroupEventTimeout) continue;
      terminal.error = error;
      terminal.eid = event.eid;
      terminal.event = event.event;
      terminal.retval = event.value;
      if (error != Error::Success || event.queue_overflows ||
          event.eid != expected_eid || event.hart_id != hart) {
        if (error == Error::Success) terminal.error = Error::DeviceError;
        std::cerr << "[security-aead] unexpected event=" << event.event
                  << " hart=" << event.hart_id << " eid=" << event.eid
                  << " error=" << event.error << " overflows=" << event.queue_overflows
                  << std::endl;
        break;
      }
      if (event.event == KEYSTONE_GROUP_EVENT_EXIT) break;
      if (event.event != KEYSTONE_GROUP_EVENT_OCALL ||
          !security_aead_ocall_identity_valid(event.value,
              enclaves[index].enclave->getOcallBuffer(),
              enclaves[index].enclave->getOcallBufferSize()) ||
          !dispatch_and_resume_group_ocall(device, kDefaultGroupId, hart,
              event.eid, event.value, &enclaves, "security-aead", true)) {
        terminal.error = Error::DeviceError;
        std::cerr << "[security-aead] rejected OCALL envelope/dispatch; resume_token="
                  << event.value << std::endl;
        break;
      }
      std::cout << "[security-aead] stage=ocall-resume-issued token=" << event.value
                << " protocol_phase=" << security_aead_host.phase
                << " reports=" << security_aead_host.reports << std::endl;
    }
    if (terminal.event != KEYSTONE_GROUP_EVENT_EXIT &&
        (stop_requested || std::chrono::steady_clock::now() >= deadline)) {
      terminal.error = Error::DeviceError;
      std::cerr << "[security-aead] interrupted or timed out before worker exit" << std::endl;
    }
  } catch (const std::exception& error) {
    terminal.error = Error::DeviceError;
    std::cerr << "[security-aead] exception=" << error.what() << std::endl;
  } catch (...) {
    terminal.error = Error::DeviceError;
    std::cerr << "[security-aead] unknown exception" << std::endl;
  }
  struct security_aead_progress progress = {};
  const bool sampled = security_aead_progress_snapshot(
      enclaves[index].enclave->getOcallBuffer(),
      enclaves[index].enclave->getOcallBufferSize(), &progress);
  std::cout << "[security-aead] progress_snapshot=best-effort valid=" << sampled
            << " worker_stage=" << security_aead_stage_name(progress.stage)
            << " algorithm=" << progress.algorithm << " iteration=" << progress.iteration
            << " scenario=" << progress.scenario << " protocol_phase=" << security_aead_host.phase
            << " reports=" << security_aead_host.reports << std::endl;
  const Error release_error = device.groupReleaseWorkers(kDefaultGroupId, flags, &lease);
  if (release_error != Error::Success) terminal.error = Error::DeviceError;
  std::cout << "[security-event] eid=" << terminal.eid << " expected_eid=" << expected_eid
            << " event=" << terminal.event << " error=" << error_name(terminal.error)
            << " retval=" << terminal.retval << " release=" << error_name(release_error)
            << std::endl;
  return terminal;
}

bool run_security_case(const std::string& name, const char* dummy,
                       const char* master, const char* worker,
                       const char* runtime, const char* loader) {
  if (name == "authorized-control")
    return run_security_authorized_control(master, worker, runtime, loader);
  const bool host_probe = name == "host-epm" || name == "host-tsr";
  const bool aead = name == "aead-gcm" || name == "aead-chacha";
  if (name == "host-epm") {
    std::ifstream capability("/sys/module/keystone_driver/parameters/security_nofault_epm");
    std::string value;
    if (!(capability >> value) || (value != "Y" && value != "1")) {
      std::cerr << "[security] refusing historical destructive EPM ioctl; reload nofault driver" << std::endl;
      return false;
    }
  }
  if (!host_probe && !aead && name != "epm-read" && name != "epm-write" &&
      name != "tsr-unacquired-read" && name != "tsr-unacquired-write" &&
      name != "tsr-cross-read" && name != "tsr-cross-write" &&
      name != "tsr-revoked-read" && name != "tsr-revoked-write") {
    std::cerr << "[security] unknown case=" << name << std::endl;
    return false;
  }
  // Immediate fault probes retain their tested entrance. Long AEAD computation
  // uses the existing production worker lease, never an online Linux CPU.
  if (!((host_probe || aead) ? configure_default_group() : configure_saturation_group())) return false;
  std::vector<EnclaveInstance> enclaves;
  const bool probe_master = host_probe || name.find("tsr-revoked") == 0;
  std::string eapp = aead ? "group-pmp-security-aead.eapp_riscv" :
                            "group-pmp-security-" + name + ".eapp_riscv";
  for (size_t i = 0; i < 4; ++i)
    add_instance(enclaves, i == (probe_master ? 0U : 1U) ? "security-probe" : "security-peer",
        host_probe || i != (probe_master ? 0U : 1U) ? dummy : eapp.c_str(), kDefaultGroupId, 4,
        kYxstmSize, kUtmSize, kYxstmSize / KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT,
        aead ? UINT64_C(4) * 1024 * 1024 : kFreeMemSize);
  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    destroy_instances(enclaves);
    return false;
  }
  const size_t index = probe_master ? 0 : 1;
  bool ok = pin_current_thread_to_cpu(aead ? kHousekeepingCpu : static_cast<int>(index), "security-probe");
  uintptr_t retval = 0;
  if (ok && host_probe) {
    const Error err = name == "host-epm" ? enclaves[0].enclave->test_os_access_epm_run(&retval) :
                                         enclaves[0].enclave->test_os_access_stm_run(&retval);
    ok = err == Error::Success && retval == KEYSTONE_OS_ACCESS_RESULT_ALL_DENIED;
    std::cout << "[security-isolation] actor=Host target=" << name
              << " read_write_mask=" << retval << " error=" << error_name(err)
              << " result=" << (ok ? "PASS" : "FAIL") << std::endl;
  } else if (ok && aead) {
    security_aead_host = SecurityAeadHost();
    security_aead_host.utm = static_cast<uint8_t*>(enclaves[index].enclave->getOcallBuffer());
    security_aead_host.size = enclaves[index].enclave->getOcallBufferSize();
    security_aead_host.algorithm = name == "aead-gcm" ? SECURITY_AEAD_GCM : SECURITY_AEAD_CHACHA;
    security_aead_host.repetitions = env_u64("GROUP_PMP_SECURITY_ATTEMPTS", 3, 1, 1000);
    security_aead_host.nonce = env_u64("GROUP_PMP_SECURITY_AEAD_NONCE", 1, 1, UINT64_MAX);
    ok = register_call(SECURITY_AEAD_OCALL, security_aead_ocall) == 0;
    if (!ok)
      std::cerr << "[security-aead] OCALL registration failed: id="
                << SECURITY_AEAD_OCALL << " table_slots=" << MAX_EDGE_CALL << std::endl;
    if (ok) {
      const SecurityGuestEvent terminal = run_security_aead_worker(enclaves, index);
      ok = terminal.error == Error::Success && terminal.event == KEYSTONE_GROUP_EVENT_EXIT &&
          terminal.eid == static_cast<uint64_t>(enclaves[index].enclave->getEid()) && terminal.retval == 0;
    }
    ok = ok && !security_aead_host.failed && security_aead_host.reports ==
         security_aead_host.repetitions * SECURITY_AEAD_SCENARIOS;
  } else if (ok) {
    const SecurityGuestEvent terminal = run_security_guest(enclaves, index);
    struct group_pmp_security_probe record = {};
    const uint8_t* utm = static_cast<uint8_t*>(enclaves[index].enclave->getOcallBuffer());
    if (utm && enclaves[index].enclave->getOcallBufferSize() >=
        GROUP_PMP_SECURITY_PROBE_OFFSET + sizeof(record))
      std::memcpy(&record, utm + GROUP_PMP_SECURITY_PROBE_OFFSET, sizeof(record));
    const uint64_t operation = name.find("write") != std::string::npos ? 2 : 1;
    const uint64_t state = name.find("tsr-revoked") == 0 ? 2 : (name.find("epm") == 0 ? 0 : 1);
    ok = security_access_denied(record, operation, state,
        enclaves[index].enclave->getEid(), terminal);
    std::cout << "[security-isolation] actor=" << (probe_master ? "Master-after-release" : "unauthorized-Worker")
              << " eid=" << enclaves[index].enclave->getEid() << " case=" << name
              << " target=0x" << std::hex << record.target << std::dec
              << " permission_state=" << record.permission_state << " attempted=" << record.attempted
              << " error=" << error_name(terminal.error) << " event=" << terminal.event
              << " retval=" << terminal.retval
              << " result=" << (ok ? "PASS" : "FAIL") << std::endl;
  }
  destroy_instances(enclaves);
  return ok;
}

bool
reset_group_perf_counters(void) {
  Keystone::KeystoneDevice device;
  Params params;
  struct keystone_group_perf_snapshot snapshot;
  std::memset(&snapshot, 0, sizeof(snapshot));
  return device.initDevice(params) &&
      device.groupPerfQuery(0, KEYSTONE_GROUP_PERF_RESET,
                            &snapshot) == Error::Success;
}

bool
query_group_perf_counters(struct keystone_group_perf_snapshot* snapshot) {
  Keystone::KeystoneDevice device;
  Params params;
  std::memset(snapshot, 0, sizeof(*snapshot));
  return device.initDevice(params) &&
      device.groupPerfQuery(0, KEYSTONE_GROUP_PERF_QUERY,
                            snapshot) == Error::Success;
}

bool
run_host_copy_benchmark(void) {
  uint64_t iterations = env_u64("GROUP_PMP_PERF_ITERS", 8, 1, 1024);
  std::vector<uint8_t> src(kPerfBatchBytes);
  std::vector<uint8_t> dst(kPerfBatchBytes);
  uint64_t checksum = 0;

  for (uint64_t i = 0; i < kPerfBatchBytes; ++i)
    src[i] = static_cast<uint8_t>((i * 131ULL + 0x5aULL) & 0xffU);

  auto start = std::chrono::steady_clock::now();
  for (uint64_t iter = 0; iter < iterations; ++iter) {
    std::memcpy(dst.data(), src.data(), src.size());
    for (size_t i = 0; i < dst.size(); i += 4096)
      checksum = checksum * 131ULL + dst[i];
    checksum = checksum * 131ULL + dst.back();
  }
  auto elapsed = std::chrono::steady_clock::now() - start;
  double seconds =
      std::chrono::duration_cast<std::chrono::duration<double>>(elapsed).count();
  double mb_per_sec = seconds > 0.0 ?
      (static_cast<double>(src.size()) * iterations / kDecimalMbBytes) /
          seconds :
      0.0;

  std::cout << "[P10][path] path=host-copy data_mb="
            << (static_cast<double>(kPerfBatchBytes) / kDecimalMbBytes)
            << " iterations=" << iterations
            << " seconds=" << seconds
            << " mb_per_sec=" << mb_per_sec
            << " checksum=" << checksum << std::endl;
  return true;
}

void
prepare_utm_shared_buffer(EnclaveInstance& instance) {
  uint8_t* buffer =
      static_cast<uint8_t*>(instance.enclave->getSharedBuffer());
  size_t size = instance.enclave->getSharedBufferSize();
  if (buffer == nullptr || size <= kPerfUtmOffset)
    return;
  size_t fill = std::min<size_t>(
      kPerfUtmChunkBytes, size - kPerfUtmOffset);
  for (size_t i = 0; i < fill; ++i)
    buffer[kPerfUtmOffset + i] =
        static_cast<uint8_t>((i * 131ULL + 0x5aULL) & 0xffU);
}

bool
run_utm_copy_benchmark_phase(const char* utm_bench,
                             const char* runtime, const char* loader) {
  std::cout << "[host] phase: p10 utm copy benchmark" << std::endl;
  if (!configure_default_group())
    return false;

  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, "p10-utm-bench", utm_bench, kDefaultGroupId, 1);
  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves))
    return false;

  prepare_utm_shared_buffer(enclaves[0]);
  bool ok = pin_current_thread_to_cpu(0, "p10-utm-bench") &&
      run_instance(enclaves[0], 0);
  destroy_instances(enclaves);
  return ok;
}

struct AesFairMetrics {
  double seconds_median;
  double seconds_p95;
  double cycles_per_byte_median;
  double cycles_per_byte_p95;
  double mb_per_sec_median;
  double mb_per_sec_p05;
  double mb_per_sec_p95;
  double effective_cycle_hz;
  uint64_t checksum;
};

struct AesPathDiagnosticSummary {
  bool valid;
  double stream_cycles_per_byte;
  double hot_cycles_per_byte;
  double read_mb_per_sec;
  double write_mb_per_sec;
};

AesPathDiagnosticSummary g_epm_aes_path = {false, 0.0, 0.0, 0.0, 0.0};

uint64_t
aes_fair_checksum(const uint8_t* data, size_t length) {
  uint64_t value = UINT64_C(1469598103934665603);

  for (size_t index = 0; index < length; ++index) {
    value ^= data[index];
    value *= UINT64_C(1099511628211);
  }
  return value;
}

void
aes_fair_fill_plaintext(uint8_t* data, size_t length) {
  for (size_t index = 0; index < length; ++index)
    data[index] = static_cast<uint8_t>(
        ((static_cast<uint64_t>(index) * UINT64_C(131)) +
         UINT64_C(0x5a)) & UINT64_C(0xff));
}

bool
run_native_aes_fair_baseline(AesFairMetrics* metrics) {
  static const uint8_t key[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  };
  static const uint8_t known_plaintext[16] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  };
  static const uint8_t known_ciphertext[16] = {
      0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
      0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  };
  void* input_storage = nullptr;
  void* output_storage = nullptr;
  std::unique_ptr<uint8_t, decltype(&std::free)> input(nullptr, &std::free);
  std::unique_ptr<uint8_t, decltype(&std::free)> output(nullptr, &std::free);
  std::vector<double> seconds;
  std::vector<double> cycles_per_byte;
  std::vector<double> mb_per_sec;
  std::vector<double> cycle_hz;
  uint8_t known_output[sizeof(known_ciphertext)];
  void* aes;

  if (!metrics || !pin_current_thread_to_cpu(1, "aes-native-fair") ||
      posix_memalign(&input_storage, GROUP_PMP_AES_BASELINE_PAGE_SIZE,
                     GROUP_PMP_AES_BASELINE_BYTES) != 0 ||
      posix_memalign(&output_storage, GROUP_PMP_AES_BASELINE_PAGE_SIZE,
                     GROUP_PMP_AES_BASELINE_BYTES) != 0) {
    std::free(input_storage);
    std::free(output_storage);
    return false;
  }
  input.reset(static_cast<uint8_t*>(input_storage));
  output.reset(static_cast<uint8_t*>(output_storage));
  std::memset(metrics, 0, sizeof(*metrics));
  aes_fair_fill_plaintext(input.get(), GROUP_PMP_AES_BASELINE_BYTES);
  aes = aes_encrypt_init(key, sizeof(key));
  if (!aes)
    return false;
  aes_encrypt(aes, known_plaintext, known_output);
  if (std::memcmp(known_output, known_ciphertext,
                  sizeof(known_ciphertext)) != 0) {
    aes_encrypt_deinit(aes);
    return false;
  }

  for (uint64_t warmup = 0; warmup < GROUP_PMP_AES_BASELINE_WARMUP;
       ++warmup)
    aes_encrypt_blocks(aes, input.get(), output.get(),
                       GROUP_PMP_AES_BASELINE_BYTES / 16);

  for (uint64_t sample = 0; sample < GROUP_PMP_AES_BASELINE_SAMPLES;
       ++sample) {
    std::chrono::steady_clock::time_point start_time =
        std::chrono::steady_clock::now();
    uint64_t start_cycle = host_rdcycle();
    aes_encrypt_blocks(aes, input.get(), output.get(),
                       GROUP_PMP_AES_BASELINE_BYTES / 16);
    uint64_t elapsed_cycles = host_rdcycle() - start_cycle;
    double elapsed_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start_time).count();

    if (elapsed_cycles == 0 || elapsed_seconds <= 0.0) {
      aes_encrypt_deinit(aes);
      return false;
    }
    seconds.push_back(elapsed_seconds);
    cycles_per_byte.push_back(
        static_cast<double>(elapsed_cycles) /
        GROUP_PMP_AES_BASELINE_BYTES);
    mb_per_sec.push_back(
        (GROUP_PMP_AES_BASELINE_BYTES / kDecimalMbBytes) /
        elapsed_seconds);
    cycle_hz.push_back(
        static_cast<double>(elapsed_cycles) / elapsed_seconds);
  }

  metrics->seconds_median = nearest_rank_percentile(seconds, 50);
  metrics->seconds_p95 = nearest_rank_percentile(seconds, 95);
  metrics->cycles_per_byte_median =
      nearest_rank_percentile(cycles_per_byte, 50);
  metrics->cycles_per_byte_p95 =
      nearest_rank_percentile(cycles_per_byte, 95);
  metrics->mb_per_sec_median = nearest_rank_percentile(mb_per_sec, 50);
  metrics->mb_per_sec_p05 = nearest_rank_percentile(mb_per_sec, 5);
  metrics->mb_per_sec_p95 = nearest_rank_percentile(mb_per_sec, 95);
  metrics->effective_cycle_hz = nearest_rank_percentile(cycle_hz, 50);
  metrics->checksum =
      aes_fair_checksum(output.get(), GROUP_PMP_AES_BASELINE_BYTES);
  aes_encrypt_deinit(aes);

  std::cout << "[AES-FAIR] environment=native backend=software "
               "operation=encrypt cpu=1 data_mb="
            << (GROUP_PMP_AES_BASELINE_BYTES / kDecimalMbBytes)
            << " samples=" << GROUP_PMP_AES_BASELINE_SAMPLES
            << " warmup=" << GROUP_PMP_AES_BASELINE_WARMUP
            << " seconds_median=" << metrics->seconds_median
            << " seconds_p95=" << metrics->seconds_p95
            << " cycles_per_byte_median="
            << metrics->cycles_per_byte_median
            << " cycles_per_byte_p95=" << metrics->cycles_per_byte_p95
            << " mb_per_sec_median=" << metrics->mb_per_sec_median
            << " mb_per_sec_p05=" << metrics->mb_per_sec_p05
            << " mb_per_sec_p95=" << metrics->mb_per_sec_p95
            << " effective_cycle_hz=" << metrics->effective_cycle_hz
            << " source=aes_core.c"
            << " opt=-O3"
            << " march=" << GROUP_PMP_AES_MARCH_STRING
            << " mabi=" << GROUP_PMP_AES_MABI_STRING
            << " input_alignment="
            << (reinterpret_cast<uintptr_t>(input.get()) &
                (GROUP_PMP_AES_BASELINE_PAGE_SIZE - 1))
            << " output_alignment="
            << (reinterpret_cast<uintptr_t>(output.get()) &
                (GROUP_PMP_AES_BASELINE_PAGE_SIZE - 1))
            << " checksum=" << metrics->checksum
            << " verify=PASS" << std::endl;
  return true;
}

bool
run_aes_enclave_fair_baseline(const char* eapp, const char* runtime,
                              const char* loader,
                              const AesFairMetrics& native_metrics) {
  std::vector<EnclaveInstance> enclaves;
  struct group_pmp_aes_baseline_result result;
  struct keystone_group_perf_snapshot perf;
  std::vector<double> seconds;
  std::vector<double> cycles_per_byte;
  std::vector<double> mb_per_sec;
  const uint64_t timebase_hz = riscv_timebase_hz();
  bool ok;

  g_epm_aes_path = {false, 0.0, 0.0, 0.0, 0.0};

  if (!pin_current_thread_to_cpu(0, "aes-fair-host") ||
      !configure_default_group() || !reset_group_perf_counters())
    return false;

  /*
   * The first member determines the group EPM slice size. Use the same eapp
   * and free-memory reserve for the holder so both members receive an equal
   * slice. The eapp owns two 8 MB demand-paged BSS buffers; the normal 1 MB
   * reserve is therefore intentionally insufficient for this diagnostic.
   */
  add_instance(enclaves, "aes-baseline-master-holder", eapp,
               kDefaultGroupId, 2, kScaleYxstmSize, kUtmSize, 0,
               kAesBaselineFreeMemSize);
  add_instance(enclaves, "aes-baseline-worker", eapp,
               kDefaultGroupId, 2, kScaleYxstmSize, kUtmSize, 0,
               kAesBaselineFreeMemSize);
  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    destroy_instances(enclaves);
    return false;
  }

  ok = pin_current_thread_to_cpu(1, "aes-enclave-fair") &&
      run_instance(enclaves[1], 0);
  std::memset(&result, 0, sizeof(result));
  std::memset(&perf, 0, sizeof(perf));
  if (ok) {
    uint8_t* utm = static_cast<uint8_t*>(
        enclaves[1].enclave->getSharedBuffer());
    size_t utm_size = enclaves[1].enclave->getSharedBufferSize();
    if (!utm ||
        utm_size < GROUP_PMP_AES_BASELINE_RESULT_OFFSET + sizeof(result)) {
      ok = false;
    } else {
      std::memcpy(&result,
                  utm + GROUP_PMP_AES_BASELINE_RESULT_OFFSET,
                  sizeof(result));
    }
  }
  if (ok && !query_group_perf_counters(&perf))
    ok = false;
  destroy_instances(enclaves);

  if (!ok || result.magic != GROUP_PMP_AES_BASELINE_MAGIC ||
      result.version != GROUP_PMP_AES_BASELINE_VERSION ||
      result.status != 1 ||
      result.bytes != GROUP_PMP_AES_BASELINE_BYTES ||
      result.samples != GROUP_PMP_AES_BASELINE_SAMPLES ||
      result.warmup != GROUP_PMP_AES_BASELINE_WARMUP ||
      result.known_answer_ok != 1 ||
      result.build_tag != GROUP_PMP_AES_BUILD_TAG ||
      result.input_alignment != 0 || result.output_alignment != 0 ||
      result.hidden_copy_bytes != 0 ||
      result.checksum != native_metrics.checksum ||
      timebase_hz == 0) {
    std::cerr << "[AES-FAIR] enclave result validation failed"
              << " status=" << result.status
              << " checksum=" << result.checksum
              << " expected_checksum=" << native_metrics.checksum
              << std::endl;
    return false;
  }

  for (uint64_t sample = 0; sample < result.samples; ++sample) {
    double sample_seconds =
        static_cast<double>(result.sample_time_ticks[sample]) /
        static_cast<double>(timebase_hz);
    if (result.sample_cycles[sample] == 0 ||
        result.sample_time_ticks[sample] == 0 || sample_seconds <= 0.0)
      return false;
    seconds.push_back(sample_seconds);
    cycles_per_byte.push_back(
        static_cast<double>(result.sample_cycles[sample]) / result.bytes);
    mb_per_sec.push_back(
        (result.bytes / kDecimalMbBytes) / sample_seconds);
  }

  double seconds_median = nearest_rank_percentile(seconds, 50);
  double seconds_p95 = nearest_rank_percentile(seconds, 95);
  double cycles_per_byte_median =
      nearest_rank_percentile(cycles_per_byte, 50);
  double cycles_per_byte_p95 =
      nearest_rank_percentile(cycles_per_byte, 95);
  double mb_per_sec_median = nearest_rank_percentile(mb_per_sec, 50);
  double mb_per_sec_p05 = nearest_rank_percentile(mb_per_sec, 5);
  double mb_per_sec_p95 = nearest_rank_percentile(mb_per_sec, 95);
  double native_ratio =
      mb_per_sec_median / native_metrics.mb_per_sec_median;

  std::cout << "[AES-FAIR] environment=enclave backend=software "
               "operation=encrypt cpu=1 sm_hart=2 data_mb="
            << (result.bytes / kDecimalMbBytes)
            << " samples=" << result.samples
            << " warmup=" << result.warmup
            << " seconds_median=" << seconds_median
            << " seconds_p95=" << seconds_p95
            << " cycles_per_byte_median=" << cycles_per_byte_median
            << " cycles_per_byte_p95=" << cycles_per_byte_p95
            << " mb_per_sec_median=" << mb_per_sec_median
            << " mb_per_sec_p05=" << mb_per_sec_p05
            << " mb_per_sec_p95=" << mb_per_sec_p95
            << " timebase_hz=" << timebase_hz
            << " source=aes_core.c"
            << " opt=-O3"
            << " march=" << GROUP_PMP_AES_MARCH_STRING
            << " mabi=" << GROUP_PMP_AES_MABI_STRING
            << " input_alignment=" << result.input_alignment
            << " output_alignment=" << result.output_alignment
            << " hidden_copy_bytes=" << result.hidden_copy_bytes
            << " checksum=" << result.checksum
            << " verify=PASS" << std::endl;
  std::cout << "[AES-FAIR] comparison native_mb_per_sec="
            << native_metrics.mb_per_sec_median
            << " enclave_mb_per_sec=" << mb_per_sec_median
            << " enclave_vs_native=" << native_ratio
            << " slowdown_percent=" << (1.0 - native_ratio) * 100.0
            << " context_switches=" << perf.context_switch_count
            << " host_services=" << perf.host_service_count
            << " pmp_updates=" << perf.pmp_update_count
            << std::endl;

  struct DiagnosticSeries {
    const char* name;
    const uint64_t* cycles;
    const uint64_t* ticks;
    double logical_bytes;
  };
  const DiagnosticSeries series[] = {
      {"aes-hot-block", result.hot_block_cycles,
       result.hot_block_time_ticks, static_cast<double>(result.bytes)},
      {"epm-read", result.epm_read_cycles, result.epm_read_time_ticks,
       static_cast<double>(result.bytes)},
      {"epm-write", result.epm_write_cycles, result.epm_write_time_ticks,
       static_cast<double>(result.bytes)},
      {"epm-copy", result.epm_copy_cycles, result.epm_copy_time_ticks,
       static_cast<double>(result.bytes)},
      {"digest", result.digest_cycles, result.digest_time_ticks,
       static_cast<double>(result.bytes)},
  };
  for (size_t metric = 0; metric < sizeof(series) / sizeof(series[0]);
       ++metric) {
    std::vector<double> metric_seconds;
    std::vector<double> metric_cycles_per_byte;
    std::vector<double> metric_mb_per_sec;

    for (uint64_t sample = 0; sample < result.samples; ++sample) {
      if (!series[metric].cycles[sample] ||
          !series[metric].ticks[sample])
        return false;
      double elapsed =
          static_cast<double>(series[metric].ticks[sample]) /
          static_cast<double>(timebase_hz);
      metric_seconds.push_back(elapsed);
      metric_cycles_per_byte.push_back(
          static_cast<double>(series[metric].cycles[sample]) /
          series[metric].logical_bytes);
      metric_mb_per_sec.push_back(
          (series[metric].logical_bytes / kDecimalMbBytes) / elapsed);
    }
    std::cout << "[AES-DIAG] memory=EPM phase=" << series[metric].name
              << " data_mb="
              << (series[metric].logical_bytes / kDecimalMbBytes)
              << " samples=" << result.samples
              << " seconds_median="
              << nearest_rank_percentile(metric_seconds, 50)
              << " cycles_per_byte_median="
              << nearest_rank_percentile(metric_cycles_per_byte, 50)
              << " mb_per_sec_median="
              << nearest_rank_percentile(metric_mb_per_sec, 50)
              << " mb_per_sec_p05="
              << nearest_rank_percentile(metric_mb_per_sec, 5)
              << std::endl;
    if (std::strcmp(series[metric].name, "aes-hot-block") == 0)
      g_epm_aes_path.hot_cycles_per_byte =
          nearest_rank_percentile(metric_cycles_per_byte, 50);
    else if (std::strcmp(series[metric].name, "epm-read") == 0)
      g_epm_aes_path.read_mb_per_sec =
          nearest_rank_percentile(metric_mb_per_sec, 50);
    else if (std::strcmp(series[metric].name, "epm-write") == 0)
      g_epm_aes_path.write_mb_per_sec =
          nearest_rank_percentile(metric_mb_per_sec, 50);
  }
  g_epm_aes_path.stream_cycles_per_byte = cycles_per_byte_median;
  g_epm_aes_path.valid = g_epm_aes_path.hot_cycles_per_byte > 0.0 &&
      g_epm_aes_path.read_mb_per_sec > 0.0 &&
      g_epm_aes_path.write_mb_per_sec > 0.0;
  std::cout << "[AES-DIAG] mapping=EPM"
            << " cache=platform-default-no-pbmt"
            << " source=runtime-map-physical-memory"
            << " input_alignment=" << result.input_alignment
            << " output_alignment=" << result.output_alignment
            << " hidden_copy_bytes=" << result.hidden_copy_bytes
            << std::endl;

  {
    std::vector<double> cycles_per_access;
    std::vector<double> ns_per_access;
    if (!result.epm_page_stride_accesses)
      return false;
    for (uint64_t sample = 0; sample < result.samples; ++sample) {
      cycles_per_access.push_back(
          static_cast<double>(result.epm_page_stride_cycles[sample]) /
          result.epm_page_stride_accesses);
      ns_per_access.push_back(
          (static_cast<double>(result.epm_page_stride_time_ticks[sample]) /
           static_cast<double>(timebase_hz)) * 1.0e9 /
          result.epm_page_stride_accesses);
    }
    std::cout << "[AES-DIAG] memory=EPM phase=page-stride"
              << " page_bytes=" << GROUP_PMP_AES_BASELINE_PAGE_SIZE
              << " accesses_per_sample=" << result.epm_page_stride_accesses
              << " cycles_per_access_median="
              << nearest_rank_percentile(cycles_per_access, 50)
              << " ns_per_access_median="
              << nearest_rank_percentile(ns_per_access, 50)
              << " hardware_tlb_miss_counter=unavailable"
              << " proxy=page-stride-latency"
              << std::endl;
  }
  return true;
}

bool
run_aes_fair_comparison_phase(const char* eapp, const char* runtime,
                              const char* loader) {
  AesFairMetrics native_metrics;

  std::cout << "[host] phase: native versus enclave pure AES baseline"
            << std::endl;
  if (!run_native_aes_fair_baseline(&native_metrics))
    return false;
  return run_aes_enclave_fair_baseline(
      eapp, runtime, loader, native_metrics);
}

uint64_t
p10_expected_digest(const std::vector<uint8_t>& expected,
                    uint64_t offset, uint64_t length) {
  uint64_t digest = 0;

  for (uint64_t base = 0; base < length; base += 16) {
    uint64_t low;
    uint64_t high;
    std::memcpy(&low, &expected[offset + base], sizeof(low));
    std::memcpy(&high, &expected[offset + base + sizeof(low)], sizeof(high));
    digest ^= low + UINT64_C(0x9e3779b97f4a7c15) +
              (digest << 6) + (digest >> 2);
    digest = (digest << 17) | (digest >> (64 - 17));
    digest ^= high;
  }
  return digest;
}

bool
prepare_p10_aes_utm(uint8_t* utm, size_t utm_size, uint64_t operation) {
  struct group_pmp_bench_expected_table* table;
  std::vector<uint8_t> expected(kPerfBatchBytes);
  uint8_t* prepared;
  void* encrypt_ctx;
  uint64_t record_count = 0;

  if (utm == nullptr ||
      utm_size < kPerfUtmOffset + kPerfBatchBytes ||
      utm_size < kPerfExpectedOffset + sizeof(*table) ||
      (operation != kPerfAesEncrypt && operation != kPerfAesDecrypt))
    return false;

  encrypt_ctx = aes_encrypt_init(kPerfAesKey, sizeof(kPerfAesKey));
  if (encrypt_ctx == nullptr)
    return false;

  prepared = utm + kPerfUtmOffset;
  for (uint64_t base = 0; base < kPerfBatchBytes; base += 16) {
    uint8_t plain[16];
    uint8_t encrypted[16];
    for (uint64_t i = 0; i < sizeof(plain); ++i)
      plain[i] = static_cast<uint8_t>(
          ((base + i) * 131ULL + 0x5aULL) & 0xffU);
    aes_encrypt(encrypt_ctx, plain, encrypted);
    if (operation == kPerfAesEncrypt) {
      std::memcpy(prepared + base, plain, sizeof(plain));
      std::memcpy(&expected[base], encrypted, sizeof(encrypted));
    } else {
      std::memcpy(prepared + base, encrypted, sizeof(encrypted));
      std::memcpy(&expected[base], plain, sizeof(plain));
    }
  }
  aes_encrypt_deinit(encrypt_ctx);

  table = reinterpret_cast<struct group_pmp_bench_expected_table*>(
      utm + kPerfExpectedOffset);
  std::memset(table, 0, sizeof(*table));
  table->magic = GROUP_PMP_BENCH_EXPECTED_MAGIC;
  table->version = GROUP_PMP_BENCH_VERSION;
  table->operation = operation;

  for (uint64_t worker_count = 1; worker_count <= 3; ++worker_count) {
    uint64_t total_offset = 0;
    uint64_t round = 0;

    while (total_offset < kPerfBatchBytes) {
      uint64_t remaining = kPerfBatchBytes - total_offset;
      uint64_t dispatched = 0;
      round++;

      for (uint64_t slice = 1; slice <= worker_count; ++slice) {
        uint64_t length = std::min<uint64_t>(remaining,
                                             kPerfPayloadCapacity);
        struct group_pmp_bench_expected_record* record;

        if (record_count >= GROUP_PMP_BENCH_EXPECTED_MAX_RECORDS)
          return false;
        record = &table->records[record_count++];
        record->operation = operation;
        record->worker_count = worker_count;
        record->round = round;
        record->slice_id = slice;
        record->global_offset = total_offset + dispatched;
        record->data_length = length;
        record->checksum = p10_expected_digest(
            expected, record->global_offset, length);
        dispatched += length;
        remaining -= length;
      }
      if (dispatched == 0)
        return false;
      total_offset += dispatched;
    }
  }
  table->record_count = record_count;
  return true;
}

bool
run_aes_benchmark_phase(const char* label, const char* master_eapp,
                        const char* worker_eapp,
                        const char* runtime, const char* loader,
                        uint64_t operation) {
  std::cout << "[host] phase: " << label << std::endl;
  if (!configure_default_group())
    return false;

  std::vector<EnclaveInstance> enclaves;
  add_instance(enclaves, "p10-master", master_eapp, kDefaultGroupId, 4,
      kPerfYxstmSize, kPerfUtmSize, kPerfYxstmSliceSize);
  add_instance(enclaves, "p10-worker1", worker_eapp, kDefaultGroupId, 4,
      kPerfYxstmSize, kUtmSize, kPerfYxstmSliceSize);
  add_instance(enclaves, "p10-worker2", worker_eapp, kDefaultGroupId, 4,
      kPerfYxstmSize, kUtmSize, kPerfYxstmSliceSize);
  add_instance(enclaves, "p10-worker3", worker_eapp, kDefaultGroupId, 4,
      kPerfYxstmSize, kUtmSize, kPerfYxstmSliceSize);

  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves))
    return false;

  uint8_t* input = static_cast<uint8_t*>(
      enclaves[0].enclave->getSharedBuffer());
  size_t input_size = enclaves[0].enclave->getSharedBufferSize();
  if (!prepare_p10_aes_utm(input, input_size, operation)) {
    std::cerr << "[host] failed to prepare P10 AES input/oracle: utm_size="
              << input_size << " operation=" << operation << std::endl;
    destroy_instances(enclaves);
    return false;
  }
  const struct group_pmp_bench_expected_table* expected_table =
      reinterpret_cast<const struct group_pmp_bench_expected_table*>(
          input + kPerfExpectedOffset);
  std::cout << "[host] P10 AES prepared: bench_version="
            << GROUP_PMP_BENCH_VERSION
            << " utm_mb="
            << (static_cast<double>(input_size) / kDecimalMbBytes)
            << " oracle_records=" << expected_table->record_count
            << " cooperative_service="
            << GROUP_PMP_AES_COOPERATIVE_SERVICE
#if GROUP_PMP_AES_COOPERATIVE_SERVICE
            << " cooperative_chunk_mb="
            << (static_cast<double>(GROUP_PMP_BENCH_COMPUTE_SERVICE_BYTES) /
                kDecimalMbBytes)
#endif
            << std::endl;

  bool ok = true;
  for (uint64_t cpu = 0; cpu < enclaves.size(); ++cpu) {
    if (!bind_and_enqueue(enclaves[cpu], sm_hart_id_for_cpu(cpu))) {
      ok = false;
      break;
    }
  }
  if (ok) {
    ok = run_group_3w1hm(kDefaultGroupId, enclaves, label);
  }

  destroy_instances(enclaves);
  return ok;
}

#define GROUP_PMP_SCALE_WORKER_NAMES \
  "scale-worker-01", "scale-worker-02", "scale-worker-03", \
  "scale-worker-04", "scale-worker-05", "scale-worker-06", \
  "scale-worker-07", "scale-worker-08", "scale-worker-09", \
  "scale-worker-10"

constexpr uint64_t kScalePerEnclaveBytes = UINT64_C(8) * 1000000;
constexpr uint64_t kScaleHeterogeneousLargeBytes =
    UINT64_C(16) * 1000000;
constexpr uint64_t kScaleHeterogeneousSmallBytes =
    UINT64_C(4) * 1000000;

struct ScaleWorkload {
  const char* profile;
  uint64_t worker_count;
  uint64_t active_lanes;
  uint64_t total_bytes;
  uint64_t lane[GROUP_PMP_SCALE_MAX_WORKERS];
  uint64_t lane_depth[GROUP_PMP_SCALE_LANES];
  uint64_t lane_rank[GROUP_PMP_SCALE_MAX_WORKERS];
  uint64_t assigned_bytes[GROUP_PMP_SCALE_MAX_WORKERS];
  bool require_timer_preemption;
};

struct ScaleRunMetrics {
  double seconds;
  double mb_per_sec;
  uint64_t total_bytes;
  uint64_t worker_wall_cycles;
};

struct ScaleRunObservation {
  ScaleRunObservation()
      : stop(false), invalid(false), final_sample_only(false) {
    std::memset(started, 0, sizeof(started));
    std::memset(completed, 0, sizeof(completed));
    std::memset(first_completion_seen, 0, sizeof(first_completion_seen));
    std::memset(started_before_first_completion, 0,
                sizeof(started_before_first_completion));
  }

  std::atomic<bool> stop;
  bool started[GROUP_PMP_SCALE_MAX_WORKERS];
  bool completed[GROUP_PMP_SCALE_MAX_WORKERS];
  bool first_completion_seen[GROUP_PMP_SCALE_LANES];
  uint64_t started_before_first_completion[GROUP_PMP_SCALE_LANES];
  bool invalid;
  bool final_sample_only;
};

bool
build_scale_workload(const char* profile, uint64_t worker_count,
                     ScaleWorkload* workload) {
  uint64_t next_rank[GROUP_PMP_SCALE_LANES] = {0, 0, 0};

  if (profile == nullptr || workload == nullptr ||
      worker_count < GROUP_PMP_SCALE_MIN_WORKERS ||
      worker_count > GROUP_PMP_SCALE_MAX_WORKERS)
    return false;
  std::memset(workload, 0, sizeof(*workload));
  workload->profile = profile;
  workload->worker_count = worker_count;
  workload->active_lanes =
      std::min<uint64_t>(worker_count, GROUP_PMP_SCALE_LANES);
  for (uint64_t worker = 0; worker < worker_count; ++worker) {
    workload->lane[worker] = worker % workload->active_lanes;
    workload->lane_depth[workload->lane[worker]]++;
  }
  for (uint64_t worker = 0; worker < worker_count; ++worker) {
    uint64_t lane = workload->lane[worker];
    workload->lane_rank[worker] = next_rank[lane]++;
  }

  if (std::strcmp(profile, "fixed-total") == 0) {
    if (GROUP_PMP_SCALE_TOTAL_BYTES % workload->active_lanes != 0)
      return false;
    for (uint64_t worker = 0; worker < worker_count; ++worker) {
      uint64_t lane = workload->lane[worker];
      uint64_t lane_blocks =
          (GROUP_PMP_SCALE_TOTAL_BYTES / workload->active_lanes) / 16;
      uint64_t base_blocks = lane_blocks / workload->lane_depth[lane];
      uint64_t extra_blocks = lane_blocks % workload->lane_depth[lane];
      workload->assigned_bytes[worker] =
          (base_blocks +
           (workload->lane_rank[worker] < extra_blocks ? 1 : 0)) * 16;
    }
  } else if (std::strcmp(profile, "fixed-per-enclave") == 0) {
    for (uint64_t worker = 0; worker < worker_count; ++worker)
      workload->assigned_bytes[worker] = kScalePerEnclaveBytes;
    workload->require_timer_preemption = worker_count > workload->active_lanes;
  } else if (std::strcmp(profile, "heterogeneous-naive") == 0 ||
             std::strcmp(profile, "heterogeneous-balanced-reference") == 0) {
    if (worker_count != GROUP_PMP_SCALE_MAX_WORKERS ||
        workload->active_lanes != GROUP_PMP_SCALE_LANES)
      return false;
    for (uint64_t worker = 0; worker < worker_count; ++worker) {
      bool large = std::strcmp(profile, "heterogeneous-naive") == 0 ?
          (worker % GROUP_PMP_SCALE_LANES == 0 && worker < 9) :
          worker < GROUP_PMP_SCALE_LANES;
      workload->assigned_bytes[worker] = large ?
          kScaleHeterogeneousLargeBytes : kScaleHeterogeneousSmallBytes;
    }
    workload->require_timer_preemption = true;
  } else {
    return false;
  }

  for (uint64_t worker = 0; worker < worker_count; ++worker) {
    if (!workload->assigned_bytes[worker] ||
        (workload->assigned_bytes[worker] & UINT64_C(15)))
      return false;
    workload->total_bytes += workload->assigned_bytes[worker];
  }
  return workload->total_bytes != 0;
}

bool
prepare_scale_worker(EnclaveInstance& instance, uint64_t worker_index,
                     uint64_t worker_count, uint64_t lane_id,
                     uint64_t lane_rank, uint64_t lane_depth,
                     uint64_t assigned_bytes) {
  uint8_t* utm = static_cast<uint8_t*>(instance.enclave->getSharedBuffer());
  size_t utm_size = instance.enclave->getSharedBufferSize();
  struct group_pmp_scale_config config;

  if (utm == nullptr ||
      utm_size < GROUP_PMP_SCALE_RESULT_OFFSET +
                     sizeof(struct group_pmp_scale_result))
    return false;
  std::memset(&config, 0, sizeof(config));
  config.magic = GROUP_PMP_SCALE_MAGIC;
  config.version = GROUP_PMP_SCALE_VERSION;
  config.worker_index = worker_index;
  config.worker_count = worker_count;
  config.lane_id = lane_id;
  config.lane_rank = lane_rank;
  config.lane_depth = lane_depth;
  config.assigned_bytes = assigned_bytes;
  config.seed = UINT64_C(0x5343414c45000000) ^
                (worker_count << 16) ^ worker_index;
  std::memcpy(utm + GROUP_PMP_SCALE_CONFIG_OFFSET, &config, sizeof(config));
  std::memset(utm + GROUP_PMP_SCALE_RESULT_OFFSET, 0,
              sizeof(struct group_pmp_scale_result));
  return true;
}

bool
read_scale_worker_result(const EnclaveInstance& instance,
                         uint64_t expected_index,
                         uint64_t expected_count,
                         uint64_t expected_lane,
                         uint64_t expected_bytes,
                         struct group_pmp_scale_result* result) {
  const uint8_t* utm = static_cast<const uint8_t*>(
      instance.enclave->getSharedBuffer());
  size_t utm_size = instance.enclave->getSharedBufferSize();

  if (utm == nullptr || result == nullptr ||
      utm_size < GROUP_PMP_SCALE_RESULT_OFFSET + sizeof(*result))
    return false;
  std::memcpy(result, utm + GROUP_PMP_SCALE_RESULT_OFFSET, sizeof(*result));
  return result->magic == GROUP_PMP_SCALE_MAGIC &&
      result->version == GROUP_PMP_SCALE_VERSION &&
      result->status == GROUP_PMP_SCALE_STATE_COMPLETED &&
      result->worker_index == expected_index &&
      result->worker_count == expected_count &&
      result->lane_id == expected_lane &&
      result->assigned_bytes == expected_bytes &&
      result->compute_cycles == result->end_cycle - result->start_cycle &&
      result->compute_cycles != 0 && result->digest != 0 &&
      result->known_answer_ok == 1;
}

uint64_t
observe_scale_worker_state(const EnclaveInstance& instance,
                           uint64_t expected_index,
                           uint64_t expected_count,
                           uint64_t expected_lane) {
  const uint8_t* utm = static_cast<const uint8_t*>(
      instance.enclave->getSharedBuffer());
  size_t utm_size = instance.enclave->getSharedBufferSize();

  if (utm == nullptr ||
      utm_size < GROUP_PMP_SCALE_RESULT_OFFSET +
                     sizeof(struct group_pmp_scale_result))
    return UINT64_MAX;
  const volatile struct group_pmp_scale_result* result =
      reinterpret_cast<const volatile struct group_pmp_scale_result*>(
          utm + GROUP_PMP_SCALE_RESULT_OFFSET);
  uint64_t status = result->status;
  __sync_synchronize();
  if (status == GROUP_PMP_SCALE_STATE_EMPTY)
    return status;
  if (result->magic != GROUP_PMP_SCALE_MAGIC ||
      result->version != GROUP_PMP_SCALE_VERSION ||
      result->worker_index != expected_index ||
      result->worker_count != expected_count ||
      result->lane_id != expected_lane ||
      (status != GROUP_PMP_SCALE_STATE_STARTED &&
       status != GROUP_PMP_SCALE_STATE_COMPLETED))
    return UINT64_MAX;
  return status;
}

void
scale_observer_sample(const std::vector<EnclaveInstance>* enclaves,
                      const ScaleWorkload* workload,
                      ScaleRunObservation* observation,
                      bool final_sample) {
  uint64_t states[GROUP_PMP_SCALE_MAX_WORKERS] = {0};

  for (uint64_t worker = 0; worker < workload->worker_count; ++worker) {
    states[worker] = observe_scale_worker_state(
        (*enclaves)[worker + 1], worker, workload->worker_count,
        workload->lane[worker]);
    if (states[worker] == UINT64_MAX) {
      observation->invalid = true;
      continue;
    }
    if (states[worker] >= GROUP_PMP_SCALE_STATE_STARTED)
      observation->started[worker] = true;
    if (states[worker] == GROUP_PMP_SCALE_STATE_COMPLETED)
      observation->completed[worker] = true;
  }

  for (uint64_t lane = 0; lane < workload->active_lanes; ++lane) {
    bool any_completed = false;
    uint64_t started = 0;
    for (uint64_t worker = 0; worker < workload->worker_count; ++worker) {
      if (workload->lane[worker] != lane)
        continue;
      if (observation->started[worker])
        started++;
      if (observation->completed[worker])
        any_completed = true;
    }
    if (any_completed && !observation->first_completion_seen[lane]) {
      observation->first_completion_seen[lane] = true;
      observation->started_before_first_completion[lane] = started;
      if (final_sample && workload->lane_depth[lane] > 1)
        observation->final_sample_only = true;
    }
  }
}

void
observe_scale_workers(const std::vector<EnclaveInstance>* enclaves,
                      const ScaleWorkload* workload,
                      ScaleRunObservation* observation) {
  (void)pin_current_thread_to_cpu(
      static_cast<int>(kHousekeepingCpu), "scale-observer");
  while (!observation->stop.load(std::memory_order_acquire)) {
    scale_observer_sample(enclaves, workload, observation, false);
    std::this_thread::sleep_for(std::chrono::microseconds(250));
  }
  scale_observer_sample(enclaves, workload, observation, true);
}

bool
run_aes_enclave_scaling_case(const char* master_eapp,
                             const char* worker_eapp,
                             const char* runtime, const char* loader,
                             const ScaleWorkload& workload,
                             const ScaleRunMetrics* baseline,
                             ScaleRunMetrics* metrics) {
  static const char* const worker_names[GROUP_PMP_SCALE_MAX_WORKERS] = {
      GROUP_PMP_SCALE_WORKER_NAMES};
  uint64_t assigned_total = 0;
  std::vector<EnclaveInstance> enclaves;
  ScaleRunObservation observation;
  struct keystone_group_test_snapshot resources;
  struct keystone_group_perf_snapshot perf;
  uint64_t worker_cycles_max = 0;
  uint64_t worker_cycles_total = 0;
  uint64_t lane_start[GROUP_PMP_SCALE_LANES] = {
      UINT64_MAX, UINT64_MAX, UINT64_MAX};
  uint64_t lane_end[GROUP_PMP_SCALE_LANES] = {0, 0, 0};
  uint64_t worker_wall_cycles = 0;
  uint64_t digest = 0;
  double normalized_min = 0.0;
  double normalized_max = 0.0;
  bool ok = true;

  if (metrics == nullptr || workload.worker_count < 1 ||
      workload.worker_count > GROUP_PMP_SCALE_MAX_WORKERS ||
      workload.active_lanes < 1 ||
      workload.active_lanes > GROUP_PMP_SCALE_LANES)
    return false;
  std::memset(metrics, 0, sizeof(*metrics));

  if (!configure_default_group() || !reset_group_perf_counters())
    return false;
  add_instance(enclaves, "scale-master", master_eapp, kDefaultGroupId,
      workload.worker_count + 1, kScaleYxstmSize, kUtmSize,
      kScaleYxstmSliceSize);
  for (uint64_t worker = 0; worker < workload.worker_count; ++worker)
    add_instance(enclaves, worker_names[worker], worker_eapp,
        kDefaultGroupId, workload.worker_count + 1,
        kScaleYxstmSize, kUtmSize,
        kScaleYxstmSliceSize);
  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    destroy_instances(enclaves);
    return false;
  }

  for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
    uint64_t lane = workload.lane[worker];
    assigned_total += workload.assigned_bytes[worker];
    if (!prepare_scale_worker(enclaves[worker + 1], worker,
                              workload.worker_count, lane,
                              workload.lane_rank[worker],
                              workload.lane_depth[lane],
                              workload.assigned_bytes[worker])) {
      ok = false;
      break;
    }
  }
  if (assigned_total != workload.total_bytes)
    ok = false;

  if (ok && !bind_and_enqueue(enclaves[0], kHousekeepingHart))
    ok = false;
  for (uint64_t worker = 0; ok && worker < workload.worker_count; ++worker) {
    uint64_t cpu = 1 + workload.lane[worker];
    if (!bind_and_enqueue(enclaves[worker + 1], sm_hart_id_for_cpu(cpu)))
      ok = false;
  }

  std::thread observer;
  if (ok)
    observer = std::thread(observe_scale_workers, &enclaves,
                           &workload, &observation);
  const std::chrono::steady_clock::time_point started =
      std::chrono::steady_clock::now();
  if (ok)
    ok = run_group_3w1hm(kDefaultGroupId, enclaves,
                         workload.profile);
  const double elapsed_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                    started).count();
  observation.stop.store(true, std::memory_order_release);
  if (observer.joinable())
    observer.join();
  if (observation.invalid)
    ok = false;

  for (uint64_t worker = 0; ok && worker < workload.worker_count; ++worker) {
    struct group_pmp_scale_result result;
    uint64_t lane = workload.lane[worker];

    std::memset(&result, 0, sizeof(result));
    if (!read_scale_worker_result(enclaves[worker + 1], worker,
                                  workload.worker_count, lane,
                                  workload.assigned_bytes[worker],
                                  &result)) {
      std::cerr << "[P10][scale] invalid worker result: workers="
                << workload.worker_count << " worker=" << worker
                << " lane=" << lane << std::endl;
      ok = false;
      break;
    }
    worker_cycles_max = std::max<uint64_t>(worker_cycles_max,
                                            result.compute_cycles);
    worker_cycles_total += result.compute_cycles;
    double normalized = static_cast<double>(result.compute_cycles) /
                        static_cast<double>(result.assigned_bytes);
    if (normalized_min == 0.0 || normalized < normalized_min)
      normalized_min = normalized;
    if (normalized > normalized_max)
      normalized_max = normalized;
    lane_start[lane] = std::min<uint64_t>(lane_start[lane],
                                           result.start_cycle);
    lane_end[lane] = std::max<uint64_t>(lane_end[lane], result.end_cycle);
    digest ^= result.digest + UINT64_C(0x9e3779b97f4a7c15) +
              (digest << 6) + (digest >> 2);
  }

  std::memset(&resources, 0, sizeof(resources));
  std::memset(&perf, 0, sizeof(perf));
  if (ok && (!take_resource_snapshot(kDefaultGroupId, &resources) ||
             resources.running_workers != 0 ||
             resources.max_running_workers == 0 ||
             resources.max_running_workers > workload.active_lanes ||
              resources.master_non_boundary_entries != 0 ||
              resources.lane_owner_switches <
                  workload.worker_count - workload.active_lanes ||
              resources.lane_scrubs < workload.active_lanes ||
              !query_group_perf_counters(&perf))) {
    print_resource_snapshot("AES scaling invariant failed", resources);
    ok = false;
  }

  bool preemption_proof = true;
  for (uint64_t lane = 0; lane < workload.active_lanes; ++lane) {
    if (!observation.first_completion_seen[lane] ||
        observation.started_before_first_completion[lane] == 0)
      preemption_proof = false;
    if (workload.require_timer_preemption &&
        workload.lane_depth[lane] > 1 &&
        observation.started_before_first_completion[lane] !=
            workload.lane_depth[lane])
      preemption_proof = false;
  }
  if (workload.require_timer_preemption &&
      (observation.final_sample_only || !preemption_proof)) {
    std::cerr << "[P10][scale] timer preemption proof failed: profile="
              << workload.profile << " workers=" << workload.worker_count
              << " started_before_first_completion="
              << observation.started_before_first_completion[0] << "/"
              << observation.started_before_first_completion[1] << "/"
              << observation.started_before_first_completion[2]
              << " final_sample_only=" << observation.final_sample_only
              << std::endl;
    ok = false;
  }

  if (ok && elapsed_seconds > 0.0) {
    for (uint64_t lane = 0; lane < workload.active_lanes; ++lane) {
      if (lane_start[lane] == UINT64_MAX || lane_end[lane] < lane_start[lane]) {
        ok = false;
        break;
      }
      worker_wall_cycles = std::max<uint64_t>(
          worker_wall_cycles, lane_end[lane] - lane_start[lane]);
    }
  }

  if (ok && elapsed_seconds > 0.0) {
    const double mb_per_sec =
        (static_cast<double>(workload.total_bytes) / kDecimalMbBytes) /
        elapsed_seconds;
    const double host_speedup = baseline && baseline->mb_per_sec > 0.0 ?
        mb_per_sec / baseline->mb_per_sec : 1.0;
    const double compute_speedup =
        baseline && baseline->total_bytes > 0 &&
        baseline->worker_wall_cycles > 0 &&
        worker_wall_cycles > 0 ?
        (static_cast<double>(workload.total_bytes) /
             static_cast<double>(worker_wall_cycles)) /
            (static_cast<double>(baseline->total_bytes) /
             static_cast<double>(baseline->worker_wall_cycles)) : 1.0;
    const double fairness = normalized_max > 0.0 ?
        normalized_min / normalized_max : 0.0;

    metrics->seconds = elapsed_seconds;
    metrics->mb_per_sec = mb_per_sec;
    metrics->total_bytes = workload.total_bytes;
    metrics->worker_wall_cycles = worker_wall_cycles;

    std::cout << "[P10][scale] profile=" << workload.profile
              << " workers=" << workload.worker_count
              << " lanes=" << workload.active_lanes
              << " lane_depth=" << workload.lane_depth[0] << "/"
              << workload.lane_depth[1] << "/"
              << workload.lane_depth[2]
              << " total_mb="
              << (static_cast<double>(workload.total_bytes) / kDecimalMbBytes)
              << " seconds=" << elapsed_seconds
              << " mb_per_sec=" << mb_per_sec
              << " host_speedup=" << host_speedup
              << " compute_speedup=" << compute_speedup
              << " worker_cycles_max=" << worker_cycles_max
              << " worker_cycles_total=" << worker_cycles_total
              << " worker_compute_wall_cycles=" << worker_wall_cycles
              << " context_switches=" << perf.context_switch_count
              << " host_services=" << perf.host_service_count
              << " max_running_workers=" << resources.max_running_workers
              << " lane_owner_switches=" << resources.lane_owner_switches
              << " lane_scrubs=" << resources.lane_scrubs
              << " started_before_first_completion="
              << observation.started_before_first_completion[0] << "/"
              << observation.started_before_first_completion[1] << "/"
              << observation.started_before_first_completion[2]
              << " timer_preemption_proof="
              << (workload.require_timer_preemption ?
                  (preemption_proof ? 1 : 0) : 2)
              << " elapsed_per_byte_fairness=" << fairness
              << " digest=" << digest
              << std::endl;
  } else if (ok) {
    ok = false;
  }

  destroy_instances(enclaves);
  return ok;
}

bool
scale_profile_selected(const char* selected, const char* profile) {
  return std::strcmp(selected, "all") == 0 ||
      std::strcmp(selected, profile) == 0;
}

void
print_scale_trend(const char* profile,
                  const ScaleRunMetrics* metrics,
                  uint64_t count) {
  std::cout << "[P10][scale-trend] profile=" << profile
            << " workers=1.." << count
            << " mb_per_sec=";
  for (uint64_t index = 0; index < count; ++index)
    std::cout << (index == 0 ? "" : "/") << metrics[index].mb_per_sec;
  std::cout << " seconds=";
  for (uint64_t index = 0; index < count; ++index)
    std::cout << (index == 0 ? "" : "/") << metrics[index].seconds;
  std::cout << " speedup=";
  for (uint64_t index = 0; index < count; ++index) {
    double speedup = metrics[0].mb_per_sec > 0.0 ?
        metrics[index].mb_per_sec / metrics[0].mb_per_sec : 0.0;
    std::cout << (index == 0 ? "" : "/") << speedup;
  }
  std::cout << std::endl;
}

bool
run_aes_enclave_scaling_phase(const char* master_eapp,
                              const char* worker_eapp,
                              const char* runtime, const char* loader) {
  const char* selected_profile = std::getenv("GROUP_PMP_SCALE_PROFILE");
  ScaleRunMetrics fixed_total_baseline;
  ScaleRunMetrics fixed_per_enclave_baseline;
  ScaleRunMetrics heterogeneous_naive;
  ScaleRunMetrics fixed_total_results[GROUP_PMP_SCALE_MAX_WORKERS];
  ScaleRunMetrics fixed_per_enclave_results[GROUP_PMP_SCALE_MAX_WORKERS];
  ScaleRunMetrics result;
  if (selected_profile == nullptr || selected_profile[0] == '\0')
    selected_profile = "all";
  if (std::strcmp(selected_profile, "all") != 0 &&
      std::strcmp(selected_profile, "fixed-total") != 0 &&
      std::strcmp(selected_profile, "fixed-per-enclave") != 0 &&
      std::strcmp(selected_profile, "heterogeneous") != 0) {
    std::cerr << "[P10][scale] invalid GROUP_PMP_SCALE_PROFILE="
              << selected_profile << std::endl;
    return false;
  }
  std::memset(&fixed_total_baseline, 0, sizeof(fixed_total_baseline));
  std::memset(&fixed_per_enclave_baseline, 0,
              sizeof(fixed_per_enclave_baseline));
  std::memset(&heterogeneous_naive, 0, sizeof(heterogeneous_naive));
  std::memset(fixed_total_results, 0, sizeof(fixed_total_results));
  std::memset(fixed_per_enclave_results, 0,
              sizeof(fixed_per_enclave_results));

  std::cout << "[host] phase: AES 1..10 worker-enclave scheduler baseline"
            << std::endl;
  if (scale_profile_selected(selected_profile, "fixed-total")) {
    for (uint64_t workers = GROUP_PMP_SCALE_MIN_WORKERS;
         workers <= GROUP_PMP_SCALE_MAX_WORKERS; ++workers) {
      ScaleWorkload workload;
      if (!build_scale_workload("fixed-total", workers, &workload) ||
          !run_aes_enclave_scaling_case(
              master_eapp, worker_eapp, runtime, loader, workload,
              workers == 1 ? nullptr : &fixed_total_baseline, &result))
        return false;
      fixed_total_results[workers - 1] = result;
      if (workers == 1)
        fixed_total_baseline = result;
    }
    print_scale_trend("fixed-total", fixed_total_results,
                      GROUP_PMP_SCALE_MAX_WORKERS);
  }

  if (scale_profile_selected(selected_profile, "fixed-per-enclave")) {
    for (uint64_t workers = GROUP_PMP_SCALE_MIN_WORKERS;
         workers <= GROUP_PMP_SCALE_MAX_WORKERS; ++workers) {
      ScaleWorkload workload;
      if (!build_scale_workload("fixed-per-enclave", workers, &workload) ||
          !run_aes_enclave_scaling_case(
              master_eapp, worker_eapp, runtime, loader, workload,
              workers == 1 ? nullptr : &fixed_per_enclave_baseline, &result))
        return false;
      fixed_per_enclave_results[workers - 1] = result;
      if (workers == 1)
        fixed_per_enclave_baseline = result;
    }
    print_scale_trend("fixed-per-enclave", fixed_per_enclave_results,
                      GROUP_PMP_SCALE_MAX_WORKERS);
  }

  if (scale_profile_selected(selected_profile, "heterogeneous")) {
    ScaleWorkload workload;
    if (!build_scale_workload("heterogeneous-naive",
                              GROUP_PMP_SCALE_MAX_WORKERS, &workload) ||
        !run_aes_enclave_scaling_case(
            master_eapp, worker_eapp, runtime, loader, workload,
            nullptr, &heterogeneous_naive))
      return false;
    if (!build_scale_workload("heterogeneous-balanced-reference",
                              GROUP_PMP_SCALE_MAX_WORKERS, &workload) ||
        !run_aes_enclave_scaling_case(
            master_eapp, worker_eapp, runtime, loader, workload,
            &heterogeneous_naive, &result))
      return false;
    std::cout << "[P10][scale-comparison] workload=heterogeneous"
              << " naive_seconds=" << heterogeneous_naive.seconds
              << " balanced_seconds=" << result.seconds
              << " balanced_makespan_speedup="
              << (result.seconds > 0.0 ?
                  heterogeneous_naive.seconds / result.seconds : 0.0)
              << std::endl;
  }
  return true;
}

struct MixedWorkload {
  uint64_t rv8_profile;
  bool kv_enabled;
  uint64_t worker_count;
  uint64_t active_lanes;
  uint64_t ocall_mode;
  uint64_t workload_id;
  uint64_t diagnostic_flags;
  uint64_t max_lane_depth;
  uint64_t lane[GROUP_PMP_MIXED_MAX_WORKERS];
  uint64_t lane_rank[GROUP_PMP_MIXED_MAX_WORKERS];
  uint64_t lane_depth[GROUP_PMP_MIXED_LANES];
  uint64_t assigned_bytes[GROUP_PMP_MIXED_MAX_WORKERS];
  uint64_t lane_bytes[GROUP_PMP_MIXED_LANES];
  uint64_t total_bytes;
};

struct MixedRunMetrics {
  uint64_t rv8_bytes, rv8_blocks, rv8_cpu_ticks, rv8_elapsed_ticks;
  uint64_t worker_count;
  uint64_t active_lanes;
  uint64_t ocall_mode;
  uint64_t lane_depth[GROUP_PMP_MIXED_LANES];
  uint64_t bytes_per_enclave;
  uint64_t total_bytes;
  uint64_t chunks_per_enclave;
  uint64_t slot_dispatches;
  uint64_t slot_aggregates;
  uint64_t slot_wait_yields;
  uint64_t sample_count;
  double seconds;
  double seconds_min;
  double seconds_max;
  double seconds_p95;
  double host_envelope_seconds;
  double host_envelope_seconds_p95;
  double mb_per_sec;
  double mb_per_sec_min;
  double mb_per_sec_max;
  double mb_per_sec_p05;
  double mb_per_sec_p95;
  double speedup_vs_one;
  double effective_cycle_hz;
  double effective_cycle_hz_p95;
  double enclave_aes_mb_per_sec;
  double enclave_aes_mb_per_sec_p95;
  double aes_stage_mb_per_sec;
  double aes_stage_mb_per_sec_p95;
  double yxstm_dispatch_mb_per_sec;
  double yxstm_dispatch_mb_per_sec_p95;
  double yxstm_effective_payload_mb_per_sec;
  double yxstm_effective_payload_mb_per_sec_p95;
  double yxstm_aggregate_mb_per_sec;
  double yxstm_aggregate_mb_per_sec_p95;
  double scheduler_efficiency;
  double scheduler_efficiency_p95;
  double lane_utilization;
  double lane_utilization_p95;
  double master_wall_seconds;
  double master_wall_seconds_p95;
  double master_dispatch_wall_seconds;
  double master_dispatch_wall_seconds_p95;
  double master_aggregate_wall_seconds;
  double master_aggregate_wall_seconds_p95;
  double compute_wall_seconds;
  double compute_wall_seconds_p95;
  double aes_wall_seconds;
  double aes_wall_seconds_p95;
  uint64_t aes_elapsed_time_ticks;
  double ocall_wall_seconds;
  double ocall_wall_seconds_p95;
  double wait_wall_seconds;
  double wait_wall_seconds_p95;
  double pmp_wall_seconds;
  double pmp_wall_seconds_p95;
  double switch_wall_seconds;
  double switch_wall_seconds_p95;
  double scheduler_wall_seconds;
  double scheduler_wall_seconds_p95;
  double protocol_wall_seconds;
  double protocol_wall_seconds_p95;
  uint64_t worker_ocalls;
  uint64_t worker_aes_cycles;
  uint64_t worker_aes_time_ticks;
  uint64_t worker_protocol_cycles;
  uint64_t worker_protocol_time_ticks;
  uint64_t worker_ready_wait_time_ticks;
  uint64_t worker_ocall_time_ticks;
  uint64_t vfs_read_bytes;
  uint64_t vfs_write_bytes;
  uint64_t vfs_encrypt_cycles;
  uint64_t vfs_decrypt_cycles;
  uint64_t vfs_submit_count;
  uint64_t vfs_wait_count;
  uint64_t vfs_yield_count;
  uint64_t vfs_wait_ticks;
  uint64_t vfs_batch_submit_count;
  uint64_t vfs_blocked_completion_count;
  uint64_t vfs_queue_depth_peak;
  uint64_t vfs_ring_doorbell_count;
  uint64_t vfs_ring_request_count;
  uint64_t vfs_completion_batch_count;
  uint64_t vfs_crypto_io_sample_ticks;
  uint64_t vfs_crypto_io_overlap_ticks;
  double vfs_crypto_io_overlap_ratio;
  uint64_t vfs_both_buffers_wait_ticks;
  uint64_t vfs_completion_local_reaps;
  uint64_t vfs_buffer_reuses;
  struct group_pmp_sqlite_pipeline_timing pipeline;
  uint64_t sqlite_task_count;
  std::array<uint64_t, SQLITE_READ100K_METRICS> sqlite_read100k;
  std::array<uint64_t, SQLITE_PIPELINE_METRICS> sqlite_io_pipeline;
  uint64_t sqlite_batch_count;
  uint64_t sqlite_queue_wait_ns;
  uint64_t sqlite_writer_wait_ns;
  uint64_t sqlite_read_service_ns;
  uint64_t sqlite_write_service_ns;
  uint64_t sqlite_control_service_ns;
  uint64_t sqlite_commit_ns;
  uint64_t sqlite_commit_count;
  uint64_t sqlite_queue_depth_peak;
  uint64_t sqlite_io_uring_submissions;
  uint64_t sqlite_registered_file_operations;
  uint64_t sqlite_registered_buffer_operations;
  uint64_t sqlite_fixed_buffer_operations;
  uint64_t sqlite_buffer_registration_attempts;
  uint64_t sqlite_buffer_registration_failures;
  uint64_t sqlite_direct_io_operations;
  uint64_t sqlite_direct_alignment_fallback_operations;
  uint64_t sqlite_posix_fallback_operations;
  uint64_t sqlite_merged_io_count;
  uint64_t sqlite_sparse_io_count;
  uint64_t sqlite_useful_io_bytes;
  uint64_t sqlite_physical_io_bytes;
  uint64_t sqlite_logical_request_count;
  uint64_t sqlite_physical_request_count;
  uint64_t sqlite_deduplicated_request_count;
  uint64_t sqlite_completion_wait_ocall_count;
  uint64_t sqlite_cache_full_hit_count;
  uint64_t sqlite_cache_partial_hit_count;
  uint64_t sqlite_cache_miss_count;
  uint64_t sqlite_cache_hit_bytes;
  uint64_t sqlite_collect_ns;
  uint64_t sqlite_sort_ns;
  uint64_t sqlite_cluster_ns;
  uint64_t sqlite_submit_ns;
  uint64_t sqlite_disk_io_ns;
  uint64_t sqlite_completion_wait_ns;
  uint64_t sqlite_storage_sync_ns;
  uint64_t sqlite_sequential_extent_count;
  uint64_t sqlite_sequential_8mb_extent_count;
  uint64_t sqlite_cross_worker_extent_count;
  uint64_t sqlite_utm_copy_ns;
  uint64_t sqlite_completion_publish_ns;
  uint64_t sqlite_wakeup_ns;
  uint64_t sqlite_submit_to_host_dequeue_ns;
  uint64_t sqlite_host_dequeue_to_io_submit_ns;
  uint64_t sqlite_io_submit_to_complete_ns;
  uint64_t sqlite_io_complete_to_publish_ns;
  uint64_t sqlite_publish_to_host_resume_request_ns;
  uint64_t sqlite_wakeup_eligible_to_host_resume_request_ns;
  uint64_t sqlite_host_resume_ioctl_ns;
  uint64_t sqlite_completion_wakeup_count;
  uint64_t sqlite_completion_ready_before_wait_count;
  uint64_t sqlite_ewma_bandwidth_bytes_per_sec;
  uint64_t sqlite_ewma_request_latency_ns;
  uint64_t sqlite_ewma_queue_wait_ns;
  uint64_t sqlite_ewma_completion_latency_ns;
  uint64_t sqlite_adaptive_collect_usec;
  uint64_t sqlite_adaptive_batch_target;
  uint64_t sqlite_adaptive_queue_depth;
  uint64_t sqlite_adaptive_gap_bytes;
  uint64_t sqlite_write_overlap_check_ns;
  uint64_t sqlite_write_overlap_checks;
  uint64_t sqlite_write_disjoint_batches;
  uint64_t sqlite_write_overlap_batches;
  uint64_t sqlite_adaptive_write_grow_count;
  uint64_t sqlite_adaptive_write_shrink_count;
  uint64_t sqlite_adaptive_write_hold_count;
  uint64_t sqlite_sequential_ready_single_batches;
  uint64_t sqlite_sequential_ready_multi_batches;
  uint64_t sqlite_sequential_ready_adjacent_pairs;
  uint64_t sqlite_sequential_ready_nonadjacent_pairs;
  uint64_t sqlite_random_sparse_fast_batches;
  uint64_t sqlite_random_sparse_fast_requests;
  uint64_t sqlite_random_planned_batches;
  uint64_t sqlite_random_precheck_fallbacks;
  uint64_t sqlite_random_precheck_ns;
  uint64_t sqlite_random_local_plan_batches;
  uint64_t sqlite_random_local_candidate_requests;
  uint64_t sqlite_cache_fill_bytes;
  uint64_t sqlite_cache_fill_ns;
  uint64_t sqlite_cache_fill_skipped_bytes;
  uint64_t sqlite_cache_admission_disables;
  uint64_t sqlite_cache_admission_reenables;
  uint64_t sqlite_readseq_initial_requests;
  uint64_t sqlite_readseq_refill_peer_io_requests;
  uint64_t sqlite_readseq_refill_peer_ready_requests;
  uint64_t sqlite_readseq_refill_peer_idle_requests;
  uint64_t sqlite_critical_path_ns;
  uint64_t sqlite_max_queue_wait_ns;
  uint64_t sqlite_max_batch_service_ns;
  uint64_t sqlite_max_completion_latency_ns;
  uint64_t io_trace_request_count;
  uint64_t io_trace_member_request_count;
  uint64_t io_trace_total_range_bytes;
  uint64_t io_trace_useful_bytes;
  uint64_t io_trace_gap_bytes;
  uint64_t io_trace_range_start;
  uint64_t io_trace_range_end;
  uint64_t io_trace_min_request_bytes;
  uint64_t io_trace_max_request_bytes;
  uint64_t io_trace_read_request_count;
  uint64_t io_trace_write_request_count;
  uint64_t io_trace_failed_request_count;
  uint64_t slot_scheduler_cycles;
  uint64_t master_dispatch_cycles;
  uint64_t master_dispatch_time_ticks;
  uint64_t master_dispatch_bytes;
  uint64_t worker_compute_wall_cycles;
  uint64_t worker_compute_wall_time_ticks;
  uint64_t master_aggregate_cycles;
  uint64_t master_aggregate_time_ticks;
  uint64_t master_aggregate_bytes;
  uint64_t master_protocol_cycles;
  uint64_t master_protocol_time_ticks;
  uint64_t task_e2e_cycles;
  uint64_t task_e2e_time_ticks;
  uint64_t context_switches;
  uint64_t context_switch_cycles;
  uint64_t context_switch_ticks;
  uint64_t context_gpr_cycles;
  uint64_t context_smode_csr_cycles;
  uint64_t context_fp_cycles;
  uint64_t context_pmp_cycles;
  uint64_t context_platform_cycles;
  uint64_t context_scheduler_lock_cycles;
  uint64_t worker_exec_runtime_ticks;
  uint64_t worker_aes_exec_runtime_ticks;
  uint64_t worker_aes_exec_runtime_min;
  uint64_t worker_aes_exec_runtime_max;
  uint64_t worker_runtime_members;
  uint64_t pmp_grant_suspend_cycles;
  uint64_t pmp_epm_revoke_cycles;
  uint64_t pmp_epm_install_cycles;
  uint64_t pmp_yxstm_restore_cycles;
  uint64_t pmp_fence_cycles;
  uint64_t pmp_validation_cycles;
  uint64_t pmp_lock_wait_cycles;
  uint64_t grant_suspend_restores;
  uint64_t grant_suspend_restore_cycles;
  uint64_t sm_ocalls;
  uint64_t sm_ocall_cycles;
  uint64_t ocall_handler_count;
  uint64_t ocall_handler_cycles;
  uint64_t ocall_wait_count;
  uint64_t ocall_wait_ticks;
  uint64_t lane_wait_blocks;
  uint64_t lane_wait_wakes;
  uint64_t lane_wait_ticks;
  uint64_t cfs_picks;
  uint64_t cfs_preemptions;
  uint64_t cfs_runtime_ticks;
  uint64_t cfs_vruntime_delta;
  uint64_t cfs_slice_ticks;
  uint64_t cfs_min_granularity_hits;
  uint64_t cfs_dynamic_min_slice_ticks;
  uint64_t heartbeats;
  uint64_t heartbeat_cycles;
  uint64_t timer_traps;
  uint64_t timer_trap_cycles;
  uint64_t host_services;
  uint64_t scrub_count;
  uint64_t scrub_bytes;
  uint64_t scrub_cycles;
  uint64_t max_running_workers;
  uint64_t digest;
};

uint64_t
mixed_worker_batch_count(const MixedWorkload& workload, uint64_t worker) {
  uint64_t chunk;

  if (worker >= workload.worker_count)
    return 0;
  if (workload.workload_id)
    return group_pmp_sqlite_task_batch_count(
        workload.workload_id, workload.assigned_bytes[worker]);
  chunk = group_pmp_mixed_stream_chunk_bytes(
      workload.lane_depth[workload.lane[worker]]);
  return chunk ?
      (workload.assigned_bytes[worker] + chunk - 1) / chunk : 0;
}

uint64_t
mixed_lane_batch_count(const MixedWorkload& workload, uint64_t lane) {
  uint64_t total = 0;

  if (lane >= GROUP_PMP_MIXED_LANES)
    return 0;
  for (uint64_t worker = 0; worker < workload.worker_count; ++worker)
    if (workload.lane[worker] == lane)
      total += mixed_worker_batch_count(workload, worker);
  return total;
}

uint64_t
mixed_max_worker_batch_count(const MixedWorkload& workload) {
  uint64_t maximum = 0;

  for (uint64_t worker = 0; worker < workload.worker_count; ++worker)
    maximum = std::max<uint64_t>(
        maximum, mixed_worker_batch_count(workload, worker));
  return maximum;
}

uint64_t
mixed_total_batch_count(const MixedWorkload& workload) {
  uint64_t total = 0;

  for (uint64_t worker = 0; worker < workload.worker_count; ++worker)
    total += mixed_worker_batch_count(workload, worker);
  return total;
}

bool
validate_mixed_slot_partition(uint64_t lane_depth) {
  uint64_t slot_size = group_pmp_mixed_slot_size(lane_depth);
  uint64_t payload_size = group_pmp_mixed_stream_chunk_bytes(lane_depth);
  uint64_t reserved = KEYSTONE_YXSTM_WORKER_LANE_SIZE -
      slot_size * lane_depth;

  return lane_depth >= 1 &&
      lane_depth <= GROUP_PMP_MIXED_MAX_LANE_DEPTH &&
      slot_size != 0 && (slot_size & UINT64_C(4095)) == 0 &&
      payload_size != 0 &&
      payload_size ==
          keystone_yxstm_slot_payload_capacity(lane_depth) &&
      payload_size <= slot_size &&
      slot_size * lane_depth >= KEYSTONE_YXSTM_WORKER_LANE_DATA_SIZE &&
      reserved == KEYSTONE_YXSTM_WORKER_LANE_SIZE -
                      slot_size * lane_depth;
}

struct MixedRunTiming {
  MixedRunTiming()
      : started(false), stopped(false), worker_ocalls(0),
        start_ns(0), stop_ns(0), perf_frozen(false) {
    std::memset(&perf, 0, sizeof(perf));
  }

  bool started;
  bool stopped;
  uint64_t worker_ocalls;
  uint64_t start_ns;
  uint64_t stop_ns;
  bool perf_frozen;
  struct keystone_group_perf_snapshot perf;
  SqliteIoPerfSnapshot sqlite_perf;
};

bool
build_mixed_workload(uint64_t worker_count, uint64_t ocall_mode,
                     MixedWorkload* workload, uint64_t workload_id = 0) {
  uint64_t next_rank[GROUP_PMP_MIXED_LANES] = {0, 0, 0};
  uint64_t total_units;
  uint64_t lane_base_units;
  uint64_t lane_remainder;

  if (mixed_lane_dynamic_artifact_marker[0] != 'k' ||
      !workload || worker_count < 1 ||
      worker_count > GROUP_PMP_MIXED_MAX_WORKERS ||
      (workload_id && !group_pmp_sqlite_valid_workload(workload_id)) ||
      (ocall_mode != GROUP_PMP_MIXED_OCALL_PER_TASK &&
       ocall_mode != GROUP_PMP_MIXED_OCALL_PER_CHUNK_STRESS))
    return false;
  std::memset(workload, 0, sizeof(*workload));
  workload->worker_count = worker_count;
  workload->ocall_mode = ocall_mode;
  workload->workload_id = workload_id;
  workload->active_lanes =
      std::min<uint64_t>(worker_count, GROUP_PMP_MIXED_LANES);
  for (uint64_t worker = 0; worker < worker_count; ++worker) {
    uint64_t lane = worker % GROUP_PMP_MIXED_LANES;
    workload->lane[worker] = lane;
    workload->lane_depth[lane]++;
  }
  for (uint64_t worker = 0; worker < worker_count; ++worker) {
    uint64_t lane = workload->lane[worker];
    workload->lane_rank[worker] = next_rank[lane]++;
  }
  for (uint64_t lane = 0; lane < workload->active_lanes; ++lane)
    if (workload->lane_depth[lane] == 0 ||
        workload->lane_depth[lane] > GROUP_PMP_MIXED_MAX_LANE_DEPTH ||
        !validate_mixed_slot_partition(workload->lane_depth[lane]))
      return false;
    else
      workload->max_lane_depth =
          std::max<uint64_t>(workload->max_lane_depth,
                             workload->lane_depth[lane]);

  const uint64_t assignment_unit = workload_id ?
      group_pmp_sqlite_value_size(workload_id) : UINT64_C(16);
  if (!assignment_unit)
    return false;
  /* SQLite is a configurable fixed-total strong-scaling benchmark. The final
   * partial record is excluded so every worker receives integral values. */
  workload->total_bytes = workload_id ?
      (env_u64("GROUP_PMP_SQLITE_TOTAL_BYTES",
               GROUP_PMP_SQLITE_DEFAULT_TOTAL_BYTES, assignment_unit,
               UINT64_MAX) /
       assignment_unit) *
          assignment_unit :
      worker_count * GROUP_PMP_MIXED_WORKER_BYTES;
  if (!workload->total_bytes || workload->total_bytes % assignment_unit)
    return false;
  total_units = workload->total_bytes / assignment_unit;
  lane_base_units = total_units / workload->active_lanes;
  lane_remainder = total_units % workload->active_lanes;
  for (uint64_t lane = 0; lane < workload->active_lanes; ++lane) {
    uint64_t lane_units = lane_base_units +
        (lane < lane_remainder ? UINT64_C(1) : UINT64_C(0));
    uint64_t worker_base_units = lane_units / workload->lane_depth[lane];
    uint64_t worker_remainder = lane_units % workload->lane_depth[lane];

    workload->lane_bytes[lane] = lane_units * assignment_unit;
    for (uint64_t rank = 0; rank < workload->lane_depth[lane]; ++rank) {
      uint64_t worker = rank * GROUP_PMP_MIXED_LANES + lane;
      uint64_t units = worker_base_units +
          (rank < worker_remainder ? UINT64_C(1) : UINT64_C(0));

      if (worker >= worker_count || !units)
        return false;
      workload->assigned_bytes[worker] = units * assignment_unit;
    }
  }
  {
    uint64_t assigned = 0;
    uint64_t min_lane_bytes = UINT64_MAX;
    uint64_t max_lane_bytes = 0;

    for (uint64_t worker = 0; worker < worker_count; ++worker)
      assigned += workload->assigned_bytes[worker];
    if (assigned != workload->total_bytes)
      return false;
    for (uint64_t lane = 0; lane < workload->active_lanes; ++lane) {
      min_lane_bytes = std::min<uint64_t>(min_lane_bytes,
                                         workload->lane_bytes[lane]);
      max_lane_bytes = std::max<uint64_t>(max_lane_bytes,
                                         workload->lane_bytes[lane]);
    }
    if (max_lane_bytes - min_lane_bytes > assignment_unit)
      return false;
  }
  if (!workload_id && worker_count == 12 &&
      mixed_total_batch_count(*workload) != 48)
    return false;
  return true;
}

bool
prepare_mixed_master(EnclaveInstance& instance,
                     const MixedWorkload& workload) {
  uint8_t* utm = static_cast<uint8_t*>(instance.enclave->getSharedBuffer());
  size_t utm_size = instance.enclave->getSharedBufferSize();
  struct group_pmp_mixed_master_config config;

  if (!utm || utm_size < GROUP_PMP_MIXED_RESULT_OFFSET +
                            sizeof(struct group_pmp_mixed_master_result))
    return false;
  std::memset(&config, 0, sizeof(config));
  config.magic = GROUP_PMP_MIXED_MAGIC;
  config.version = GROUP_PMP_MIXED_VERSION;
  config.worker_count = workload.worker_count;
  config.active_lanes = workload.active_lanes;
  config.data_bytes_per_worker = GROUP_PMP_MIXED_WORKER_BYTES;
  config.total_data_bytes = workload.total_bytes;
  config.chunk_bytes =
      group_pmp_mixed_stream_chunk_bytes(workload.max_lane_depth);
  config.ocall_mode = workload.ocall_mode;
  config.diagnostic_flags = workload.diagnostic_flags;
  config.reserved[0] = workload.workload_id;
  config.max_lane_depth = workload.max_lane_depth;
  for (uint64_t lane = 0; lane < GROUP_PMP_MIXED_LANES; ++lane)
    config.lane_depth[lane] = workload.lane_depth[lane];
  for (uint64_t worker = 0; worker < workload.worker_count; ++worker)
    config.worker_data_bytes[worker] = workload.assigned_bytes[worker];
  std::memcpy(utm + GROUP_PMP_MIXED_CONFIG_OFFSET, &config, sizeof(config));
  std::memset(utm + GROUP_PMP_MIXED_RESULT_OFFSET, 0,
              sizeof(struct group_pmp_mixed_master_result));
  return true;
}

bool
prepare_mixed_worker(EnclaveInstance& instance,
                     const MixedWorkload& workload,
                     uint64_t worker) {
  uint8_t* utm = static_cast<uint8_t*>(instance.enclave->getSharedBuffer());
  size_t utm_size = instance.enclave->getSharedBufferSize();
  struct group_pmp_mixed_worker_config config;
  uint64_t lane = workload.lane[worker];
  const uint64_t config_offset = workload.workload_id ?
      GROUP_PMP_SQLITE_VFS_CONFIG_OFFSET : GROUP_PMP_MIXED_CONFIG_OFFSET;
  const uint64_t result_offset = workload.workload_id ?
      GROUP_PMP_SQLITE_VFS_RESULT_OFFSET : GROUP_PMP_MIXED_RESULT_OFFSET;

  if (!utm || worker >= workload.worker_count ||
      utm_size < result_offset +
                     sizeof(struct group_pmp_mixed_worker_result))
    return false;
  std::memset(&config, 0, sizeof(config));
  config.magic = GROUP_PMP_MIXED_MAGIC;
  config.version = GROUP_PMP_MIXED_VERSION;
  config.worker_index = worker;
  config.worker_count = workload.worker_count;
  config.lane_id = lane;
  config.lane_rank = workload.lane_rank[worker];
  config.lane_depth = workload.lane_depth[lane];
  config.data_bytes = workload.assigned_bytes[worker];
  config.chunk_bytes =
      group_pmp_mixed_stream_chunk_bytes(workload.lane_depth[lane]);
  config.seed = UINT64_C(0x4d49584544000000) ^
                (workload.worker_count << 16) ^ worker;
  config.ocall_mode = workload.ocall_mode;
  config.diagnostic_flags = sqlite_worker_diagnostic_flags(
      workload.workload_id, workload.diagnostic_flags);
  if (MotivationSystem::enabled() && MotivationSystem::trace_path())
    config.diagnostic_flags |= MOT_SYSTEM_TRACE_FLAG;
  if (workload.workload_id)
    config.diagnostic_flags |= uint64_t(selected_benchmark_cipher()) << BENCHMARK_CIPHER_FLAG_SHIFT;
  if (workload.workload_id && security_scan_nonce()) {
    config.seed = security_scan_nonce();
    config.diagnostic_flags |= GROUP_PMP_SECURITY_SENTINEL_FLAG;
  }
  config.reserved[0] = workload.workload_id;
  for (uint64_t prior = 0; prior < worker; ++prior)
    config.reserved[1] += workload.assigned_bytes[prior];
  if (workload.workload_id) {
    const char* cache = std::getenv("GROUP_PMP_SQLITE_CACHE_MODE");
    const bool direct_layout = cache && std::strcmp(cache, "direct") == 0;
    if (direct_layout)
      config.diagnostic_flags |= GROUP_PMP_SQLITE_DIRECT_LAYOUT;
    for (uint64_t prior = 0; prior < worker; ++prior) {
      const uint64_t span = group_pmp_sqlite_file_span(workload.workload_id,
          workload.assigned_bytes[prior], direct_layout);
      if (!span || span > INT64_MAX - config.reserved[2]) return false;
      config.reserved[2] += span;
    }
  }
  config.max_lane_depth = workload.max_lane_depth;
  std::memcpy(utm + config_offset, &config, sizeof(config));
  std::memset(utm + result_offset, 0,
              sizeof(struct group_pmp_mixed_worker_result));
  return true;
}

uint64_t
mixed_worker_state(const EnclaveInstance& instance,
                   const MixedWorkload& workload, uint64_t worker) {
  const uint8_t* utm = static_cast<const uint8_t*>(
      instance.enclave->getSharedBuffer());
  size_t utm_size = instance.enclave->getSharedBufferSize();
  const uint64_t result_offset = workload.workload_id ?
      GROUP_PMP_SQLITE_VFS_RESULT_OFFSET : GROUP_PMP_MIXED_RESULT_OFFSET;

  if (!utm || worker >= workload.worker_count ||
      utm_size < result_offset +
                     sizeof(struct group_pmp_mixed_worker_result))
    return UINT64_MAX;
  const volatile struct group_pmp_mixed_worker_result* result =
      reinterpret_cast<const volatile struct group_pmp_mixed_worker_result*>(
          utm + result_offset);
  uint64_t status = result->status;
  __sync_synchronize();
  if (status == GROUP_PMP_MIXED_STATE_EMPTY)
    return status;
  return result->magic == GROUP_PMP_MIXED_MAGIC &&
      result->version == GROUP_PMP_MIXED_VERSION &&
      result->worker_index == worker &&
      result->worker_count == workload.worker_count &&
      result->lane_id == workload.lane[worker] &&
      result->lane_rank == workload.lane_rank[worker] ? status : UINT64_MAX;
}

bool
mixed_worker_finished_warmup(uint64_t state) {
  return state == GROUP_PMP_MIXED_STATE_WARMED ||
      state == GROUP_PMP_MIXED_STATE_RUNNING ||
      state == GROUP_PMP_MIXED_STATE_COMPLETED;
}

bool
wait_mixed_workers_warmed(Keystone::KeystoneDevice& device,
                          uint64_t group_id,
                          const std::vector<EnclaveInstance>& enclaves,
                          const MixedWorkload& workload,
                          std::map<uint64_t, uint64_t>*
                              queue_overflow_baseline) {
  /* Drain every event type while the SQLite database is prepared. Leaving an
   * unmatched event in the bounded driver queue can turn a later valid OCALL
   * into an apparent performance-window overflow. */
  const uint64_t warmup_event_mask = ~UINT64_C(0);
  const uint64_t timeout_ms = env_u64(
      "GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS", 1800000, 100, 3600000);
  const uint64_t stall_timeout_ms = env_u64(
      "GROUP_PMP_MIXED_WARMUP_STALL_TIMEOUT_MS", 120000, 10000, 1800000);
  const std::chrono::steady_clock::time_point deadline =
      std::chrono::steady_clock::now() +
      std::chrono::milliseconds(timeout_ms);
  std::chrono::steady_clock::time_point next_progress =
      std::chrono::steady_clock::now() + std::chrono::seconds(10);
  uint64_t warmup_ocalls = 0;
  uint64_t quiet_polls = 0;
  std::chrono::steady_clock::time_point last_progress =
      std::chrono::steady_clock::now();

  if (!queue_overflow_baseline)
    return false;
  queue_overflow_baseline->clear();
  GroupWarmupWatchdog watchdog(group_warmup_diagnostics,
                                group_id, workload.worker_count);
  std::cerr << "[P10][mixed-warmup] monitor=v1 sync_submit=deferred-event "
               "group=" << group_id << " workers=" << workload.worker_count
            << std::endl;

  for (;;) {
    group_warmup_diagnostics.mark(GroupWarmupDiagnostics::MAIN,
                                   "flush-completions");
    if (!resume_completed_group_ocalls(device, group_id, "sqlite-warmup"))
      return false;
    if (stop_requested) {
      std::cerr << "[P10][mixed-scale] interrupted during worker warmup; "
                   "releasing worker lease"
                << std::endl;
      return false;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      std::cerr << "[P10][mixed-scale] worker warmup timed out after "
                << timeout_ms << " ms" << std::endl;
      return false;
    }
    struct keystone_group_wait_event event;
    std::memset(&event, 0, sizeof(event));
    group_warmup_diagnostics.mark(GroupWarmupDiagnostics::MAIN,
                                   "wait-driver-event");
    Error event_error = device.groupWaitEvent(
        group_id, warmup_event_mask, 1, &event);
    if (event_error == Error::Success)
      (*queue_overflow_baseline)[event.hart_id] = std::max(
          (*queue_overflow_baseline)[event.hart_id],
          static_cast<uint64_t>(event.queue_overflows));
    if (event_error == Error::Success &&
        event.event == KEYSTONE_GROUP_EVENT_OCALL) {
      if (!dispatch_and_resume_group_ocall(
              device, group_id, event.hart_id, event.eid, event.value,
              &enclaves, "sqlite-warmup", true))
        return false;
      ++warmup_ocalls;
      last_progress = std::chrono::steady_clock::now();
      quiet_polls = 0;
      continue;
    }
    if (event_error == Error::Success &&
        event.event == KEYSTONE_GROUP_EVENT_EXIT) {
      uint64_t worker_index = workload.worker_count;
      uint64_t worker_state = UINT64_MAX;
      uint64_t failure_stage = 0;

      for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
        if (static_cast<uint64_t>(enclaves[worker + 1].enclave->getEid()) ==
            event.eid) {
          worker_index = worker;
          worker_state = mixed_worker_state(
              enclaves[worker + 1], workload, worker);
          const uint8_t* utm = static_cast<const uint8_t*>(
              enclaves[worker + 1].enclave->getSharedBuffer());
          const uint64_t result_offset = workload.workload_id ?
              GROUP_PMP_SQLITE_VFS_RESULT_OFFSET :
              GROUP_PMP_MIXED_RESULT_OFFSET;
          if (utm && worker_state == GROUP_PMP_MIXED_STATE_FAILED) {
            const volatile struct group_pmp_mixed_worker_result* result =
                reinterpret_cast<const volatile
                    struct group_pmp_mixed_worker_result*>(
                        utm + result_offset);
            failure_stage = result->digest;
          }
          break;
        }
      }
      std::cerr << "[P10][mixed-scale] worker exited during warmup: worker="
                << worker_index << " eid=" << event.eid
                << " eapp_status=" << event.value
                << " state=" << worker_state
                << " failure_stage=" << failure_stage
                << " ocalls_completed=" << warmup_ocalls << std::endl;
      return false;
    }
    if (event_error == Error::Success) {
      std::cerr << "[P10][mixed-scale] unexpected event during warmup: event="
                << event.event << " hart=" << event.hart_id
                << " eid=" << event.eid << " detail=" << event.error
                << " value=" << event.value
                << " queue_overflows=" << event.queue_overflows
                << std::endl;
      return false;
    }
    if (event_error != Error::GroupEventTimeout) {
      std::cerr << "[P10][mixed-scale] worker failed during warmup: error="
                << error_name(event_error) << " event=" << event.event
                << " hart=" << event.hart_id << " eid=" << event.eid
                << " detail=" << event.error << " value=" << event.value
                << std::endl;
      return false;
    }

    group_warmup_diagnostics.mark(GroupWarmupDiagnostics::MAIN,
                                   "scan-worker-state");
    bool all_warmed = true;
    for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
      uint64_t state = mixed_worker_state(
          enclaves[worker + 1], workload, worker);
      if (state == UINT64_MAX) {
        const uint8_t* utm = static_cast<const uint8_t*>(
            enclaves[worker + 1].enclave->getSharedBuffer());
        const volatile struct group_pmp_mixed_worker_result* result =
            utm ? reinterpret_cast<const volatile
                struct group_pmp_mixed_worker_result*>(
                    utm + GROUP_PMP_SQLITE_VFS_RESULT_OFFSET) : nullptr;
        std::cerr << "[P10][mixed-scale] invalid warmup record: worker="
                  << worker
                  << " magic=0x" << std::hex
                  << (result ? result->magic : 0)
                  << " version=" << std::dec
                  << (result ? result->version : 0)
                  << " state=" << (result ? result->status : UINT64_MAX)
                  << " record_worker="
                  << (result ? result->worker_index : UINT64_MAX)
                  << " record_count="
                  << (result ? result->worker_count : 0)
                  << " lane=" << (result ? result->lane_id : UINT64_MAX)
                  << " lane_rank="
                  << (result ? result->lane_rank : UINT64_MAX)
                  << std::endl;
        return false;
      }
      if (state == GROUP_PMP_MIXED_STATE_FAILED) {
        const uint8_t* utm = static_cast<const uint8_t*>(
            enclaves[worker + 1].enclave->getSharedBuffer());
        const volatile struct group_pmp_mixed_worker_result* result =
            reinterpret_cast<const volatile
                struct group_pmp_mixed_worker_result*>(
                    utm + GROUP_PMP_SQLITE_VFS_RESULT_OFFSET);
        __sync_synchronize();
        std::cerr << "[P10][mixed-scale] worker failed during warmup: worker="
                  << worker
                  << " eid=" << enclaves[worker + 1].enclave->getEid()
                  << " failure_stage=" << result->digest
                  << " batches=" << result->batch_count
                  << " vfs_submits=" << result->vfs_submit_count
                  << " vfs_waits=" << result->vfs_wait_count
                  << " vfs_read_bytes=" << result->vfs_read_bytes
                  << " vfs_write_bytes=" << result->vfs_write_bytes
                  << " vfs_last_error=" << result->vfs_last_error
                  << " ocalls_completed=" << warmup_ocalls << std::endl;
        return false;
      }
      if (state != GROUP_PMP_MIXED_STATE_EMPTY &&
          !mixed_worker_finished_warmup(state)) {
        std::cerr << "[P10][mixed-scale] invalid warmup state: worker="
                  << worker << " state=" << state << std::endl;
        return false;
      }
      if (!mixed_worker_finished_warmup(state))
        all_warmed = false;
    }
    if (all_warmed && ++quiet_polls >= 10) {
      for (const auto& baseline : *queue_overflow_baseline) {
        if (baseline.second)
          std::cout << "[P10][mixed-warmup] event overflow baseline: hart="
                    << baseline.first << " count=" << baseline.second
                    << " (excluded from performance window)" << std::endl;
      }
      return true;
    }
    if (!all_warmed)
      quiet_polls = 0;
    if (!all_warmed &&
        std::chrono::steady_clock::now() - last_progress >=
            std::chrono::milliseconds(stall_timeout_ms)) {
      std::cerr << "[P10][mixed-scale] worker warmup made no OCALL progress for "
                << stall_timeout_ms << " ms; ocalls_completed="
                << warmup_ocalls << std::endl;
      return false;
    }
    if (std::chrono::steady_clock::now() >= next_progress) {
      std::cout << "[P10][mixed-warmup] waiting group=" << group_id
                << " workers=" << workload.worker_count
                << " ocalls_completed=" << warmup_ocalls
                << " pending:";
      for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
        uint64_t state = mixed_worker_state(
            enclaves[worker + 1], workload, worker);
        if (!mixed_worker_finished_warmup(state))
          std::cout << " worker=" << worker
                    << "/lane=" << workload.lane[worker]
                    << "/state=" << state;
      }
      std::cout << std::endl;
      next_progress = std::chrono::steady_clock::now() +
          std::chrono::seconds(10);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

void
print_mixed_timeout_diagnostics(
    Keystone::KeystoneDevice& device, uint64_t group_id,
    const std::vector<EnclaveInstance>& enclaves,
    const MixedWorkload& workload, uint64_t master_markers,
    uint64_t worker_ready_events, bool master_exited,
    bool master_waiting_for_workers, size_t worker_exit_count) {
  struct keystone_group_test_snapshot group;
  struct keystone_group_perf_snapshot perf;

  std::cerr << "[P10][mixed-timeout] control: master_markers="
            << master_markers
            << " master_exited=" << master_exited
            << " master_waiting=" << master_waiting_for_workers
            << " worker_ready_events=" << worker_ready_events
            << " worker_exits=" << worker_exit_count << "/"
            << workload.worker_count << std::endl;

  for (uint64_t index = 0; index < enclaves.size(); ++index) {
    const uint8_t* utm = static_cast<const uint8_t*>(
        enclaves[index].enclave->getSharedBuffer());
    size_t utm_size = enclaves[index].enclave->getSharedBufferSize();

    const uint64_t result_offset = index > 0 && workload.workload_id ?
        GROUP_PMP_SQLITE_VFS_RESULT_OFFSET : GROUP_PMP_MIXED_RESULT_OFFSET;
    if (!utm || utm_size < result_offset +
                             sizeof(struct group_pmp_mixed_worker_result)) {
      std::cerr << "[P10][mixed-timeout] utm unavailable: member="
                << index << std::endl;
      continue;
    }
    __sync_synchronize();
    if (index == 0) {
      struct group_pmp_mixed_master_result result;

      std::memcpy(&result, utm + result_offset,
                  sizeof(result));
      std::cerr << "[P10][mixed-timeout] master: status=" << result.status
                << " sequence=" << result.sequence
                << " dispatches=" << result.slot_dispatches
                << " aggregates=" << result.slot_aggregates
                << " wait_yields=" << result.slot_wait_yields
                << " validation=" << result.validation_ok << std::endl;
    } else {
      struct group_pmp_mixed_worker_result result;

      std::memcpy(&result, utm + result_offset,
                  sizeof(result));
      std::cerr << "[P10][mixed-timeout] worker=" << (index - 1)
                << " eid=" << enclaves[index].enclave->getEid()
                << " lane=" << workload.lane[index - 1]
                << " rank=" << workload.lane_rank[index - 1]
                << " status=" << result.status
                << " failure_stage="
                << (result.status == GROUP_PMP_MIXED_STATE_FAILED ?
                    result.digest : 0)
                << " batches=" << result.batch_count
                << " ocalls=" << result.ocall_count
                << " aes_cycles=" << result.aes_cycles
                << " protocol_cycles=" << result.protocol_cycles
                << " grant_revoke=" << result.grant_revoke_ok << std::endl;
      if (workload.workload_id) {
        for (uint64_t slot = 0; slot < GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT;
             ++slot) {
          const uint64_t offset = GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot);
          if (offset > utm_size ||
              sizeof(group_pmp_sqlite_vfs_ring_header) > utm_size - offset)
            continue;
          const auto* ring = reinterpret_cast<const
              group_pmp_sqlite_vfs_ring_header*>(utm + offset);
          std::cerr << "[P10][mixed-timeout] worker=" << (index - 1)
                    << " ring=" << slot
                    << " generation=" << __atomic_load_n(&ring->generation, __ATOMIC_ACQUIRE)
                    << " producer=" << __atomic_load_n(&ring->producer, __ATOMIC_ACQUIRE)
                    << " consumer=" << __atomic_load_n(&ring->consumer, __ATOMIC_ACQUIRE)
                    << " completed=" << __atomic_load_n(&ring->completion_count, __ATOMIC_ACQUIRE)
                    << " host_received=" << __atomic_load_n(&ring->host_received_ticks, __ATOMIC_ACQUIRE)
                    << " host_ack=" << __atomic_load_n(&ring->host_ack_ticks, __ATOMIC_ACQUIRE)
                    << " resume_requested=" << __atomic_load_n(&ring->host_resume_request_ticks, __ATOMIC_ACQUIRE)
                    << std::endl;
        }
      }
    }
  }

  {
    std::lock_guard<std::mutex> lock(deferred_group_ocall_mutex);
    for (const auto& pending : deferred_group_ocalls) {
      if (pending.group_id == group_id)
        std::cerr << "[P10][mixed-timeout] pending-ocall: eid=" << pending.eid
                  << " hart=" << pending.hart_id << " ocall=" << pending.ocall_id
                  << " io_complete=" << (pending.completion && pending.completion->isComplete())
                  << std::endl;
    }
    for (const auto& completed : completed_group_ocalls) {
      if (completed.group_id == group_id)
        std::cerr << "[P10][mixed-timeout] queued-resume: eid=" << completed.eid
                  << " hart=" << completed.hart_id << " ocall=" << completed.ocall_id
                  << std::endl;
    }
  }

  std::memset(&group, 0, sizeof(group));
  if (device.groupTestSnapshot(group_id, &group) == Error::Success) {
    std::cerr << "[P10][mixed-timeout] sm: generation="
              << group.group_generation
              << " active_harts=0x" << std::hex << group.active_harts
              << " acquired_yxstm=0x" << group.acquired_yxstm_harts
              << std::dec
              << " runqueue=" << group.runqueue_entries
              << " events=" << group.event_queue_entries
              << " event_overflows=" << group.event_queue_overflows
              << " running_workers=" << group.running_workers
              << " max_running_workers=" << group.max_running_workers
              << " lane_switches=" << group.lane_owner_switches
              << " lane_scrubs=" << group.lane_scrubs << std::endl;
  } else {
    std::cerr << "[P10][mixed-timeout] SM group snapshot failed"
              << std::endl;
  }

  std::memset(&perf, 0, sizeof(perf));
  if (device.groupPerfQuery(
          group_id, KEYSTONE_GROUP_PERF_QUERY, &perf) == Error::Success) {
    std::cerr << "[P10][mixed-timeout] perf: window=" << perf.window_state
              << " acquire=" << perf.acquire_count
              << " release=" << perf.release_count
              << " lane_wait_block=" << perf.lane_wait_block_count
              << " lane_wait_wake=" << perf.lane_wait_wake_count
              << " context_switch=" << perf.context_switch_count
              << " cfs_pick=" << perf.cfs_pick_count
              << " cfs_preempt=" << perf.cfs_preempt_count
              << " timer_traps=" << perf.timer_trap_count
              << " host_services=" << perf.host_service_count
              << " sm_ocalls=" << perf.ocall_count << std::endl;
  } else {
    std::cerr << "[P10][mixed-timeout] SM performance snapshot failed"
              << std::endl;
  }
}

bool
run_mixed_group_3w1hm(uint64_t group_id,
                      std::vector<EnclaveInstance>& enclaves,
                      const MixedWorkload& workload,
                      MixedRunTiming* timing) {
  const uint64_t event_mask =
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_WORKERS_READY) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_EXIT) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_OCALL) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_FAULT) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_WATCHDOG) |
      KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_HEARTBEAT);
  const uint64_t overall_timeout_sec = env_u64(
      "GROUP_PMP_MIXED_TIMEOUT_SEC", 300, 10, 3600);
  const uint64_t stall_timeout_sec = env_u64(
      "GROUP_PMP_MIXED_STALL_TIMEOUT_SEC", 60, 10, 3600);
  uint64_t lease_flags = KEYSTONE_GROUP_LEASE_FLAG_REQUIRE_ISOLATION |
      KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE |
      KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE;
  const char* fallback = std::getenv("GROUP_PMP_LEASE_TEST_FALLBACK");
  Keystone::KeystoneDevice device;
  Params params;
  struct keystone_group_topology topology;
  struct keystone_group_lease lease;
  std::vector<uint64_t> worker_exit_eids;
  uint64_t master_markers = 0;
  uint64_t worker_ready_events = 0;
  std::map<uint64_t, uint64_t> queue_overflow_baseline;
  bool master_exited = false;
  bool master_waiting_for_workers = false;
  bool ok = true;

  if (!timing || enclaves.size() != workload.worker_count + 1 ||
      !pin_current_thread_to_cpu(static_cast<int>(kHousekeepingCpu),
                                 "mixed-scale") ||
      !device.initDevice(params))
    return false;
  if (group_has_deferred_ocalls(group_id))
    return false;
  deferred_group_ocall_failure.store(false, std::memory_order_release);
  if (fallback && std::strcmp(fallback, "1") == 0) {
    lease_flags &= ~(KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE |
                     KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE);
    lease_flags |= KEYSTONE_GROUP_LEASE_FLAG_TEST_FALLBACK |
                   KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT;
  }
  std::memset(&topology, 0, sizeof(topology));
  std::memset(&lease, 0, sizeof(lease));
  if (device.groupQueryTopology(group_id, &topology) != Error::Success ||
      topology.execution_mode != GROUP_MODE_3W_1HM ||
      topology.master_hart != kHousekeepingHart ||
      topology.worker_hart_mask != KEYSTONE_VF2_WORKER_HART_MASK)
    return false;
  Error lease_error = device.groupLeaseWorkers(
      group_id, lease_flags, &lease);
  if (lease_error != Error::Success) {
    std::cerr << "[P10][mixed-scale] worker lease failed: "
              << error_name(lease_error) << std::endl;
    return false;
  }
  if (!wait_mixed_workers_warmed(device, group_id, enclaves, workload,
                                 &queue_overflow_baseline))
    ok = false;
  if (ok) {
    struct keystone_group_perf_snapshot warmup_perf;

    std::cerr << "[P10][mixed-warmup] complete group=" << group_id
              << " workers=" << workload.worker_count
              << "; entering measured flow" << std::endl;
    std::memset(&warmup_perf, 0, sizeof(warmup_perf));
    if (device.groupPerfQuery(group_id, KEYSTONE_GROUP_PERF_RESET,
                              &warmup_perf) != Error::Success) {
      std::cerr << "[P10][mixed-scale] failed to reset post-warmup "
                   "performance counters"
                << std::endl;
      ok = false;
    }
  }

  const std::chrono::steady_clock::time_point overall_deadline =
      std::chrono::steady_clock::now() +
      std::chrono::seconds(overall_timeout_sec);
  const bool security_capture = std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR") != nullptr;
  const auto progress_clock = [security_capture]() {
    return security_capture ? security_checkpoint_clock().workload_now()
                            : std::chrono::steady_clock::now();
  };
  auto last_event_progress = progress_clock();
  for (uint64_t step = 0; ok && step < 1000000; ++step) {
    if (!resume_completed_group_ocalls(
            device, group_id, "mixed-worker-async-io")) {
      ok = false;
      break;
    }
    if (stop_requested) {
      std::cerr << "[P10][mixed-scale] interrupted; releasing worker lease"
                << std::endl;
      print_mixed_timeout_diagnostics(
          device, group_id, enclaves, workload, master_markers,
          worker_ready_events, master_exited, master_waiting_for_workers,
          worker_exit_eids.size());
      ok = false;
      break;
    }
    if (!master_exited && !master_waiting_for_workers) {
      uintptr_t value = 0;
      uint64_t event_eid = 0;
      uint64_t event = KEYSTONE_GROUP_EVENT_NONE;
      uint64_t overflows = 0;
      Error error = device.groupRunMaster(
          group_id, &event_eid, &event, &value, nullptr, nullptr,
          &overflows);
      last_event_progress = progress_clock();
      if (overflows || error == Error::EnclaveFatalFault ||
          event == KEYSTONE_GROUP_EVENT_FAULT ||
          event == KEYSTONE_GROUP_EVENT_WATCHDOG) {
        std::cerr << "[P10][mixed-scale] master fault: error="
                  << error_name(error) << " event=" << event
                  << " eid=" << event_eid << " value=" << value
                  << std::endl;
        ok = false;
        break;
      }
      if (event == KEYSTONE_GROUP_EVENT_OCALL) {
        uint64_t master_eid =
            static_cast<uint64_t>(enclaves[0].enclave->getEid());
        if (event_eid != master_eid || master_markers >= 2) {
          ok = false;
          break;
        }
        if (master_markers == 0) {
          struct keystone_group_perf_snapshot begin_perf;

          std::memset(&begin_perf, 0, sizeof(begin_perf));
          if (device.groupPerfQuery(
                  group_id, KEYSTONE_GROUP_PERF_BEGIN,
                  &begin_perf) != Error::Success ||
              begin_perf.window_state !=
                  KEYSTONE_GROUP_PERF_WINDOW_ACTIVE) {
            std::cerr << "[P10][mixed-scale] failed to begin performance "
                         "window"
                      << std::endl;
            ok = false;
            break;
          }
          if (workload.workload_id && !workload.rv8_profile && !sqlite_selected_io_reset_perf()) {
            std::cerr << "[P10][sqlite] failed to establish "
                      << sqlite_benchmark_cache_mode_name()
                      << " cache state after data preparation" << std::endl;
            ok = false;
            break;
          }
          if (workload.workload_id)
            sqlite_gantt_trace().beginWindow(group_id);
          if (workload.workload_id)
            sqlite_io_range_trace().beginWindow();
          timing->start_ns = monotonic_raw_ns();
          timing->started = true;
        }
        if (!dispatch_and_resume_group_ocall(
                device, group_id, topology.master_hart, event_eid,
                value, &enclaves, "mixed-master", true)) {
          ok = false;
          break;
        }
        master_markers++;
        continue;
      } else if (event == KEYSTONE_GROUP_EVENT_EXIT) {
        const uint64_t expected_eid = static_cast<uint64_t>(
            enclaves[0].enclave->getEid());
        if (event_eid != expected_eid || value != 0) {
          std::cerr << "[P10][mixed-scale] master exited with error: eid="
                    << event_eid << " expected=" << expected_eid
                    << " eapp_status=" << value
                    << " markers=" << master_markers << std::endl;
          ok = false;
        } else {
          master_exited = true;
        }
      } else if (error == Error::EnclaveInterrupted ||
                 error == Error::GroupNotRunnable ||
                 event == KEYSTONE_GROUP_EVENT_INTERRUPTED) {
        if (!timing->started) {
          std::cerr << "[P10][mixed-scale] unexpected master wait: markers="
                    << master_markers
                    << " event=" << event << std::endl;
          ok = false;
          break;
        }
        master_waiting_for_workers = true;
        if (workload.workload_id)
          sqlite_gantt_trace().recordPoint(
              SQLITE_GANTT_MASTER_WAIT_BEGIN, group_id,
              topology.master_hart, event_eid, event);
      } else if (error != Error::Success &&
                 error != Error::EnclaveInterrupted &&
                 error != Error::GroupNotRunnable) {
        std::cerr << "[P10][mixed-scale] groupRunMaster failed: "
                  << error_name(error) << " event=" << event << std::endl;
        ok = false;
        break;
      }
    }

    if (master_exited &&
        worker_exit_eids.size() == workload.worker_count) {
      timing->stop_ns = monotonic_raw_ns();
      timing->stopped = true;
      if (device.groupPerfQuery(
              group_id, KEYSTONE_GROUP_PERF_FREEZE,
              &timing->perf) != Error::Success ||
          timing->perf.window_state != KEYSTONE_GROUP_PERF_WINDOW_FROZEN) {
        std::cerr << "[P10][mixed-scale] failed to freeze performance window"
                  << std::endl;
        ok = false;
      } else {
        timing->perf_frozen = true;
      }
      if (workload.workload_id && !workload.rv8_profile) {
        // Publication can precede final Host stats; drain outside both timing windows.
        timing->sqlite_perf = sqlite_selected_io_snapshot(true);
        sqlite_gantt_trace().endWindow(true);
        sqlite_io_range_trace().endWindow();
      }
      break;
    }
    const auto now = std::chrono::steady_clock::now();
    const auto progress_now = progress_clock();
    const bool event_stalled = progress_now - last_event_progress >=
        std::chrono::seconds(stall_timeout_sec);
    if (now >= overall_deadline || event_stalled) {
      std::cerr << "[P10][mixed-scale] "
                << (event_stalled ? "no task/OCALL event progress" : "run timed out")
                << ": idle_seconds="
                << std::chrono::duration_cast<std::chrono::seconds>(
                       progress_now - last_event_progress).count()
                << " worker_exits="
                << worker_exit_eids.size() << "/"
                << workload.worker_count << std::endl;
      print_mixed_timeout_diagnostics(
          device, group_id, enclaves, workload, master_markers,
          worker_ready_events, master_exited, master_waiting_for_workers,
          worker_exit_eids.size());
      ok = false;
      break;
    }

    struct keystone_group_wait_event ready;
    std::memset(&ready, 0, sizeof(ready));
    /* SQLite completion directly resumes the BLOCKED enclave from the I/O
     * service thread. CPU0 can remain asleep on the driver event waitqueue. */
    const uint64_t event_timeout_ms = UINT64_C(1000);
    Error wait_error = device.groupWaitEvent(
        group_id, event_mask, event_timeout_ms, &ready);
    if (wait_error == Error::GroupEventTimeout)
      continue;
    const uint64_t ready_overflow_baseline =
        queue_overflow_baseline[ready.hart_id];
    if (ready.queue_overflows > ready_overflow_baseline ||
        wait_error == Error::EnclaveFatalFault ||
        wait_error == Error::GroupIOError ||
        ready.event == KEYSTONE_GROUP_EVENT_FAULT ||
        ready.event == KEYSTONE_GROUP_EVENT_WATCHDOG ||
        ready.event == KEYSTONE_GROUP_EVENT_HEARTBEAT) {
      std::cerr << "[P10][mixed-scale] worker event failure: error="
                << error_name(wait_error) << " event=" << ready.event
                << " hart=" << ready.hart_id << " eid=" << ready.eid
                << " value=" << ready.value
                << " queue_overflows=" << ready.queue_overflows
                << " warmup_overflow_baseline="
                << ready_overflow_baseline << std::endl;
      ok = false;
      break;
    }
    if (wait_error != Error::Success) {
      std::cerr << "[P10][mixed-scale] groupWaitEvent failed: "
                << error_name(wait_error) << std::endl;
      ok = false;
      break;
    }
    last_event_progress = progress_clock();
    if (ready.event == KEYSTONE_GROUP_EVENT_OCALL) {
      if (!is_worker_eid(enclaves, ready.eid) ||
          !dispatch_and_resume_group_ocall(
              device, group_id, ready.hart_id, ready.eid, ready.value,
              &enclaves, "mixed-worker", true)) {
        std::cerr << "[P10][mixed-scale] invalid worker OCALL: eid="
                  << ready.eid << std::endl;
        ok = false;
        break;
      }
      timing->worker_ocalls++;
      continue;
    } else if (ready.event == KEYSTONE_GROUP_EVENT_EXIT) {
      if (workload.workload_id)
        sqlite_gantt_trace().recordPoint(
            SQLITE_GANTT_ENCLAVE_EXIT, group_id, ready.hart_id, ready.eid,
            ready.value);
      if (!is_worker_eid(enclaves, ready.eid) || ready.value != 0 ||
          std::find(worker_exit_eids.begin(), worker_exit_eids.end(),
                    ready.eid) != worker_exit_eids.end()) {
        uint64_t worker_index = workload.worker_count;
        uint64_t worker_state = UINT64_MAX;
        uint64_t failure_stage = 0;
        uint64_t batches = 0;
        uint64_t vfs_submits = 0;
        uint64_t vfs_waits = 0;
        uint64_t vfs_read_bytes = 0;
        uint64_t vfs_write_bytes = 0;
        uint64_t vfs_last_error = 0;

        for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
          if (static_cast<uint64_t>(
                  enclaves[worker + 1].enclave->getEid()) != ready.eid)
            continue;
          worker_index = worker;
          worker_state = mixed_worker_state(
              enclaves[worker + 1], workload, worker);
          const uint8_t* utm = static_cast<const uint8_t*>(
              enclaves[worker + 1].enclave->getSharedBuffer());
          if (utm) {
            const volatile struct group_pmp_mixed_worker_result* result =
                reinterpret_cast<const volatile
                    struct group_pmp_mixed_worker_result*>(
                        utm + (workload.workload_id ?
                            GROUP_PMP_SQLITE_VFS_RESULT_OFFSET :
                            GROUP_PMP_MIXED_RESULT_OFFSET));
            __sync_synchronize();
            failure_stage = worker_state == GROUP_PMP_MIXED_STATE_FAILED ?
                result->digest : 0;
            batches = result->batch_count;
            vfs_submits = result->vfs_submit_count;
            vfs_waits = result->vfs_wait_count;
            vfs_read_bytes = result->vfs_read_bytes;
            vfs_write_bytes = result->vfs_write_bytes;
            vfs_last_error = result->vfs_last_error;
          }
          break;
        }
        std::cerr << "[P10][mixed-scale] worker exited with error: eid="
                  << ready.eid << " eapp_status=" << ready.value
                  << " error=" << error_name(wait_error)
                  << " hart=" << ready.hart_id
                  << " worker=" << worker_index
                  << " state=" << worker_state
                  << " failure_stage=" << failure_stage
                  << " batches=" << batches
                  << " vfs_submits=" << vfs_submits
                  << " vfs_waits=" << vfs_waits
                  << " vfs_read_bytes=" << vfs_read_bytes
                  << " vfs_write_bytes=" << vfs_write_bytes
                  << " vfs_last_error=" << vfs_last_error << std::endl;
        ok = false;
        break;
      }
      worker_exit_eids.push_back(ready.eid);
    } else if (ready.event == KEYSTONE_GROUP_EVENT_WORKERS_READY) {
      const uint64_t ready_phase = ready.value >> 56;
      const uint64_t ready_bank = (ready.value >> 48) & UINT64_C(0xff);
      const uint64_t ready_task_epoch =
          ready.value & UINT64_C(0x0000ffffffffffff);
      const uint64_t master_eid = static_cast<uint64_t>(
          enclaves[0].enclave->getEid());

      /* Slot metadata remains authoritative; this event only wakes CPU0. */
      if (ready.eid != master_eid ||
          ready_phase != YXSTM_PHASE_COMPUTE ||
          ready_bank >= GROUP_PMP_MIXED_BANK_COUNT || !ready_task_epoch) {
        std::cerr << "[P10][mixed-scale] invalid slot-complete wake: phase="
                  << ready_phase << " bank=" << ready_bank
                  << " task_epoch=" << ready_task_epoch
                  << " waiting=" << master_waiting_for_workers
                  << " eid=" << ready.eid << std::endl;
        ok = false;
        break;
      }
      worker_ready_events++;
      if (workload.workload_id)
        sqlite_gantt_trace().recordPoint(
            SQLITE_GANTT_WORKERS_READY, group_id, ready.hart_id, ready.eid,
            ready.value);
      if (workload.workload_id && master_waiting_for_workers)
        sqlite_gantt_trace().recordPoint(
            SQLITE_GANTT_MASTER_WAKEUP, group_id, topology.master_hart,
            static_cast<uint64_t>(enclaves[0].enclave->getEid()),
            ready.value);
      master_waiting_for_workers = false;
      if (master_exited) {
        uintptr_t value = 0;
        uint64_t event_eid = 0;
        uint64_t event = KEYSTONE_GROUP_EVENT_NONE;
        uint64_t overflows = 0;
        Error commit_error = device.groupRunMaster(
            group_id, &event_eid, &event, &value, nullptr, nullptr,
            &overflows);

        /*
         * The final slot completion can reach CPU0 after the master has
         * already aggregated that slot and exited. groupRunMaster still
         * commits the HSM WORKERS_READY sequence in the driver before the SM
         * reports that no master is runnable. Without this terminal commit,
         * the lane runner cannot expose the worker's following OCALL/EXIT.
         */
        if (overflows || event == KEYSTONE_GROUP_EVENT_FAULT ||
            event == KEYSTONE_GROUP_EVENT_WATCHDOG ||
            (commit_error != Error::Success &&
             commit_error != Error::EnclaveInterrupted &&
             commit_error != Error::GroupNotRunnable)) {
          std::cerr << "[P10][mixed-scale] terminal worker-ready commit "
                       "failed: error="
                    << error_name(commit_error) << " event=" << event
                    << " eid=" << event_eid << " value=" << value
                    << " overflows=" << overflows << std::endl;
          ok = false;
          break;
        }
      }
      continue;
    } else {
      std::cerr << "[P10][mixed-scale] unsupported event="
                << ready.event << " eid=" << ready.eid << std::endl;
      ok = false;
      break;
    }
  }

  if (ok && timing->perf_frozen) {
    uint64_t member_exec_sum = 0;
    uint64_t member_aes_sum = 0;

    for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
      struct keystone_group_perf_snapshot member_perf;
      uint64_t member_eid = static_cast<uint64_t>(
          enclaves[worker + 1].enclave->getEid());

      std::memset(&member_perf, 0, sizeof(member_perf));
      if (device.groupPerfQuery(
              group_id, KEYSTONE_GROUP_PERF_QUERY, &member_perf,
              member_eid) != Error::Success ||
          member_perf.window_state != KEYSTONE_GROUP_PERF_WINDOW_FROZEN ||
          member_perf.member_eid != member_eid ||
          member_perf.member_role != GROUP_ROLE_WORKER ||
          member_perf.member_aes_exec_runtime_ticks == 0 ||
          member_perf.member_exec_runtime_ticks <
              member_perf.member_aes_exec_runtime_ticks) {
        std::cerr << "[P10][mixed-scale] invalid per-member runtime: eid="
                  << member_eid
                  << " exec_mtime_ticks="
                  << member_perf.member_exec_runtime_ticks
                  << " aes_oncpu_mtime_ticks="
                  << member_perf.member_aes_exec_runtime_ticks << std::endl;
        ok = false;
        break;
      }
      member_exec_sum += member_perf.member_exec_runtime_ticks;
      member_aes_sum += member_perf.member_aes_exec_runtime_ticks;
    }
    if (ok &&
        (member_exec_sum != timing->perf.worker_exec_runtime_ticks ||
         member_aes_sum != timing->perf.worker_aes_exec_runtime_ticks ||
         timing->perf.worker_aes_exec_runtime_ticks == 0 ||
         timing->perf.worker_aes_exec_runtime_min == 0 ||
         timing->perf.worker_aes_exec_runtime_max == 0 ||
         timing->perf.worker_runtime_members != workload.worker_count)) {
      std::cerr << "[P10][mixed-scale] per-member runtime sum mismatch: "
                << "exec=" << member_exec_sum << "/"
                << timing->perf.worker_exec_runtime_ticks
                << " aes=" << member_aes_sum << "/"
                << timing->perf.worker_aes_exec_runtime_ticks
                << " members=" << timing->perf.worker_runtime_members << "/"
                << workload.worker_count << std::endl;
      ok = false;
    }
  }

  if (ok && (!resume_completed_group_ocalls(
                  device, group_id, "mixed-worker-final") ||
             group_has_deferred_ocalls(group_id))) {
    std::cerr << "[P10][mixed-scale] incomplete deferred SQLite OCALLs at "
                 "worker lease release"
              << std::endl;
    ok = false;
  }
  Error release_error = device.groupReleaseWorkers(
      group_id, lease_flags, &lease);
  if (release_error != Error::Success) {
    std::cerr << "[P10][mixed-scale] lease release failed: "
              << error_name(release_error) << std::endl;
    ok = false;
  }
  clear_deferred_group_ocalls(group_id);
  const uint64_t expected_batches = mixed_total_batch_count(workload);
  const uint64_t fixed_worker_ocalls =
      workload.worker_count *
          group_pmp_mixed_expected_ocalls(workload.ocall_mode);
  /*
   * AES mixed mode has a fixed synthetic OCALL contract. SQLite's encrypted
   * asynchronous VFS submits one OCALL per descriptor batch, so its count
   * depends on the workload, request granularity and UTM packing capacity.
   * Require at least one VFS transaction per worker here; after
   * reading the enclave result records, run_mixed_scaling_case() verifies the
   * exact host-event count against the summed VFS submit counters.
   *
   * Deployment marker: keystone-sqlite-vfs-ocall-accounting-v1
   */
  const bool worker_ocalls_valid = workload.rv8_profile ? timing->worker_ocalls == 0 : workload.workload_id ?
      timing->worker_ocalls >= workload.worker_count :
      timing->worker_ocalls == fixed_worker_ocalls;
  if (ok && (!timing->started || !timing->stopped ||
      !timing->perf_frozen ||
      master_markers != 2 ||
      worker_ready_events == 0 || worker_ready_events > expected_batches ||
      !master_exited || worker_exit_eids.size() != workload.worker_count ||
      !worker_ocalls_valid)) {
    std::cerr << "[P10][mixed-scale] final invariant failed: started="
              << timing->started << " stopped=" << timing->stopped
              << " perf_frozen=" << timing->perf_frozen
              << " master_markers=" << master_markers << "/2"
              << " worker_ready_events=" << worker_ready_events
              << " expected_range=1.." << expected_batches
              << " master_exited=" << master_exited
              << " worker_exits=" << worker_exit_eids.size() << "/"
              << workload.worker_count
              << " worker_ocalls=" << timing->worker_ocalls << "/"
              << (workload.workload_id ? workload.worker_count :
                  fixed_worker_ocalls)
              << (workload.workload_id ? "-or-more-vfs" : "-fixed")
              << std::endl;
    ok = false;
  }
  return ok;
}

bool
mixed_double_percentile(const std::vector<MixedRunMetrics>& samples,
                        double MixedRunMetrics::*field,
                        uint64_t percent,
                        double* value) {
  std::vector<double> values;

  if (!value || samples.empty() || percent > 100)
    return false;
  values.reserve(samples.size());
  for (size_t i = 0; i < samples.size(); ++i)
    values.push_back(samples[i].*field);
  *value = nearest_rank_percentile(values, percent);
  return true;
}

struct MixedWorkerResultTotals {
  uint64_t rv8_bytes, rv8_blocks, rv8_cpu_ticks, rv8_elapsed_ticks;
  uint64_t aes_cycles;
  uint64_t aes_time_ticks;
  uint64_t aes_elapsed_time_ticks;
  uint64_t protocol_cycles;
  uint64_t protocol_time_ticks;
  uint64_t ready_wait_time_ticks;
  uint64_t ocall_time_ticks;
  uint64_t vfs_read_bytes;
  uint64_t vfs_write_bytes;
  uint64_t vfs_encrypt_cycles;
  uint64_t vfs_decrypt_cycles;
  uint64_t vfs_submit_count;
  uint64_t vfs_wait_count;
  uint64_t vfs_yield_count;
  uint64_t vfs_wait_ticks;
  uint64_t vfs_batch_submit_count;
  uint64_t vfs_blocked_completion_count;
  uint64_t vfs_queue_depth_peak;
  uint64_t vfs_ring_doorbell_count;
  uint64_t vfs_ring_request_count;
  uint64_t vfs_completion_batch_count;
  uint64_t vfs_crypto_io_sample_ticks;
  uint64_t vfs_crypto_io_overlap_ticks;
  uint64_t vfs_both_buffers_wait_ticks;
  uint64_t vfs_completion_local_reaps;
  uint64_t vfs_buffer_reuses;
  struct group_pmp_sqlite_pipeline_timing pipeline;
};

bool
read_mixed_results(const std::vector<EnclaveInstance>& enclaves,
                   const MixedWorkload& workload,
                   struct MixedWorkerResultTotals* worker_totals,
                   struct group_pmp_mixed_master_result* master_result,
                   uint64_t* digest) {
  const uint8_t* master_utm = static_cast<const uint8_t*>(
      enclaves[0].enclave->getSharedBuffer());
  struct group_pmp_mixed_master_result master;
  const uint64_t aggregate_record_bytes = workload.workload_id ?
      sizeof(struct group_pmp_sqlite_packet_header) : UINT64_C(64);
  const uint64_t expected_dispatch_bytes = workload.workload_id ?
      mixed_total_batch_count(workload) *
          sizeof(struct group_pmp_sqlite_packet_header) :
      workload.total_bytes;

  if (!master_utm || !worker_totals ||
      !master_result || !digest)
    return false;
  std::memcpy(&master, master_utm + GROUP_PMP_MIXED_RESULT_OFFSET,
              sizeof(master));
  if (master.magic != GROUP_PMP_MIXED_MAGIC ||
      master.version != GROUP_PMP_MIXED_VERSION ||
      master.status != GROUP_PMP_MIXED_STATE_COMPLETED ||
      master.worker_count != workload.worker_count ||
      master.active_lanes != workload.active_lanes ||
      master.sequence != mixed_total_batch_count(workload) ||
      master.slot_dispatches != mixed_total_batch_count(workload) ||
      master.slot_aggregates != master.slot_dispatches ||
      master.validation_ok != 1 || master.aggregate_digest == 0 ||
      master.dispatch_cycles == 0 || master.compute_wall_cycles == 0 ||
      master.aggregate_cycles == 0 || master.protocol_cycles == 0 ||
      master.task_e2e_cycles == 0 || master.dispatch_time_ticks == 0 ||
      master.compute_wall_time_ticks == 0 ||
      master.aggregate_time_ticks == 0 ||
      master.protocol_time_ticks == 0 ||
      master.task_e2e_time_ticks == 0 ||
      master.dispatch_bytes != expected_dispatch_bytes ||
      master.aggregate_bytes !=
          master.slot_aggregates * aggregate_record_bytes) {
    std::cerr << "[P10][mixed-result] invalid master result: status="
              << master.status << " sequence=" << master.sequence
              << " dispatches=" << master.slot_dispatches
              << " aggregates=" << master.slot_aggregates
              << " validation=" << master.validation_ok
              << " dispatch_bytes=" << master.dispatch_bytes
              << " expected_dispatch_bytes=" << expected_dispatch_bytes
              << " aggregate_bytes=" << master.aggregate_bytes
              << " expected_aggregate_bytes="
              << master.slot_aggregates * aggregate_record_bytes
              << " expected_batches=" << mixed_total_batch_count(workload)
              << std::endl;
    return false;
  }
  for (uint64_t lane = 0; lane < workload.active_lanes; ++lane) {
    uint64_t expected = mixed_lane_batch_count(workload, lane);
    if (master.lane_dispatches[lane] != expected ||
        master.lane_aggregates[lane] != expected ||
        master.lane_dispatch_bytes[lane] != workload.lane_bytes[lane])
      return false;
  }

  *master_result = master;
  std::memset(worker_totals, 0, sizeof(*worker_totals));
  *digest = master.aggregate_digest;
  for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
    const uint8_t* utm = static_cast<const uint8_t*>(
        enclaves[worker + 1].enclave->getSharedBuffer());
    struct group_pmp_mixed_worker_result result;
    const uint64_t result_offset = workload.workload_id ?
        GROUP_PMP_SQLITE_VFS_RESULT_OFFSET : GROUP_PMP_MIXED_RESULT_OFFSET;
    uintptr_t expected_va = KEYSTONE_YXSTM_ENCLAVE_VA_BASE +
        (workload.lane[worker] + 1) * kMixedYxstmSliceSize +
        workload.lane_rank[worker] *
            group_pmp_mixed_slot_size(
                workload.lane_depth[workload.lane[worker]]);

    if (!utm)
      return false;
    std::memcpy(&result, utm + result_offset,
                sizeof(result));
    if (result.magic != GROUP_PMP_MIXED_MAGIC ||
        result.version != GROUP_PMP_MIXED_VERSION ||
        result.status != GROUP_PMP_MIXED_STATE_COMPLETED ||
        result.worker_index != worker ||
        result.worker_count != workload.worker_count ||
        result.lane_id != workload.lane[worker] ||
        result.lane_rank != workload.lane_rank[worker] ||
        result.data_bytes != workload.assigned_bytes[worker] ||
        result.end_cycle <= result.start_cycle ||
        (!workload.rv8_profile && (result.aes_cycles == 0 || result.aes_time_ticks == 0)) ||
        result.protocol_cycles == 0 || result.protocol_time_ticks == 0 ||
        result.ready_wait_time_ticks == 0 ||
        (!workload.rv8_profile && result.ocall_time_ticks == 0) ||
        (workload.rv8_profile ? result.ocall_count != 0 : workload.workload_id ? result.ocall_count == 0 :
         result.ocall_count !=
             group_pmp_mixed_expected_ocalls(workload.ocall_mode)) ||
        result.digest == 0 || result.known_answer_ok != 1 ||
        result.batch_count != mixed_worker_batch_count(workload, worker) ||
        result.cross_slot_denied != 1 || result.grant_revoke_ok != 1 ||
        result.observed_payload_va != expected_va) {
      std::cerr << "[P10][mixed-result] invalid worker result: worker="
                << worker << " status=" << result.status
                << " failure_stage="
                << (result.status == GROUP_PMP_MIXED_STATE_FAILED ?
                    result.digest : 0)
                << " lane=" << result.lane_id
                << " rank=" << result.lane_rank
                << " batches=" << result.batch_count
                << " ocalls=" << result.ocall_count
                << " revoke=" << result.grant_revoke_ok
                << " known_answer=" << result.known_answer_ok
                << std::endl;
      return false;
    }
    if (workload.workload_id && !workload.rv8_profile) {
      const bool read_workload =
          group_pmp_sqlite_is_read(workload.workload_id);
      const bool common_vfs_valid =
          result.vfs_submit_count &&
          result.aes_time_ticks &&
          result.aes_elapsed_time_ticks >= result.aes_time_ticks &&
          result.vfs_crypto_io_overlap_ticks <=
              result.vfs_crypto_io_sample_ticks &&
          result.vfs_batch_submit_count == result.ocall_count &&
          result.vfs_blocked_completion_count <= result.vfs_wait_count &&
          result.vfs_blocked_completion_count <= result.vfs_submit_count &&
          result.vfs_yield_count == 0 && result.vfs_queue_depth_peak &&
          result.vfs_submit_count >= result.vfs_batch_submit_count &&
          sqlite_ring_counts_valid(workload.workload_id,
              result.vfs_ring_doorbell_count, result.vfs_ring_request_count,
              result.vfs_completion_batch_count) &&
          result.hidden_copy_bytes ==
              result.vfs_read_bytes + result.vfs_write_bytes;
      const bool direction_vfs_valid = read_workload ?
          result.vfs_read_bytes && result.vfs_decrypt_cycles :
          result.vfs_write_bytes && result.vfs_encrypt_cycles;

      /*
       * Pre-window database setup is excluded from VFS counters. A measured
       * read workload therefore need not write/encrypt, and a measured write
       * workload need not read/decrypt. Validate only the required data-path
       * direction while retaining exact request and byte accounting.
       * A detached request may finish before wait_buffer observes PENDING, so
       * real BLOCKED completions are bounded by waits/submits rather than
       * being equal to the submission count.
       *
       * Deployment marker: keystone-sqlite-vfs-directional-accounting-v1
       * Deployment marker: keystone-sqlite-async-completion-accounting-v2
       */
      if (!common_vfs_valid || !direction_vfs_valid) {
        std::cerr << "[P10][sqlite] invalid directional VFS result: worker="
                  << worker << " workload=" << workload.workload_id
                  << " direction=" << (read_workload ? "read" : "write")
                  << " ocalls=" << result.ocall_count
                  << " submits=" << result.vfs_submit_count
                  << " batches=" << result.vfs_batch_submit_count
                  << " blocked=" << result.vfs_blocked_completion_count
                  << " queue_depth_peak=" << result.vfs_queue_depth_peak
                  << " ring_doorbells=" << result.vfs_ring_doorbell_count
                  << " ring_requests=" << result.vfs_ring_request_count
                  << " completion_batches="
                  << result.vfs_completion_batch_count
                  << " yields=" << result.vfs_yield_count
                  << " waits=" << result.vfs_wait_count
                  << " wait_ticks=" << result.vfs_wait_ticks
                  << " read_bytes=" << result.vfs_read_bytes
                  << " write_bytes=" << result.vfs_write_bytes
                  << " encrypt_cycles=" << result.vfs_encrypt_cycles
                  << " decrypt_cycles=" << result.vfs_decrypt_cycles
                  << " hidden_copy_bytes=" << result.hidden_copy_bytes
                  << std::endl;
        return false;
      }
    }
    if (workload.kv_enabled) {
      struct kv_bench_stats kv;
      std::memcpy(&kv, utm + KV_RESULT_OFFSET, sizeof(kv));
      const bool get = workload.workload_id == GROUP_PMP_SQLITE_READRANDOM;
      if (kv.magic != KV_RESULT_MAGIC || kv.version != 1 ||
          kv.workload != workload.workload_id || kv.bytes != result.data_bytes ||
          kv.puts + kv.gets != result.vfs_ring_request_count ||
          kv.gets != kv.validated_gets ||
          (get ? (kv.puts != 0 || kv.gets == 0) : (kv.gets != 0 || kv.puts == 0))) {
        std::cerr << "[secure-kv] invalid KV coverage/result: worker=" << worker << std::endl;
        return false;
      }
    }
    if (workload.rv8_profile) {
      struct rv8_kernel_stats kernel;
      std::memcpy(&kernel, utm + RV8_RESULT_OFFSET, sizeof(kernel));
      if (kernel.magic != RV8_RESULT_MAGIC || kernel.version != 2 ||
          kernel.profile != workload.rv8_profile || !kernel.validated ||
          kernel.bytes != result.data_bytes || !kernel.blocks || !kernel.digest ||
          !kernel.cpu_ticks || kernel.cpu_ticks > kernel.elapsed_ticks ||
          result.aes_cycles || result.aes_time_ticks || result.vfs_read_bytes ||
          result.vfs_write_bytes || result.vfs_submit_count || result.vfs_wait_count ||
          result.hidden_copy_bytes || result.ocall_count) {
        std::cerr << "[rv8] invalid kernel coverage/timing: worker=" << worker << std::endl;
        return false;
      }
      worker_totals->rv8_bytes += kernel.bytes;
      worker_totals->rv8_blocks += kernel.blocks;
      worker_totals->rv8_cpu_ticks += kernel.cpu_ticks;
      worker_totals->rv8_elapsed_ticks += kernel.elapsed_ticks;
    }
    if (workload.diagnostic_flags & GROUP_PMP_MIXED_DIAG_MEMORY) {
      const uint64_t timebase_hz = riscv_timebase_hz();
      if (result.diagnostic_bytes != GROUP_PMP_AES_BASELINE_BYTES ||
          !result.yxstm_read_cycles || !result.yxstm_read_time_ticks ||
          !result.yxstm_write_cycles || !result.yxstm_write_time_ticks ||
          !result.yxstm_page_stride_cycles ||
          !result.yxstm_page_stride_time_ticks ||
          !result.yxstm_page_stride_accesses ||
          !result.diagnostic_aes_cycles ||
          !result.diagnostic_aes_time_ticks ||
          result.diagnostic_aes_bytes !=
              GROUP_PMP_AES_BASELINE_BYTES ||
          !result.diagnostic_hot_aes_cycles ||
          !result.diagnostic_hot_aes_time_ticks ||
          result.diagnostic_hot_aes_bytes !=
              GROUP_PMP_AES_BASELINE_BYTES ||
          !result.digest_cycles || !result.digest_time_ticks ||
          result.digest_bytes != result.batch_count * UINT64_C(64) ||
          !result.mapping_pte_flags || !result.mapping_leaf_count ||
          !result.mapping_min_leaf_size || !result.mapping_max_leaf_size ||
          result.mapping_cache_mode !=
              KEYSTONE_YXSTM_CACHE_PLATFORM_DEFAULT ||
          result.mapping_nx != 1 || result.mapping_linear != 1 ||
          result.mapping_alias_count != 0 ||
          !result.mapping_page_table_pages ||
          result.mapping_tlb_counter_supported !=
              KEYSTONE_YXSTM_TLB_COUNTER_UNAVAILABLE ||
          result.mapping_max_leaf_size < UINT64_C(2) * 1024 * 1024 ||
          result.payload_alignment != 0 ||
          result.hidden_copy_bytes != 0 || result.in_place != 1 ||
          !timebase_hz)
        return false;

      struct YxstmDiagnostic {
        const char* phase;
        uint64_t cycles;
        uint64_t ticks;
        uint64_t bytes;
      };
      const YxstmDiagnostic diagnostics[] = {
          {"input-read", result.yxstm_read_cycles,
           result.yxstm_read_time_ticks, result.diagnostic_bytes},
          {"output-write-rmw", result.yxstm_write_cycles,
           result.yxstm_write_time_ticks, result.diagnostic_bytes},
          {"aes-core", result.diagnostic_aes_cycles,
           result.diagnostic_aes_time_ticks,
           result.diagnostic_aes_bytes},
          {"aes-hot-block", result.diagnostic_hot_aes_cycles,
           result.diagnostic_hot_aes_time_ticks,
           result.diagnostic_hot_aes_bytes},
          {"digest-sparse", result.digest_cycles, result.digest_time_ticks,
           result.digest_bytes},
      };
      for (size_t metric = 0;
           metric < sizeof(diagnostics) / sizeof(diagnostics[0]);
           ++metric) {
        double elapsed =
            static_cast<double>(diagnostics[metric].ticks) /
            static_cast<double>(timebase_hz);
        std::cout << "[AES-DIAG] memory=YXSTM phase="
                  << diagnostics[metric].phase
                  << " data_mb="
                  << (static_cast<double>(diagnostics[metric].bytes) /
                      kDecimalMbBytes)
                  << " seconds=" << elapsed
                  << " cycles=" << diagnostics[metric].cycles
                  << " cycles_per_byte="
                  << (static_cast<double>(diagnostics[metric].cycles) /
                      diagnostics[metric].bytes)
                  << " mb_per_sec="
                  << ((static_cast<double>(diagnostics[metric].bytes) /
                       kDecimalMbBytes) / elapsed)
                  << std::endl;
      }
      std::cout << "[AES-DIAG] memory=YXSTM phase=page-stride"
                << " page_bytes=4096"
                << " accesses=" << result.yxstm_page_stride_accesses
                << " cycles_per_access="
                << (static_cast<double>(result.yxstm_page_stride_cycles) /
                    result.yxstm_page_stride_accesses)
                << " ns_per_access="
                << ((static_cast<double>(
                         result.yxstm_page_stride_time_ticks) /
                     static_cast<double>(timebase_hz)) * 1.0e9 /
                    result.yxstm_page_stride_accesses)
                << " hardware_tlb_miss_counter=unavailable"
                << " proxy=page-stride-latency"
                << std::endl;
      std::cout << "[AES-DIAG] mapping=YXSTM"
                << " pte_flags=0x" << std::hex
                << result.mapping_pte_flags << std::dec
                << " leaf_count=" << result.mapping_leaf_count
                << " min_leaf_bytes=" << result.mapping_min_leaf_size
                << " max_leaf_bytes=" << result.mapping_max_leaf_size
                << " cache=platform-default-no-pbmt"
                << " pte_pbmt=none"
                << " pma_source=linux-cma-or-buddy-normal-ram"
                << " sv39_2m_leaf="
                << (result.mapping_max_leaf_size >=
                    UINT64_C(2) * 1024 * 1024)
                << " nx=" << result.mapping_nx
                << " linear_va_pa_offset=" << result.mapping_linear
                << " aliases=" << result.mapping_alias_count
                << " page_table_pages=" << result.mapping_page_table_pages
                << " payload_alignment=" << result.payload_alignment
                << " direct_mapped_va=1 in_place=" << result.in_place
                << " hidden_copy_bytes=" << result.hidden_copy_bytes
                << std::endl;
      std::cout << "[AES-DIAG] bottleneck=YXSTM-AES"
                << " stream_cycles_per_byte="
                << (static_cast<double>(result.diagnostic_aes_cycles) /
                    result.diagnostic_aes_bytes)
                << " hot_block_cycles_per_byte="
                << (static_cast<double>(result.diagnostic_hot_aes_cycles) /
                    result.diagnostic_hot_aes_bytes)
                << " stream_over_hot_ratio="
                << ((static_cast<double>(result.diagnostic_aes_cycles) /
                     result.diagnostic_aes_bytes) /
                    (static_cast<double>(result.diagnostic_hot_aes_cycles) /
                     result.diagnostic_hot_aes_bytes))
                << " cache_policy=platform-default-no-pbmt"
                << " hidden_copy_bytes=" << result.hidden_copy_bytes
                << std::endl;
      if (g_epm_aes_path.valid) {
        double yxstm_stream_cpb =
            static_cast<double>(result.diagnostic_aes_cycles) /
            result.diagnostic_aes_bytes;
        double yxstm_hot_cpb =
            static_cast<double>(result.diagnostic_hot_aes_cycles) /
            result.diagnostic_hot_aes_bytes;
        double yxstm_read_mb_per_sec =
            (static_cast<double>(result.diagnostic_bytes) /
             kDecimalMbBytes) /
            (static_cast<double>(result.yxstm_read_time_ticks) /
             timebase_hz);
        double yxstm_write_mb_per_sec =
            (static_cast<double>(result.diagnostic_bytes) /
             kDecimalMbBytes) /
            (static_cast<double>(result.yxstm_write_time_ticks) /
             timebase_hz);

        std::cout << "[AES-DIAG] comparison=EPM-vs-YXSTM"
                  << " stream_cpb_ratio="
                  << (yxstm_stream_cpb /
                      g_epm_aes_path.stream_cycles_per_byte)
                  << " hot_cpb_ratio="
                  << (yxstm_hot_cpb / g_epm_aes_path.hot_cycles_per_byte)
                  << " read_bandwidth_ratio="
                  << (yxstm_read_mb_per_sec /
                      g_epm_aes_path.read_mb_per_sec)
                  << " write_bandwidth_ratio="
                  << (yxstm_write_mb_per_sec /
                      g_epm_aes_path.write_mb_per_sec)
                  << " interpretation=hot-ratio-is-instruction-path;"
                     "stream-minus-hot-and-bandwidth-ratios-is-memory-path"
                  << std::endl;
      }
    }
    worker_totals->aes_cycles += result.aes_cycles;
    worker_totals->aes_time_ticks += result.aes_time_ticks;
    worker_totals->aes_elapsed_time_ticks += result.aes_elapsed_time_ticks;
    worker_totals->protocol_cycles += result.protocol_cycles;
    worker_totals->protocol_time_ticks += result.protocol_time_ticks;
    worker_totals->ready_wait_time_ticks +=
        result.ready_wait_time_ticks;
    worker_totals->ocall_time_ticks += result.ocall_time_ticks;
    worker_totals->vfs_read_bytes += result.vfs_read_bytes;
    worker_totals->vfs_write_bytes += result.vfs_write_bytes;
    worker_totals->vfs_encrypt_cycles += result.vfs_encrypt_cycles;
    worker_totals->vfs_decrypt_cycles += result.vfs_decrypt_cycles;
    worker_totals->vfs_submit_count += result.vfs_submit_count;
    worker_totals->vfs_wait_count += result.vfs_wait_count;
    worker_totals->vfs_yield_count += result.vfs_yield_count;
    worker_totals->vfs_wait_ticks += result.vfs_wait_ticks;
    worker_totals->vfs_batch_submit_count += result.vfs_batch_submit_count;
    worker_totals->vfs_blocked_completion_count +=
        result.vfs_blocked_completion_count;
    worker_totals->vfs_queue_depth_peak = std::max(
        worker_totals->vfs_queue_depth_peak, result.vfs_queue_depth_peak);
    worker_totals->vfs_ring_doorbell_count +=
        result.vfs_ring_doorbell_count;
    worker_totals->vfs_ring_request_count += result.vfs_ring_request_count;
    worker_totals->vfs_completion_batch_count +=
        result.vfs_completion_batch_count;
    worker_totals->vfs_crypto_io_sample_ticks += result.vfs_crypto_io_sample_ticks;
    worker_totals->vfs_crypto_io_overlap_ticks += result.vfs_crypto_io_overlap_ticks;
    worker_totals->vfs_both_buffers_wait_ticks += result.vfs_both_buffers_wait_ticks;
    worker_totals->vfs_completion_local_reaps += result.vfs_completion_local_reaps;
    worker_totals->vfs_buffer_reuses += result.vfs_buffer_reuses;
    group_pmp_sqlite_pipeline_add(&worker_totals->pipeline, &result.pipeline);
  }
  return true;
}

bool
run_mixed_scaling_case(const char* master_eapp, const char* worker_eapp,
                       const char* runtime, const char* loader,
                       const MixedWorkload& workload,
                       const MixedRunMetrics* baseline,
                       MixedRunMetrics* metrics) {
  char worker_names[GROUP_PMP_MIXED_MAX_WORKERS][32] = {{0}};
  std::vector<EnclaveInstance> enclaves;
  MixedRunTiming timing;
  struct keystone_group_test_snapshot resources;
  struct keystone_group_perf_snapshot perf;
  struct MixedWorkerResultTotals worker_totals;
  struct group_pmp_mixed_master_result master_result;
  uint64_t digest = 0;
  const uint64_t base_worker_quantum = workload.workload_id ?
      env_u64("GROUP_PMP_SQLITE_CFS_QUANTUM_MULTIPLIER", 4, 1,
              KEYSTONE_GROUP_SCHED_QUANTUM_MAX) :
      KEYSTONE_GROUP_SCHED_QUANTUM_DEFAULT;
  const uint64_t lane_depth_scale = workload.workload_id ?
      std::max<uint64_t>(UINT64_C(1),
          std::min<uint64_t>(UINT64_C(8), workload.max_lane_depth)) :
      UINT64_C(1);
  const uint64_t worker_quantum = std::min<uint64_t>(
      KEYSTONE_GROUP_SCHED_QUANTUM_MAX,
      base_worker_quantum > KEYSTONE_GROUP_SCHED_QUANTUM_MAX /
              lane_depth_scale ?
          KEYSTONE_GROUP_SCHED_QUANTUM_MAX :
          base_worker_quantum * lane_depth_scale);
  bool ok = true;

  std::memset(&worker_totals, 0, sizeof(worker_totals));
  std::memset(&master_result, 0, sizeof(master_result));
  if (!metrics || !configure_default_group() ||
      !reset_group_perf_counters())
    return false;
  std::memset(metrics, 0, sizeof(*metrics));
  add_instance(enclaves, "mixed-master", master_eapp, kDefaultGroupId,
      workload.worker_count + 1, kMixedYxstmSize, kUtmSize,
      kMixedYxstmSliceSize,
      workload.workload_id ? kSqliteMasterFreeMemSize : kFreeMemSize);
  for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
    std::snprintf(worker_names[worker], sizeof(worker_names[worker]),
                  "mixed-worker-%02llu",
                  static_cast<unsigned long long>(worker + 1));
    add_instance(enclaves, worker_names[worker], worker_eapp,
        kDefaultGroupId, workload.worker_count + 1,
        kMixedYxstmSize,
        workload.rv8_profile ? UINT64_C(4096) : workload.workload_id ? kSqliteWorkerUtmSize : kUtmSize,
        kMixedYxstmSliceSize,
        workload.workload_id ? kSqliteWorkerFreeMemSize : kFreeMemSize);
  }
  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    destroy_instances(enclaves);
    return false;
  }
  if (!prepare_mixed_master(enclaves[0], workload))
    ok = false;
  for (uint64_t worker = 0; ok && worker < workload.worker_count; ++worker)
    if (!prepare_mixed_worker(enclaves[worker + 1], workload, worker))
      ok = false;
  if (ok && workload.workload_id && !workload.rv8_profile &&
      sqlite_benchmark_io_mode() != SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT) {
    std::vector<uint8_t*> utms(workload.worker_count);
    std::vector<size_t> utm_sizes(workload.worker_count);
    for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
      utms[worker] = reinterpret_cast<uint8_t*>(
          enclaves[worker + 1].enclave->getOcallBuffer());
      utm_sizes[worker] =
          enclaves[worker + 1].enclave->getOcallBufferSize();
    }
    if (!sqlite_selected_io_prepare_case(
            workload.workload_id, utms.data(), utm_sizes.data(),
            utms.size())) {
      std::cerr << "[P10][sqlite] failed to register data file and worker "
                   "UTM buffers before performance window"
                << std::endl;
      ok = false;
    }
  }
  if (ok && !bind_and_enqueue(enclaves[0], kHousekeepingHart,
                              KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT,
                              KEYSTONE_GROUP_SCHED_QUANTUM_DEFAULT))
    ok = false;
  for (uint64_t worker = 0; ok && worker < workload.worker_count; ++worker) {
    uint64_t cpu = 1 + workload.lane[worker];
    if (!bind_and_enqueue(enclaves[worker + 1], sm_hart_id_for_cpu(cpu),
                          KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT,
                          worker_quantum))
      ok = false;
  }
  if (ok)
    ok = run_mixed_group_3w1hm(
        kDefaultGroupId, enclaves, workload, &timing);
  if (ok)
    ok = read_mixed_results(enclaves, workload, &worker_totals,
                            &master_result,
                            &digest);
  const uint64_t expected_vfs_host_ocalls =
      sqlite_expected_host_ocalls(worker_totals.vfs_batch_submit_count,
                                  timing.sqlite_perf);
  if (ok && workload.workload_id && !workload.rv8_profile &&
      expected_vfs_host_ocalls != timing.worker_ocalls) {
    std::cerr << "[P10][sqlite] VFS OCALL accounting mismatch: host_events="
              << timing.worker_ocalls
              << " expected=" << expected_vfs_host_ocalls
              << " submit_batches="
              << worker_totals.vfs_batch_submit_count
              << " completion_waits="
              << timing.sqlite_perf.completion_wait_ocall_count
              << " intent_plans="
              << timing.sqlite_perf.pipeline[SQLITE_PIPELINE_INTENT_WINDOWS]
              << " extent_requests=" << worker_totals.vfs_submit_count
              << std::endl;
    ok = false;
  }
  if (ok && workload.workload_id && !workload.rv8_profile &&
      (timing.sqlite_perf.task_count != worker_totals.vfs_submit_count ||
       timing.sqlite_perf.batch_count !=
           worker_totals.vfs_batch_submit_count ||
        worker_totals.vfs_queue_depth_peak <
            GROUP_PMP_SQLITE_VFS_BUFFER_COUNT)) {
    std::cerr << "[P10][sqlite] Host/enclave async queue mismatch: host_tasks="
              << timing.sqlite_perf.task_count
              << " enclave_requests=" << worker_totals.vfs_submit_count
              << " host_batches=" << timing.sqlite_perf.batch_count
              << " enclave_batches="
              << worker_totals.vfs_batch_submit_count
              << " host_queue_depth_peak="
              << timing.sqlite_perf.queue_depth_peak
              << " worker_buffer_depth_peak="
              << worker_totals.vfs_queue_depth_peak
              << " required_depth=" << GROUP_PMP_SQLITE_VFS_BUFFER_COUNT
              << std::endl;
    ok = false;
  }
  if (ok && workload.workload_id && !workload.rv8_profile &&
      sqlite_benchmark_io_mode() != SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT &&
      (timing.sqlite_perf.buffer_registration_attempts != 1 ||
       timing.sqlite_perf.buffer_registration_failures != 0 ||
       timing.sqlite_perf.registered_file_operations == 0 ||
       timing.sqlite_perf.registered_buffer_operations == 0)) {
    std::cerr << "[P10][sqlite] registered I/O fast path was not exercised: "
              << "mode=" << sqlite_benchmark_io_mode_name()
              << " attempts="
              << timing.sqlite_perf.buffer_registration_attempts
              << " failures="
              << timing.sqlite_perf.buffer_registration_failures
              << " registered_file_ops="
              << timing.sqlite_perf.registered_file_operations
              << " registered_buffer_ops="
              << timing.sqlite_perf.registered_buffer_operations
              << " fixed_buffer_ops="
              << timing.sqlite_perf.fixed_buffer_operations
              << std::endl;
    ok = false;
  }
  const uint64_t allowed_read_amplification_permille =
      workload.workload_id && group_pmp_sqlite_is_read(workload.workload_id) &&
              sqlite_benchmark_io_mode() ==
                  SQLITE_BENCHMARK_IO_ADAPTIVE_EXTENT ?
          env_u64("GROUP_PMP_SQLITE_IO_READ_AMP_PERMILLE", 1100, 1000,
                  1200) :
          UINT64_C(1000);
  if (ok && workload.workload_id &&
      timing.sqlite_perf.useful_io_bytes &&
      timing.sqlite_perf.physical_io_bytes * UINT64_C(1000) >
          timing.sqlite_perf.useful_io_bytes *
              allowed_read_amplification_permille) {
    std::cerr << "[P10][sqlite] invalid extent read amplification: mode="
              << sqlite_benchmark_io_mode_name()
              << " physical_bytes="
              << timing.sqlite_perf.physical_io_bytes
              << " useful_bytes=" << timing.sqlite_perf.useful_io_bytes
              << " allowed_permille="
              << allowed_read_amplification_permille
              << " policy_version=" << sqlite_extent_io_policy_version()
              << std::endl;
    ok = false;
  }

  std::memset(&resources, 0, sizeof(resources));
  perf = timing.perf;
  if (ok && (!take_resource_snapshot(kDefaultGroupId, &resources) ||
              resources.running_workers != 0 ||
              resources.max_running_workers == 0 ||
              resources.max_running_workers > workload.active_lanes ||
              perf.window_state != KEYSTONE_GROUP_PERF_WINDOW_FROZEN ||
              perf.worker_runtime_members != workload.worker_count))
    ok = false;
  if (ok && perf.ocall_count < timing.worker_ocalls) {
    std::cerr << "[P10][mixed-scale] OCALL metric undercount: worker_host="
              << timing.worker_ocalls << " all_group_sm=" << perf.ocall_count
              << std::endl;
    ok = false;
  }
  /*
   * PERF_BEGIN resets the aggregate counters without cancelling waits that
   * were registered during startup. Such a wait can legitimately contribute
   * a wake, but no block, to this window. A block registered after PERF_BEGIN
   * must still be matched before the frozen snapshot is accepted.
   */
  if (ok && workload.worker_count > workload.active_lanes &&
      perf.lane_wait_block_count > perf.lane_wait_wake_count) {
    std::cerr << "[P10][mixed-scale] lane streaming wait incomplete: workers="
              << workload.worker_count
              << " blocked=" << perf.lane_wait_block_count
              << " woken=" << perf.lane_wait_wake_count << std::endl;
    ok = false;
  }
  const char* lease_fallback =
      std::getenv("GROUP_PMP_LEASE_TEST_FALLBACK");
  if (ok && !(lease_fallback && std::strcmp(lease_fallback, "1") == 0) &&
      perf.heartbeat_count != 0) {
    std::cerr << "[P10][mixed-scale] exclusive lease emitted heartbeat: count="
              << perf.heartbeat_count << std::endl;
    ok = false;
  }
  if (ok) {
    const uint64_t timebase_hz = riscv_timebase_hz();
    const uint64_t configured_cycle_hz = env_u64(
        "GROUP_PMP_CYCLE_HZ", kPerfDefaultCycleHz, 1, UINT64_MAX);
    double host_envelope_seconds = timing.stop_ns > timing.start_ns ?
        static_cast<double>(timing.stop_ns - timing.start_ns) / 1.0e9 : 0.0;
    /*
     * The benchmark contract starts immediately before the master's first
     * dispatch and ends immediately after its final aggregate. rdtime keeps
     * advancing while the master is descheduled, so this includes worker
     * SQLite execution, OCALL blocking/resume, lane scheduling and protocol
     * waits. The host envelope also includes terminal eapp EXIT handling and
     * is diagnostic only.
     */
    double master_full_flow_seconds = timebase_hz ?
        static_cast<double>(master_result.task_e2e_time_ticks) /
            static_cast<double>(timebase_hz) : 0.0;
    double seconds = workload.workload_id ?
        master_full_flow_seconds : host_envelope_seconds;
    uint64_t bytes = workload.total_bytes;
    double mb_per_sec = seconds > 0.0 ?
        (static_cast<double>(bytes) / kDecimalMbBytes) / seconds : 0.0;
    double speedup = baseline && baseline->mb_per_sec > 0.0 ?
        mb_per_sec / baseline->mb_per_sec : 0.0;
    const uint64_t cycle_interval_ticks = workload.workload_id ?
        worker_totals.aes_elapsed_time_ticks : worker_totals.aes_time_ticks;
    double effective_cycle_hz =
        cycle_interval_ticks && timebase_hz ?
        static_cast<double>(worker_totals.aes_cycles) *
            static_cast<double>(timebase_hz) /
            static_cast<double>(cycle_interval_ticks) :
        static_cast<double>(configured_cycle_hz);
    /* SQLite uses the SM member clock at crypto boundaries. Keep elapsed time
     * separately: raw rdcycle also advances while a peer runs, so only the
     * elapsed (not on-CPU) denominator may be used to infer cycle frequency. */
    double aes_wall_seconds = timebase_hz ?
        static_cast<double>(worker_totals.aes_time_ticks) /
            static_cast<double>(timebase_hz) : 0.0;
    double compute_wall_seconds = timebase_hz ?
        static_cast<double>(master_result.compute_wall_time_ticks) /
            static_cast<double>(timebase_hz) : 0.0;
    double master_wall_seconds = timebase_hz ?
        static_cast<double>(master_result.task_e2e_time_ticks) /
            static_cast<double>(timebase_hz) : 0.0;
    double worker_data_mb =
        static_cast<double>(bytes) / kDecimalMbBytes;
    uint64_t pmp_cycles = perf.pmp_grant_suspend_cycles +
        perf.pmp_epm_revoke_cycles + perf.pmp_epm_install_cycles +
        perf.pmp_yxstm_restore_cycles + perf.pmp_fence_cycles +
        perf.pmp_validation_cycles + perf.pmp_lock_wait_cycles;

    if (seconds <= 0.0 || master_full_flow_seconds <= 0.0 ||
        host_envelope_seconds <= 0.0 ||
        mb_per_sec <= 0.0 ||
        !timebase_hz || effective_cycle_hz <= 0.0 ||
        (!workload.rv8_profile && aes_wall_seconds <= 0.0) || compute_wall_seconds <= 0.0 ||
        master_wall_seconds <= 0.0)
      ok = false;
    else {
      metrics->worker_count = workload.worker_count;
      metrics->active_lanes = workload.active_lanes;
      metrics->ocall_mode = workload.ocall_mode;
      for (uint64_t lane = 0; lane < GROUP_PMP_MIXED_LANES; ++lane)
        metrics->lane_depth[lane] = workload.lane_depth[lane];
      metrics->bytes_per_enclave = workload.worker_count ?
          bytes / workload.worker_count : 0;
      metrics->total_bytes = bytes;
      metrics->chunks_per_enclave = mixed_max_worker_batch_count(workload);
      metrics->slot_dispatches = master_result.slot_dispatches;
      metrics->slot_aggregates = master_result.slot_aggregates;
      metrics->slot_wait_yields = master_result.slot_wait_yields;
      metrics->sample_count = 1;
      metrics->seconds = seconds;
      metrics->seconds_p95 = seconds;
      metrics->host_envelope_seconds = host_envelope_seconds;
      metrics->host_envelope_seconds_p95 = host_envelope_seconds;
      metrics->mb_per_sec = mb_per_sec;
      metrics->mb_per_sec_p05 = mb_per_sec;
      metrics->mb_per_sec_p95 = mb_per_sec;
      metrics->speedup_vs_one = speedup;
      metrics->effective_cycle_hz = effective_cycle_hz;
      metrics->enclave_aes_mb_per_sec =
          aes_wall_seconds > 0.0 ? worker_data_mb / aes_wall_seconds : 0.0;
      metrics->enclave_aes_mb_per_sec_p95 =
          metrics->enclave_aes_mb_per_sec;
      metrics->aes_stage_mb_per_sec =
          workload.rv8_profile ? 0.0 : worker_data_mb / compute_wall_seconds;
      metrics->aes_stage_mb_per_sec_p95 =
          metrics->aes_stage_mb_per_sec;
      metrics->yxstm_dispatch_mb_per_sec =
          (static_cast<double>(master_result.dispatch_bytes) /
           kDecimalMbBytes) /
          (static_cast<double>(master_result.dispatch_time_ticks) /
           static_cast<double>(timebase_hz));
      metrics->yxstm_dispatch_mb_per_sec_p95 =
          metrics->yxstm_dispatch_mb_per_sec;
      metrics->yxstm_effective_payload_mb_per_sec =
          ((static_cast<double>(master_result.dispatch_bytes) +
            (workload.rv8_profile ? 0.0 : static_cast<double>(bytes) * 2.0) +
            static_cast<double>(master_result.aggregate_bytes)) /
           kDecimalMbBytes) /
          master_wall_seconds;
      metrics->yxstm_effective_payload_mb_per_sec_p95 =
          metrics->yxstm_effective_payload_mb_per_sec;
      metrics->yxstm_aggregate_mb_per_sec =
          (static_cast<double>(master_result.aggregate_bytes) /
           kDecimalMbBytes) /
          (static_cast<double>(master_result.aggregate_time_ticks) /
           static_cast<double>(timebase_hz));
      metrics->yxstm_aggregate_mb_per_sec_p95 =
          metrics->yxstm_aggregate_mb_per_sec;
      metrics->scheduler_efficiency =
          perf.worker_exec_runtime_ticks ?
          static_cast<double>(perf.worker_aes_exec_runtime_ticks) /
              static_cast<double>(perf.worker_exec_runtime_ticks) : 0.0;
      metrics->scheduler_efficiency_p95 =
          metrics->scheduler_efficiency;
      metrics->lane_utilization =
          master_result.task_e2e_time_ticks && workload.active_lanes ?
          static_cast<double>(perf.worker_exec_runtime_ticks) /
              (static_cast<double>(master_result.task_e2e_time_ticks) *
               static_cast<double>(workload.active_lanes)) : 0.0;
      metrics->lane_utilization_p95 = metrics->lane_utilization;
      metrics->master_wall_seconds = master_wall_seconds;
      metrics->master_wall_seconds_p95 = master_wall_seconds;
      metrics->master_dispatch_wall_seconds =
          static_cast<double>(master_result.dispatch_time_ticks) /
          static_cast<double>(timebase_hz);
      metrics->master_dispatch_wall_seconds_p95 =
          metrics->master_dispatch_wall_seconds;
      metrics->master_aggregate_wall_seconds =
          static_cast<double>(master_result.aggregate_time_ticks) /
          static_cast<double>(timebase_hz);
      metrics->master_aggregate_wall_seconds_p95 =
          metrics->master_aggregate_wall_seconds;
      metrics->compute_wall_seconds = compute_wall_seconds;
      metrics->compute_wall_seconds_p95 = compute_wall_seconds;
      metrics->aes_wall_seconds = aes_wall_seconds;
      metrics->aes_elapsed_time_ticks = worker_totals.aes_elapsed_time_ticks;
      metrics->aes_wall_seconds_p95 = aes_wall_seconds;
      metrics->ocall_wall_seconds =
          static_cast<double>(worker_totals.ocall_time_ticks) /
          static_cast<double>(timebase_hz);
      metrics->ocall_wall_seconds_p95 = metrics->ocall_wall_seconds;
      metrics->wait_wall_seconds =
          static_cast<double>(worker_totals.ready_wait_time_ticks) /
          static_cast<double>(timebase_hz);
      metrics->wait_wall_seconds_p95 = metrics->wait_wall_seconds;
      metrics->pmp_wall_seconds =
          static_cast<double>(pmp_cycles) / effective_cycle_hz;
      metrics->pmp_wall_seconds_p95 = metrics->pmp_wall_seconds;
      metrics->switch_wall_seconds =
          static_cast<double>(perf.context_switch_ticks) /
          static_cast<double>(timebase_hz);
      metrics->switch_wall_seconds_p95 = metrics->switch_wall_seconds;
      metrics->scheduler_wall_seconds =
          static_cast<double>(perf.context_scheduler_lock_cycles +
                              perf.timer_trap_cycles) /
          effective_cycle_hz;
      metrics->scheduler_wall_seconds_p95 =
          metrics->scheduler_wall_seconds;
      metrics->protocol_wall_seconds =
          static_cast<double>(worker_totals.protocol_time_ticks +
                              master_result.protocol_time_ticks) /
          static_cast<double>(timebase_hz);
      metrics->protocol_wall_seconds_p95 =
          metrics->protocol_wall_seconds;
      metrics->worker_ocalls = timing.worker_ocalls;
      metrics->rv8_bytes = worker_totals.rv8_bytes;
      metrics->rv8_blocks = worker_totals.rv8_blocks;
      metrics->rv8_cpu_ticks = worker_totals.rv8_cpu_ticks;
      metrics->rv8_elapsed_ticks = worker_totals.rv8_elapsed_ticks;
      metrics->worker_aes_cycles = worker_totals.aes_cycles;
      metrics->worker_aes_time_ticks = worker_totals.aes_time_ticks;
      metrics->worker_protocol_cycles = worker_totals.protocol_cycles;
      metrics->worker_protocol_time_ticks =
          worker_totals.protocol_time_ticks;
      metrics->worker_ready_wait_time_ticks =
          worker_totals.ready_wait_time_ticks;
      metrics->worker_ocall_time_ticks =
          worker_totals.ocall_time_ticks;
      metrics->vfs_read_bytes = worker_totals.vfs_read_bytes;
      metrics->vfs_write_bytes = worker_totals.vfs_write_bytes;
      metrics->vfs_encrypt_cycles = worker_totals.vfs_encrypt_cycles;
      metrics->vfs_decrypt_cycles = worker_totals.vfs_decrypt_cycles;
      metrics->vfs_submit_count = worker_totals.vfs_submit_count;
      metrics->vfs_wait_count = worker_totals.vfs_wait_count;
      metrics->vfs_yield_count = worker_totals.vfs_yield_count;
      metrics->vfs_wait_ticks = worker_totals.vfs_wait_ticks;
      metrics->vfs_batch_submit_count =
          worker_totals.vfs_batch_submit_count;
      metrics->vfs_blocked_completion_count =
          worker_totals.vfs_blocked_completion_count;
      metrics->vfs_queue_depth_peak = worker_totals.vfs_queue_depth_peak;
      metrics->vfs_ring_doorbell_count =
          worker_totals.vfs_ring_doorbell_count;
      metrics->vfs_ring_request_count = worker_totals.vfs_ring_request_count;
      metrics->vfs_completion_batch_count =
          worker_totals.vfs_completion_batch_count;
      metrics->vfs_crypto_io_sample_ticks = worker_totals.vfs_crypto_io_sample_ticks;
      metrics->vfs_crypto_io_overlap_ticks = worker_totals.vfs_crypto_io_overlap_ticks;
      metrics->vfs_crypto_io_overlap_ratio =
          worker_totals.vfs_crypto_io_sample_ticks ?
          static_cast<double>(worker_totals.vfs_crypto_io_overlap_ticks) /
              worker_totals.vfs_crypto_io_sample_ticks : 0.0;
      metrics->vfs_both_buffers_wait_ticks = worker_totals.vfs_both_buffers_wait_ticks;
      metrics->vfs_completion_local_reaps = worker_totals.vfs_completion_local_reaps;
      metrics->vfs_buffer_reuses = worker_totals.vfs_buffer_reuses;
      metrics->pipeline = worker_totals.pipeline;
      metrics->sqlite_task_count = timing.sqlite_perf.task_count;
      metrics->sqlite_batch_count = timing.sqlite_perf.batch_count;
      metrics->sqlite_read100k = timing.sqlite_perf.read100k;
      metrics->sqlite_io_pipeline = timing.sqlite_perf.pipeline;
      metrics->sqlite_queue_wait_ns = timing.sqlite_perf.queue_wait_ns;
      metrics->sqlite_writer_wait_ns = timing.sqlite_perf.writer_wait_ns;
      metrics->sqlite_read_service_ns = timing.sqlite_perf.read_service_ns;
      metrics->sqlite_write_service_ns = timing.sqlite_perf.write_service_ns;
      metrics->sqlite_control_service_ns =
          timing.sqlite_perf.control_service_ns;
      metrics->sqlite_commit_ns = timing.sqlite_perf.commit_ns;
      metrics->sqlite_commit_count = timing.sqlite_perf.commit_count;
      metrics->sqlite_queue_depth_peak = timing.sqlite_perf.queue_depth_peak;
      metrics->sqlite_io_uring_submissions =
          timing.sqlite_perf.io_uring_submissions;
      metrics->sqlite_registered_file_operations =
          timing.sqlite_perf.registered_file_operations;
      metrics->sqlite_registered_buffer_operations =
          timing.sqlite_perf.registered_buffer_operations;
      metrics->sqlite_fixed_buffer_operations =
          timing.sqlite_perf.fixed_buffer_operations;
      metrics->sqlite_buffer_registration_attempts =
          timing.sqlite_perf.buffer_registration_attempts;
      metrics->sqlite_buffer_registration_failures =
          timing.sqlite_perf.buffer_registration_failures;
      metrics->sqlite_direct_io_operations =
          timing.sqlite_perf.direct_io_operations;
      metrics->sqlite_direct_alignment_fallback_operations =
          timing.sqlite_perf.direct_alignment_fallback_operations;
      metrics->sqlite_posix_fallback_operations =
          timing.sqlite_perf.posix_fallback_operations;
      metrics->sqlite_merged_io_count = timing.sqlite_perf.merged_io_count;
      metrics->sqlite_sparse_io_count = timing.sqlite_perf.sparse_io_count;
      metrics->sqlite_useful_io_bytes = timing.sqlite_perf.useful_io_bytes;
      metrics->sqlite_physical_io_bytes = timing.sqlite_perf.physical_io_bytes;
      metrics->sqlite_logical_request_count =
          timing.sqlite_perf.logical_request_count;
      metrics->sqlite_physical_request_count =
          timing.sqlite_perf.physical_request_count;
      metrics->sqlite_deduplicated_request_count =
          timing.sqlite_perf.deduplicated_request_count;
      metrics->sqlite_completion_wait_ocall_count =
          timing.sqlite_perf.completion_wait_ocall_count;
      metrics->sqlite_cache_full_hit_count =
          timing.sqlite_perf.cache_full_hit_count;
      metrics->sqlite_cache_partial_hit_count =
          timing.sqlite_perf.cache_partial_hit_count;
      metrics->sqlite_cache_miss_count =
          timing.sqlite_perf.cache_miss_count;
      metrics->sqlite_cache_hit_bytes = timing.sqlite_perf.cache_hit_bytes;
      metrics->sqlite_collect_ns = timing.sqlite_perf.collect_ns;
      metrics->sqlite_sort_ns = timing.sqlite_perf.sort_ns;
      metrics->sqlite_cluster_ns = timing.sqlite_perf.cluster_ns;
      metrics->sqlite_submit_ns = timing.sqlite_perf.submit_ns;
      metrics->sqlite_disk_io_ns = timing.sqlite_perf.disk_io_ns;
      metrics->sqlite_completion_wait_ns = timing.sqlite_perf.completion_wait_ns;
      metrics->sqlite_storage_sync_ns = timing.sqlite_perf.storage_sync_ns;
      metrics->sqlite_sequential_extent_count = timing.sqlite_perf.sequential_extent_count;
      metrics->sqlite_sequential_8mb_extent_count = timing.sqlite_perf.sequential_8mb_extent_count;
      metrics->sqlite_cross_worker_extent_count = timing.sqlite_perf.cross_worker_extent_count;
      metrics->sqlite_utm_copy_ns = timing.sqlite_perf.utm_copy_ns;
      metrics->sqlite_completion_publish_ns =
          timing.sqlite_perf.completion_publish_ns;
      metrics->sqlite_wakeup_ns = timing.sqlite_perf.wakeup_ns;
      metrics->sqlite_submit_to_host_dequeue_ns =
          timing.sqlite_perf.submit_to_host_dequeue_ns;
      metrics->sqlite_host_dequeue_to_io_submit_ns =
          timing.sqlite_perf.host_dequeue_to_io_submit_ns;
      metrics->sqlite_io_submit_to_complete_ns =
          timing.sqlite_perf.io_submit_to_complete_ns;
      metrics->sqlite_io_complete_to_publish_ns =
          timing.sqlite_perf.io_complete_to_publish_ns;
      metrics->sqlite_publish_to_host_resume_request_ns =
          timing.sqlite_perf.publish_to_host_resume_request_ns;
      metrics->sqlite_wakeup_eligible_to_host_resume_request_ns =
          timing.sqlite_perf.wakeup_eligible_to_host_resume_request_ns;
      metrics->sqlite_host_resume_ioctl_ns =
          timing.sqlite_perf.host_resume_ioctl_ns;
      metrics->sqlite_completion_wakeup_count =
          timing.sqlite_perf.completion_wakeup_count;
      metrics->sqlite_completion_ready_before_wait_count =
          timing.sqlite_perf.completion_ready_before_wait_count;
      metrics->sqlite_ewma_bandwidth_bytes_per_sec =
          timing.sqlite_perf.ewma_bandwidth_bytes_per_sec;
      metrics->sqlite_ewma_request_latency_ns =
          timing.sqlite_perf.ewma_request_latency_ns;
      metrics->sqlite_ewma_queue_wait_ns =
          timing.sqlite_perf.ewma_queue_wait_ns;
      metrics->sqlite_ewma_completion_latency_ns =
          timing.sqlite_perf.ewma_completion_latency_ns;
      metrics->sqlite_adaptive_collect_usec =
          timing.sqlite_perf.adaptive_collect_usec;
      metrics->sqlite_adaptive_batch_target =
          timing.sqlite_perf.adaptive_batch_target;
      metrics->sqlite_adaptive_queue_depth =
          timing.sqlite_perf.adaptive_queue_depth;
      metrics->sqlite_adaptive_gap_bytes =
          timing.sqlite_perf.adaptive_gap_bytes;
      metrics->sqlite_write_overlap_check_ns =
          timing.sqlite_perf.write_overlap_check_ns;
      metrics->sqlite_write_overlap_checks =
          timing.sqlite_perf.write_overlap_checks;
      metrics->sqlite_write_disjoint_batches =
          timing.sqlite_perf.write_disjoint_batches;
      metrics->sqlite_write_overlap_batches =
          timing.sqlite_perf.write_overlap_batches;
      metrics->sqlite_adaptive_write_grow_count =
          timing.sqlite_perf.adaptive_write_grow_count;
      metrics->sqlite_adaptive_write_shrink_count =
          timing.sqlite_perf.adaptive_write_shrink_count;
      metrics->sqlite_adaptive_write_hold_count =
          timing.sqlite_perf.adaptive_write_hold_count;
      metrics->sqlite_sequential_ready_single_batches =
          timing.sqlite_perf.sequential_ready_single_batches;
      metrics->sqlite_sequential_ready_multi_batches =
          timing.sqlite_perf.sequential_ready_multi_batches;
      metrics->sqlite_sequential_ready_adjacent_pairs =
          timing.sqlite_perf.sequential_ready_adjacent_pairs;
      metrics->sqlite_sequential_ready_nonadjacent_pairs =
          timing.sqlite_perf.sequential_ready_nonadjacent_pairs;
      metrics->sqlite_random_sparse_fast_batches = timing.sqlite_perf.random_sparse_fast_batches;
      metrics->sqlite_random_sparse_fast_requests = timing.sqlite_perf.random_sparse_fast_requests;
      metrics->sqlite_random_planned_batches = timing.sqlite_perf.random_planned_batches;
      metrics->sqlite_random_precheck_fallbacks = timing.sqlite_perf.random_precheck_fallbacks;
      metrics->sqlite_random_precheck_ns = timing.sqlite_perf.random_precheck_ns;
      metrics->sqlite_random_local_plan_batches = timing.sqlite_perf.random_local_plan_batches;
      metrics->sqlite_random_local_candidate_requests = timing.sqlite_perf.random_local_candidate_requests;
      metrics->sqlite_cache_fill_bytes = timing.sqlite_perf.cache_fill_bytes;
      metrics->sqlite_cache_fill_ns = timing.sqlite_perf.cache_fill_ns;
      metrics->sqlite_cache_fill_skipped_bytes = timing.sqlite_perf.cache_fill_skipped_bytes;
      metrics->sqlite_cache_admission_disables = timing.sqlite_perf.cache_admission_disables;
      metrics->sqlite_cache_admission_reenables = timing.sqlite_perf.cache_admission_reenables;
      metrics->sqlite_readseq_initial_requests = timing.sqlite_perf.readseq_initial_requests;
      metrics->sqlite_readseq_refill_peer_io_requests = timing.sqlite_perf.readseq_refill_peer_io_requests;
      metrics->sqlite_readseq_refill_peer_ready_requests = timing.sqlite_perf.readseq_refill_peer_ready_requests;
      metrics->sqlite_readseq_refill_peer_idle_requests = timing.sqlite_perf.readseq_refill_peer_idle_requests;
      metrics->sqlite_critical_path_ns = timing.sqlite_perf.critical_path_ns;
      metrics->sqlite_max_queue_wait_ns =
          timing.sqlite_perf.max_queue_wait_ns;
      metrics->sqlite_max_batch_service_ns =
          timing.sqlite_perf.max_batch_service_ns;
      metrics->sqlite_max_completion_latency_ns =
          timing.sqlite_perf.max_completion_latency_ns;
      metrics->slot_scheduler_cycles = worker_totals.protocol_cycles +
          master_result.protocol_cycles;
      metrics->master_dispatch_cycles = master_result.dispatch_cycles;
      metrics->master_dispatch_time_ticks =
          master_result.dispatch_time_ticks;
      metrics->master_dispatch_bytes = master_result.dispatch_bytes;
      metrics->worker_compute_wall_cycles =
          master_result.compute_wall_cycles;
      metrics->worker_compute_wall_time_ticks =
          master_result.compute_wall_time_ticks;
      metrics->master_aggregate_cycles = master_result.aggregate_cycles;
      metrics->master_aggregate_time_ticks =
          master_result.aggregate_time_ticks;
      metrics->master_aggregate_bytes = master_result.aggregate_bytes;
      metrics->master_protocol_cycles = master_result.protocol_cycles;
      metrics->master_protocol_time_ticks =
          master_result.protocol_time_ticks;
      metrics->task_e2e_cycles = master_result.task_e2e_cycles;
      metrics->task_e2e_time_ticks =
          master_result.task_e2e_time_ticks;
      metrics->context_switches = perf.context_switch_count;
      metrics->context_switch_cycles = perf.context_switch_cycles;
      metrics->context_switch_ticks = perf.context_switch_ticks;
      metrics->context_gpr_cycles = perf.context_gpr_cycles;
      metrics->context_smode_csr_cycles = perf.context_smode_csr_cycles;
      metrics->context_fp_cycles = perf.context_fp_cycles;
      metrics->context_pmp_cycles = perf.context_pmp_cycles;
      metrics->context_platform_cycles = perf.context_platform_cycles;
      metrics->context_scheduler_lock_cycles =
          perf.context_scheduler_lock_cycles;
      metrics->worker_exec_runtime_ticks =
          perf.worker_exec_runtime_ticks;
      metrics->worker_aes_exec_runtime_ticks =
          perf.worker_aes_exec_runtime_ticks;
      metrics->worker_aes_exec_runtime_min =
          perf.worker_aes_exec_runtime_min;
      metrics->worker_aes_exec_runtime_max =
          perf.worker_aes_exec_runtime_max;
      metrics->worker_runtime_members = perf.worker_runtime_members;
      metrics->pmp_grant_suspend_cycles = perf.pmp_grant_suspend_cycles;
      metrics->pmp_epm_revoke_cycles = perf.pmp_epm_revoke_cycles;
      metrics->pmp_epm_install_cycles = perf.pmp_epm_install_cycles;
      metrics->pmp_yxstm_restore_cycles = perf.pmp_yxstm_restore_cycles;
      metrics->pmp_fence_cycles = perf.pmp_fence_cycles;
      metrics->pmp_validation_cycles = perf.pmp_validation_cycles;
      metrics->pmp_lock_wait_cycles = perf.pmp_lock_wait_cycles;
      metrics->grant_suspend_restores =
          perf.grant_suspend_restore_count;
      metrics->grant_suspend_restore_cycles =
          perf.grant_suspend_restore_cycles;
      metrics->sm_ocalls = perf.ocall_count;
      metrics->sm_ocall_cycles = perf.ocall_cycles;
      metrics->ocall_handler_count = perf.ocall_handler_count;
      metrics->ocall_handler_cycles = perf.ocall_handler_cycles;
      metrics->ocall_wait_count = perf.ocall_wait_count;
      metrics->ocall_wait_ticks = perf.ocall_wait_ticks;
      metrics->lane_wait_blocks = perf.lane_wait_block_count;
      metrics->lane_wait_wakes = perf.lane_wait_wake_count;
      metrics->lane_wait_ticks = perf.lane_wait_ticks;
      metrics->cfs_picks = perf.cfs_pick_count;
      metrics->cfs_preemptions = perf.cfs_preempt_count;
      metrics->cfs_runtime_ticks = perf.cfs_runtime_ticks;
      metrics->cfs_vruntime_delta = perf.cfs_vruntime_delta;
      metrics->cfs_slice_ticks = perf.cfs_slice_ticks;
      metrics->cfs_min_granularity_hits =
          perf.cfs_min_granularity_count;
      metrics->cfs_dynamic_min_slice_ticks =
          perf.cfs_dynamic_min_slice_ticks;
      metrics->heartbeats = perf.heartbeat_count;
      metrics->heartbeat_cycles = perf.heartbeat_cycles;
      metrics->timer_traps = perf.timer_trap_count;
      metrics->timer_trap_cycles = perf.timer_trap_cycles;
      metrics->host_services = perf.host_service_count;
      metrics->scrub_count = perf.scrub_count;
      metrics->scrub_bytes = perf.scrub_bytes;
      metrics->scrub_cycles = perf.scrub_cycles;
      metrics->max_running_workers = resources.max_running_workers;
      metrics->digest = digest;
      std::cout << "[P10][mixed-scale] workers=" << workload.worker_count
                << " lanes=" << workload.active_lanes
                << " lane_depth=" << workload.lane_depth[0] << "/"
                << workload.lane_depth[1] << "/"
                << workload.lane_depth[2]
                << " lane_work_mb="
                << (static_cast<double>(workload.lane_bytes[0]) /
                    kDecimalMbBytes) << "/"
                << (static_cast<double>(workload.lane_bytes[1]) /
                    kDecimalMbBytes) << "/"
                << (static_cast<double>(workload.lane_bytes[2]) /
                    kDecimalMbBytes)
                << " mb_per_enclave="
                << (GROUP_PMP_MIXED_WORKER_BYTES / kDecimalMbBytes)
                << " total_mb="
                << (static_cast<double>(bytes) / kDecimalMbBytes)
                 << " max_batches_per_enclave="
                  << mixed_max_worker_batch_count(workload)
                 << " slot_dispatches=" << master_result.slot_dispatches
                 << " expected_slot_dispatches="
                 << mixed_total_batch_count(workload)
                 << " slot_aggregates=" << master_result.slot_aggregates
                 << " lane_dispatches="
                 << master_result.lane_dispatches[0] << "/"
                 << master_result.lane_dispatches[1] << "/"
                 << master_result.lane_dispatches[2]
                 << " lane_aggregates="
                 << master_result.lane_aggregates[0] << "/"
                 << master_result.lane_aggregates[1] << "/"
                 << master_result.lane_aggregates[2]
                 << " slot_wait_yields=" << master_result.slot_wait_yields
                 << " ocall_mode="
                 << (workload.ocall_mode == GROUP_PMP_MIXED_OCALL_PER_TASK ?
                     "per-task" : "per-chunk-stress")
                << " seconds=" << seconds
                << " host_envelope_seconds=" << host_envelope_seconds
                << " mb_per_sec=" << mb_per_sec
                << " speedup_vs_one="
                << (baseline ? speedup : 0.0)
                << " speedup_deferred=" << (baseline ? 0 : 1)
                << " worker_ocalls=" << timing.worker_ocalls
                << " enclave_aes_mb_per_sec="
                << metrics->enclave_aes_mb_per_sec
                << " aes_stage_mb_per_sec="
                << metrics->aes_stage_mb_per_sec
                << " yxstm_dispatch_mb_per_sec="
                << metrics->yxstm_dispatch_mb_per_sec
                << " yxstm_effective_payload_mb_per_sec="
                << metrics->yxstm_effective_payload_mb_per_sec
                << " yxstm_aggregate_sample_mb_per_sec="
                << metrics->yxstm_aggregate_mb_per_sec
                << " scheduler_efficiency="
                << metrics->scheduler_efficiency
                << " lane_utilization=" << metrics->lane_utilization
                << " worker_aes_cycles=" << worker_totals.aes_cycles
                 << " worker_protocol_cycles="
                 << worker_totals.protocol_cycles
                 << " slot_scheduler_cycles="
                 << metrics->slot_scheduler_cycles
                 << " master_dispatch_cycles="
                 << master_result.dispatch_cycles
                 << " worker_compute_wall_cycles="
                 << master_result.compute_wall_cycles
                 << " master_aggregate_cycles="
                 << master_result.aggregate_cycles
                 << " master_protocol_cycles="
                 << master_result.protocol_cycles
                 << " task_e2e_cycles="
                 << master_result.task_e2e_cycles
                 << " worker_exec_runtime_mtime_ticks="
                 << perf.worker_exec_runtime_ticks
                 << " worker_aes_oncpu_mtime_ticks="
                 << perf.worker_aes_exec_runtime_ticks
                 << " worker_aes_oncpu_min_mtime_ticks="
                 << perf.worker_aes_exec_runtime_min
                 << " worker_aes_oncpu_max_mtime_ticks="
                 << perf.worker_aes_exec_runtime_max
                 << " worker_runtime_members="
                 << perf.worker_runtime_members
                 << " context_switches=" << perf.context_switch_count
                 << " context_switch_cycles=" << perf.context_switch_cycles
                 << " context_switch_mtime_ticks="
                 << perf.context_switch_ticks
                 << " context_gpr_cycles=" << perf.context_gpr_cycles
                 << " context_smode_csr_cycles="
                 << perf.context_smode_csr_cycles
                 << " context_fp_cycles=" << perf.context_fp_cycles
                 << " context_pmp_cycles=" << perf.context_pmp_cycles
                 << " context_platform_cycles="
                 << perf.context_platform_cycles
                 << " context_scheduler_lock_cycles="
                 << perf.context_scheduler_lock_cycles
                 << " grant_suspend_restores="
                 << perf.grant_suspend_restore_count
                 << " grant_suspend_restore_cycles="
                 << perf.grant_suspend_restore_cycles
                 << " pmp_grant_suspend_cycles="
                 << perf.pmp_grant_suspend_cycles
                 << " pmp_epm_revoke_cycles="
                 << perf.pmp_epm_revoke_cycles
                 << " pmp_epm_install_cycles="
                 << perf.pmp_epm_install_cycles
                 << " pmp_yxstm_restore_cycles="
                 << perf.pmp_yxstm_restore_cycles
                 << " pmp_fence_cycles=" << perf.pmp_fence_cycles
                 << " pmp_validation_cycles="
                 << perf.pmp_validation_cycles
                 << " pmp_lock_wait_cycles="
                 << perf.pmp_lock_wait_cycles
                << " sm_ocalls=" << perf.ocall_count
                << " sm_ocall_e2e_cycles=" << perf.ocall_cycles
                << " ocall_handler_count=" << perf.ocall_handler_count
                << " ocall_handler_cycles=" << perf.ocall_handler_cycles
                << " ocall_wait_count=" << perf.ocall_wait_count
                << " ocall_wait_mtime_ticks=" << perf.ocall_wait_ticks
                << " lane_wait_blocks=" << perf.lane_wait_block_count
                << " lane_wait_wakes=" << perf.lane_wait_wake_count
                 << " lane_wait_mtime_ticks=" << perf.lane_wait_ticks
                 << " cfs_picks=" << perf.cfs_pick_count
                 << " cfs_preemptions=" << perf.cfs_preempt_count
                 << " cfs_runtime_mtime_ticks=" << perf.cfs_runtime_ticks
                 << " cfs_vruntime_delta=" << perf.cfs_vruntime_delta
                 << " cfs_slice_ticks=" << perf.cfs_slice_ticks
                 << " cfs_min_granularity_hits="
                 << perf.cfs_min_granularity_count
                 << " cfs_dynamic_min_slice_mtime_ticks="
                 << perf.cfs_dynamic_min_slice_ticks
                << " heartbeats=" << perf.heartbeat_count
                << " heartbeat_cycles=" << perf.heartbeat_cycles
                << " timer_traps=" << perf.timer_trap_count
                << " timer_trap_cycles=" << perf.timer_trap_cycles
                << " timing_clock="
                << (workload.workload_id ? "riscv-rdtime" :
                                             "monotonic_raw")
                << " timing_scope="
                << (workload.workload_id ?
                    "master-first-dispatch-to-final-aggregate" :
                    "host-run-envelope")
                << " host_envelope_clock=monotonic_raw"
                << " sm_cycles=sum_per_hart"
                 << " timer_trap_cycles_exclude_switch=1"
                 << " perf_window_epoch=" << perf.window_epoch
                 << " perf_window_ticks="
                 << (perf.window_stop_ticks - perf.window_start_ticks)
                 << " host_services=" << perf.host_service_count
                << " scrub_count=" << perf.scrub_count
                << " scrub_bytes=" << perf.scrub_bytes
                << " scrub_cycles=" << perf.scrub_cycles
                << " max_running_workers=" << resources.max_running_workers
                 << " scheduler=exclusive-lease-cfs-lite-data-ready-slots"
                << " digest=" << digest << std::endl;
    }
  }
  if (ok && MotivationSystem::enabled() && MotivationSystem::trace_path()) {
    std::vector<std::pair<const void*,size_t>> buffers;
    std::vector<uint64_t> assigned;
    for(uint64_t w=0;w<workload.worker_count;++w) {
      buffers.push_back({enclaves[w+1].enclave->getOcallBuffer(),enclaves[w+1].enclave->getOcallBufferSize()});
      assigned.push_back(workload.assigned_bytes[w]);
    }
    if(!MotivationSystem::export_trace(MotivationSystem::trace_path(),buffers,assigned,riscv_timebase_hz())) {
      std::cerr<<"[motivation-system] incomplete enclave crypto trace"<<std::endl; ok=false;
    }
  }
  if (workload.workload_id && !workload.rv8_profile &&
      sqlite_benchmark_io_mode() != SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT)
    sqlite_async_io_service().clearRegisteredUtmBuffers();
  destroy_instances(enclaves);
  return ok;
}

bool
run_yxstm_memory_diagnostic_phase(const char* master_eapp,
                                  const char* worker_eapp,
                                  const char* runtime,
                                  const char* loader) {
  MixedWorkload workload;
  MixedRunMetrics metrics;

  std::cout << "[host] phase: YXSTM direct-map memory/AES diagnostics"
            << std::endl;
  if (register_call(1, group_pmp_ocall_ack) != 0 ||
      !build_mixed_workload(1, GROUP_PMP_MIXED_OCALL_PER_TASK,
                            &workload))
    return false;
  workload.diagnostic_flags = GROUP_PMP_MIXED_DIAG_MEMORY;
  return run_mixed_scaling_case(master_eapp, worker_eapp, runtime, loader,
                                workload, nullptr, &metrics);
}

bool run_security_authorized_control(const char* master, const char* worker,
                                     const char* runtime, const char* loader) {
  MixedWorkload workload;
  MixedRunMetrics metrics;
  if (register_call(1, group_pmp_ocall_ack) != 0 ||
      !build_mixed_workload(4, GROUP_PMP_MIXED_OCALL_PER_TASK, &workload)) return false;
  const bool ok = run_mixed_scaling_case(master, worker, runtime, loader,
      workload, nullptr, &metrics);
  std::cout << "[security-isolation] actor=authorized-Master-and-Workers workers=4"
            << " protocol=frozen-task-slots dispatch-and-aggregate=" << (ok ? "verified" : "failed")
            << " result=" << (ok ? "PASS" : "FAIL") << std::endl;
  return ok;
}

bool
mixed_metric_percentile(const std::vector<MixedRunMetrics>& samples,
                        uint64_t MixedRunMetrics::*field,
                        uint64_t percent,
                        uint64_t* value) {
  std::vector<uint64_t> values;

  if (!value || samples.empty() || percent > 100)
    return false;
  values.reserve(samples.size());
  for (size_t i = 0; i < samples.size(); ++i)
    values.push_back(samples[i].*field);
  std::sort(values.begin(), values.end());
  size_t rank = static_cast<size_t>(
      (percent * values.size() + 99) / 100);
  if (rank == 0)
    rank = 1;
  if (rank > values.size())
    rank = values.size();
  *value = values[rank - 1];
  return true;
}

bool
validate_mixed_sample(const MixedRunMetrics& sample,
                       const MixedRunMetrics& reference, size_t sample_index,
                       std::ostream* diagnostics = nullptr) {
  const auto mismatch = [&](const char* field, uint64_t actual,
                            uint64_t expected) {
    if (diagnostics)
      *diagnostics << "[P10][sample-validation] sample=" << sample_index + 1
                   << " field=" << field << " actual=" << actual
                   << " expected=" << expected << std::endl;
    return false;
  };
  const struct {
    const char* name;
    double MixedRunMetrics::*field;
  } timings[] = {{"seconds", &MixedRunMetrics::seconds},
                 {"mb_per_sec", &MixedRunMetrics::mb_per_sec}};
  for (const auto& timing : timings) {
    const double value = sample.*timing.field;
    if (!std::isfinite(value) || value <= 0.0) {
      if (diagnostics)
        *diagnostics << "[P10][sample-validation] sample=" << sample_index + 1
                     << " field=" << timing.name << " actual=" << value
                     << " expected=finite-positive" << std::endl;
      return false;
    }
  }
  const struct {
    const char* name;
    uint64_t MixedRunMetrics::*field;
  } invariants[] = {{"worker_count", &MixedRunMetrics::worker_count},
                    {"active_lanes", &MixedRunMetrics::active_lanes},
                    {"ocall_mode", &MixedRunMetrics::ocall_mode},
                    {"digest", &MixedRunMetrics::digest},
                    {"slot_dispatches", &MixedRunMetrics::slot_dispatches}};
  for (const auto& invariant : invariants)
    if (sample.*invariant.field != reference.*invariant.field)
      return mismatch(invariant.name, sample.*invariant.field,
                       reference.*invariant.field);
  if (!sample.slot_dispatches)
    return mismatch("slot_dispatches_minimum", 0, 1);
  if (sample.slot_aggregates != sample.slot_dispatches)
    return mismatch("slot_aggregates", sample.slot_aggregates,
                     sample.slot_dispatches);
  for (uint64_t lane = 0; lane < GROUP_PMP_MIXED_LANES; ++lane)
    if (sample.lane_depth[lane] != reference.lane_depth[lane]) {
      const std::string name = "lane_depth[" + std::to_string(lane) + "]";
      return mismatch(name.c_str(), sample.lane_depth[lane],
                       reference.lane_depth[lane]);
    }
  return true;
}

bool
aggregate_mixed_samples(const std::vector<MixedRunMetrics>& samples,
                         MixedRunMetrics* aggregate,
                         std::ostream* diagnostics = nullptr) {
  std::vector<double> seconds;
  std::vector<double> throughput;
  double median_throughput;

  /*
   * mixed-scale enforces at least five repetitions in its CLI contract,
   * while sqlite-bench deliberately permits 1..20 for long board runs.
   * Percentiles over one observation are well-defined and equal that sample.
   */
  if (!aggregate || samples.empty())
    return false;
  seconds.reserve(samples.size());
  throughput.reserve(samples.size());
  for (size_t i = 0; i < samples.size(); ++i) {
    if (!validate_mixed_sample(samples[i], samples[0], i, diagnostics))
      return false;
    seconds.push_back(samples[i].seconds);
    throughput.push_back(samples[i].mb_per_sec);
  }

  median_throughput = nearest_rank_percentile(throughput, 50);
  *aggregate = samples[0];
  aggregate->sample_count = samples.size();
  /*
   * Dispatch and aggregate are one-to-one protocol events, not independent
   * performance samples. Keep their validated pair correlated instead of
   * taking two unrelated per-field medians.
   */
  aggregate->slot_dispatches = samples[0].slot_dispatches;
  aggregate->slot_aggregates = samples[0].slot_dispatches;
  aggregate->seconds = nearest_rank_percentile(seconds, 50);
  aggregate->seconds_min = *std::min_element(seconds.begin(), seconds.end());
  aggregate->seconds_max = *std::max_element(seconds.begin(), seconds.end());
  aggregate->seconds_p95 = nearest_rank_percentile(seconds, 95);
  aggregate->mb_per_sec = median_throughput;
  aggregate->mb_per_sec_min =
      *std::min_element(throughput.begin(), throughput.end());
  aggregate->mb_per_sec_max =
      *std::max_element(throughput.begin(), throughput.end());
  aggregate->mb_per_sec_p05 = nearest_rank_percentile(throughput, 5);
  aggregate->mb_per_sec_p95 = nearest_rank_percentile(throughput, 95);

#define MIXED_DOUBLE_PERCENTILES(field, p95_field)                            \
  do {                                                                        \
    if (!mixed_double_percentile(samples, &MixedRunMetrics::field, 50,        \
                                 &aggregate->field) ||                         \
        !mixed_double_percentile(samples, &MixedRunMetrics::field, 95,        \
                                 &aggregate->p95_field))                       \
      return false;                                                           \
  } while (0)
  MIXED_DOUBLE_PERCENTILES(effective_cycle_hz, effective_cycle_hz_p95);
  MIXED_DOUBLE_PERCENTILES(enclave_aes_mb_per_sec,
                           enclave_aes_mb_per_sec_p95);
  MIXED_DOUBLE_PERCENTILES(aes_stage_mb_per_sec,
                           aes_stage_mb_per_sec_p95);
  MIXED_DOUBLE_PERCENTILES(yxstm_dispatch_mb_per_sec,
                           yxstm_dispatch_mb_per_sec_p95);
  MIXED_DOUBLE_PERCENTILES(yxstm_effective_payload_mb_per_sec,
                           yxstm_effective_payload_mb_per_sec_p95);
  MIXED_DOUBLE_PERCENTILES(yxstm_aggregate_mb_per_sec,
                           yxstm_aggregate_mb_per_sec_p95);
  MIXED_DOUBLE_PERCENTILES(scheduler_efficiency,
                           scheduler_efficiency_p95);
  MIXED_DOUBLE_PERCENTILES(lane_utilization, lane_utilization_p95);
  MIXED_DOUBLE_PERCENTILES(host_envelope_seconds,
                           host_envelope_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(master_wall_seconds,
                           master_wall_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(master_dispatch_wall_seconds,
                           master_dispatch_wall_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(master_aggregate_wall_seconds,
                           master_aggregate_wall_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(compute_wall_seconds,
                           compute_wall_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(aes_wall_seconds, aes_wall_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(ocall_wall_seconds, ocall_wall_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(wait_wall_seconds, wait_wall_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(pmp_wall_seconds, pmp_wall_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(switch_wall_seconds, switch_wall_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(scheduler_wall_seconds,
                           scheduler_wall_seconds_p95);
  MIXED_DOUBLE_PERCENTILES(protocol_wall_seconds,
                           protocol_wall_seconds_p95);
#undef MIXED_DOUBLE_PERCENTILES

#define MIXED_MEDIAN(field)                                                   \
  do {                                                                        \
    if (!mixed_metric_percentile(samples, &MixedRunMetrics::field, 50,        \
                                 &aggregate->field))                           \
      return false;                                                           \
  } while (0)
  MIXED_MEDIAN(worker_ocalls);
  MIXED_MEDIAN(worker_aes_cycles);
  MIXED_MEDIAN(worker_aes_time_ticks);
  MIXED_MEDIAN(worker_protocol_cycles);
  MIXED_MEDIAN(worker_protocol_time_ticks);
  MIXED_MEDIAN(worker_ready_wait_time_ticks);
  MIXED_MEDIAN(worker_ocall_time_ticks);
  MIXED_MEDIAN(vfs_read_bytes);
  MIXED_MEDIAN(vfs_write_bytes);
  MIXED_MEDIAN(vfs_encrypt_cycles);
  MIXED_MEDIAN(aes_elapsed_time_ticks);
  MIXED_MEDIAN(vfs_decrypt_cycles);
  MIXED_MEDIAN(vfs_submit_count);
  MIXED_MEDIAN(vfs_wait_count);
  MIXED_MEDIAN(vfs_yield_count);
  MIXED_MEDIAN(vfs_wait_ticks);
  MIXED_MEDIAN(vfs_batch_submit_count);
  MIXED_MEDIAN(vfs_blocked_completion_count);
  MIXED_MEDIAN(vfs_queue_depth_peak);
  MIXED_MEDIAN(vfs_ring_doorbell_count);
  MIXED_MEDIAN(vfs_ring_request_count);
  MIXED_MEDIAN(vfs_completion_batch_count);
  MIXED_MEDIAN(vfs_crypto_io_sample_ticks);
  MIXED_MEDIAN(vfs_crypto_io_overlap_ticks);
  if (!mixed_double_percentile(samples,
          &MixedRunMetrics::vfs_crypto_io_overlap_ratio, 50,
          &aggregate->vfs_crypto_io_overlap_ratio))
    return false;
  MIXED_MEDIAN(vfs_both_buffers_wait_ticks);
  MIXED_MEDIAN(vfs_completion_local_reaps);
  MIXED_MEDIAN(vfs_buffer_reuses);
  uint64_t group_pmp_sqlite_pipeline_timing::* const pipeline_fields[] = {
      &group_pmp_sqlite_pipeline_timing::doorbell_count,
      &group_pmp_sqlite_pipeline_timing::doorbell_ack_ticks,
      &group_pmp_sqlite_pipeline_timing::doorbell_ack_max_ticks,
      &group_pmp_sqlite_pipeline_timing::completion_to_consume_count,
      &group_pmp_sqlite_pipeline_timing::completion_to_consume_ticks,
      &group_pmp_sqlite_pipeline_timing::completion_to_consume_max_ticks,
      &group_pmp_sqlite_pipeline_timing::completion_timestamp_invalid,
      &group_pmp_sqlite_pipeline_timing::ack_to_consume_ticks,
      &group_pmp_sqlite_pipeline_timing::ack_to_consume_max_ticks,
      &group_pmp_sqlite_pipeline_timing::buffer_consume_count,
      &group_pmp_sqlite_pipeline_timing::buffer_consume_ticks,
      &group_pmp_sqlite_pipeline_timing::buffer_consume_max_ticks,
      &group_pmp_sqlite_pipeline_timing::buffer_refill_count,
      &group_pmp_sqlite_pipeline_timing::buffer_refill_ticks,
      &group_pmp_sqlite_pipeline_timing::buffer_refill_max_ticks,
      &group_pmp_sqlite_pipeline_timing::request_prepare_ticks,
      &group_pmp_sqlite_pipeline_timing::submission_timing_count,
      &group_pmp_sqlite_pipeline_timing::submission_timestamp_invalid,
      &group_pmp_sqlite_pipeline_timing::submit_to_host_ticks,
      &group_pmp_sqlite_pipeline_timing::submit_to_host_max_ticks,
      &group_pmp_sqlite_pipeline_timing::host_to_ack_ticks,
      &group_pmp_sqlite_pipeline_timing::host_to_ack_max_ticks,
      &group_pmp_sqlite_pipeline_timing::ack_to_resume_request_ticks,
      &group_pmp_sqlite_pipeline_timing::ack_to_resume_request_max_ticks,
      &group_pmp_sqlite_pipeline_timing::resume_request_to_return_ticks,
      &group_pmp_sqlite_pipeline_timing::resume_request_to_return_max_ticks,
      &group_pmp_sqlite_pipeline_timing::wait_timing_count,
      &group_pmp_sqlite_pipeline_timing::wait_timestamp_invalid,
      &group_pmp_sqlite_pipeline_timing::wait_submit_to_host_ticks,
      &group_pmp_sqlite_pipeline_timing::wait_host_to_resume_ticks,
      &group_pmp_sqlite_pipeline_timing::wait_resume_to_return_ticks,
      &group_pmp_sqlite_pipeline_timing::wait_resume_to_return_max_ticks,
      &group_pmp_sqlite_pipeline_timing::wait_oncpu_ticks,
      &group_pmp_sqlite_pipeline_timing::wait_offcpu_ticks,
      &group_pmp_sqlite_pipeline_timing::wait_clock_invalid,
  };
  for (const auto field : pipeline_fields) {
    std::vector<uint64_t> values;
    for (const auto& sample : samples)
      values.push_back(sample.pipeline.*field);
    std::sort(values.begin(), values.end());
    aggregate->pipeline.*field = values[(values.size() - 1) / 2];
  }
  for (size_t i = 0; i < aggregate->sqlite_read100k.size(); ++i) {
    std::vector<uint64_t> values;
    for (const auto& sample : samples)
      values.push_back(sample.sqlite_read100k[i]);
    std::sort(values.begin(), values.end());
    aggregate->sqlite_read100k[i] = values[(values.size() - 1) / 2];
  }
  for (size_t i = 0; i < aggregate->sqlite_io_pipeline.size(); ++i) {
    std::vector<uint64_t> values;
    for (const auto& sample : samples) values.push_back(sample.sqlite_io_pipeline[i]);
    std::sort(values.begin(), values.end());
    aggregate->sqlite_io_pipeline[i] = values[(values.size() - 1) / 2];
  }
  MIXED_MEDIAN(sqlite_task_count);
  MIXED_MEDIAN(sqlite_batch_count);
  MIXED_MEDIAN(sqlite_queue_wait_ns);
  MIXED_MEDIAN(sqlite_writer_wait_ns);
  MIXED_MEDIAN(sqlite_read_service_ns);
  MIXED_MEDIAN(sqlite_write_service_ns);
  MIXED_MEDIAN(sqlite_control_service_ns);
  MIXED_MEDIAN(sqlite_commit_ns);
  MIXED_MEDIAN(sqlite_commit_count);
  MIXED_MEDIAN(sqlite_queue_depth_peak);
  MIXED_MEDIAN(sqlite_io_uring_submissions);
  MIXED_MEDIAN(sqlite_registered_file_operations);
  MIXED_MEDIAN(sqlite_registered_buffer_operations);
  MIXED_MEDIAN(sqlite_fixed_buffer_operations);
  MIXED_MEDIAN(sqlite_buffer_registration_attempts);
  MIXED_MEDIAN(sqlite_buffer_registration_failures);
  MIXED_MEDIAN(sqlite_direct_io_operations);
  MIXED_MEDIAN(sqlite_direct_alignment_fallback_operations);
  MIXED_MEDIAN(sqlite_posix_fallback_operations);
  MIXED_MEDIAN(sqlite_merged_io_count);
  MIXED_MEDIAN(sqlite_sparse_io_count);
  MIXED_MEDIAN(sqlite_useful_io_bytes);
  MIXED_MEDIAN(sqlite_physical_io_bytes);
  MIXED_MEDIAN(sqlite_logical_request_count);
  MIXED_MEDIAN(sqlite_physical_request_count);
  MIXED_MEDIAN(sqlite_deduplicated_request_count);
  MIXED_MEDIAN(sqlite_completion_wait_ocall_count);
  MIXED_MEDIAN(sqlite_cache_full_hit_count);
  MIXED_MEDIAN(sqlite_cache_partial_hit_count);
  MIXED_MEDIAN(sqlite_cache_miss_count);
  MIXED_MEDIAN(sqlite_cache_hit_bytes);
  MIXED_MEDIAN(sqlite_collect_ns);
  MIXED_MEDIAN(sqlite_sort_ns);
  MIXED_MEDIAN(sqlite_cluster_ns);
  MIXED_MEDIAN(sqlite_submit_ns);
  MIXED_MEDIAN(sqlite_disk_io_ns);
  MIXED_MEDIAN(sqlite_completion_wait_ns);
  MIXED_MEDIAN(sqlite_storage_sync_ns);
  MIXED_MEDIAN(sqlite_sequential_extent_count);
  MIXED_MEDIAN(sqlite_sequential_8mb_extent_count);
  MIXED_MEDIAN(sqlite_cross_worker_extent_count);
  MIXED_MEDIAN(sqlite_utm_copy_ns);
  MIXED_MEDIAN(sqlite_completion_publish_ns);
  MIXED_MEDIAN(sqlite_wakeup_ns);
  MIXED_MEDIAN(sqlite_submit_to_host_dequeue_ns);
  MIXED_MEDIAN(sqlite_host_dequeue_to_io_submit_ns);
  MIXED_MEDIAN(sqlite_io_submit_to_complete_ns);
  MIXED_MEDIAN(sqlite_io_complete_to_publish_ns);
  MIXED_MEDIAN(sqlite_publish_to_host_resume_request_ns);
  MIXED_MEDIAN(sqlite_wakeup_eligible_to_host_resume_request_ns);
  MIXED_MEDIAN(sqlite_host_resume_ioctl_ns);
  MIXED_MEDIAN(sqlite_completion_wakeup_count);
  MIXED_MEDIAN(sqlite_completion_ready_before_wait_count);
  MIXED_MEDIAN(sqlite_ewma_bandwidth_bytes_per_sec);
  MIXED_MEDIAN(sqlite_ewma_request_latency_ns);
  MIXED_MEDIAN(sqlite_ewma_queue_wait_ns);
  MIXED_MEDIAN(sqlite_ewma_completion_latency_ns);
  MIXED_MEDIAN(sqlite_adaptive_collect_usec);
  MIXED_MEDIAN(sqlite_adaptive_batch_target);
  MIXED_MEDIAN(sqlite_adaptive_queue_depth);
  MIXED_MEDIAN(sqlite_adaptive_gap_bytes);
  MIXED_MEDIAN(sqlite_write_overlap_check_ns);
  MIXED_MEDIAN(sqlite_write_overlap_checks);
  MIXED_MEDIAN(sqlite_write_disjoint_batches);
  MIXED_MEDIAN(sqlite_write_overlap_batches);
  MIXED_MEDIAN(sqlite_adaptive_write_grow_count);
  MIXED_MEDIAN(sqlite_adaptive_write_shrink_count);
  MIXED_MEDIAN(sqlite_adaptive_write_hold_count);
  MIXED_MEDIAN(sqlite_sequential_ready_single_batches);
  MIXED_MEDIAN(sqlite_sequential_ready_multi_batches);
  MIXED_MEDIAN(sqlite_sequential_ready_adjacent_pairs);
  MIXED_MEDIAN(sqlite_sequential_ready_nonadjacent_pairs);
  MIXED_MEDIAN(sqlite_random_sparse_fast_batches);
  MIXED_MEDIAN(sqlite_random_sparse_fast_requests);
  MIXED_MEDIAN(sqlite_random_planned_batches);
  MIXED_MEDIAN(sqlite_random_precheck_fallbacks);
  MIXED_MEDIAN(sqlite_random_precheck_ns);
  MIXED_MEDIAN(sqlite_random_local_plan_batches);
  MIXED_MEDIAN(sqlite_random_local_candidate_requests);
  MIXED_MEDIAN(sqlite_cache_fill_bytes);
  MIXED_MEDIAN(sqlite_cache_fill_ns);
  MIXED_MEDIAN(sqlite_cache_fill_skipped_bytes);
  MIXED_MEDIAN(sqlite_cache_admission_disables);
  MIXED_MEDIAN(sqlite_cache_admission_reenables);
  MIXED_MEDIAN(sqlite_readseq_initial_requests);
  MIXED_MEDIAN(sqlite_readseq_refill_peer_io_requests);
  MIXED_MEDIAN(sqlite_readseq_refill_peer_ready_requests);
  MIXED_MEDIAN(sqlite_readseq_refill_peer_idle_requests);
  MIXED_MEDIAN(sqlite_critical_path_ns);
  MIXED_MEDIAN(sqlite_max_queue_wait_ns);
  MIXED_MEDIAN(sqlite_max_batch_service_ns);
  MIXED_MEDIAN(sqlite_max_completion_latency_ns);
  MIXED_MEDIAN(io_trace_request_count);
  MIXED_MEDIAN(io_trace_member_request_count);
  MIXED_MEDIAN(io_trace_total_range_bytes);
  MIXED_MEDIAN(io_trace_useful_bytes);
  MIXED_MEDIAN(io_trace_gap_bytes);
  MIXED_MEDIAN(io_trace_range_start);
  MIXED_MEDIAN(io_trace_range_end);
  MIXED_MEDIAN(io_trace_min_request_bytes);
  MIXED_MEDIAN(io_trace_max_request_bytes);
  MIXED_MEDIAN(io_trace_read_request_count);
  MIXED_MEDIAN(io_trace_write_request_count);
  MIXED_MEDIAN(io_trace_failed_request_count);
  MIXED_MEDIAN(slot_scheduler_cycles);
  MIXED_MEDIAN(slot_wait_yields);
  MIXED_MEDIAN(master_dispatch_cycles);
  MIXED_MEDIAN(master_dispatch_time_ticks);
  MIXED_MEDIAN(master_dispatch_bytes);
  MIXED_MEDIAN(worker_compute_wall_cycles);
  MIXED_MEDIAN(worker_compute_wall_time_ticks);
  MIXED_MEDIAN(master_aggregate_cycles);
  MIXED_MEDIAN(master_aggregate_time_ticks);
  MIXED_MEDIAN(master_aggregate_bytes);
  MIXED_MEDIAN(master_protocol_cycles);
  MIXED_MEDIAN(master_protocol_time_ticks);
  MIXED_MEDIAN(task_e2e_cycles);
  MIXED_MEDIAN(task_e2e_time_ticks);
  MIXED_MEDIAN(context_switches);
  MIXED_MEDIAN(context_switch_cycles);
  MIXED_MEDIAN(context_switch_ticks);
  MIXED_MEDIAN(context_gpr_cycles);
  MIXED_MEDIAN(context_smode_csr_cycles);
  MIXED_MEDIAN(context_fp_cycles);
  MIXED_MEDIAN(context_pmp_cycles);
  MIXED_MEDIAN(context_platform_cycles);
  MIXED_MEDIAN(context_scheduler_lock_cycles);
  MIXED_MEDIAN(worker_exec_runtime_ticks);
  MIXED_MEDIAN(worker_aes_exec_runtime_ticks);
  MIXED_MEDIAN(worker_aes_exec_runtime_min);
  MIXED_MEDIAN(worker_aes_exec_runtime_max);
  MIXED_MEDIAN(worker_runtime_members);
  MIXED_MEDIAN(pmp_grant_suspend_cycles);
  MIXED_MEDIAN(pmp_epm_revoke_cycles);
  MIXED_MEDIAN(pmp_epm_install_cycles);
  MIXED_MEDIAN(pmp_yxstm_restore_cycles);
  MIXED_MEDIAN(pmp_fence_cycles);
  MIXED_MEDIAN(pmp_validation_cycles);
  MIXED_MEDIAN(pmp_lock_wait_cycles);
  MIXED_MEDIAN(grant_suspend_restores);
  MIXED_MEDIAN(grant_suspend_restore_cycles);
  MIXED_MEDIAN(sm_ocalls);
  MIXED_MEDIAN(sm_ocall_cycles);
  MIXED_MEDIAN(ocall_handler_count);
  MIXED_MEDIAN(ocall_handler_cycles);
  MIXED_MEDIAN(ocall_wait_count);
  MIXED_MEDIAN(ocall_wait_ticks);
  MIXED_MEDIAN(lane_wait_blocks);
  MIXED_MEDIAN(lane_wait_wakes);
  MIXED_MEDIAN(lane_wait_ticks);
  MIXED_MEDIAN(cfs_picks);
  MIXED_MEDIAN(cfs_preemptions);
  MIXED_MEDIAN(cfs_runtime_ticks);
  MIXED_MEDIAN(cfs_vruntime_delta);
  MIXED_MEDIAN(cfs_slice_ticks);
  MIXED_MEDIAN(cfs_min_granularity_hits);
  MIXED_MEDIAN(cfs_dynamic_min_slice_ticks);
  MIXED_MEDIAN(heartbeats);
  MIXED_MEDIAN(heartbeat_cycles);
  MIXED_MEDIAN(timer_traps);
  MIXED_MEDIAN(timer_trap_cycles);
  MIXED_MEDIAN(host_services);
  MIXED_MEDIAN(scrub_count);
  MIXED_MEDIAN(scrub_bytes);
  MIXED_MEDIAN(scrub_cycles);
  MIXED_MEDIAN(max_running_workers);
#undef MIXED_MEDIAN
  return true;
}

bool
write_mixed_scaling_csv(const std::string& path,
                        const MixedRunMetrics* results,
                        uint64_t result_count) {
  std::ofstream csv(path.c_str(), std::ios::out | std::ios::trunc);

  if (!csv.is_open()) {
    std::cerr << "[P10][mixed-scale-csv] cannot open: " << path
              << std::endl;
    return false;
  }
  csv << "worker_count,active_lanes,lane0_depth,lane1_depth,lane2_depth,"
         "mb_per_enclave,total_mb,max_batches_per_enclave,ocall_mode,"
         "sample_count,seconds_median,seconds_min,seconds_max,seconds_p95,"
         "mb_per_sec_median,mb_per_sec_min,mb_per_sec_max,mb_per_sec_p05,"
         "mb_per_sec_p95,speedup_vs_one,worker_ocalls,"
         "effective_cycle_hz_median,effective_cycle_hz_p95,"
         "enclave_aes_mb_per_sec_median,enclave_aes_mb_per_sec_p95,"
         "aes_stage_mb_per_sec_median,aes_stage_mb_per_sec_p95,"
         "yxstm_dispatch_mb_per_sec_median,yxstm_dispatch_mb_per_sec_p95,"
         "yxstm_effective_payload_mb_per_sec_median,"
         "yxstm_effective_payload_mb_per_sec_p95,"
         "yxstm_aggregate_sample_mb_per_sec_median,"
         "yxstm_aggregate_sample_mb_per_sec_p95,"
         "scheduler_efficiency_median,scheduler_efficiency_p95,"
         "lane_utilization_median,lane_utilization_p95,"
         "master_wall_seconds_median,master_wall_seconds_p95,"
         "master_dispatch_wall_seconds_median,"
         "master_dispatch_wall_seconds_p95,"
         "master_aggregate_wall_seconds_median,"
         "master_aggregate_wall_seconds_p95,"
         "compute_wall_seconds_median,compute_wall_seconds_p95,"
         "aes_oncpu_wall_seconds_median,aes_oncpu_wall_seconds_p95,"
         "ocall_wall_seconds_median,ocall_wall_seconds_p95,"
         "ready_wait_wall_seconds_median,ready_wait_wall_seconds_p95,"
         "pmp_wall_seconds_estimated_median,"
         "pmp_wall_seconds_estimated_p95,"
         "switch_wall_seconds_median,switch_wall_seconds_p95,"
         "scheduler_wall_seconds_estimated_median,"
         "scheduler_wall_seconds_estimated_p95,"
         "protocol_wall_seconds_median,protocol_wall_seconds_p95,"
         "worker_aes_cycles,worker_aes_mtime_ticks,"
         "worker_protocol_cycles,worker_protocol_mtime_ticks,"
         "worker_ready_wait_mtime_ticks,worker_ocall_mtime_ticks,"
         "slot_scheduler_cycles,"
         "slot_dispatches,"
         "slot_aggregates,slot_wait_yields,master_dispatch_cycles,"
         "master_dispatch_mtime_ticks,master_dispatch_bytes,"
         "worker_compute_wall_cycles,worker_compute_wall_mtime_ticks,"
         "master_aggregate_cycles,master_aggregate_mtime_ticks,"
         "master_aggregate_sample_bytes,master_protocol_cycles,"
         "master_protocol_mtime_ticks,task_e2e_cycles,"
         "task_e2e_mtime_ticks,context_switches,"
         "context_switch_cycles,context_switch_mtime_ticks,"
         "context_gpr_cycles,context_smode_csr_cycles,"
         "context_fp_cycles,context_pmp_cycles,context_platform_cycles,"
         "context_scheduler_lock_cycles,worker_exec_runtime_mtime_ticks,"
         "worker_aes_oncpu_mtime_ticks,worker_aes_oncpu_min_mtime_ticks,"
         "worker_aes_oncpu_max_mtime_ticks,worker_runtime_members,"
         "pmp_grant_suspend_cycles,pmp_epm_revoke_cycles,"
         "pmp_epm_install_cycles,pmp_yxstm_restore_cycles,pmp_fence_cycles,"
         "pmp_validation_cycles,pmp_lock_wait_cycles,grant_suspend_restores,"
         "grant_suspend_restore_cycles,sm_ocalls,sm_ocall_e2e_cycles,"
         "ocall_handler_count,ocall_handler_cycles,ocall_wait_count,"
         "ocall_wait_mtime_ticks,lane_wait_blocks,lane_wait_wakes,"
         "lane_wait_mtime_ticks,cfs_picks,cfs_preemptions,"
         "cfs_runtime_mtime_ticks,cfs_vruntime_delta,cfs_slice_ticks,"
         "cfs_min_granularity_hits,cfs_dynamic_min_slice_mtime_ticks,heartbeats,"
         "heartbeat_cycles,timer_traps,timer_trap_cycles,host_services,"
         "scrub_count,scrub_bytes,scrub_cycles,max_running_workers,digest,scheduler\n";
  csv << std::setprecision(12);
  for (uint64_t i = 0; i < result_count; ++i) {
    const MixedRunMetrics& metrics = results[i];

    csv << metrics.worker_count << ","
        << metrics.active_lanes << ","
        << metrics.lane_depth[0] << ","
        << metrics.lane_depth[1] << ","
        << metrics.lane_depth[2] << ","
        << (static_cast<double>(metrics.bytes_per_enclave) /
            kDecimalMbBytes) << ","
        << (static_cast<double>(metrics.total_bytes) /
            kDecimalMbBytes) << ","
        << metrics.chunks_per_enclave << ","
        << (metrics.ocall_mode == GROUP_PMP_MIXED_OCALL_PER_TASK ?
            "per-task" : "per-chunk-stress") << ","
        << metrics.sample_count << ","
        << metrics.seconds << ","
        << metrics.seconds_min << ","
        << metrics.seconds_max << ","
        << metrics.seconds_p95 << ","
        << metrics.mb_per_sec << ","
        << metrics.mb_per_sec_min << ","
        << metrics.mb_per_sec_max << ","
        << metrics.mb_per_sec_p05 << ","
        << metrics.mb_per_sec_p95 << ","
        << metrics.speedup_vs_one << ","
        << metrics.worker_ocalls << ","
        << metrics.effective_cycle_hz << ","
        << metrics.effective_cycle_hz_p95 << ","
        << metrics.enclave_aes_mb_per_sec << ","
        << metrics.enclave_aes_mb_per_sec_p95 << ","
        << metrics.aes_stage_mb_per_sec << ","
        << metrics.aes_stage_mb_per_sec_p95 << ","
        << metrics.yxstm_dispatch_mb_per_sec << ","
        << metrics.yxstm_dispatch_mb_per_sec_p95 << ","
        << metrics.yxstm_effective_payload_mb_per_sec << ","
        << metrics.yxstm_effective_payload_mb_per_sec_p95 << ","
        << metrics.yxstm_aggregate_mb_per_sec << ","
        << metrics.yxstm_aggregate_mb_per_sec_p95 << ","
        << metrics.scheduler_efficiency << ","
        << metrics.scheduler_efficiency_p95 << ","
        << metrics.lane_utilization << ","
        << metrics.lane_utilization_p95 << ","
        << metrics.master_wall_seconds << ","
        << metrics.master_wall_seconds_p95 << ","
        << metrics.master_dispatch_wall_seconds << ","
        << metrics.master_dispatch_wall_seconds_p95 << ","
        << metrics.master_aggregate_wall_seconds << ","
        << metrics.master_aggregate_wall_seconds_p95 << ","
        << metrics.compute_wall_seconds << ","
        << metrics.compute_wall_seconds_p95 << ","
        << metrics.aes_wall_seconds << ","
        << metrics.aes_wall_seconds_p95 << ","
        << metrics.ocall_wall_seconds << ","
        << metrics.ocall_wall_seconds_p95 << ","
        << metrics.wait_wall_seconds << ","
        << metrics.wait_wall_seconds_p95 << ","
        << metrics.pmp_wall_seconds << ","
        << metrics.pmp_wall_seconds_p95 << ","
        << metrics.switch_wall_seconds << ","
        << metrics.switch_wall_seconds_p95 << ","
        << metrics.scheduler_wall_seconds << ","
        << metrics.scheduler_wall_seconds_p95 << ","
        << metrics.protocol_wall_seconds << ","
        << metrics.protocol_wall_seconds_p95 << ","
        << metrics.worker_aes_cycles << ","
        << metrics.worker_aes_time_ticks << ","
        << metrics.worker_protocol_cycles << ","
        << metrics.worker_protocol_time_ticks << ","
        << metrics.worker_ready_wait_time_ticks << ","
        << metrics.worker_ocall_time_ticks << ","
        << metrics.slot_scheduler_cycles << ","
        << metrics.slot_dispatches << ","
        << metrics.slot_aggregates << ","
        << metrics.slot_wait_yields << ","
        << metrics.master_dispatch_cycles << ","
        << metrics.master_dispatch_time_ticks << ","
        << metrics.master_dispatch_bytes << ","
        << metrics.worker_compute_wall_cycles << ","
        << metrics.worker_compute_wall_time_ticks << ","
        << metrics.master_aggregate_cycles << ","
        << metrics.master_aggregate_time_ticks << ","
        << metrics.master_aggregate_bytes << ","
        << metrics.master_protocol_cycles << ","
        << metrics.master_protocol_time_ticks << ","
        << metrics.task_e2e_cycles << ","
        << metrics.task_e2e_time_ticks << ","
        << metrics.context_switches << ","
        << metrics.context_switch_cycles << ","
        << metrics.context_switch_ticks << ","
        << metrics.context_gpr_cycles << ","
        << metrics.context_smode_csr_cycles << ","
        << metrics.context_fp_cycles << ","
        << metrics.context_pmp_cycles << ","
        << metrics.context_platform_cycles << ","
        << metrics.context_scheduler_lock_cycles << ","
        << metrics.worker_exec_runtime_ticks << ","
        << metrics.worker_aes_exec_runtime_ticks << ","
        << metrics.worker_aes_exec_runtime_min << ","
        << metrics.worker_aes_exec_runtime_max << ","
        << metrics.worker_runtime_members << ","
        << metrics.pmp_grant_suspend_cycles << ","
        << metrics.pmp_epm_revoke_cycles << ","
        << metrics.pmp_epm_install_cycles << ","
        << metrics.pmp_yxstm_restore_cycles << ","
        << metrics.pmp_fence_cycles << ","
        << metrics.pmp_validation_cycles << ","
        << metrics.pmp_lock_wait_cycles << ","
        << metrics.grant_suspend_restores << ","
        << metrics.grant_suspend_restore_cycles << ","
        << metrics.sm_ocalls << ","
        << metrics.sm_ocall_cycles << ","
        << metrics.ocall_handler_count << ","
        << metrics.ocall_handler_cycles << ","
        << metrics.ocall_wait_count << ","
        << metrics.ocall_wait_ticks << ","
        << metrics.lane_wait_blocks << ","
        << metrics.lane_wait_wakes << ","
        << metrics.lane_wait_ticks << ","
        << metrics.cfs_picks << ","
        << metrics.cfs_preemptions << ","
        << metrics.cfs_runtime_ticks << ","
        << metrics.cfs_vruntime_delta << ","
        << metrics.cfs_slice_ticks << ","
        << metrics.cfs_min_granularity_hits << ","
        << metrics.cfs_dynamic_min_slice_ticks << ","
        << metrics.heartbeats << ","
        << metrics.heartbeat_cycles << ","
        << metrics.timer_traps << ","
        << metrics.timer_trap_cycles << ","
        << metrics.host_services << ","
        << metrics.scrub_count << ","
        << metrics.scrub_bytes << ","
        << metrics.scrub_cycles << ","
        << metrics.max_running_workers << ","
        << metrics.digest << ","
        << "exclusive-lease-cfs-lite-data-ready-slots\n";
  }
  csv.close();
  if (csv.fail()) {
    std::cerr << "[P10][mixed-scale-csv] write failed: " << path
              << std::endl;
    return false;
  }
  std::cout << "[P10][mixed-scale-csv] path=" << path
            << " rows=" << result_count << std::endl;
  return true;
}

bool
run_mixed_scaling_phase(const char* master_eapp, const char* worker_eapp,
                        const char* runtime, const char* loader,
                        uint64_t ocall_mode) {
  const uint64_t max_workers = env_u64(
      "GROUP_PMP_MIXED_MAX_WORKERS", GROUP_PMP_MIXED_MAX_WORKERS, 1,
      GROUP_PMP_MIXED_MAX_WORKERS);
  const char* csv_env = std::getenv("GROUP_PMP_MIXED_CSV");
  const bool write_csv = csv_env && csv_env[0] != '\0';
  const std::string csv_path = write_csv ? csv_env : "";
  const uint64_t repetitions = env_u64(
      "GROUP_PMP_MIXED_REPETITIONS", 5, 5, 50);
  const uint64_t random_seed = env_u64(
      "GROUP_PMP_MIXED_RANDOM_SEED", UINT64_C(557103871172), 0,
      UINT64_MAX);
  MixedRunMetrics baseline;
  MixedRunMetrics results[GROUP_PMP_MIXED_MAX_WORKERS];
  std::vector<std::vector<MixedRunMetrics> > samples(max_workers + 1);
  std::vector<uint64_t> run_order;
  std::mt19937_64 random(random_seed);

  std::memset(&baseline, 0, sizeof(baseline));
  std::memset(results, 0, sizeof(results));
  for (uint64_t lane_depth = 1;
       lane_depth <= GROUP_PMP_MIXED_MAX_LANE_DEPTH; ++lane_depth)
    if (!validate_mixed_slot_partition(lane_depth)) {
      std::cerr << "[P10][mixed-scale] invalid slot partition depth="
                << lane_depth << std::endl;
      return false;
    }
  if (register_call(1, group_pmp_ocall_ack) != 0) {
    std::cerr << "[P10][mixed-scale] failed to register OCALL handler"
              << std::endl;
    return false;
  }
  const char* ocall_mode_name =
      ocall_mode == GROUP_PMP_MIXED_OCALL_PER_TASK ?
          "per-task" : "per-chunk-stress";

  std::cout << "[host] phase: mixed-scale 1.." << max_workers
             << " workers, one 12 MB task per enclave split by dynamic slot capacity, "
                 "exclusive lease: CFS-lite competes only data-ready lane members"
             << " ocall_mode=" << ocall_mode_name
             << " repetitions=" << repetitions
             << " randomized_seed=" << random_seed
             << std::endl;
  run_order.reserve(max_workers * repetitions);
  for (uint64_t repeat = 0; repeat < repetitions; ++repeat)
    for (uint64_t workers = 1; workers <= max_workers; ++workers)
      run_order.push_back(workers);
  std::shuffle(run_order.begin(), run_order.end(), random);

  for (size_t run = 0; run < run_order.size(); ++run) {
    uint64_t workers = run_order[run];
    MixedWorkload workload;
    MixedRunMetrics metrics;

    if (!build_mixed_workload(workers, ocall_mode, &workload) ||
        !run_mixed_scaling_case(
            master_eapp, worker_eapp, runtime, loader, workload,
            nullptr, &metrics))
      return false;
    samples[workers].push_back(metrics);
  }
  for (uint64_t workers = 1; workers <= max_workers; ++workers) {
    if (!aggregate_mixed_samples(samples[workers], &results[workers - 1],
                                 &std::cerr))
      return false;
  }
  baseline = results[0];
  for (uint64_t workers = 1; workers <= max_workers; ++workers) {
    MixedRunMetrics& metrics = results[workers - 1];

    metrics.speedup_vs_one = metrics.mb_per_sec / baseline.mb_per_sec;
    std::cout << "[P10][mixed-scale-summary] workers=" << workers
              << " samples=" << metrics.sample_count
              << " seconds_median=" << metrics.seconds
              << " seconds_min=" << metrics.seconds_min
              << " seconds_max=" << metrics.seconds_max
              << " seconds_p95=" << metrics.seconds_p95
              << " mb_per_sec_median=" << metrics.mb_per_sec
              << " mb_per_sec_min=" << metrics.mb_per_sec_min
              << " mb_per_sec_max=" << metrics.mb_per_sec_max
              << " mb_per_sec_p05=" << metrics.mb_per_sec_p05
              << " mb_per_sec_p95=" << metrics.mb_per_sec_p95
              << " speedup_vs_one=" << metrics.speedup_vs_one
              << " enclave_aes_mb_per_sec_median="
              << metrics.enclave_aes_mb_per_sec
              << " enclave_aes_mb_per_sec_p95="
              << metrics.enclave_aes_mb_per_sec_p95
              << " aes_stage_mb_per_sec_median="
              << metrics.aes_stage_mb_per_sec
              << " aes_stage_mb_per_sec_p95="
              << metrics.aes_stage_mb_per_sec_p95
              << " yxstm_dispatch_mb_per_sec_median="
              << metrics.yxstm_dispatch_mb_per_sec
              << " yxstm_dispatch_mb_per_sec_p95="
              << metrics.yxstm_dispatch_mb_per_sec_p95
              << " yxstm_effective_payload_mb_per_sec_median="
              << metrics.yxstm_effective_payload_mb_per_sec
              << " yxstm_effective_payload_mb_per_sec_p95="
              << metrics.yxstm_effective_payload_mb_per_sec_p95
              << " yxstm_aggregate_sample_mb_per_sec_median="
              << metrics.yxstm_aggregate_mb_per_sec
              << " yxstm_aggregate_sample_mb_per_sec_p95="
              << metrics.yxstm_aggregate_mb_per_sec_p95
              << " scheduler_efficiency_median="
              << metrics.scheduler_efficiency
              << " scheduler_efficiency_p95="
              << metrics.scheduler_efficiency_p95
              << " lane_utilization_median="
              << metrics.lane_utilization
              << " lane_utilization_p95="
              << metrics.lane_utilization_p95
              << " master_wall_seconds_median="
              << metrics.master_wall_seconds
              << " master_wall_seconds_p95="
              << metrics.master_wall_seconds_p95
              << " aes_oncpu_wall_seconds_median="
              << metrics.aes_wall_seconds
              << " aes_oncpu_wall_seconds_p95="
              << metrics.aes_wall_seconds_p95
              << " ocall_wall_seconds_median="
              << metrics.ocall_wall_seconds
              << " ocall_wall_seconds_p95="
              << metrics.ocall_wall_seconds_p95
              << " ready_wait_wall_seconds_median="
              << metrics.wait_wall_seconds
              << " ready_wait_wall_seconds_p95="
              << metrics.wait_wall_seconds_p95
              << " pmp_wall_seconds_estimated_median="
              << metrics.pmp_wall_seconds
              << " pmp_wall_seconds_estimated_p95="
              << metrics.pmp_wall_seconds_p95
              << " switch_wall_seconds_median="
              << metrics.switch_wall_seconds
              << " switch_wall_seconds_p95="
              << metrics.switch_wall_seconds_p95
              << " scheduler_wall_seconds_estimated_median="
              << metrics.scheduler_wall_seconds
              << " scheduler_wall_seconds_estimated_p95="
              << metrics.scheduler_wall_seconds_p95
              << " protocol_wall_seconds_median="
              << metrics.protocol_wall_seconds
              << " protocol_wall_seconds_p95="
              << metrics.protocol_wall_seconds_p95
              << " worker_aes_oncpu_mtime_ticks="
              << metrics.worker_aes_exec_runtime_ticks
              << " worker_exec_runtime_mtime_ticks="
              << metrics.worker_exec_runtime_ticks
              << " master_dispatch_cycles="
              << metrics.master_dispatch_cycles
              << " worker_compute_wall_cycles="
              << metrics.worker_compute_wall_cycles
              << " master_aggregate_cycles="
              << metrics.master_aggregate_cycles
              << " master_protocol_cycles="
              << metrics.master_protocol_cycles
               << " task_e2e_cycles="
               << metrics.task_e2e_cycles
              << " slot_dispatches=" << metrics.slot_dispatches
              << " slot_aggregates=" << metrics.slot_aggregates
              << " slot_wait_yields=" << metrics.slot_wait_yields
              << " slot_scheduler_cycles=" << metrics.slot_scheduler_cycles
              << " pmp_grant_suspend_cycles="
              << metrics.pmp_grant_suspend_cycles
              << " pmp_epm_revoke_cycles="
              << metrics.pmp_epm_revoke_cycles
              << " pmp_epm_install_cycles="
              << metrics.pmp_epm_install_cycles
              << " pmp_yxstm_restore_cycles="
              << metrics.pmp_yxstm_restore_cycles
              << " pmp_fence_cycles=" << metrics.pmp_fence_cycles
              << " pmp_validation_cycles="
              << metrics.pmp_validation_cycles
              << " pmp_lock_wait_cycles="
              << metrics.pmp_lock_wait_cycles
              << " cfs_dynamic_min_slice_mtime_ticks="
              << metrics.cfs_dynamic_min_slice_ticks
              << " scrub_count=" << metrics.scrub_count
              << " scrub_bytes=" << metrics.scrub_bytes
              << " scrub_cycles=" << metrics.scrub_cycles
              << " counter_sample=per-field-median"
              << std::endl;
  }
  std::cout << "[P10][mixed-scale-trend] speedup=";
  for (uint64_t worker = 0; worker < max_workers; ++worker) {
    if (worker)
      std::cout << ",";
    std::cout << (results[worker].mb_per_sec / baseline.mb_per_sec);
  }
  std::cout << " baseline_mb_per_sec=" << baseline.mb_per_sec
            << " ocall_mode=" << ocall_mode_name
            << std::endl;
  if (!write_csv) {
    std::cout << "[P10][mixed-scale-csv] disabled" << std::endl;
    return true;
  }
  return write_mixed_scaling_csv(csv_path, results, max_workers);
}

const char* sqlite_workload_name(uint64_t workload) {
  const char* fio_profile = std::getenv("GROUP_PMP_FIO_PROFILE");
  if (fio_profile && fio_profile[0]) {
    if (workload == GROUP_PMP_SQLITE_FILLSEQ &&
        std::strcmp(fio_profile, "seq-write-2m") == 0)
      return "fio-seq-write-2m";
    if (workload == GROUP_PMP_SQLITE_READSEQ &&
        std::strcmp(fio_profile, "seq-read-2m") == 0)
      return "fio-seq-read-2m";
    if (workload == GROUP_PMP_SQLITE_FILLRANDOM &&
        std::strcmp(fio_profile, "rand-write-4k") == 0)
      return "fio-rand-write-4k";
    if (workload == GROUP_PMP_SQLITE_READRANDOM &&
        std::strcmp(fio_profile, "rand-read-4k") == 0)
      return "fio-rand-read-4k";
    if (workload == GROUP_PMP_SQLITE_READRAND100K &&
        std::strcmp(fio_profile, "rand-read-100k") == 0)
      return "fio-rand-read-100k";
  }
  switch (workload) {
    case GROUP_PMP_SQLITE_FILLSEQ: return "fillseq";
    case GROUP_PMP_SQLITE_FILLSEQBATCH: return "fillseqbatch";
    case GROUP_PMP_SQLITE_FILLRANDOM: return "fillrandom";
    case GROUP_PMP_SQLITE_FILLRANDOMBATCH: return "fillrandombatch";
    case GROUP_PMP_SQLITE_OVERWRITE: return "overwrite";
    case GROUP_PMP_SQLITE_READSEQ: return "readseq";
    case GROUP_PMP_SQLITE_READRANDOM: return "readrandom";
    case GROUP_PMP_SQLITE_READRAND100K: return "readrand100k";
    default: return "invalid";
  }
}

bool sqlite_workload_selected(uint64_t workload) {
  if(MotivationSystem::enabled()) return workload==GROUP_PMP_SQLITE_READSEQ;
  const char* security_case = std::getenv("GROUP_PMP_SECURITY_CAPTURE_WORKLOAD");
  if (security_case && std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR"))
    return std::strcmp(security_case, sqlite_workload_name(workload)) == 0;
  const char* selection = std::getenv("GROUP_PMP_SQLITE_WORKLOAD_SET");
  if (selection && std::strncmp(selection, "fio-", 4) == 0)
    return std::strcmp(selection, sqlite_workload_name(workload)) == 0;
  return !selection || !selection[0] || std::strcmp(selection, "all") == 0 ||
      (std::strcmp(selection, "random-pair") == 0 &&
       (workload == GROUP_PMP_SQLITE_FILLRANDOM ||
        workload == GROUP_PMP_SQLITE_READRANDOM));
}

uint64_t sqlite_selected_workload_count() {
  uint64_t count = 0;
  for (uint64_t workload = GROUP_PMP_SQLITE_FILLSEQ;
       workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload)
    count += sqlite_workload_selected(workload) ? 1 : 0;
  return count;
}

bool sqlite_worker_count_selected(uint64_t workers) {
  if(MotivationSystem::enabled())
    return workers==env_u64("GROUP_PMP_MOTIVATION_WORKERS",0,1,3);
  const char* single = std::getenv("GROUP_PMP_SECURITY_CAPTURE_WORKERS");
  if (single && std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR"))
    return workers == static_cast<uint64_t>(std::strtoul(single, nullptr, 10));
  const char* selection = std::getenv("GROUP_PMP_SECURITY_WORKER_SET");
  return !selection || !selection[0] ||
      (std::strcmp(selection, "1,4") == 0 && (workers == 1 || workers == 4));
}

uint64_t sqlite_selected_worker_count(uint64_t max_workers) {
  uint64_t count = 0;
  for (uint64_t workers = 1; workers <= max_workers; ++workers)
    count += sqlite_worker_count_selected(workers) ? 1 : 0;
  return count;
}

struct SqliteNoExtentBaseline {
  bool available;
  uint64_t samples;
  uint64_t total_bytes;
  double seconds_median;
  double seconds_min;
  double seconds_max;
  double seconds_p95;
  double mb_per_sec_median;
  double mb_per_sec_min;
  double mb_per_sec_max;
  double mb_per_sec_p05;
  double mb_per_sec_p95;

  SqliteNoExtentBaseline()
      : available(false), samples(0), total_bytes(0), seconds_median(0.0),
        seconds_min(0.0), seconds_max(0.0), seconds_p95(0.0),
        mb_per_sec_median(0.0), mb_per_sec_min(0.0),
        mb_per_sec_max(0.0), mb_per_sec_p05(0.0), mb_per_sec_p95(0.0) {}
};

typedef std::vector<std::vector<SqliteNoExtentBaseline> >
    SqliteNoExtentScaleBaselines;

std::vector<std::string> split_simple_csv_row(const std::string& line) {
  std::vector<std::string> fields;
  size_t begin = 0;
  for (;;) {
    const size_t comma = line.find(',', begin);
    fields.push_back(line.substr(begin, comma == std::string::npos ?
        std::string::npos : comma - begin));
    if (comma == std::string::npos)
      break;
    begin = comma + 1;
  }
  return fields;
}

bool parse_csv_u64(const std::string& value, uint64_t* parsed) {
  char* end = nullptr;
  unsigned long long converted;
  if (!parsed || value.empty())
    return false;
  errno = 0;
  converted = std::strtoull(value.c_str(), &end, 10);
  if (errno || !end || *end != '\0')
    return false;
  *parsed = static_cast<uint64_t>(converted);
  return true;
}

bool parse_csv_double(const std::string& value, double* parsed) {
  char* end = nullptr;
  double converted;
  if (!parsed || value.empty())
    return false;
  errno = 0;
  converted = std::strtod(value.c_str(), &end);
  if (errno || !end || *end != '\0')
    return false;
  *parsed = converted;
  return true;
}

bool sqlite_workload_from_name(const std::string& name, uint64_t* workload) {
  if (!workload)
    return false;
  for (uint64_t candidate = GROUP_PMP_SQLITE_FILLSEQ;
       candidate <= GROUP_PMP_SQLITE_READRAND100K; ++candidate) {
    if (name == sqlite_workload_name(candidate)) {
      *workload = candidate;
      return true;
    }
  }
  return false;
}

bool csv_column_index(const std::map<std::string, size_t>& columns,
                      const char* name, size_t* index) {
  const std::map<std::string, size_t>::const_iterator it =
      columns.find(name);
  if (!index || it == columns.end())
    return false;
  *index = it->second;
  return true;
}

bool sqlite_baseline_mode_matches(const std::string& actual,
                                  const char* expected) {
  if (!expected)
    return false;
  if (actual == expected)
    return true;
  return std::strcmp(expected, "sync-no-extent") == 0 &&
      actual == "no-extent";
}

bool load_sqlite_no_extent_baselines(
    const std::string& path, const char* expected_io_mode,
    uint64_t max_workers,
    std::vector<SqliteNoExtentBaseline>* baselines,
    SqliteNoExtentScaleBaselines* scale_baselines) {
  static const char* const required_columns[] = {
      "io_mode", "workload", "worker_count", "total_bytes", "samples",
      "seconds_median", "seconds_min", "seconds_max", "seconds_p95",
      "mb_per_sec_median", "mb_per_sec_min", "mb_per_sec_max",
      "mb_per_sec_p05", "mb_per_sec_p95"};
  std::ifstream input(path.c_str());
  std::string line;
  std::map<std::string, size_t> columns;
  std::vector<size_t> required_indexes(
      sizeof(required_columns) / sizeof(required_columns[0]));
  if (!max_workers || !baselines || !scale_baselines || !input ||
      !std::getline(input, line))
    return false;
  const std::vector<std::string> header = split_simple_csv_row(line);
  for (size_t i = 0; i < header.size(); ++i) {
    if (!columns.insert(std::make_pair(header[i], i)).second)
      return false;
  }
  for (size_t i = 0; i < required_indexes.size(); ++i) {
    if (!csv_column_index(columns, required_columns[i],
                          &required_indexes[i]))
      return false;
  }
  size_t layout_index;
  if (!csv_column_index(columns, "file_layout_version", &layout_index)) {
    std::cerr << "[P10][sqlite-baseline] missing packed-layout version; remeasure all modes: "
              << path << std::endl;
    return false;
  }
  size_t address_index;
  if (!csv_column_index(columns, "address_mode", &address_index)) {
    std::cerr << "[P10][sqlite-baseline] missing address mode; remeasure this workload: "
              << path << std::endl;
    return false;
  }

  size_t common_index, descriptor_index, cluster_index;
  if (!csv_column_index(columns, "common_path_version", &common_index) ||
      !csv_column_index(columns, "descriptor_limit", &descriptor_index) ||
      !csv_column_index(columns, "cluster_mode", &cluster_index)) {
    std::cerr << "[P10][sqlite-baseline] missing common execution contract; remeasure Async/Sync: "
              << path << std::endl;
    return false;
  }
  baselines->assign(GROUP_PMP_SQLITE_WORKLOAD_COUNT + 1,
                    SqliteNoExtentBaseline());
  scale_baselines->assign(
      GROUP_PMP_SQLITE_WORKLOAD_COUNT + 1,
      std::vector<SqliteNoExtentBaseline>(max_workers + 1));
  while (std::getline(input, line)) {
    if (line.empty())
      continue;
    const std::vector<std::string> fields = split_simple_csv_row(line);
    uint64_t workers = 0;
    uint64_t workload = 0;
    if (fields.size() != header.size())
      return false;
    const auto cipher_column = columns.find("cipher");
    if ((cipher_column == columns.end() && selected_benchmark_cipher() != BENCHMARK_AES_ECB) ||
        (cipher_column != columns.end() && fields[cipher_column->second] != selected_benchmark_cipher_name())) {
      std::cerr << "[P10][sqlite-baseline] cipher mismatch: " << path << std::endl;
      return false;
    }
    uint64_t common_version = 0, descriptors = 0;
    if (!parse_csv_u64(fields[common_index], &common_version) ||
        !parse_csv_u64(fields[descriptor_index], &descriptors) ||
        common_version != kGroupPmpSqliteCommonPathVersion ||
        descriptors != GROUP_PMP_SQLITE_VFS_BATCH_MAX || fields[cluster_index] != "off") {
      std::cerr << "[P10][sqlite-baseline] incompatible common path/descriptor/ablation contract: "
                << path << std::endl;
      return false;
    }
    if (fields[address_index] != sqlite_address_mode_name()) {
      std::cerr << "[P10][sqlite-baseline] incompatible address mode: " << path << std::endl;
      return false;
    }
    const auto timing = columns.find("timing_scope");
    if (timing != columns.end() && fields[timing->second].find("diagnostic-") == 0) {
      std::cerr << "[P10][sqlite-baseline] diagnostic timing cannot be a performance baseline: " << path << std::endl;
      return false;
    }
    uint64_t layout_version = 0;
    if (!parse_csv_u64(fields[layout_index], &layout_version) ||
        layout_version != GROUP_PMP_SQLITE_FILE_LAYOUT_VERSION) {
      std::cerr << "[P10][sqlite-baseline] incompatible file layout; remeasure all modes: "
                << path << std::endl;
      return false;
    }
    if (!sqlite_baseline_mode_matches(fields[required_indexes[0]],
                                      expected_io_mode))
      return false;
    if (!parse_csv_u64(fields[required_indexes[2]], &workers) || !workers)
      return false;
    if (workers > max_workers)
      continue;
    if (!sqlite_workload_from_name(fields[required_indexes[1]], &workload) ||
        workload >= scale_baselines->size() ||
        (*scale_baselines)[workload][workers].available)
      return false;
    SqliteNoExtentBaseline& baseline =
        (*scale_baselines)[workload][workers];
    if (!parse_csv_u64(fields[required_indexes[3]], &baseline.total_bytes) ||
        !parse_csv_u64(fields[required_indexes[4]], &baseline.samples) ||
        !parse_csv_double(fields[required_indexes[5]],
                          &baseline.seconds_median) ||
        !parse_csv_double(fields[required_indexes[6]],
                          &baseline.seconds_min) ||
        !parse_csv_double(fields[required_indexes[7]],
                          &baseline.seconds_max) ||
        !parse_csv_double(fields[required_indexes[8]],
                          &baseline.seconds_p95) ||
        !parse_csv_double(fields[required_indexes[9]],
                          &baseline.mb_per_sec_median) ||
        !parse_csv_double(fields[required_indexes[10]],
                          &baseline.mb_per_sec_min) ||
        !parse_csv_double(fields[required_indexes[11]],
                          &baseline.mb_per_sec_max) ||
        !parse_csv_double(fields[required_indexes[12]],
                          &baseline.mb_per_sec_p05) ||
        !parse_csv_double(fields[required_indexes[13]],
                          &baseline.mb_per_sec_p95) ||
        !baseline.samples || !baseline.total_bytes ||
        baseline.seconds_median <= 0.0 ||
        baseline.mb_per_sec_median <= 0.0)
      return false;
    baseline.available = true;
    if (workers == 1)
      (*baselines)[workload] = baseline;
  }
  if (input.bad())
    return false;
  for (uint64_t workload = GROUP_PMP_SQLITE_FILLSEQ;
       workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload) {
    if (!sqlite_workload_selected(workload)) continue;
    for (uint64_t workers = 1; workers <= max_workers; ++workers)
      if (sqlite_worker_count_selected(workers) &&
          !(*scale_baselines)[workload][workers].available)
        return false;
  }
  return true;
}

SqliteNoExtentBaseline sqlite_baseline_from_metric(
    const MixedRunMetrics& metric) {
  SqliteNoExtentBaseline baseline;
  baseline.available = metric.sample_count && metric.total_bytes &&
      metric.seconds > 0.0 && metric.mb_per_sec > 0.0;
  baseline.samples = metric.sample_count;
  baseline.total_bytes = metric.total_bytes;
  baseline.seconds_median = metric.seconds;
  baseline.seconds_min = metric.seconds_min;
  baseline.seconds_max = metric.seconds_max;
  baseline.seconds_p95 = metric.seconds_p95;
  baseline.mb_per_sec_median = metric.mb_per_sec;
  baseline.mb_per_sec_min = metric.mb_per_sec_min;
  baseline.mb_per_sec_max = metric.mb_per_sec_max;
  baseline.mb_per_sec_p05 = metric.mb_per_sec_p05;
  baseline.mb_per_sec_p95 = metric.mb_per_sec_p95;
  return baseline;
}

void capture_current_no_extent_baselines(
    const std::vector<std::vector<MixedRunMetrics> >& results,
    uint64_t max_workers,
    std::vector<SqliteNoExtentBaseline>* baselines,
    SqliteNoExtentScaleBaselines* scale_baselines) {
  baselines->assign(GROUP_PMP_SQLITE_WORKLOAD_COUNT + 1,
                    SqliteNoExtentBaseline());
  scale_baselines->assign(
      GROUP_PMP_SQLITE_WORKLOAD_COUNT + 1,
      std::vector<SqliteNoExtentBaseline>(max_workers + 1));
  for (uint64_t workload = GROUP_PMP_SQLITE_FILLSEQ;
       workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload) {
    if (!sqlite_workload_selected(workload)) continue;
    for (uint64_t workers = 1; workers <= max_workers; ++workers)
      (*scale_baselines)[workload][workers] =
          sqlite_baseline_from_metric(results[workload][workers]);
    (*baselines)[workload] = (*scale_baselines)[workload][1];
  }
}

bool resolve_sqlite_no_extent_baselines(
    const std::vector<std::vector<MixedRunMetrics> >& results,
    const char* expected_io_mode, const char* baseline_env,
    const char* legacy_baseline_env,
    std::vector<SqliteNoExtentBaseline>* baselines,
    SqliteNoExtentScaleBaselines* scale_baselines,
    uint64_t max_workers,
    std::string* source) {
  if (!expected_io_mode || !baseline_env || !baselines ||
      !scale_baselines || !max_workers || !source)
    return false;
  if (std::strcmp(sqlite_benchmark_io_mode_name(), expected_io_mode) == 0) {
    capture_current_no_extent_baselines(
        results, max_workers, baselines, scale_baselines);
    *source = "current-run";
  } else {
    const char* path = std::getenv(baseline_env);
    if ((!path || !path[0]) && legacy_baseline_env)
      path = std::getenv(legacy_baseline_env);
    if (!path || !path[0]) {
      baselines->assign(GROUP_PMP_SQLITE_WORKLOAD_COUNT + 1,
                        SqliteNoExtentBaseline());
      scale_baselines->assign(
          GROUP_PMP_SQLITE_WORKLOAD_COUNT + 1,
          std::vector<SqliteNoExtentBaseline>(max_workers + 1));
      *source = "unavailable";
      std::cerr << "[P10][sqlite-baseline] no " << expected_io_mode
                << " reference; cross-mode speedup is unavailable"
                << std::endl;
      return true;
    }
    if (!load_sqlite_no_extent_baselines(
            path, expected_io_mode, max_workers, baselines,
            scale_baselines)) {
      std::cerr << "[P10][sqlite-baseline] invalid " << expected_io_mode
                << " reference CSV: " << path << std::endl;
      return false;
    }
    *source = "reference-csv";
    std::cout << "[P10][sqlite-baseline] mode=" << expected_io_mode
              << " source=reference-csv path=" << path
              << " workloads=" << sqlite_selected_workload_count()
              << std::endl;
  }
  for (uint64_t workload = GROUP_PMP_SQLITE_FILLSEQ;
       workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload) {
    if (!sqlite_workload_selected(workload)) continue;
    for (uint64_t workers = 1; workers <= max_workers; ++workers) {
      const SqliteNoExtentBaseline& baseline =
          (*scale_baselines)[workload][workers];
      if (!sqlite_worker_count_selected(workers)) continue;
      const MixedRunMetrics& current = results[workload][workers];
      if (!baseline.available || baseline.total_bytes != current.total_bytes) {
        std::cerr << "[P10][sqlite-baseline] incompatible "
                  << expected_io_mode << " reference: workload="
                  << sqlite_workload_name(workload)
                  << " workers=" << workers
                  << " reference_bytes=" << baseline.total_bytes
                  << " current_bytes=" << current.total_bytes << std::endl;
        return false;
      }
    }
  }
  return true;
}

bool csv_has_uniform_columns(const std::string& path,
                             uint64_t expected_data_rows) {
  std::ifstream input(path.c_str());
  std::string line;
  uint64_t rows = 0;
  size_t expected_commas = 0;
  if (!input || !std::getline(input, line))
    return false;
  expected_commas = static_cast<size_t>(
      std::count(line.begin(), line.end(), ','));
  while (std::getline(input, line)) {
    if (line.empty())
      continue;
    ++rows;
    if (static_cast<size_t>(std::count(line.begin(), line.end(), ',')) !=
        expected_commas)
      return false;
  }
  return !input.bad() && rows == expected_data_rows;
}

bool check_sqlite_random_ring_result(const MixedRunMetrics& metric,
                                     const MixedWorkload& workload,
                                     std::ostream& diagnostics) {
  if (!group_pmp_sqlite_page_random(workload.workload_id))
    return true;
  if (!workload.worker_count || workload.worker_count > GROUP_PMP_MIXED_MAX_WORKERS) {
    diagnostics << "[P10][sqlite] invalid worker count for ring accounting" << std::endl;
    return false;
  }
  const uint64_t chunk = GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES;
  // Sentinel-enabled workers use compact batches to exercise buffer reuse.
  const uint64_t batch = security_scan_nonce()
      ? std::min(GROUP_PMP_SQLITE_VFS_BATCH_MAX, GROUP_PMP_SECURITY_BATCH_REQUESTS)
      : GROUP_PMP_SQLITE_VFS_BATCH_MAX;
  const bool planned = (sqlite_worker_diagnostic_flags(workload.workload_id, 0) &
                        GROUP_PMP_SQLITE_INTENT_LOOKAHEAD) != 0;
  const uint64_t window = std::min(GROUP_PMP_SQLITE_INTENT_MAX,
                                  GROUP_PMP_SQLITE_INTENT_WINDOW_BYTES / chunk);
  uint64_t requests = 0, doorbells = 0, windows = 0;
  for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
    const uint64_t bytes = workload.assigned_bytes[worker];
    const uint64_t count = bytes / chunk + (bytes % chunk != 0);
    requests += count;
    // Every intent window ends a ring batch, even when the worker task continues.
    // Derive boundaries from assigned work, not reported counters that could be wrong.
    if (planned) {
      const uint64_t full = count / window, tail = count % window;
      windows += full + (tail != 0);
      doorbells += full * (window / batch + (window % batch != 0)) +
                   tail / batch + (tail % batch != 0);
    } else {
      doorbells += count / batch + (count % batch != 0);
    }
  }
  const uint64_t intent_requests = planned ? requests : 0;
  if (metric.vfs_ring_request_count == requests &&
      metric.vfs_ring_doorbell_count == doorbells &&
      metric.sqlite_io_pipeline[SQLITE_PIPELINE_INTENT_WINDOWS] == windows &&
      metric.sqlite_io_pipeline[SQLITE_PIPELINE_INTENT_REQUESTS] == intent_requests)
    return true;
  diagnostics << "[P10][sqlite] random request-ring accounting mismatch: workload="
              << sqlite_workload_name(workload.workload_id)
              << " workers=" << workload.worker_count
              << " requests=" << metric.vfs_ring_request_count
              << " expected_requests=" << requests
              << " doorbells=" << metric.vfs_ring_doorbell_count
              << " expected_doorbells=" << doorbells
              << " window_requests=" << (planned ? window : 0)
              << " intent_windows=" << metric.sqlite_io_pipeline[SQLITE_PIPELINE_INTENT_WINDOWS]
              << " expected_intent_windows=" << windows
              << " intent_requests=" << metric.sqlite_io_pipeline[SQLITE_PIPELINE_INTENT_REQUESTS]
              << " expected_intent_requests=" << intent_requests << std::endl;
  return false;
}

bool check_sqlite_sequential_io_result(const MixedRunMetrics& metric,
                                       uint64_t workload_id,
                                       uint64_t workers,
                                       std::ostream& diagnostics) {
  const bool invalid = metric.io_trace_failed_request_count != 0 ||
      metric.sqlite_physical_request_count > metric.sqlite_logical_request_count ||
      metric.io_trace_max_request_bytes > UINT64_C(8000000);
  // Merging depends on simultaneously available adjacent requests. Independent
  // prefetch is correct even when each request completes before its peer arrives.
  // Keep the observation (and its zero merge count), not a selection-biased CSV.
  const bool unexercised = metric.sqlite_logical_request_count >= 2 &&
      metric.sqlite_physical_request_count != 0 &&
      (metric.sqlite_merged_io_count == 0 ||
       metric.sqlite_physical_request_count >= metric.sqlite_logical_request_count ||
       (metric.io_trace_request_count != 0 &&
        metric.io_trace_max_request_bytes < UINT64_C(4000000)));
  if (!invalid && !unexercised)
    return true;
  diagnostics << (invalid ? "[P10][sqlite][ERROR] invalid sequential I/O result" :
      "[P10][sqlite][WARN] sequential coalescing target not observed")
      << ": workload=" << sqlite_workload_name(workload_id)
      << " workers=" << workers
      << " logical=" << metric.sqlite_logical_request_count
      << " physical=" << metric.sqlite_physical_request_count
      << " merged=" << metric.sqlite_merged_io_count
      << " max_request_bytes=" << metric.io_trace_max_request_bytes
      << " failed_requests=" << metric.io_trace_failed_request_count
      << " sample_retained=" << (invalid ? 0 : 1) << std::endl;
  return !invalid;
}

bool write_sqlite_scaling_csv(
    const std::string& path,
    const std::vector<std::vector<MixedRunMetrics> >& results,
    uint64_t max_workers,
    const std::vector<SqliteNoExtentBaseline>& sync_no_extent_baselines,
    const SqliteNoExtentScaleBaselines& sync_no_extent_scale_baselines,
    const std::string& sync_no_extent_baseline_source,
    const std::vector<SqliteNoExtentBaseline>& async_no_extent_baselines,
    const SqliteNoExtentScaleBaselines& async_no_extent_scale_baselines,
    const std::string& async_no_extent_baseline_source,
    uint64_t adaptive_gain_target_permille) {
  std::ofstream csv(path.c_str(), std::ios::out | std::ios::trunc);
  const double timebase_hz = static_cast<double>(riscv_timebase_hz());
  if (!csv)
    return false;
  csv << "io_mode,address_mode,cache_mode,io_policy_version,workload,worker_count,records_per_worker,total_bytes,samples,"
         "seconds_median,seconds_min,seconds_max,seconds_p95,"
         "host_envelope_seconds_median,"
         "host_envelope_seconds_p95,mb_per_sec_median,mb_per_sec_min,"
         "mb_per_sec_max,mb_per_sec_p05,mb_per_sec_p95,speedup_vs_one,"
         "speedup_vs_sync_no_extent_one,speedup_vs_async_no_extent_one,"
         "throughput_ratio_vs_sync_no_extent_same_workers,"
         "throughput_ratio_vs_async_no_extent_same_workers,"
         "adaptive_gain_target,adaptive_gain_target_met,"
         "sync_no_extent_baseline_available,"
         "sync_no_extent_baseline_source,sync_no_extent_one_samples,"
         "sync_no_extent_one_total_bytes,sync_no_extent_one_seconds_median,"
         "sync_no_extent_one_seconds_min,sync_no_extent_one_seconds_max,"
         "sync_no_extent_one_seconds_p95,"
         "sync_no_extent_one_mb_per_sec_median,"
         "sync_no_extent_one_mb_per_sec_min,"
         "sync_no_extent_one_mb_per_sec_max,"
         "sync_no_extent_one_mb_per_sec_p05,"
         "sync_no_extent_one_mb_per_sec_p95,"
         "async_no_extent_baseline_available,"
         "async_no_extent_baseline_source,async_no_extent_one_samples,"
         "async_no_extent_one_total_bytes,"
         "async_no_extent_one_seconds_median,"
         "async_no_extent_one_seconds_min,async_no_extent_one_seconds_max,"
         "async_no_extent_one_seconds_p95,"
         "async_no_extent_one_mb_per_sec_median,"
         "async_no_extent_one_mb_per_sec_min,"
         "async_no_extent_one_mb_per_sec_max,"
         "async_no_extent_one_mb_per_sec_p05,"
         "async_no_extent_one_mb_per_sec_p95,"
         "baseline_full_flow_mb_per_sec,"
         "baseline_full_flow_seconds,"
         "slot_dispatches,slot_aggregates,"
         "worker_compute_cycles,protocol_cycles,context_switches,pmp_cycles,"
         "ocalls,vfs_read_bytes,vfs_write_bytes,vfs_encrypt_cycles,"
         "vfs_decrypt_cycles,vfs_submit_count,vfs_wait_count,"
         "vfs_yield_count,vfs_wait_ticks,vfs_batch_submit_count,"
         "vfs_blocked_completion_count,vfs_queue_depth_peak,"
         "vfs_ring_doorbells,vfs_ring_requests,vfs_completion_batches,"
         "sqlite_task_count,sqlite_batch_count,sqlite_queue_depth_peak,"
         "sqlite_queue_wait_seconds,sqlite_single_writer_wait_seconds,"
         "sqlite_read_seconds,sqlite_write_seconds,sqlite_control_seconds,"
         "sqlite_commit_seconds,sqlite_commit_count,io_uring_submissions,"
         "registered_file_operations,registered_buffer_operations,"
         "fixed_buffer_operations,buffer_registration_attempts,"
         "buffer_registration_failures,"
         "direct_io_operations,direct_alignment_fallback_operations,"
         "posix_fallback_operations,"
         "merged_io_count,sparse_io_count,useful_io_bytes,"
         "physical_io_bytes,read_amplification,logical_request_count,"
         "physical_request_count,"
         "merge_rate,deduplicated_request_count,deduplication_rate,"
         "completion_wait_ocalls,"
         "cache_full_hits,cache_partial_hits,cache_misses,cache_hit_bytes,"
         "cache_hit_rate,request_collect_seconds,request_sort_seconds,"
         "request_cluster_seconds,io_submit_seconds,disk_io_seconds,"
         "utm_copy_seconds,completion_publish_seconds,wakeup_seconds,"
         "worker_submit_to_host_dequeue_seconds,"
         "host_dequeue_to_io_submit_seconds,io_submit_to_complete_seconds,"
         "io_complete_to_completion_publish_seconds,"
         "completion_publish_to_host_resume_request_seconds,"
         "wakeup_eligible_to_host_resume_request_seconds,"
         "host_resume_ioctl_seconds,completion_wakeup_count,"
         "completion_ready_before_wait_count,"
         "ewma_bandwidth_bytes_per_sec,ewma_request_latency_ns,"
         "ewma_queue_wait_ns,ewma_completion_latency_ns,"
         "adaptive_collect_usec,adaptive_batch_target,"
         "adaptive_queue_depth,adaptive_gap_bytes,"
         "io_critical_path_seconds,io_max_queue_wait_seconds,"
         "io_max_batch_service_seconds,io_max_completion_latency_seconds,"
         "io_request_count,"
         "io_member_request_count,io_total_range_bytes,io_useful_bytes,"
         "io_gap_bytes,io_range_start,io_range_end,io_covered_span_bytes,"
         "io_min_request_bytes,io_max_request_bytes,io_read_requests,"
         "io_write_requests,io_failed_requests,aes_seconds,"
         "enclave_ocall_seconds,sm_ocall_wait_seconds,"
         "context_switch_seconds,scheduler_seconds_estimated,"
         "sm_ocalls,sm_ocall_cycles,"
         "ocall_handler_count,ocall_handler_cycles,ocall_wait_count,"
         "ocall_wait_ticks,cfs_preemptions,host_services,max_running_workers,"
         "digest,security_boundary,"
         "timing_scope,vfs_crypto_sample_seconds,"
         "vfs_crypto_io_overlap_seconds,vfs_crypto_io_overlap_ratio,"
         "vfs_both_buffers_wait_seconds,vfs_completion_local_reaps,"
         "vfs_buffer_reuses,io_api_seconds,io_completion_wait_seconds,"
         "storage_sync_seconds,sequential_extent_count,"
         "sequential_8mb_extent_count,cross_worker_extent_count,"
         "io_timing_scope,cache_contract,crypto_io_overlap_scope,"
         "aes_oncpu_seconds,aes_elapsed_seconds,aes_descheduled_seconds,"
         "aes_oncpu_mb_per_sec,aes_timing_scope,"
         "request_queue_wait_mean_us,host_resume_ioctl_mean_us,"
         "write_overlap_check_seconds,write_overlap_checks,"
         "write_disjoint_batches,write_overlap_batches,"
         "adaptive_write_grow_count,adaptive_write_shrink_count,"
         "adaptive_write_hold_count,sequential_ready_single_batches,"
         "sequential_ready_multi_batches,sequential_ready_adjacent_pairs,"
         "sequential_ready_nonadjacent_pairs,"
         "random_sparse_fast_batches,"
         "random_sparse_fast_requests,"
         "random_planned_batches,"
         "random_precheck_fallbacks,"
         "random_precheck_ns,"
         "readseq_initial_requests,"
         "readseq_refill_peer_io_requests,"
         "readseq_refill_peer_ready_requests,"
         "readseq_refill_peer_idle_requests,"
         "random_local_plan_batches,"
         "random_local_candidate_requests,"
         "cache_fill_bytes,"
         "cache_fill_ns,"
         "cache_fill_skipped_bytes,"
         "cache_admission_disables,"
         "cache_admission_reenables,"
         "pipeline_doorbell_count,"
         "pipeline_doorbell_ack_seconds,"
         "pipeline_doorbell_ack_max_us,"
         "pipeline_completion_to_consume_count,"
         "pipeline_completion_to_consume_seconds,"
         "pipeline_completion_to_consume_max_us,"
         "pipeline_completion_timestamp_invalid,"
         "pipeline_ack_to_consume_seconds,"
         "pipeline_ack_to_consume_max_us,"
         "pipeline_buffer_consume_count,"
         "pipeline_buffer_consume_seconds,"
         "pipeline_buffer_consume_max_us,"
         "pipeline_buffer_refill_count,"
         "pipeline_buffer_refill_seconds,"
         "pipeline_buffer_refill_max_us,"
         "pipeline_request_prepare_seconds,"
         "pipeline_submission_timing_count,"
         "pipeline_submission_timestamp_invalid,"
         "pipeline_submit_to_host_seconds,"
         "pipeline_submit_to_host_max_us,"
         "pipeline_host_to_ack_seconds,"
         "pipeline_host_to_ack_max_us,"
         "pipeline_ack_to_resume_request_seconds,"
         "pipeline_ack_to_resume_request_max_us,"
         "pipeline_resume_request_to_return_seconds,"
         "pipeline_resume_request_to_return_max_us,"
         "worker_submit_resume_mean_us,worker_resume_timing_scope,host_resume_timing_scope,"
         "read100k_discrete_batches,read100k_merged_batches,"
         "read100k_discrete_bytes,read100k_merged_bytes,"
         "read100k_discrete_service_ns,read100k_merged_service_ns,"
         "read100k_merge_backoffs,read100k_merge_probes,"
         "wait_timing_count,wait_timestamp_invalid,wait_submit_to_host_seconds,"
         "wait_host_to_resume_seconds,wait_resume_to_return_seconds,"
         "wait_resume_to_return_max_us,wait_oncpu_seconds,wait_offcpu_seconds,"
         "wait_clock_invalid,wait_timing_scope,";
  for (const char* name : sqlite_pipeline_metric_names) csv << "io_pipeline_" << name << ',';
  csv << "file_layout_version,common_path_version,descriptor_limit,cluster_mode,io_pipeline_version,cipher\n";
  csv << std::setprecision(12);
  for (uint64_t workload = GROUP_PMP_SQLITE_FILLSEQ;
       workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload) {
    if (!sqlite_workload_selected(workload)) continue;
    const MixedRunMetrics& baseline = results[workload][1];
    const SqliteNoExtentBaseline& sync_no_extent =
        sync_no_extent_baselines[workload];
    const SqliteNoExtentBaseline& async_no_extent =
        async_no_extent_baselines[workload];
    for (uint64_t workers = 1; workers <= max_workers; ++workers) {
      const MixedRunMetrics& metric = results[workload][workers];
      if (!sqlite_worker_count_selected(workers)) continue;
      const SqliteNoExtentBaseline& sync_same_workers =
          sync_no_extent_scale_baselines[workload][workers];
      const SqliteNoExtentBaseline& async_same_workers =
          async_no_extent_scale_baselines[workload][workers];
      const double sync_same_worker_ratio =
          sync_same_workers.available ?
              metric.mb_per_sec / sync_same_workers.mb_per_sec_median : 0.0;
      const double async_same_worker_ratio =
          async_same_workers.available ?
              metric.mb_per_sec / async_same_workers.mb_per_sec_median : 0.0;
      const double adaptive_gain_target =
          static_cast<double>(adaptive_gain_target_permille) / 1000.0;
      const int adaptive_gain_target_met =
          sqlite_benchmark_io_mode() ==
                  SQLITE_BENCHMARK_IO_ADAPTIVE_EXTENT &&
              sync_same_workers.available ?
          (sync_same_worker_ratio >= adaptive_gain_target ? 1 : 0) : -1;
      uint64_t records = metric.bytes_per_enclave /
          group_pmp_sqlite_value_size(workload);
      uint64_t pmp_cycles = metric.pmp_grant_suspend_cycles +
          metric.pmp_epm_revoke_cycles + metric.pmp_epm_install_cycles +
          metric.pmp_yxstm_restore_cycles + metric.pmp_fence_cycles +
          metric.pmp_validation_cycles + metric.pmp_lock_wait_cycles;
      csv << sqlite_benchmark_io_mode_name() << ","
          << sqlite_address_mode_name() << ","
          << sqlite_benchmark_cache_mode_name() << ","
          << (sqlite_benchmark_io_mode() ==
                      SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT ?
              UINT64_C(1) :
              (sqlite_benchmark_io_mode() ==
                       SQLITE_BENCHMARK_IO_ASYNC_NO_EXTENT ?
                   UINT64_C(2) : sqlite_extent_io_policy_version())) << ","
          << sqlite_workload_name(workload) << "," << workers << ","
          << records << "," << metric.total_bytes << ","
          << metric.sample_count << "," << metric.seconds << ","
          << metric.seconds_min << "," << metric.seconds_max << ","
          << metric.seconds_p95 << ","
          << metric.host_envelope_seconds << ","
          << metric.host_envelope_seconds_p95 << ","
          << metric.mb_per_sec << ","
          << metric.mb_per_sec_min << "," << metric.mb_per_sec_max << ","
          << metric.mb_per_sec_p05 << "," << metric.mb_per_sec_p95 << ","
          << (metric.seconds ? baseline.seconds / metric.seconds : 0.0)
          << "," << (sync_no_extent.available ?
              metric.mb_per_sec / sync_no_extent.mb_per_sec_median : 0.0)
          << "," << (async_no_extent.available ?
              metric.mb_per_sec / async_no_extent.mb_per_sec_median : 0.0)
          << "," << sync_same_worker_ratio
          << "," << async_same_worker_ratio
          << "," << adaptive_gain_target
          << "," << adaptive_gain_target_met
          << "," << (sync_no_extent.available ? 1 : 0)
          << "," << sync_no_extent_baseline_source
          << "," << sync_no_extent.samples
          << "," << sync_no_extent.total_bytes
          << "," << sync_no_extent.seconds_median
          << "," << sync_no_extent.seconds_min
          << "," << sync_no_extent.seconds_max
          << "," << sync_no_extent.seconds_p95
          << "," << sync_no_extent.mb_per_sec_median
          << "," << sync_no_extent.mb_per_sec_min
          << "," << sync_no_extent.mb_per_sec_max
          << "," << sync_no_extent.mb_per_sec_p05
          << "," << sync_no_extent.mb_per_sec_p95
          << "," << (async_no_extent.available ? 1 : 0)
          << "," << async_no_extent_baseline_source
          << "," << async_no_extent.samples
          << "," << async_no_extent.total_bytes
          << "," << async_no_extent.seconds_median
          << "," << async_no_extent.seconds_min
          << "," << async_no_extent.seconds_max
          << "," << async_no_extent.seconds_p95
          << "," << async_no_extent.mb_per_sec_median
          << "," << async_no_extent.mb_per_sec_min
          << "," << async_no_extent.mb_per_sec_max
          << "," << async_no_extent.mb_per_sec_p05
          << "," << async_no_extent.mb_per_sec_p95
          << "," << baseline.mb_per_sec << "," << baseline.seconds << ","
          << metric.slot_dispatches << "," << metric.slot_aggregates << ","
          << metric.worker_aes_cycles << ","
          << metric.worker_protocol_cycles + metric.master_protocol_cycles
          << "," << metric.context_switches << "," << pmp_cycles << ","
          << metric.worker_ocalls << "," << metric.vfs_read_bytes << ","
          << metric.vfs_write_bytes << "," << metric.vfs_encrypt_cycles
          << "," << metric.vfs_decrypt_cycles << ","
          << metric.vfs_submit_count << "," << metric.vfs_wait_count << ","
          << metric.vfs_yield_count << "," << metric.vfs_wait_ticks << ","
          << metric.vfs_batch_submit_count << ","
          << metric.vfs_blocked_completion_count << ","
          << metric.vfs_queue_depth_peak << ","
          << metric.vfs_ring_doorbell_count << ","
          << metric.vfs_ring_request_count << ","
          << metric.vfs_completion_batch_count << ","
          << metric.sqlite_task_count << "," << metric.sqlite_batch_count
          << "," << metric.sqlite_queue_depth_peak << ","
          << (static_cast<double>(metric.sqlite_queue_wait_ns) / 1.0e9)
          << ","
          << (static_cast<double>(metric.sqlite_writer_wait_ns) / 1.0e9)
          << ","
          << (static_cast<double>(metric.sqlite_read_service_ns) / 1.0e9)
          << ","
          << (static_cast<double>(metric.sqlite_write_service_ns) / 1.0e9)
          << ","
          << (static_cast<double>(metric.sqlite_control_service_ns) / 1.0e9)
          << "," << (static_cast<double>(metric.sqlite_commit_ns) / 1.0e9)
          << "," << metric.sqlite_commit_count << ","
          << metric.sqlite_io_uring_submissions << ","
          << metric.sqlite_registered_file_operations << ","
          << metric.sqlite_registered_buffer_operations << ","
          << metric.sqlite_fixed_buffer_operations << ","
          << metric.sqlite_buffer_registration_attempts << ","
          << metric.sqlite_buffer_registration_failures << ","
          << metric.sqlite_direct_io_operations << ","
          << metric.sqlite_direct_alignment_fallback_operations << ","
          << metric.sqlite_posix_fallback_operations << ","
          << metric.sqlite_merged_io_count << ","
          << metric.sqlite_sparse_io_count << ","
          << metric.sqlite_useful_io_bytes << ","
          << metric.sqlite_physical_io_bytes << ","
          << (metric.sqlite_useful_io_bytes ?
              static_cast<double>(metric.sqlite_physical_io_bytes) /
                  static_cast<double>(metric.sqlite_useful_io_bytes) : 0.0)
          << "," << metric.sqlite_logical_request_count
          << "," << metric.sqlite_physical_request_count
          << "," << (metric.sqlite_logical_request_count ?
              static_cast<double>(metric.sqlite_logical_request_count -
                  std::min(metric.sqlite_logical_request_count,
                           metric.sqlite_physical_request_count)) /
                  static_cast<double>(metric.sqlite_logical_request_count) : 0.0)
          << "," << metric.sqlite_deduplicated_request_count
          << "," << (metric.sqlite_logical_request_count ?
              static_cast<double>(metric.sqlite_deduplicated_request_count) /
                  static_cast<double>(metric.sqlite_logical_request_count) : 0.0)
          << "," << metric.sqlite_completion_wait_ocall_count
          << "," << metric.sqlite_cache_full_hit_count
          << "," << metric.sqlite_cache_partial_hit_count
          << "," << metric.sqlite_cache_miss_count
          << "," << metric.sqlite_cache_hit_bytes
          << "," << (metric.sqlite_logical_request_count ?
              static_cast<double>(metric.sqlite_cache_full_hit_count +
                                  metric.sqlite_cache_partial_hit_count) /
                  static_cast<double>(metric.sqlite_logical_request_count) : 0.0)
          << "," << static_cast<double>(metric.sqlite_collect_ns) / 1.0e9
          << "," << static_cast<double>(metric.sqlite_sort_ns) / 1.0e9
          << "," << static_cast<double>(metric.sqlite_cluster_ns) / 1.0e9
          << "," << static_cast<double>(metric.sqlite_submit_ns) / 1.0e9
          << "," << static_cast<double>(metric.sqlite_disk_io_ns) / 1.0e9
          << "," << static_cast<double>(metric.sqlite_utm_copy_ns) / 1.0e9
          << "," << static_cast<double>(
              metric.sqlite_completion_publish_ns) / 1.0e9
          << "," << static_cast<double>(metric.sqlite_wakeup_ns) / 1.0e9
          << "," << static_cast<double>(
              metric.sqlite_submit_to_host_dequeue_ns) / 1.0e9
          << "," << static_cast<double>(
              metric.sqlite_host_dequeue_to_io_submit_ns) / 1.0e9
          << "," << static_cast<double>(
              metric.sqlite_io_submit_to_complete_ns) / 1.0e9
          << "," << static_cast<double>(
              metric.sqlite_io_complete_to_publish_ns) / 1.0e9
          << "," << static_cast<double>(
              metric.sqlite_publish_to_host_resume_request_ns) / 1.0e9
          << "," << static_cast<double>(
              metric.sqlite_wakeup_eligible_to_host_resume_request_ns) / 1.0e9
          << "," << static_cast<double>(
              metric.sqlite_host_resume_ioctl_ns) / 1.0e9
          << "," << metric.sqlite_completion_wakeup_count
          << "," << metric.sqlite_completion_ready_before_wait_count
          << "," << metric.sqlite_ewma_bandwidth_bytes_per_sec
          << "," << metric.sqlite_ewma_request_latency_ns
          << "," << metric.sqlite_ewma_queue_wait_ns
          << "," << metric.sqlite_ewma_completion_latency_ns
          << "," << metric.sqlite_adaptive_collect_usec
          << "," << metric.sqlite_adaptive_batch_target
          << "," << metric.sqlite_adaptive_queue_depth
          << "," << metric.sqlite_adaptive_gap_bytes
          << "," << static_cast<double>(metric.sqlite_critical_path_ns) /
              1.0e9
          << "," << static_cast<double>(metric.sqlite_max_queue_wait_ns) /
              1.0e9
          << "," << static_cast<double>(
              metric.sqlite_max_batch_service_ns) / 1.0e9
          << "," << static_cast<double>(
              metric.sqlite_max_completion_latency_ns) / 1.0e9
          << "," << metric.io_trace_request_count
          << "," << metric.io_trace_member_request_count
          << "," << metric.io_trace_total_range_bytes
          << "," << metric.io_trace_useful_bytes
          << "," << metric.io_trace_gap_bytes
          << "," << metric.io_trace_range_start
          << "," << metric.io_trace_range_end
          << "," << (metric.io_trace_range_end >=
                          metric.io_trace_range_start ?
                      metric.io_trace_range_end -
                          metric.io_trace_range_start : 0)
          << "," << metric.io_trace_min_request_bytes
          << "," << metric.io_trace_max_request_bytes
          << "," << metric.io_trace_read_request_count
          << "," << metric.io_trace_write_request_count
          << "," << metric.io_trace_failed_request_count
          << ","
          << (static_cast<double>(metric.worker_aes_time_ticks) / timebase_hz)
          << ","
          << (static_cast<double>(metric.worker_ocall_time_ticks) / timebase_hz)
          << "," << (static_cast<double>(metric.ocall_wait_ticks) / timebase_hz)
          << "," << metric.switch_wall_seconds << ","
          << metric.scheduler_wall_seconds << ","
          << metric.sm_ocalls << "," << metric.sm_ocall_cycles << ","
          << metric.ocall_handler_count << ","
          << metric.ocall_handler_cycles << ","
          << metric.ocall_wait_count << "," << metric.ocall_wait_ticks << ","
          << metric.cfs_preemptions << ","
          << metric.host_services << ","
          << metric.max_running_workers << "," << metric.digest << ","
          << "host-sees-aes128-encrypted-shards-only,"
          << ((MotivationSystem::enabled() && MotivationSystem::trace_path()) ? "diagnostic-motivation-system-" : "")
          << ((std::getenv("GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC") &&
               std::strcmp(std::getenv("GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC"), "1") == 0) ?
              "diagnostic-neighbor-trace-" : "")
          << "master-first-dispatch-to-final-aggregate-includes-sqlite-"
             "aes128-vfs-ocall-disk-blocking-resume-scheduling"
          << "," << static_cast<double>(metric.vfs_crypto_io_sample_ticks) /
              timebase_hz
          << "," << static_cast<double>(metric.vfs_crypto_io_overlap_ticks) /
              timebase_hz
          << "," << metric.vfs_crypto_io_overlap_ratio
          << "," << static_cast<double>(metric.vfs_both_buffers_wait_ticks) /
              timebase_hz
          << "," << metric.vfs_completion_local_reaps
          << "," << metric.vfs_buffer_reuses
          << "," << static_cast<double>(metric.sqlite_disk_io_ns) / 1.0e9
          << "," << static_cast<double>(metric.sqlite_completion_wait_ns) / 1.0e9
          << "," << static_cast<double>(metric.sqlite_storage_sync_ns) / 1.0e9
          << "," << metric.sqlite_sequential_extent_count
          << "," << metric.sqlite_sequential_8mb_extent_count
          << "," << metric.sqlite_cross_worker_extent_count
          << "," << (sqlite_benchmark_io_mode() !=
              SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT ?
              "submit-syscalls+reactor-io-wait-excludes-planning-copy-metadata" :
              "unavailable-sqlite-internal")
          << "," << (std::strcmp(sqlite_benchmark_cache_mode_name(), "cold") == 0 ?
              "buffered-fdatasync-fadvise-after-prefill" :
              std::strcmp(sqlite_benchmark_cache_mode_name(), "direct") == 0 ?
              "direct-when-aligned-check-fallback-counters" : "buffered-hot")
          << ",crypto-while-peer-buffer-outstanding-not-cpu-utilization"
          << "," << static_cast<double>(metric.worker_aes_time_ticks) / timebase_hz
          << "," << static_cast<double>(metric.aes_elapsed_time_ticks) / timebase_hz
          << "," << static_cast<double>(metric.aes_elapsed_time_ticks >=
                      metric.worker_aes_time_ticks ?
                      metric.aes_elapsed_time_ticks - metric.worker_aes_time_ticks : 0) /
                      timebase_hz
          << "," << metric.enclave_aes_mb_per_sec
          << ",sm-member-runtime-crypto-boundaries"
          << "," << (metric.sqlite_task_count ?
              static_cast<double>(metric.sqlite_queue_wait_ns) /
                  (1000.0 * metric.sqlite_task_count) : 0.0)
          << "," << (metric.sqlite_completion_wakeup_count ?
              static_cast<double>(metric.sqlite_host_resume_ioctl_ns) /
                  (1000.0 * metric.sqlite_completion_wakeup_count) : 0.0)
          << "," << static_cast<double>(metric.sqlite_write_overlap_check_ns) /
              1.0e9
          << "," << metric.sqlite_write_overlap_checks
          << "," << metric.sqlite_write_disjoint_batches
          << "," << metric.sqlite_write_overlap_batches
          << "," << metric.sqlite_adaptive_write_grow_count
          << "," << metric.sqlite_adaptive_write_shrink_count
          << "," << metric.sqlite_adaptive_write_hold_count
          << "," << metric.sqlite_sequential_ready_single_batches
          << "," << metric.sqlite_sequential_ready_multi_batches
          << "," << metric.sqlite_sequential_ready_adjacent_pairs
          << "," << metric.sqlite_sequential_ready_nonadjacent_pairs
          << "," << metric.sqlite_random_sparse_fast_batches
          << "," << metric.sqlite_random_sparse_fast_requests
          << "," << metric.sqlite_random_planned_batches
          << "," << metric.sqlite_random_precheck_fallbacks
          << "," << metric.sqlite_random_precheck_ns
          << "," << metric.sqlite_readseq_initial_requests
          << "," << metric.sqlite_readseq_refill_peer_io_requests
          << "," << metric.sqlite_readseq_refill_peer_ready_requests
          << "," << metric.sqlite_readseq_refill_peer_idle_requests
          << "," << metric.sqlite_random_local_plan_batches
          << "," << metric.sqlite_random_local_candidate_requests
          << "," << metric.sqlite_cache_fill_bytes
          << "," << metric.sqlite_cache_fill_ns
          << "," << metric.sqlite_cache_fill_skipped_bytes
          << "," << metric.sqlite_cache_admission_disables
          << "," << metric.sqlite_cache_admission_reenables
          << "," << metric.pipeline.doorbell_count
          << "," << static_cast<double>(metric.pipeline.doorbell_ack_ticks) * 1.0 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.doorbell_ack_max_ticks) * 1e6 / timebase_hz
          << "," << metric.pipeline.completion_to_consume_count
          << "," << static_cast<double>(metric.pipeline.completion_to_consume_ticks) * 1.0 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.completion_to_consume_max_ticks) * 1e6 / timebase_hz
          << "," << metric.pipeline.completion_timestamp_invalid
          << "," << static_cast<double>(metric.pipeline.ack_to_consume_ticks) * 1.0 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.ack_to_consume_max_ticks) * 1e6 / timebase_hz
          << "," << metric.pipeline.buffer_consume_count
          << "," << static_cast<double>(metric.pipeline.buffer_consume_ticks) * 1.0 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.buffer_consume_max_ticks) * 1e6 / timebase_hz
          << "," << metric.pipeline.buffer_refill_count
          << "," << static_cast<double>(metric.pipeline.buffer_refill_ticks) * 1.0 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.buffer_refill_max_ticks) * 1e6 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.request_prepare_ticks) * 1.0 / timebase_hz
          << "," << metric.pipeline.submission_timing_count
          << "," << metric.pipeline.submission_timestamp_invalid
          << "," << static_cast<double>(metric.pipeline.submit_to_host_ticks) * 1.0 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.submit_to_host_max_ticks) * 1e6 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.host_to_ack_ticks) * 1.0 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.host_to_ack_max_ticks) * 1e6 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.ack_to_resume_request_ticks) * 1.0 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.ack_to_resume_request_max_ticks) * 1e6 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.resume_request_to_return_ticks) * 1.0 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.resume_request_to_return_max_ticks) * 1e6 / timebase_hz
          << "," << (metric.pipeline.submission_timing_count ?
              static_cast<double>(metric.pipeline.resume_request_to_return_ticks) *
                  1e6 / timebase_hz / metric.pipeline.submission_timing_count : 0.0)
          << ",submit-ocall-host-request-to-worker-return-includes-runnable-queue-not-wait-ocall"
          << "," << (sqlite_benchmark_io_mode() == SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT ?
              "unavailable-sync-service" : "completion-backed-host-resume-ioctl-only");
      for (const auto value : metric.sqlite_read100k)
        csv << "," << value;
      csv << "," << metric.pipeline.wait_timing_count
          << "," << metric.pipeline.wait_timestamp_invalid
          << "," << static_cast<double>(metric.pipeline.wait_submit_to_host_ticks) / timebase_hz
          << "," << static_cast<double>(metric.pipeline.wait_host_to_resume_ticks) / timebase_hz
          << "," << static_cast<double>(metric.pipeline.wait_resume_to_return_ticks) / timebase_hz
          << "," << static_cast<double>(metric.pipeline.wait_resume_to_return_max_ticks) * 1e6 / timebase_hz
          << "," << static_cast<double>(metric.pipeline.wait_oncpu_ticks) / timebase_hz
          << "," << static_cast<double>(metric.pipeline.wait_offcpu_ticks) / timebase_hz
          << "," << metric.pipeline.wait_clock_invalid
          << ",ring-completion-wait-ocall-offcpu-includes-blocked-and-runnable-queue";
      for (const auto value : metric.sqlite_io_pipeline) csv << "," << value;
      csv << "," << GROUP_PMP_SQLITE_FILE_LAYOUT_VERSION
          << "," << kGroupPmpSqliteCommonPathVersion
          << "," << GROUP_PMP_SQLITE_VFS_BATCH_MAX
          << "," << sqlite_cluster_mode_name() << "," << kGroupPmpSqlitePipelineVersion
          << "," << selected_benchmark_cipher_name();
      csv << "\n";
    }
  }
  csv.close();
  if (csv.fail() || !csv_has_uniform_columns(
                        path, sqlite_selected_worker_count(max_workers) * sqlite_selected_workload_count())) {
    std::cerr << "[P10][sqlite-csv] invalid row/column shape: " << path
              << std::endl;
    return false;
  }
  std::cout << "[P10][sqlite-csv] path=" << path
            << " rows=" << sqlite_selected_worker_count(max_workers) * sqlite_selected_workload_count()
            << std::endl;
  return true;
}

bool write_sqlite_io_summary_csv(
    const std::string& path,
    const std::vector<std::vector<MixedRunMetrics> >& results,
    uint64_t max_workers,
    const std::vector<SqliteNoExtentBaseline>& sync_no_extent_baselines,
    const SqliteNoExtentScaleBaselines& sync_no_extent_scale_baselines,
    const std::vector<SqliteNoExtentBaseline>& async_no_extent_baselines,
    const SqliteNoExtentScaleBaselines& async_no_extent_scale_baselines,
    uint64_t adaptive_gain_target_permille) {
  std::ofstream csv(path.c_str(), std::ios::out | std::ios::trunc);
  if (!csv)
    return false;
  csv << "io_mode,address_mode,cache_mode,io_policy_version,workload,worker_count,samples,seconds_median,"
         "mb_per_sec_median,speedup_vs_one,"
         "speedup_vs_sync_no_extent_one,speedup_vs_async_no_extent_one,"
         "throughput_ratio_vs_sync_no_extent_same_workers,"
         "throughput_ratio_vs_async_no_extent_same_workers,"
         "adaptive_gain_target,adaptive_gain_target_met,"
         "io_request_count_median,"
         "member_request_count_median,total_range_bytes_median,"
         "useful_bytes_median,gap_bytes_median,range_start_median,"
         "range_end_median,covered_span_bytes_median,"
         "min_request_bytes_median,max_request_bytes_median,"
         "read_request_count_median,write_request_count_median,"
         "failed_request_count_median,file_layout_version,common_path_version,descriptor_limit,cluster_mode,cipher\n";
  csv << std::setprecision(12);
  for (uint64_t workload = GROUP_PMP_SQLITE_FILLSEQ;
       workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload) {
    if (!sqlite_workload_selected(workload)) continue;
    const MixedRunMetrics& baseline = results[workload][1];
    const SqliteNoExtentBaseline& sync_no_extent =
        sync_no_extent_baselines[workload];
    const SqliteNoExtentBaseline& async_no_extent =
        async_no_extent_baselines[workload];
    for (uint64_t workers = 1; workers <= max_workers; ++workers) {
      const MixedRunMetrics& metric = results[workload][workers];
      if (!sqlite_worker_count_selected(workers)) continue;
      const SqliteNoExtentBaseline& sync_same_workers =
          sync_no_extent_scale_baselines[workload][workers];
      const SqliteNoExtentBaseline& async_same_workers =
          async_no_extent_scale_baselines[workload][workers];
      const double sync_same_worker_ratio =
          sync_same_workers.available ?
              metric.mb_per_sec / sync_same_workers.mb_per_sec_median : 0.0;
      const double async_same_worker_ratio =
          async_same_workers.available ?
              metric.mb_per_sec / async_same_workers.mb_per_sec_median : 0.0;
      const double adaptive_gain_target =
          static_cast<double>(adaptive_gain_target_permille) / 1000.0;
      const int adaptive_gain_target_met =
          sqlite_benchmark_io_mode() ==
                  SQLITE_BENCHMARK_IO_ADAPTIVE_EXTENT &&
              sync_same_workers.available ?
          (sync_same_worker_ratio >= adaptive_gain_target ? 1 : 0) : -1;
      const uint64_t covered_span = metric.io_trace_range_end >=
          metric.io_trace_range_start ?
          metric.io_trace_range_end - metric.io_trace_range_start : 0;
      csv << sqlite_benchmark_io_mode_name() << ','
          << sqlite_address_mode_name() << ','
          << sqlite_benchmark_cache_mode_name() << ','
          << (sqlite_benchmark_io_mode() ==
                      SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT ?
              UINT64_C(1) :
              (sqlite_benchmark_io_mode() ==
                       SQLITE_BENCHMARK_IO_ASYNC_NO_EXTENT ?
                   UINT64_C(2) : sqlite_extent_io_policy_version())) << ','
          << sqlite_workload_name(workload) << ',' << workers << ','
          << metric.sample_count << ',' << metric.seconds << ','
          << metric.mb_per_sec << ','
          << (metric.seconds ? baseline.seconds / metric.seconds : 0.0)
          << ',' << (sync_no_extent.available ?
              metric.mb_per_sec / sync_no_extent.mb_per_sec_median : 0.0)
          << ',' << (async_no_extent.available ?
              metric.mb_per_sec / async_no_extent.mb_per_sec_median : 0.0)
          << ',' << sync_same_worker_ratio
          << ',' << async_same_worker_ratio
          << ',' << adaptive_gain_target
          << ',' << adaptive_gain_target_met
          << ',' << metric.io_trace_request_count
          << ',' << metric.io_trace_member_request_count
          << ',' << metric.io_trace_total_range_bytes
          << ',' << metric.io_trace_useful_bytes
          << ',' << metric.io_trace_gap_bytes
          << ',' << metric.io_trace_range_start
          << ',' << metric.io_trace_range_end
          << ',' << covered_span
          << ',' << metric.io_trace_min_request_bytes
          << ',' << metric.io_trace_max_request_bytes
          << ',' << metric.io_trace_read_request_count
          << ',' << metric.io_trace_write_request_count
          << ',' << metric.io_trace_failed_request_count
          << ',' << GROUP_PMP_SQLITE_FILE_LAYOUT_VERSION
          << ',' << kGroupPmpSqliteCommonPathVersion
          << ',' << GROUP_PMP_SQLITE_VFS_BATCH_MAX
          << ',' << sqlite_cluster_mode_name() << ',' << selected_benchmark_cipher_name() << '\n';
    }
  }
  csv.close();
  if (csv.fail() || !csv_has_uniform_columns(
                        path, sqlite_selected_worker_count(max_workers) * sqlite_selected_workload_count())) {
    std::cerr << "[P10][sqlite-io-csv] invalid row/column shape: " << path
              << std::endl;
    return false;
  }
  std::cout << "[P10][sqlite-io-summary] path=" << path
            << " rows=" << sqlite_selected_worker_count(max_workers) * sqlite_selected_workload_count()
            << std::endl;
  return true;
}

bool run_sqlite_scaling_phase(const char* master_eapp,
                              const char* worker_eapp,
                              const char* runtime, const char* loader) {
  const uint64_t max_workers = env_u64(
      "GROUP_PMP_SQLITE_MAX_WORKERS", 15, 1,
      GROUP_PMP_MIXED_MAX_WORKERS);
  const uint64_t repetitions = env_u64(
      "GROUP_PMP_SQLITE_REPETITIONS", 5, 1, 20);
  const uint64_t seed = env_u64(
      "GROUP_PMP_SQLITE_RANDOM_SEED", UINT64_C(1397519439), 0,
      UINT64_MAX);
  const uint64_t total_bytes = env_u64(
      "GROUP_PMP_SQLITE_TOTAL_BYTES",
      GROUP_PMP_SQLITE_DEFAULT_TOTAL_BYTES, 1, UINT64_MAX);
  const bool capture_enabled = std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR") != nullptr;
  const uint64_t minimum_bytes_per_worker = capture_enabled ? UINT64_C(100000) : env_u64(
      "GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER", UINT64_C(4000000),
      UINT64_C(100000), UINT64_MAX);
  const uint64_t cfs_quantum_multiplier = env_u64(
      "GROUP_PMP_SQLITE_CFS_QUANTUM_MULTIPLIER", 4, 1,
      KEYSTONE_GROUP_SCHED_QUANTUM_MAX);
  const char* csv_env = std::getenv("GROUP_PMP_SQLITE_CSV");
  const char* gantt_csv_env = std::getenv("GROUP_PMP_SQLITE_GANTT_CSV");
  const char* io_range_csv_env =
      std::getenv("GROUP_PMP_SQLITE_IO_RANGE_CSV");
  const char* io_mode_env = std::getenv("GROUP_PMP_SQLITE_IO_MODE");
  const char* cache_mode_env = std::getenv("GROUP_PMP_SQLITE_CACHE_MODE");
  const char* workload_set_env = std::getenv("GROUP_PMP_SQLITE_WORKLOAD_SET");
  const char* fio_profile_env = std::getenv("GROUP_PMP_FIO_PROFILE");
  if (MotivationSystem::enabled()) {
    const char* selected=std::getenv("GROUP_PMP_MOTIVATION_WORKERS");
    if (!selected || (std::strcmp(selected,"1") && std::strcmp(selected,"3")) ||
        max_workers!=static_cast<uint64_t>(std::strtoul(selected,nullptr,10)) || repetitions!=1 ||
        !MotivationSystem::valid_selection(workload_set_env,fio_profile_env) || capture_enabled || security_scan_nonce() ||
        total_bytes>UINT64_C(500000000) ||
        (sqlite_benchmark_io_mode()!=SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT &&
         sqlite_benchmark_io_mode()!=SQLITE_BENCHMARK_IO_ASYNC_NO_EXTENT) ||
        ((MotivationSystem::trace_path()!=nullptr) != (gantt_csv_env && *gantt_csv_env)) ||
        (MotivationSystem::trace_path() && !*MotivationSystem::trace_path())) {
      std::cerr<<"[motivation-system] requires one real sequential-read case, Sync/Async, N=1/3 and separate diagnostic trace"<<std::endl;
      return false;
    }
  } else if(MotivationSystem::trace_path()) {
    std::cerr<<"[motivation-system] crypto trace requires the explicit system experiment"<<std::endl;
    return false;
  }
  const char* security_worker_set = std::getenv("GROUP_PMP_SECURITY_WORKER_SET");
  const char* capture_workers = std::getenv("GROUP_PMP_SECURITY_CAPTURE_WORKERS");
  const char* capture_workload = std::getenv("GROUP_PMP_SECURITY_CAPTURE_WORKLOAD");
  if (capture_enabled &&
      (!security_scan_nonce() || !capture_workers || !capture_workload ||
       (std::strcmp(capture_workers, "1") && std::strcmp(capture_workers, "4")) ||
       (std::strcmp(capture_workload, "readrandom") && std::strcmp(capture_workload, "fillrandom")) ||
       max_workers != 4 || repetitions != 1 || total_bytes != GROUP_PMP_SECURITY_INPUT_BYTES)) {
    std::cerr << "[security] extended capture requires one readrandom/fillrandom case, N=1/4 and 1MB" << std::endl;
    return false;
  }
  if (security_worker_set && security_worker_set[0] &&
      (std::strcmp(security_worker_set, "1,4") != 0 ||
       !security_scan_nonce() || max_workers != 4 || repetitions != 1 ||
       !workload_set_env || std::strcmp(workload_set_env, "random-pair") != 0 ||
       fio_profile_env)) {
    std::cerr << "[security] worker selection requires sentinel scan, workers=1,4, "
                 "max_workers=4, one sample and random-pair" << std::endl;
    return false;
  }
  const bool fio_profile_run = fio_profile_env && fio_profile_env[0];
  const bool valid_fio_profile = fio_profile_run &&
      ((std::strcmp(fio_profile_env, "seq-write-2m") == 0 &&
        workload_set_env && std::strcmp(workload_set_env, "fio-seq-write-2m") == 0) ||
       (std::strcmp(fio_profile_env, "seq-read-2m") == 0 &&
        workload_set_env && std::strcmp(workload_set_env, "fio-seq-read-2m") == 0) ||
       (std::strcmp(fio_profile_env, "rand-write-4k") == 0 &&
        workload_set_env && std::strcmp(workload_set_env, "fio-rand-write-4k") == 0) ||
       (std::strcmp(fio_profile_env, "rand-read-4k") == 0 &&
        workload_set_env && std::strcmp(workload_set_env, "fio-rand-read-4k") == 0) ||
       (std::strcmp(fio_profile_env, "rand-read-100k") == 0 &&
        workload_set_env && std::strcmp(workload_set_env, "fio-rand-read-100k") == 0));
  if (fio_profile_run && !valid_fio_profile) {
    std::cerr << "[P10][fio-profile] invalid profile/selection pair" << std::endl;
    return false;
  }
  if (workload_set_env && std::strcmp(workload_set_env, "all") != 0 &&
      std::strcmp(workload_set_env, "random-pair") != 0 &&
      !(MotivationSystem::enabled() && !std::strcmp(workload_set_env,"motivation-readseq")) &&
      !valid_fio_profile) {
    std::cerr << "[P10][sqlite] invalid GROUP_PMP_SQLITE_WORKLOAD_SET="
              << workload_set_env << std::endl;
    return false;
  }
  std::vector<std::vector<std::vector<MixedRunMetrics> > > samples(
      GROUP_PMP_SQLITE_WORKLOAD_COUNT + 1,
      std::vector<std::vector<MixedRunMetrics> >(max_workers + 1));
  std::vector<std::vector<MixedRunMetrics> > results(
      GROUP_PMP_SQLITE_WORKLOAD_COUNT + 1,
      std::vector<MixedRunMetrics>(max_workers + 1));
  std::vector<std::pair<uint64_t, uint64_t> > order;
  std::mt19937_64 random(seed);

  if (!io_mode_env ||
      (std::strcmp(io_mode_env, "extent") != 0 &&
       std::strcmp(io_mode_env, "adaptive-extent") != 0 &&
       std::strcmp(io_mode_env, "no-extent") != 0 &&
       std::strcmp(io_mode_env, "sync-no-extent") != 0 &&
       std::strcmp(io_mode_env, "async-no-extent") != 0)) {
    std::cerr << "[P10][sqlite] GROUP_PMP_SQLITE_IO_MODE must be "
                 "sync-no-extent, async-no-extent, or adaptive-extent"
              << std::endl;
    return false;
  }
  if (cache_mode_env && std::strcmp(cache_mode_env, "hot") != 0 &&
      std::strcmp(cache_mode_env, "cold") != 0 &&
      std::strcmp(cache_mode_env, "direct") != 0) {
    std::cerr << "[P10][sqlite] GROUP_PMP_SQLITE_CACHE_MODE must be hot, "
                 "cold, or direct"
              << std::endl;
    return false;
  }
  const char* address_mode_env = std::getenv("GROUP_PMP_SQLITE_ADDRESS_MODE");
  if (address_mode_env && std::strcmp(address_mode_env, sqlite_address_mode_name()) != 0) {
    std::cerr << "[P10][sqlite] GROUP_PMP_SQLITE_ADDRESS_MODE must be locality-random-v1" << std::endl;
    return false;
  }
  if (sqlite_benchmark_io_mode() != SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT &&
      sqlite_extent_io_policy_version() !=
          kGroupPmpSqliteExtentIoPolicyVersion) {
    std::cerr << "[P10][sqlite] incompatible extent I/O policy: expected="
              << kGroupPmpSqliteExtentIoPolicyVersion << " got="
              << sqlite_extent_io_policy_version() << std::endl;
    return false;
  }

  if (gantt_csv_env && gantt_csv_env[0] && csv_env && csv_env[0] &&
      std::strcmp(gantt_csv_env, csv_env) == 0) {
    std::cerr << "[P10][sqlite] aggregate and Gantt CSV paths must differ: "
              << gantt_csv_env << std::endl;
    return false;
  }
  if (!sqlite_gantt_trace().configureOutput(gantt_csv_env)) {
    std::cerr << "[P10][sqlite] cannot create Gantt trace: "
              << (gantt_csv_env ? gantt_csv_env : "") << std::endl;
    return false;
  }
  if (io_range_csv_env && io_range_csv_env[0] && csv_env && csv_env[0] &&
      std::strcmp(io_range_csv_env, csv_env) == 0) {
    std::cerr << "[P10][sqlite] aggregate and I/O range CSV paths must differ: "
              << io_range_csv_env << std::endl;
    return false;
  }
  if (io_range_csv_env && io_range_csv_env[0] && gantt_csv_env &&
      gantt_csv_env[0] && std::strcmp(io_range_csv_env, gantt_csv_env) == 0) {
    std::cerr << "[P10][sqlite] Gantt and I/O range CSV paths must differ: "
              << io_range_csv_env << std::endl;
    return false;
  }
  if (!sqlite_io_range_trace().configureOutput(io_range_csv_env)) {
    std::cerr << "[P10][sqlite] cannot create I/O range trace: "
              << (io_range_csv_env ? io_range_csv_env : "") << std::endl;
    return false;
  }

  if (minimum_bytes_per_worker > UINT64_MAX / max_workers ||
      total_bytes < minimum_bytes_per_worker * max_workers) {
    std::cerr << "[P10][sqlite] configured total data is too small for a "
                 "steady async pipeline: total="
              << total_bytes << " workers=" << max_workers
              << " minimum_per_worker=" << minimum_bytes_per_worker
              << std::endl;
    return false;
  }
  if (sqlite_yxstm_artifact_marker[0] != 'k' ||
      sqlite_full_flow_baseline_artifact_marker[0] != 'k' ||
      sqlite_no_extent_baseline_artifact_marker[0] != 'k' ||
      sqlite_no_extent_io_artifact_marker[0] != 'k' ||
      sqlite_async_vfs_artifact_marker[0] != 'k' ||
      sqlite_configurable_total_artifact_marker[0] != 'k' ||
      sqlite_warmup_ocall_artifact_marker[0] != 'k' ||
      sqlite_lane_pool_artifact_marker[0] != 'k' ||
      sqlite_immediate_ocall_artifact_marker[0] != 'k' ||
      sqlite_batched_random_read_artifact_marker[0] != 'k' ||
      sqlite_status_commit_artifact_marker[0] != 'k' ||
      sqlite_blocking_pipeline_artifact_marker[0] != 'k' ||
      sqlite_double_buffer_artifact_marker[0] != 'k' ||
      sqlite_static_freemem_artifact_marker[0] != 'k' ||
      register_call(1, group_pmp_ocall_ack) != 0 ||
      register_call(GROUP_PMP_SQLITE_VFS_OCALL_ID,
                    group_pmp_sqlite_async_vfs) != 0)
    return false;
  static const volatile char neighbor_diagnostic_marker[] __attribute__((used)) =
      "keystone-sqlite-neighbor-admission-diagnostic-v2";
  const bool diagnostic_only = std::getenv("GROUP_PMP_SQLITE_NEIGHBOR_ONLY") &&
      std::strcmp(std::getenv("GROUP_PMP_SQLITE_NEIGHBOR_ONLY"), "1") == 0;
  const uint64_t diagnostic_workload = env_u64("GROUP_PMP_SQLITE_NEIGHBOR_WORKLOAD", 0, 0, 8);
  const uint64_t diagnostic_workers = env_u64("GROUP_PMP_SQLITE_NEIGHBOR_WORKERS", 0, 0, max_workers);
  if (diagnostic_only &&
      (!std::getenv("GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC") ||
       std::strcmp(std::getenv("GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC"), "1") != 0 ||
       !gantt_csv_env || !gantt_csv_env[0] || repetitions != 1 || !diagnostic_workers ||
       (diagnostic_workload != GROUP_PMP_SQLITE_READSEQ && diagnostic_workload != GROUP_PMP_SQLITE_READRAND100K) ||
       sqlite_benchmark_io_mode() == SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT ||
       env_u64("GROUP_PMP_SQLITE_NEIGHBOR_SAMPLE", 1, 0, UINT64_MAX) != 1 ||
       neighbor_diagnostic_marker[0] != 'k')) {
    std::cerr << "[P10][sqlite] diagnostic-only requires readseq/100KB, one sample, a worker selection and a trace path" << std::endl;
    return false;
  }
  /* Remove extents left by an interrupted or older benchmark before the
   * randomized run order starts consuming storage. */
  for (uint64_t workload = GROUP_PMP_SQLITE_FILLSEQ;
       workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload)
    sqlite_selected_io_cleanup_case(0, workload);
  for (uint64_t repeat = 0; repeat < repetitions; ++repeat)
    for (uint64_t workload = GROUP_PMP_SQLITE_FILLSEQ;
         workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload)
      for (uint64_t workers = 1; workers <= max_workers; ++workers)
        if (sqlite_worker_count_selected(workers) && sqlite_workload_selected(workload) &&
            (!diagnostic_only || (workload == diagnostic_workload && workers == diagnostic_workers)))
          order.push_back(std::make_pair(workload, workers));
  std::shuffle(order.begin(), order.end(), random);
  const bool no_extent_io = sqlite_benchmark_io_mode() ==
      SQLITE_BENCHMARK_IO_SYNC_NO_EXTENT;
  const bool async_no_extent_io = sqlite_benchmark_io_mode() ==
      SQLITE_BENCHMARK_IO_ASYNC_NO_EXTENT;
  std::cout << "[host] phase: sqlite-bench workloads="
            << sqlite_selected_workload_count() << " workers="
            << (capture_workers && std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR") ? capture_workers : security_worker_set && security_worker_set[0] ? "1,4" :
                "1.." + std::to_string(max_workers)) << " repetitions=" << repetitions
            << " io_mode=" << sqlite_benchmark_io_mode_name()
            << (fio_profile_run ? " source=fio-job-profile address_stream=locality-random-v1-not-fio-native" : "")
            << " cache_mode=" << sqlite_benchmark_cache_mode_name()
            << " io_policy_version="
            << (no_extent_io ? UINT64_C(1) :
                (async_no_extent_io ? UINT64_C(2) :
                 sqlite_extent_io_policy_version()))
            << " database="
            << (no_extent_io ? "sqlite-ciphertext-blob-rows" :
                               "sqlite-metadata-only+external-ciphertext-extents")
            << " crypto=" << selected_benchmark_cipher_name()
            << " crypto_scope=enclave cipher_snapshot=AEAD-only key_source="
            << (selected_benchmark_cipher() ? "SM-platform-test-only" : "fixed-test-key")
            << " crypto_timing=transform+AEAD-auth-snapshot-wipe"
            << " validation=one-block-selftest+extent-edge-samples"
            << " utm=4KiB-control+2x2MB-data"
            << " sqlite=host-only-per-lane-connection-pool"
            << " queue="
            << (no_extent_io ? "independent-request-depth-" :
                               "central-offset-sorted-depth-")
            << kSqliteAsyncQueueDepth
            << " io="
            << (no_extent_io ? "sqlite-blob-no-range-merge" :
                (async_no_extent_io ? "io_uring-batched-no-merge" :
                 "io_uring-adaptive-extent"))
            << " merge_max_mb="
            << ((no_extent_io || async_no_extent_io) ? 0.0 :
                static_cast<double>(env_u64(
                    "GROUP_PMP_SQLITE_IO_MERGE_MAX_BYTES",
                    UINT64_C(8000000), UINT64_C(2000000),
                    UINT64_C(8000000))) / kDecimalMbBytes)
            << " completion=submit-only+event-wait-double-buffer"
            << " descriptors_per_ocall=" << GROUP_PMP_SQLITE_VFS_BATCH_MAX
            << " min_bytes_per_worker=" << minimum_bytes_per_worker
            << " cfs_min_slice_multiplier=" << cfs_quantum_multiplier
            << " writer=sqlite-single-writer"
            << " io_granularity=seq:2MB,random:4KB,readrand100k:100KB"
            << " utm_transport=two-independent-2MB-buffers"
            << " prefill=read-and-overwrite-before-warmed"
            << " io=encrypted-async-ocall"
            << " transport=protected-YXSTM-slots"
            << " cache_reset="
            << (sqlite_benchmark_cache_mode_name() ==
                        std::string("cold") ?
                    "fdatasync+posix_fadvise-dontneed-after-prefill" :
                (sqlite_benchmark_cache_mode_name() ==
                         std::string("direct") ?
                     "aligned-o_direct+buffered-unaligned-tail" :
                     "warm-page-cache"))
            << " configured_total_mb="
            << static_cast<double>(total_bytes) / kDecimalMbBytes
            << " baseline=one-worker-full-flow"
            << " timing=master-first-dispatch-to-final-aggregate"
            << " includes=sqlite+ocall+blocking+resume+scheduling+aggregation"
             << " excludes=create+warmup+control-markers+exit-cleanup"
             << " gantt="
             << (gantt_csv_env && gantt_csv_env[0] ? gantt_csv_env :
                  "disabled")
             << " io_ranges="
             << (io_range_csv_env && io_range_csv_env[0] ? io_range_csv_env :
                 "disabled")
             << std::endl;
  for (size_t run = 0; run < order.size(); ++run) {
    uint64_t workload_id = order[run].first;
    uint64_t workers = order[run].second;
    MixedWorkload workload;
    MixedRunMetrics metric;
    SqliteIoRangeSummary io_summary = {};
    const uint64_t sample_id = samples[workload_id][workers].size() + 1;
    std::cout << "[P10][sqlite-run] start=" << (run + 1)
              << "/" << order.size()
              << " workload=" << sqlite_workload_name(workload_id)
              << " workers=" << workers
              << " sample=" << sample_id
              << "/" << repetitions << std::endl;
    const bool workload_ok = build_mixed_workload(
        workers, GROUP_PMP_MIXED_OCALL_PER_TASK, &workload, workload_id);
    sqlite_gantt_trace().beginCase(
        run + 1, sample_id, workload_id, workers,
        static_cast<uint64_t>(sqlite_benchmark_io_mode()));
    sqlite_io_range_trace().beginCase(
        run + 1, sample_id, workload_id, workers,
        static_cast<uint64_t>(sqlite_benchmark_io_mode()));
    const bool run_ok = workload_ok && run_mixed_scaling_case(
        master_eapp, worker_eapp, runtime, loader, workload, nullptr,
        &metric);
    sqlite_gantt_trace().endWindow(run_ok);
    sqlite_io_range_trace().endWindow();
    const uint64_t dropped_gantt_events =
        sqlite_gantt_trace().droppedEvents();
    const uint64_t sampled_gantt_request_events =
        sqlite_gantt_trace().sampledRequestEvents();
    const uint64_t gantt_request_sample_stride =
        sqlite_gantt_trace().requestSampleStride();
    const bool gantt_ok = sqlite_gantt_trace().flushCase();
    const uint64_t dropped_io_range_records =
        sqlite_io_range_trace().droppedRecords();
    const bool io_range_ok = sqlite_io_range_trace().flushCase();
    const bool io_summary_ok = !sqlite_io_range_trace().enabled() ||
        sqlite_io_range_trace().lastSummary(&io_summary);
    sqlite_selected_io_cleanup_case(workers, workload_id);
    if (!run_ok || !gantt_ok || dropped_gantt_events || !io_range_ok ||
        dropped_io_range_records || !io_summary_ok) {
      std::cerr << "[P10][sqlite] failed workload="
                << sqlite_workload_name(workload_id)
                << " workers=" << workers
                << " gantt_write=" << gantt_ok
                << " gantt_dropped=" << dropped_gantt_events
                << " io_range_write=" << io_range_ok
                << " io_range_dropped=" << dropped_io_range_records
                << " io_summary=" << io_summary_ok
                << std::endl;
      return false;
    }
    if (sampled_gantt_request_events) {
      std::cout << "[P10][sqlite-gantt] bounded request trace: workload="
                << sqlite_workload_name(workload_id)
                << " workers=" << workers
                << " sample_stride=" << gantt_request_sample_stride
                << " omitted_request_events="
                << sampled_gantt_request_events
                << " ocall_block_wake_events=complete" << std::endl;
    }
    metric.io_trace_request_count = io_summary.request_count;
    metric.io_trace_member_request_count = io_summary.member_request_count;
    metric.io_trace_total_range_bytes = io_summary.total_range_bytes;
    metric.io_trace_useful_bytes = io_summary.useful_bytes;
    metric.io_trace_gap_bytes = io_summary.gap_bytes;
    metric.io_trace_range_start = io_summary.range_start;
    metric.io_trace_range_end = io_summary.range_end;
    metric.io_trace_min_request_bytes = io_summary.min_request_bytes;
    metric.io_trace_max_request_bytes = io_summary.max_request_bytes;
    metric.io_trace_read_request_count = io_summary.read_request_count;
    metric.io_trace_write_request_count = io_summary.write_request_count;
    metric.io_trace_failed_request_count = io_summary.failed_request_count;
    const bool adaptive_mode = sqlite_benchmark_io_mode() ==
        SQLITE_BENCHMARK_IO_ADAPTIVE_EXTENT;
    const bool sequential_workload =
        workload_id == GROUP_PMP_SQLITE_FILLSEQ ||
        workload_id == GROUP_PMP_SQLITE_FILLSEQBATCH ||
        workload_id == GROUP_PMP_SQLITE_READSEQ;
    const bool random_page_workload =
        workload_id == GROUP_PMP_SQLITE_FILLRANDOM ||
        workload_id == GROUP_PMP_SQLITE_FILLRANDOMBATCH ||
        workload_id == GROUP_PMP_SQLITE_OVERWRITE ||
        workload_id == GROUP_PMP_SQLITE_READRANDOM;
    if (adaptive_mode && sequential_workload &&
        !check_sqlite_sequential_io_result(metric, workload_id, workers,
                                            std::cerr)) {
      return false;
    }
    if (adaptive_mode && random_page_workload &&
        !check_sqlite_random_ring_result(metric, workload, std::cerr)) {
      return false;
    }
    if (adaptive_mode && cache_mode_env &&
        std::strcmp(cache_mode_env, "direct") == 0 &&
        random_page_workload && metric.sqlite_logical_request_count &&
        metric.sqlite_direct_io_operations == 0) {
      std::cerr << "[P10][sqlite] aligned direct-I/O workload used no "
                   "O_DIRECT operations: workload="
                << sqlite_workload_name(workload_id)
                << " workers=" << workers << std::endl;
      return false;
    }
    if (adaptive_mode && metric.sqlite_completion_wakeup_count) {
      const uint64_t wakeup_count = metric.sqlite_completion_wakeup_count;
      const uint64_t publish_to_wake_average =
          metric.sqlite_publish_to_host_resume_request_ns / wakeup_count;
      const uint64_t eligible_to_wake_average =
          metric.sqlite_wakeup_eligible_to_host_resume_request_ns / wakeup_count;
      const uint64_t wake_ioctl_average =
          metric.sqlite_host_resume_ioctl_ns / wakeup_count;
      const uint64_t wake_latency_average =
          eligible_to_wake_average + wake_ioctl_average;
      if (wake_latency_average >= UINT64_C(1000000))
        std::cerr << "[P10][sqlite][WARN] wake-eligible-to-host-resume-ioctl-return latency "
                     "is not sub-millisecond: workload="
                  << sqlite_workload_name(workload_id)
                  << " workers=" << workers
                  << " average_ns=" << wake_latency_average
                  << " publish_to_wake_average_ns="
                  << publish_to_wake_average
                  << " eligible_to_wake_average_ns="
                  << eligible_to_wake_average
                  << " wake_ioctl_average_ns=" << wake_ioctl_average
                  << " ready_before_wait="
                  << metric.sqlite_completion_ready_before_wait_count
                  << std::endl;
    }
    // Check outside the timed case, before another long experiment can start.
    auto& collected = samples[workload_id][workers];
    if (!validate_mixed_sample(metric, collected.empty() ? metric : collected[0],
                               collected.size(), &std::cerr)) {
      std::cerr << "[P10][sqlite] sample validation failed: workload="
                << sqlite_workload_name(workload_id) << " workers=" << workers
                << " sample=" << collected.size() + 1 << "/" << repetitions
                << std::endl;
      return false;
    }
    collected.push_back(metric);
    std::cout << "[P10][sqlite-run] complete=" << (run + 1)
              << "/" << order.size()
              << " workload=" << sqlite_workload_name(workload_id)
              << " workers=" << workers
              << " seconds=" << metric.seconds << std::endl;
  }
  if (diagnostic_only) {
    std::cout << "[P10][sqlite-diagnostic] selected cases=" << order.size()
              << " trace=" << gantt_csv_env
              << " complete; no performance summary or baseline comparison" << std::endl;
    return true;
  }
  for (uint64_t workload = GROUP_PMP_SQLITE_FILLSEQ;
       workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload) {
    if (!sqlite_workload_selected(workload)) continue;
    for (uint64_t workers = 1; workers <= max_workers; ++workers) {
      if (!sqlite_worker_count_selected(workers)) continue;
      if (!aggregate_mixed_samples(samples[workload][workers],
                                   &results[workload][workers], &std::cerr)) {
        std::cerr << "[P10][sqlite] sample aggregation failed: workload="
                  << sqlite_workload_name(workload)
                  << " workers=" << workers
                  << " samples=" << samples[workload][workers].size()
                  << " expected=" << repetitions << std::endl;
        return false;
      }
    }
  }
  std::vector<SqliteNoExtentBaseline> sync_no_extent_baselines;
  std::vector<SqliteNoExtentBaseline> async_no_extent_baselines;
  SqliteNoExtentScaleBaselines sync_no_extent_scale_baselines;
  SqliteNoExtentScaleBaselines async_no_extent_scale_baselines;
  std::string sync_no_extent_baseline_source;
  std::string async_no_extent_baseline_source;
  const uint64_t adaptive_gain_target_permille = env_u64(
      "GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE", UINT64_C(1100),
      UINT64_C(1000), UINT64_C(2000));
  uint64_t adaptive_gain_rows = 0;
  uint64_t adaptive_gain_misses = 0;
  if (!resolve_sqlite_no_extent_baselines(
          results, "sync-no-extent",
          "GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV",
          "GROUP_PMP_SQLITE_NO_EXTENT_BASELINE_CSV",
          &sync_no_extent_baselines,
          &sync_no_extent_scale_baselines, max_workers,
          &sync_no_extent_baseline_source) ||
      !resolve_sqlite_no_extent_baselines(
          results, "async-no-extent",
          "GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV", nullptr,
          &async_no_extent_baselines,
          &async_no_extent_scale_baselines, max_workers,
          &async_no_extent_baseline_source))
    return false;
  for (uint64_t workload = GROUP_PMP_SQLITE_FILLSEQ;
       workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload) {
    if (!sqlite_workload_selected(workload)) continue;
    const MixedRunMetrics& base = results[workload][1];
    const SqliteNoExtentBaseline& sync_no_extent =
        sync_no_extent_baselines[workload];
    const SqliteNoExtentBaseline& async_no_extent =
        async_no_extent_baselines[workload];
    for (uint64_t workers = 1; workers <= max_workers; ++workers) {
      MixedRunMetrics& metric = results[workload][workers];
      if (!sqlite_worker_count_selected(workers)) continue;
      const SqliteNoExtentBaseline& sync_same_workers =
          sync_no_extent_scale_baselines[workload][workers];
      const SqliteNoExtentBaseline& async_same_workers =
          async_no_extent_scale_baselines[workload][workers];
      const double sync_same_worker_ratio =
          sync_same_workers.available ?
              metric.mb_per_sec / sync_same_workers.mb_per_sec_median : 0.0;
      const double async_same_worker_ratio =
          async_same_workers.available ?
              metric.mb_per_sec / async_same_workers.mb_per_sec_median : 0.0;
      const double adaptive_gain_target =
          static_cast<double>(adaptive_gain_target_permille) / 1000.0;
      const bool adaptive_gain_available =
          sqlite_benchmark_io_mode() ==
              SQLITE_BENCHMARK_IO_ADAPTIVE_EXTENT &&
          sync_same_workers.available;
      const bool adaptive_gain_met = adaptive_gain_available &&
          sync_same_worker_ratio >= adaptive_gain_target;
      if (adaptive_gain_available) {
        ++adaptive_gain_rows;
        if (!adaptive_gain_met)
          ++adaptive_gain_misses;
      }
      metric.speedup_vs_one = metric.seconds ?
          base.seconds / metric.seconds : 0.0;
      std::cout << "[P10][sqlite-summary] workload="
                << sqlite_workload_name(workload)
                << " io_mode=" << sqlite_benchmark_io_mode_name()
                << " workers=" << workers
                << " samples=" << metric.sample_count
                << " seconds_median=" << metric.seconds
                << " seconds_min=" << metric.seconds_min
                << " seconds_max=" << metric.seconds_max
                << " seconds_p95=" << metric.seconds_p95
                << " host_envelope_seconds_median="
                << metric.host_envelope_seconds
                << " mb_per_sec_median=" << metric.mb_per_sec
                << " mb_per_sec_min=" << metric.mb_per_sec_min
                << " mb_per_sec_max=" << metric.mb_per_sec_max
                << " mb_per_sec_p05=" << metric.mb_per_sec_p05
                << " mb_per_sec_p95=" << metric.mb_per_sec_p95
                << " speedup_vs_one=" << metric.speedup_vs_one
                << " speedup_vs_sync_no_extent_one="
                << (sync_no_extent.available ?
                    metric.mb_per_sec /
                        sync_no_extent.mb_per_sec_median : 0.0)
                << " speedup_vs_async_no_extent_one="
                << (async_no_extent.available ?
                    metric.mb_per_sec /
                        async_no_extent.mb_per_sec_median : 0.0)
                << " throughput_ratio_vs_sync_same_workers="
                << sync_same_worker_ratio
                << " throughput_ratio_vs_async_same_workers="
                << async_same_worker_ratio
                << " adaptive_gain_target=" << adaptive_gain_target
                << " adaptive_gain_target_met="
                << (adaptive_gain_available ?
                    (adaptive_gain_met ? 1 : 0) : -1)
                << " sync_no_extent_baseline_available="
                << (sync_no_extent.available ? 1 : 0)
                << " sync_no_extent_baseline_source="
                << sync_no_extent_baseline_source
                << " sync_no_extent_baseline_mb_per_sec="
                << sync_no_extent.mb_per_sec_median
                << " sync_no_extent_baseline_mb_per_sec_min="
                << sync_no_extent.mb_per_sec_min
                << " sync_no_extent_baseline_mb_per_sec_max="
                << sync_no_extent.mb_per_sec_max
                << " async_no_extent_baseline_available="
                << (async_no_extent.available ? 1 : 0)
                << " async_no_extent_baseline_source="
                << async_no_extent_baseline_source
                << " async_no_extent_baseline_mb_per_sec="
                << async_no_extent.mb_per_sec_median
                << " async_no_extent_baseline_mb_per_sec_min="
                << async_no_extent.mb_per_sec_min
                << " async_no_extent_baseline_mb_per_sec_max="
                << async_no_extent.mb_per_sec_max
                << " baseline_full_flow_mb_per_sec=" << base.mb_per_sec
                << " baseline_full_flow_seconds=" << base.seconds
                << " timing_scope=master-first-dispatch-to-final-aggregate"
                << " vfs_read_bytes=" << metric.vfs_read_bytes
                << " vfs_write_bytes=" << metric.vfs_write_bytes
                << " vfs_aes_cycles="
                << metric.vfs_encrypt_cycles + metric.vfs_decrypt_cycles
                << " vfs_submits=" << metric.vfs_submit_count
                << " vfs_batches=" << metric.vfs_batch_submit_count
                << " vfs_ring_doorbells="
                << metric.vfs_ring_doorbell_count
                << " vfs_ring_requests=" << metric.vfs_ring_request_count
                << " vfs_completion_batches="
                << metric.vfs_completion_batch_count
                << " vfs_queue_depth_peak="
                << metric.vfs_queue_depth_peak
                << " vfs_wait_ticks=" << metric.vfs_wait_ticks
                << " vfs_crypto_io_overlap_ratio="
                << metric.vfs_crypto_io_overlap_ratio
                << " vfs_both_buffers_wait_ticks="
                << metric.vfs_both_buffers_wait_ticks
                << " vfs_completion_local_reaps="
                << metric.vfs_completion_local_reaps
                << " sqlite_queue_wait_seconds="
                << static_cast<double>(metric.sqlite_queue_wait_ns) / 1.0e9
                << " sqlite_single_writer_wait_seconds="
                << static_cast<double>(metric.sqlite_writer_wait_ns) / 1.0e9
                << " sqlite_storage_service_seconds="
                << static_cast<double>(metric.sqlite_read_service_ns +
                                       metric.sqlite_write_service_ns +
                                       metric.sqlite_control_service_ns) /
                       1.0e9
                << " submit_to_dequeue_seconds="
                << static_cast<double>(
                    metric.sqlite_submit_to_host_dequeue_ns) / 1.0e9
                << " dequeue_to_io_submit_seconds="
                << static_cast<double>(
                    metric.sqlite_host_dequeue_to_io_submit_ns) / 1.0e9
                << " io_submit_to_complete_seconds="
                << static_cast<double>(
                    metric.sqlite_io_submit_to_complete_ns) / 1.0e9
                << " io_complete_to_publish_seconds="
                << static_cast<double>(
                    metric.sqlite_io_complete_to_publish_ns) / 1.0e9
                << " publish_to_host_resume_request_seconds="
                << static_cast<double>(
                    metric.sqlite_publish_to_host_resume_request_ns) / 1.0e9
                << " eligible_to_host_resume_request_seconds="
                << static_cast<double>(
                    metric.sqlite_wakeup_eligible_to_host_resume_request_ns) / 1.0e9
                << " host_resume_ioctl_seconds="
                << static_cast<double>(
                    metric.sqlite_host_resume_ioctl_ns) / 1.0e9
                << " completion_ready_before_wait="
                << metric.sqlite_completion_ready_before_wait_count
                << " sqlite_commit_seconds="
                << static_cast<double>(metric.sqlite_commit_ns) / 1.0e9
                << " io_uring_submissions="
                << metric.sqlite_io_uring_submissions
                << " registered_file_ops="
                << metric.sqlite_registered_file_operations
                << " registered_buffer_ops="
                << metric.sqlite_registered_buffer_operations
                << " fixed_buffer_ops="
                << metric.sqlite_fixed_buffer_operations
                << " buffer_registration_attempts="
                << metric.sqlite_buffer_registration_attempts
                << " buffer_registration_failures="
                << metric.sqlite_buffer_registration_failures
                << " direct_io_ops="
                << metric.sqlite_direct_io_operations
                << " direct_alignment_fallback_ops="
                << metric.sqlite_direct_alignment_fallback_operations
                << " posix_fallback_ops="
                << metric.sqlite_posix_fallback_operations
                << " merged_io=" << metric.sqlite_merged_io_count
                << " sparse_io=" << metric.sqlite_sparse_io_count
                << " logical_requests="
                << metric.sqlite_logical_request_count
                << " physical_requests="
                << metric.sqlite_physical_request_count
                << " deduplicated_requests="
                << metric.sqlite_deduplicated_request_count
                << " completion_wait_ocalls="
                << metric.sqlite_completion_wait_ocall_count
                << " cache_hits="
                << metric.sqlite_cache_full_hit_count +
                       metric.sqlite_cache_partial_hit_count
                << " cache_misses=" << metric.sqlite_cache_miss_count
                << " read_amplification="
                << (metric.sqlite_useful_io_bytes ?
                    static_cast<double>(metric.sqlite_physical_io_bytes) /
                        static_cast<double>(metric.sqlite_useful_io_bytes) :
                    0.0)
                << " io_request_count=" << metric.io_trace_request_count
                << " io_range_start=" << metric.io_trace_range_start
                << " io_range_end=" << metric.io_trace_range_end
                << " io_range_bytes=" << metric.io_trace_total_range_bytes
                << " io_useful_bytes=" << metric.io_trace_useful_bytes
                << " io_gap_bytes=" << metric.io_trace_gap_bytes
                << " collect_seconds="
                << static_cast<double>(metric.sqlite_collect_ns) / 1.0e9
                << " cluster_seconds="
                << static_cast<double>(metric.sqlite_cluster_ns) / 1.0e9
                << " io_submit_seconds="
                << static_cast<double>(metric.sqlite_submit_ns) / 1.0e9
                << " io_api_seconds="
                << static_cast<double>(metric.sqlite_disk_io_ns) / 1.0e9
                << " io_completion_wait_seconds="
                << static_cast<double>(metric.sqlite_completion_wait_ns) / 1.0e9
                << " storage_sync_seconds="
                << static_cast<double>(metric.sqlite_storage_sync_ns) / 1.0e9
                << " sequential_8mb_extent_count="
                << metric.sqlite_sequential_8mb_extent_count
                << " cross_worker_extent_count="
                << metric.sqlite_cross_worker_extent_count
                << " utm_copy_seconds="
                << static_cast<double>(metric.sqlite_utm_copy_ns) / 1.0e9
                << " wakeup_seconds="
                << static_cast<double>(metric.sqlite_wakeup_ns) / 1.0e9
                << " adaptive_batch="
                << metric.sqlite_adaptive_batch_target
                << " adaptive_qd=" << metric.sqlite_adaptive_queue_depth
                << " adaptive_gap=" << metric.sqlite_adaptive_gap_bytes
                << " write_overlap_check_seconds="
                << static_cast<double>(metric.sqlite_write_overlap_check_ns) /
                    1.0e9
                << " write_overlap_checks=" << metric.sqlite_write_overlap_checks
                << " write_disjoint_batches="
                << metric.sqlite_write_disjoint_batches
                << " write_overlap_batches=" << metric.sqlite_write_overlap_batches
                << " adaptive_write_grow_count="
                << metric.sqlite_adaptive_write_grow_count
                << " adaptive_write_shrink_count="
                << metric.sqlite_adaptive_write_shrink_count
                << " adaptive_write_hold_count="
                << metric.sqlite_adaptive_write_hold_count
                << " sequential_ready_single_batches="
                << metric.sqlite_sequential_ready_single_batches
                << " sequential_ready_multi_batches="
                << metric.sqlite_sequential_ready_multi_batches
                << " sequential_ready_adjacent_pairs="
                << metric.sqlite_sequential_ready_adjacent_pairs
                << " sequential_ready_nonadjacent_pairs="
                << metric.sqlite_sequential_ready_nonadjacent_pairs
                << " random_sparse_fast_batches=" << metric.sqlite_random_sparse_fast_batches
                << " random_sparse_fast_requests=" << metric.sqlite_random_sparse_fast_requests
                << " random_planned_batches=" << metric.sqlite_random_planned_batches
                << " random_precheck_fallbacks=" << metric.sqlite_random_precheck_fallbacks
                << " random_precheck_ns=" << metric.sqlite_random_precheck_ns
                << " readseq_initial_requests=" << metric.sqlite_readseq_initial_requests
                << " readseq_refill_peer_io_requests=" << metric.sqlite_readseq_refill_peer_io_requests
                << " readseq_refill_peer_ready_requests=" << metric.sqlite_readseq_refill_peer_ready_requests
                << " readseq_refill_peer_idle_requests=" << metric.sqlite_readseq_refill_peer_idle_requests
                << " random_local_plan_batches=" << metric.sqlite_random_local_plan_batches
                << " random_local_candidate_requests=" << metric.sqlite_random_local_candidate_requests
                << " cache_fill_bytes=" << metric.sqlite_cache_fill_bytes
                << " cache_fill_ns=" << metric.sqlite_cache_fill_ns
                << " cache_fill_skipped_bytes=" << metric.sqlite_cache_fill_skipped_bytes
                << " cache_admission_disables=" << metric.sqlite_cache_admission_disables
                << " cache_admission_reenables=" << metric.sqlite_cache_admission_reenables
                << " pipeline_doorbell_count=" << metric.pipeline.doorbell_count
                << " pipeline_doorbell_ack_ticks=" << metric.pipeline.doorbell_ack_ticks
                << " pipeline_doorbell_ack_max_ticks=" << metric.pipeline.doorbell_ack_max_ticks
                << " pipeline_completion_to_consume_count=" << metric.pipeline.completion_to_consume_count
                << " pipeline_completion_to_consume_ticks=" << metric.pipeline.completion_to_consume_ticks
                << " pipeline_completion_to_consume_max_ticks=" << metric.pipeline.completion_to_consume_max_ticks
                << " pipeline_completion_timestamp_invalid=" << metric.pipeline.completion_timestamp_invalid
                << " pipeline_ack_to_consume_ticks=" << metric.pipeline.ack_to_consume_ticks
                << " pipeline_ack_to_consume_max_ticks=" << metric.pipeline.ack_to_consume_max_ticks
                << " pipeline_buffer_consume_count=" << metric.pipeline.buffer_consume_count
                << " pipeline_buffer_consume_ticks=" << metric.pipeline.buffer_consume_ticks
                << " pipeline_buffer_consume_max_ticks=" << metric.pipeline.buffer_consume_max_ticks
                << " pipeline_buffer_refill_count=" << metric.pipeline.buffer_refill_count
                << " pipeline_buffer_refill_ticks=" << metric.pipeline.buffer_refill_ticks
                << " pipeline_buffer_refill_max_ticks=" << metric.pipeline.buffer_refill_max_ticks
                << " pipeline_request_prepare_ticks=" << metric.pipeline.request_prepare_ticks
                << " pipeline_submission_timing_count=" << metric.pipeline.submission_timing_count
                << " pipeline_submission_timestamp_invalid=" << metric.pipeline.submission_timestamp_invalid
                << " pipeline_submit_to_host_ticks=" << metric.pipeline.submit_to_host_ticks
                << " pipeline_submit_to_host_max_ticks=" << metric.pipeline.submit_to_host_max_ticks
                << " pipeline_host_to_ack_ticks=" << metric.pipeline.host_to_ack_ticks
                << " pipeline_host_to_ack_max_ticks=" << metric.pipeline.host_to_ack_max_ticks
                << " pipeline_ack_to_resume_request_ticks=" << metric.pipeline.ack_to_resume_request_ticks
                << " pipeline_ack_to_resume_request_max_ticks=" << metric.pipeline.ack_to_resume_request_max_ticks
                << " pipeline_resume_request_to_return_ticks=" << metric.pipeline.resume_request_to_return_ticks
                << " pipeline_resume_request_to_return_max_ticks=" << metric.pipeline.resume_request_to_return_max_ticks
                << " io_critical_path_seconds="
                << static_cast<double>(metric.sqlite_critical_path_ns) /
                    1.0e9
                << " io_max_queue_wait_seconds="
                << static_cast<double>(metric.sqlite_max_queue_wait_ns) /
                    1.0e9
                << " io_max_batch_service_seconds="
                << static_cast<double>(
                    metric.sqlite_max_batch_service_ns) / 1.0e9
                << " io_max_completion_latency_seconds="
                << static_cast<double>(
                    metric.sqlite_max_completion_latency_ns) / 1.0e9
                << " aes_seconds=" << metric.aes_wall_seconds
                << " ocall_seconds=" << metric.ocall_wall_seconds
                << " scheduler_seconds=" << metric.scheduler_wall_seconds
                << " dispatches=" << metric.slot_dispatches
                << " aggregates=" << metric.slot_aggregates
                << " digest=" << metric.digest << std::endl;
    }
  }
  if (sqlite_benchmark_io_mode() ==
      SQLITE_BENCHMARK_IO_ADAPTIVE_EXTENT) {
    std::cout << "[P10][sqlite-adaptive-target] target="
              << static_cast<double>(adaptive_gain_target_permille) / 1000.0
              << " compared_rows=" << adaptive_gain_rows
              << " met_rows=" << adaptive_gain_rows - adaptive_gain_misses
              << " missed_rows=" << adaptive_gain_misses
              << " reference=sync-no-extent-same-workload-same-workers"
              << std::endl;
    if (adaptive_gain_misses)
      std::cerr << "[P10][sqlite][WARN] adaptive I/O did not reach the "
                   "configured gain target for every comparable row; "
                   "the CSV identifies each miss"
                << std::endl;
  }
  if (io_range_csv_env && io_range_csv_env[0] &&
      !write_sqlite_io_summary_csv(
          io_range_csv_env, results, max_workers,
          sync_no_extent_baselines, sync_no_extent_scale_baselines,
          async_no_extent_baselines, async_no_extent_scale_baselines,
          adaptive_gain_target_permille)) {
    std::cerr << "[P10][sqlite] cannot write compact I/O summary: "
              << io_range_csv_env << std::endl;
    return false;
  }
  return !csv_env || !csv_env[0] ||
      write_sqlite_scaling_csv(csv_env, results, max_workers,
                               sync_no_extent_baselines,
                               sync_no_extent_scale_baselines,
                               sync_no_extent_baseline_source,
                               async_no_extent_baselines,
                               async_no_extent_scale_baselines,
                               async_no_extent_baseline_source,
                               adaptive_gain_target_permille);
}

#if GROUP_PMP_ENABLE_SPARK_SCHEDULER
bool
run_task_scheduler_scale_case(uint64_t mode, uint64_t tasks_per_job) {
  struct keystone_group_task_scheduler scheduler;
  uint64_t completed[3] = {0, 0, 0};
  uint64_t lane_completed[3] = {0, 0, 0};
  const uint64_t total = tasks_per_job * 3;

  keystone_group_task_scheduler_init(&scheduler, mode, UINT64_C(0xe));
  for (uint64_t job = 0; job < 3; ++job) {
    struct keystone_group_stage_descriptor stage;
    std::memset(&stage, 0, sizeof(stage));
    stage.job_id = UINT64_C(0x1500) + job;
    stage.stage_id = 0;
    stage.required_workers = 1;
    if (keystone_group_task_add_stage(&scheduler, &stage) !=
        KEYSTONE_GROUP_TASK_OK)
      return false;
    for (uint64_t task_index = 0; task_index < tasks_per_job;
         ++task_index) {
      struct keystone_group_task_descriptor task;
      std::memset(&task, 0, sizeof(task));
      KEYSTONE_ABI_INIT(&task, KEYSTONE_GROUP_ABI_FEATURES);
      task.job_id = stage.job_id;
      task.stage_id = stage.stage_id;
      task.task_id = task_index;
      task.partition_id = task_index;
      task.input_bank = task_index % KEYSTONE_YXSTM_TASK_BANK_COUNT;
      task.output_bank = task.input_bank;
      task.length = 64;
      task.opcode = KEYSTONE_GROUP_TASK_OPCODE_COPY;
      task.task_epoch = task_index + 1;
      task.active_worker_mask = UINT64_C(0xe);
      task.flags = KEYSTONE_GROUP_TASK_FLAG_RETRYABLE |
                   KEYSTONE_GROUP_TASK_FLAG_IDEMPOTENT;
      task.weight = 1;
      task.max_attempts = 3;
      task.commit_token = (task.job_id << 32) ^ (task.task_id + 1);
      if (keystone_group_task_submit(&scheduler, &task) !=
          KEYSTONE_GROUP_TASK_OK)
        return false;
    }
  }

  while (scheduler.completed_count < total) {
    struct keystone_group_task_descriptor dispatched[3];
    uint64_t lanes[3] = {0, 0, 0};
    int count = keystone_group_task_dispatch(
        &scheduler, dispatched, lanes, 3);

    if (count <= 0 || count > 3)
      return false;
    for (int i = 0; i < count; ++i) {
      struct keystone_group_task_result result;
      uint64_t job_index;

      if (dispatched[i].job_id < UINT64_C(0x1500) ||
          dispatched[i].job_id >= UINT64_C(0x1503) ||
          lanes[i] < 1 || lanes[i] > 3)
        return false;
      job_index = dispatched[i].job_id - UINT64_C(0x1500);
      std::memset(&result, 0, sizeof(result));
      KEYSTONE_ABI_INIT(&result, KEYSTONE_GROUP_ABI_FEATURES);
      result.job_id = dispatched[i].job_id;
      result.stage_id = dispatched[i].stage_id;
      result.task_id = dispatched[i].task_id;
      result.attempt_id = dispatched[i].attempt_id;
      result.partition_id = dispatched[i].partition_id;
      result.lane_id = lanes[i];
      result.bank_id = dispatched[i].output_bank;
      result.task_epoch = dispatched[i].task_epoch;
      result.status = KEYSTONE_GROUP_TASK_STATE_SUCCEEDED;
      result.digest = dispatched[i].commit_token ^ UINT64_C(0x5a5a);
      result.commit_token = dispatched[i].commit_token;
      if (keystone_group_task_complete(&scheduler, &result) !=
          KEYSTONE_GROUP_TASK_OK ||
          keystone_group_task_complete(&scheduler, &result) !=
          KEYSTONE_GROUP_TASK_OK)
        return false;
      completed[job_index]++;
      lane_completed[lanes[i] - 1]++;
    }

    if (mode != KEYSTONE_GROUP_TASK_SCHED_FIFO) {
      uint64_t minimum = completed[0];
      uint64_t maximum = completed[0];
      for (size_t i = 1; i < 3; ++i) {
        minimum = std::min(minimum, completed[i]);
        maximum = std::max(maximum, completed[i]);
      }
      if (maximum - minimum > 3)
        return false;
    }
  }

  if (!keystone_group_task_idle(&scheduler))
    return false;
  for (size_t i = 0; i < 3; ++i)
    if (completed[i] != tasks_per_job || !lane_completed[i])
      return false;
  std::cout << "[P15][task-fairness] mode=" << mode
            << " tasks_per_job=" << tasks_per_job
            << " completed=" << completed[0] << "/" << completed[1]
            << "/" << completed[2]
            << " lanes=" << lane_completed[0] << "/"
            << lane_completed[1] << "/" << lane_completed[2]
            << std::endl;
  return true;
}

bool
run_task_scheduler_scale_policy() {
  const uint64_t counts[] = {10, 50, 100};
  const uint64_t modes[] = {
      KEYSTONE_GROUP_TASK_SCHED_FAIR,
      KEYSTONE_GROUP_TASK_SCHED_ROUND_ROBIN,
  };

  for (size_t mode = 0; mode < sizeof(modes) / sizeof(modes[0]); ++mode)
    for (size_t count = 0; count < sizeof(counts) / sizeof(counts[0]);
         ++count)
      if (!run_task_scheduler_scale_case(modes[mode], counts[count]))
        return false;
  return true;
}

bool
run_task_scheduler_phase(const char* master_eapp, const char* worker_eapp,
                         const char* runtime, const char* loader) {
  const char* label = "spark-style two-level task scheduler";
  std::vector<EnclaveInstance> enclaves;
  bool ok = true;

  std::cout << "[host] phase: " << label << std::endl;
  if (!run_task_scheduler_scale_policy())
    return false;
  if (!configure_default_group())
    return false;
  add_instance(enclaves, "task-master", master_eapp, kDefaultGroupId, 4,
      kPerfYxstmSize, kUtmSize, kPerfYxstmSliceSize);
  add_instance(enclaves, "task-worker1", worker_eapp, kDefaultGroupId, 4,
      kPerfYxstmSize, kUtmSize, kPerfYxstmSliceSize);
  add_instance(enclaves, "task-worker2", worker_eapp, kDefaultGroupId, 4,
      kPerfYxstmSize, kUtmSize, kPerfYxstmSliceSize);
  add_instance(enclaves, "task-worker3", worker_eapp, kDefaultGroupId, 4,
      kPerfYxstmSize, kUtmSize, kPerfYxstmSliceSize);
  if (!init_all(enclaves, runtime, loader) || !finalize_all(enclaves)) {
    destroy_instances(enclaves);
    return false;
  }
  for (uint64_t cpu = 0; cpu < enclaves.size(); ++cpu) {
    if (!bind_and_enqueue(enclaves[cpu], sm_hart_id_for_cpu(cpu))) {
      ok = false;
      break;
    }
  }
  if (ok)
    ok = run_group_3w1hm(kDefaultGroupId, enclaves, label);
  if (ok) {
    struct keystone_group_test_snapshot snapshot;
    std::memset(&snapshot, 0, sizeof(snapshot));
    if (!take_resource_snapshot(kDefaultGroupId, &snapshot) ||
        snapshot.running_workers != 0 ||
        snapshot.max_running_workers == 0 ||
        snapshot.max_running_workers > 3 ||
        snapshot.master_non_boundary_entries != 0) {
      print_resource_snapshot("task scheduler concurrency invariant failed",
                              snapshot);
      ok = false;
    }
  }
  destroy_instances(enclaves);
  return ok;
}
#endif

bool
run_perf_phase(const char* utm_bench,
               const char* aes_master_encrypt,
               const char* aes_master_decrypt,
               const char* aes_worker,
               const char* runtime, const char* loader) {
  struct keystone_group_perf_snapshot snapshot;
  uint64_t cycle_hz = env_u64(
      "GROUP_PMP_CYCLE_HZ", kPerfDefaultCycleHz, 1, UINT64_MAX);
  bool ok = reset_group_perf_counters();
  if (!ok) {
    std::cerr << "[host] failed to reset group perf counters" << std::endl;
    return false;
  }

  ok = run_host_copy_benchmark();
  ok = ok && run_utm_copy_benchmark_phase(utm_bench, runtime, loader);
  ok = ok && run_aes_benchmark_phase("p10 aes encrypt",
      aes_master_encrypt, aes_worker, runtime, loader, kPerfAesEncrypt);
  ok = ok && run_aes_benchmark_phase("p10 aes decrypt",
      aes_master_decrypt, aes_worker, runtime, loader, kPerfAesDecrypt);
  if (!ok)
    return false;

  if (!query_group_perf_counters(&snapshot)) {
    std::cerr << "[host] failed to query group perf counters" << std::endl;
    return false;
  }

#if !GROUP_PMP_AES_COOPERATIVE_SERVICE
  if (snapshot.host_service_count == 0) {
    std::cerr << "[host] P10 scheduler-owned host service was not observed"
              << std::endl;
    return false;
  }
  if (snapshot.grant_suspend_restore_count == 0 ||
      snapshot.grant_suspend_restore_count >
          snapshot.host_service_count + snapshot.context_switch_count) {
    std::cerr << "[host] P10 YXSTM grant suspend/restore was not observed or "
                  "reported an invalid count: host_service="
              << snapshot.host_service_count
              << " context_switch=" << snapshot.context_switch_count
              << " grant_suspend_restore="
              << snapshot.grant_suspend_restore_count << std::endl;
    return false;
  }
#endif
  print_group_perf_summary(snapshot, cycle_hz);
  return true;
}

void
print_usage(const char* argv0) {
  std::cerr
      << "usage: " << argv0
      << " [private-probe.eapp timeslice-a.eapp timeslice-b.eapp timeslice-check.eapp ocall-blocker.eapp mw-master-dispatch.eapp mw-worker.eapp mw-master-aggregate.eapp mw-master-miss.eapp mw-worker-dispatch-rw-denied.eapp mw-worker-cross-slice-fault.eapp mw-worker-slice0-fault.eapp mw-master-aggregate-rw-denied.eapp mw-no-acquire-fault.eapp mw-release-fault.eapp mw-hold-yield.eapp mw-inherit-fault.eapp mw-exec-fault.eapp eyrie-rt loader.bin [utm-bench.eapp aes-master-encrypt.eapp aes-master-decrypt.eapp aes-worker.eapp]]"
      << std::endl;
  std::cerr << "Security experiments: sh ./run-security-experiments.sh [all|scan|isolation|integrity] [workers] [attempts] [new-output-dir]" << std::endl;
}

bool
verify_loader_abi(const char* loader) {
  std::ifstream input(loader, std::ios::in | std::ios::binary);
  if (!input) {
    std::cerr << "[host] cannot open loader artifact: " << loader << std::endl;
    return false;
  }

  std::string image((std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>());
  if (image.find(kLoaderAbiMarker) != std::string::npos)
    return true;

  std::cerr << "[host] stale loader ABI: " << loader
            << " does not contain marker '" << kLoaderAbiMarker << "'\n"
            << "[host] rebuild with examples/group-pmp-test/"
               "rebuild-and-test.sh and deploy the complete directory"
            << std::endl;
  return false;
}

bool
recover_worker_leases() {
  constexpr uint64_t kMaxGroups = 4;
  Keystone::KeystoneDevice device;
  Params params;
  bool ok = true;

  if (!device.initDevice(params))
    return false;
  for (uint64_t group_id = 1; group_id <= kMaxGroups; ++group_id) {
    struct keystone_group_lease lease;

    std::memset(&lease, 0, sizeof(lease));
    Error error = device.groupReleaseWorkers(group_id, 0, &lease);
    if (error != Error::Success) {
      std::cerr << "[host][lease-recover] group=" << group_id
                << " error=" << error_name(error) << std::endl;
      ok = false;
    }
  }
  std::cout << "[host][lease-recover] "
            << (ok ? "worker harts released" : "release failed")
            << std::endl;
  return ok;
}

#include "rv8-scaling.hpp"
#include "motivation.hpp"
#include "kv-scaling.hpp"
#include "crypto-compute.hpp"

}  // namespace

int
main(int argc, char** argv) {
  if (argc >= 2 && std::strcmp(argv[1], "--crypto-compute") == 0)
    return run_crypto_compute(argc, argv);
  if (argc == 2 && std::strcmp(argv[1], "--crypto-compute-info") == 0) {
    std::cout << "crypto_compute_version=1 marker=" << CRYPTO_COMPUTE_MARKER
              << " startup_revision=2 free_bytes_per_member=" << CRYPTO_COMPUTE_FREE_BYTES
              << " worker_enclaves=1 data_io=0 timed_ocalls=0 block_bytes="
              << CRYPTO_COMPUTE_BLOCK_BYTES << std::endl;
    return 0;
  }
  if (benchmark_cipher_marker[0] != 'k' || selected_benchmark_cipher() > BENCHMARK_CHACHA_POLY) {
    std::cerr << "Invalid GROUP_PMP_BENCH_CIPHER" << std::endl;
    return 2;
  }
  security_positive_control();
  if (argc == 2 && std::strcmp(argv[1], "--security-crypto-info") == 0) {
    std::cout << "performance_cipher=" << selected_benchmark_cipher_name()
              << " performance_aead=" << (selected_benchmark_cipher() != BENCHMARK_AES_ECB) << ' '
              <<
                 "security_fixture=aes-128-gcm,chacha20-poly1305 security_version=1 "
                 "security_worker_set=1,4 security_fixture_version=7 security_aead_ocall=9 "
                 "security_gcm_memory=inline-block-cipher "
                 "security_scan_scope=registered-ciphertext security_aead_execution=exclusive-worker-lease "
                 "security_capture_version=1 scan_workload_ciphers=aes-128-ecb "
                 "security_checkpoint_watchdog=2 security_capture_input_bytes=1000000 "
                 "security_capture_batch_requests=8 security_capture_ring_accounting=2" << std::endl;
    return 0;
  }
  const char* cluster_mode = std::getenv("GROUP_PMP_SQLITE_CLUSTER_MODE");
  if (cluster_mode && std::strcmp(cluster_mode, "merge") && std::strcmp(cluster_mode, "plan-only")) {
    std::cerr << "[P10][sqlite] cluster mode must be merge or plan-only" << std::endl;
    return 1;
  }
  if (argc == 2 && std::strcmp(argv[1], "--artifact-info") == 0) {
    std::cout << "artifact=group-pmp-test-runner"
              << " sqlite_csv_schema=" << kSqliteCsvSchemaVersion
              << " sqlite_extent_policy="
              << sqlite_extent_io_policy_version()
              << " sqlite_vfs_batch_max="
              << GROUP_PMP_SQLITE_VFS_BATCH_MAX
              << " sqlite_vfs_ring_bytes="
              << GROUP_PMP_SQLITE_VFS_RING_BYTES
              << " sqlite_vfs_utm_bytes="
              << GROUP_PMP_SQLITE_VFS_UTM_BYTES
              << " kv_bench_version=1 benchmark_cipher_version=1 supported_ciphers=aes-ecb-128,aes-gcm-128,chacha20-poly1305"
              << " marker=keystone-sqlite-workload-aware-io-policy-v3"
               << " common_path_version=" << kGroupPmpSqliteCommonPathVersion
               << " features=shared-execution-v3+batch-metadata-lookup+arrival-order-groups+mixed-cost-profile-v1+calibrated-read-bypass+submit-cpu-switch-breakdown+cluster-ablation+common-cost-clock+mixed-batch-probe-v2+no-extra-cipher-cache+locality-random-v1+arrived-sequential-four-plan+net-benefit-cluster+"
                 "lane-batched-wakeup+rolling-collect+double-buffer-event-wait+"
                 "overlap-dedup-scatter+sequence-safe-write+"
                 "write-overlap-accounting+adaptive-write-decisions+"
                 "sequential-ready-accounting+"
                 "common-async-readseq-paired-doorbell+independent-ring-completions+"
                 "registered-files-buffers+capacity-bound-wire-version+"
                 "scale-matched-baseline+inline-isolated-io+same-region-fixed-fold+cross-buffer-probe-v1"
                 "+persistent-inflight+per-buffer-completion+latency-bounded-depth"
                 "+fio-profile-rw-bs-v1"
              << " sqlite_pipeline=1"
              << std::endl;
    return sqlite_extent_io_policy_version() ==
                   kGroupPmpSqliteExtentIoPolicyVersion
             ? 0
             : 1;
  }
  if ((argc == 2 || argc == 3) &&
      std::strcmp(argv[1], "--sqlite-io-path-probe") == 0) {
    uint64_t iterations = 100;
    if (argc == 3 && (!parse_csv_u64(argv[2], &iterations) ||
                      iterations < 5 || iterations > 10000)) {
      std::cerr << "usage: " << argv[0]
                << " --sqlite-io-path-probe [iterations:5..10000]" << std::endl;
      return 2;
    }
    return sqlite_io_path_probe(static_cast<unsigned>(iterations));
  }
  if (argc == 4 && std::strcmp(argv[1], "--sqlite-io-calibrate") == 0) {
    uint64_t iterations = 0;
    if (!parse_csv_u64(argv[2], &iterations) || iterations < 15 || iterations > 1000 || !argv[3][0]) {
      std::cerr << "usage: " << argv[0] << " --sqlite-io-calibrate iterations:15..1000 profile-path" << std::endl;
      return 2;
    }
    return sqlite_io_mixed_batch_probe(static_cast<unsigned>(iterations), argv[3]);
  }
  const char* private_probe = "group-pmp-private-probe.eapp_riscv";
  const char* timeslice_a = "group-pmp-timeslice-a.eapp_riscv";
  const char* timeslice_b = "group-pmp-timeslice-b.eapp_riscv";
  const char* timeslice_check = "group-pmp-timeslice-check.eapp_riscv";
  const char* lease_hold = "group-pmp-lease-hold.eapp_riscv";
  const char* ocall_blocker = "group-pmp-ocall-blocker.eapp_riscv";
  const char* mw_master_dispatch =
      "group-pmp-mw-master-dispatch.eapp_riscv";
  const char* mw_worker = "group-pmp-mw-worker.eapp_riscv";
  const char* mw_master_aggregate =
      "group-pmp-mw-master-aggregate.eapp_riscv";
  const char* mw_worker_dispatch_rw_denied =
      "group-pmp-mw-worker-dispatch-rw-denied.eapp_riscv";
  const char* mw_worker_cross_slice_fault =
      "group-pmp-mw-worker-cross-slice-fault.eapp_riscv";
  const char* mw_worker_slice0_fault =
      "group-pmp-mw-worker-slice0-fault.eapp_riscv";
  const char* mw_master_aggregate_rw_denied =
      "group-pmp-mw-master-aggregate-rw-denied.eapp_riscv";
  const char* mw_no_acquire_fault =
      "group-pmp-mw-no-acquire-fault.eapp_riscv";
  const char* mw_release_fault =
      "group-pmp-mw-release-fault.eapp_riscv";
  const char* mw_hold_yield =
      "group-pmp-mw-hold-yield.eapp_riscv";
  const char* mw_inherit_fault =
      "group-pmp-mw-inherit-fault.eapp_riscv";
  const char* mw_exec_fault =
      "group-pmp-mw-exec-fault.eapp_riscv";
  const char* mw_master_fault =
      "group-pmp-mw-master-fault.eapp_riscv";
  const char* utm_bench =
      "group-pmp-utm-bench.eapp_riscv";
  const char* aes_master_encrypt =
      "group-pmp-aes-master-encrypt.eapp_riscv";
  const char* aes_master_decrypt =
      "group-pmp-aes-master-decrypt.eapp_riscv";
  const char* aes_worker =
      "group-pmp-aes-worker.eapp_riscv";
#if GROUP_PMP_ENABLE_SPARK_SCHEDULER
  const char* task_master =
      "group-pmp-task-master.eapp_riscv";
  const char* task_worker =
      "group-pmp-task-worker.eapp_riscv";
#endif
  const char* aes_scale_worker =
      "group-pmp-aes-scale-worker.eapp_riscv";
  const char* aes_enclave_baseline =
      "group-pmp-aes-enclave-baseline.eapp_riscv";
  const char* mixed_master =
      "group-pmp-mixed-master.eapp_riscv";
  const char* mixed_worker =
      "group-pmp-mixed-worker.eapp_riscv";
  const char* sqlite_master =
      "group-pmp-sqlite-master.eapp_riscv";
  const char* sqlite_worker =
      "group-pmp-sqlite-worker.eapp_riscv";
  const char* runtime = "eyrie-rt";
  const char* loader = "loader.bin";

  const char* early_mode_env = std::getenv("GROUP_PMP_TEST_MODE");
  if (early_mode_env &&
      std::strcmp(early_mode_env, "lease-recover") == 0)
    return recover_worker_leases() ? 0 : 1;

  std::signal(SIGINT, request_stop);
  std::signal(SIGTERM, request_stop);

  if (early_mode_env && std::strcmp(early_mode_env, "motivation") == 0)
    return run_motivation(runtime, loader) ? 0 : 1;

  if (argc == 25) {
    private_probe = argv[1];
    timeslice_a = argv[2];
    timeslice_b = argv[3];
    timeslice_check = argv[4];
    ocall_blocker = argv[5];
    mw_master_dispatch = argv[6];
    mw_worker = argv[7];
    mw_master_aggregate = argv[8];
    mw_worker_dispatch_rw_denied = argv[10];
    mw_worker_cross_slice_fault = argv[11];
    mw_worker_slice0_fault = argv[12];
    mw_master_aggregate_rw_denied = argv[13];
    mw_no_acquire_fault = argv[14];
    mw_release_fault = argv[15];
    mw_hold_yield = argv[16];
    mw_inherit_fault = argv[17];
    mw_exec_fault = argv[18];
    runtime = argv[19];
    loader = argv[20];
    utm_bench = argv[21];
    aes_master_encrypt = argv[22];
    aes_master_decrypt = argv[23];
    aes_worker = argv[24];
  } else if (argc == 21) {
    private_probe = argv[1];
    timeslice_a = argv[2];
    timeslice_b = argv[3];
    timeslice_check = argv[4];
    ocall_blocker = argv[5];
    mw_master_dispatch = argv[6];
    mw_worker = argv[7];
    mw_master_aggregate = argv[8];
    mw_worker_dispatch_rw_denied = argv[10];
    mw_worker_cross_slice_fault = argv[11];
    mw_worker_slice0_fault = argv[12];
    mw_master_aggregate_rw_denied = argv[13];
    mw_no_acquire_fault = argv[14];
    mw_release_fault = argv[15];
    mw_hold_yield = argv[16];
    mw_inherit_fault = argv[17];
    mw_exec_fault = argv[18];
    runtime = argv[19];
    loader = argv[20];
  } else if (argc != 1) {
    print_usage(argv[0]);
    return 2;
  }

  if (!verify_loader_abi(loader))
    return 2;

  const char* mode_env = std::getenv("GROUP_PMP_TEST_MODE");
  std::string mode = mode_env ? mode_env : "smoke";
#if !GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS
  if (mode == "perf" || mode == "scale") {
    std::cerr << "[host] GROUP_PMP_TEST_MODE=" << mode
              << " is retired; future performance results use the mixed "
                 "AES/YXSTM/OCALL/host-service baseline"
              << std::endl;
    return 2;
  }
#endif
  bool run_smoke = mode == "smoke" || mode == "all";
  bool run_stress = mode == "stress" || mode == "all";
  bool run_fault = mode == "fault" || mode == "all";
  bool run_host_access = mode == "host-access";
  bool run_security = mode == "security";
  bool run_perf =
#if GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS
      mode == "perf";
#else
      false;
#endif
#if GROUP_PMP_ENABLE_SPARK_SCHEDULER
  bool run_task = mode == "task";
#else
  bool run_task = false;
#endif
  bool run_scale =
#if GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS
      mode == "scale";
#else
      false;
#endif
  bool run_acceptance = mode == "acceptance";
  bool run_mixed_scale = mode == "mixed-scale";
  bool run_mixed_ocall_stress = mode == "mixed-ocall-stress";
  bool run_sqlite_bench = mode == "sqlite-bench";
  bool run_rv8_bench = mode == "rv8-bench";
  bool run_kv_bench = mode == "secure-kv-bench";
  bool run_aes_baseline = mode == "aes-baseline";
  bool run_aes_diagnostic = mode == "aes-diagnostic";
  if (!run_smoke && !run_stress && !run_fault &&
      !run_host_access && !run_security && !run_perf && !run_task && !run_scale &&
      !run_acceptance && !run_mixed_scale && !run_mixed_ocall_stress &&
      !run_sqlite_bench && !run_rv8_bench && !run_kv_bench && !run_aes_baseline && !run_aes_diagnostic) {
    std::cerr << "[host] invalid GROUP_PMP_TEST_MODE=" << mode
              << " expected smoke|stress|fault|acceptance|all|host-access|security"
              << "|mixed-scale|mixed-ocall-stress|aes-baseline"
              << "|aes-diagnostic|sqlite-bench|rv8-bench|secure-kv-bench"
#if GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS
              << "|perf|scale"
#endif
#if !GROUP_PMP_ENABLE_SPARK_SCHEDULER
              << " (Spark-style task mode is disabled at build time)"
#else
              << "|task"
#endif
              << std::endl;
    return 2;
  }

  bool ok = true;
  if (run_security) {
    const char* name = std::getenv("GROUP_PMP_SECURITY_CASE");
    ok = name && run_security_case(name, timeslice_check, mixed_master,
        mixed_worker, runtime, loader);
  }
  if (run_smoke) {
    ok = ok && run_master_worker_pipeline_phase(
        mw_master_dispatch, mw_worker, mw_master_aggregate, runtime, loader);
    ok = ok && run_master_worker_denied_fault_phase(
        mw_master_dispatch, mw_worker, mw_worker_dispatch_rw_denied,
        mw_worker_cross_slice_fault, mw_worker_slice0_fault,
        mw_master_aggregate_rw_denied, mw_no_acquire_fault, mw_release_fault,
        mw_hold_yield, mw_inherit_fault, mw_exec_fault, runtime, loader);
    ok = ok && run_non_old_semantics_regression_phase(
        timeslice_a, timeslice_b, timeslice_check, private_probe,
        timeslice_check, timeslice_check, ocall_blocker, timeslice_check,
        timeslice_check, runtime, loader);
  }
  if (run_stress) {
    uint64_t lifecycle_iters = env_u64(
        "GROUP_PMP_LIFECYCLE_ITERS", 2000, 1, 1000000);
    uint64_t scheduler_rounds = env_u64(
        "GROUP_PMP_SCHED_STRESS_ROUNDS", 100, 1, 100000);
    uint64_t two_group_rounds = env_u64(
        "GROUP_PMP_TWO_GROUP_ROUNDS", 100, 1, 100000);
    ok = ok && run_lifecycle_leak_stress(
        timeslice_check, runtime, loader, lifecycle_iters);
    ok = ok && run_active_worker_lease_release_phase(
        timeslice_check, lease_hold, runtime, loader);
    ok = ok && run_scheduler_long_stress(timeslice_a, timeslice_b,
        timeslice_check, runtime, loader, scheduler_rounds);
    ok = ok && run_two_group_concurrency_stress(
        timeslice_check, runtime, loader, two_group_rounds);
  }
  if (run_fault) {
    ok = ok && run_fault_cleanup_phase(mw_master_fault,
        mw_no_acquire_fault, timeslice_check, runtime, loader);
    ok = ok && run_yxstm_execute_fault_phase(mw_exec_fault, mw_worker,
        mw_master_aggregate, runtime, loader);
    ok = ok && run_yxstm_release_fault_phase(mw_release_fault, mw_worker,
        mw_master_aggregate, runtime, loader);
    ok = ok && run_ipi_injection_control_phase(mw_master_dispatch,
        mw_worker, mw_master_aggregate, runtime, loader);
  }
  if (run_host_access)
    ok = run_host_yxstm_access_denial(
        timeslice_check, runtime, loader);
  if (run_perf) {
    ok = run_perf_phase(utm_bench, aes_master_encrypt,
        aes_master_decrypt, aes_worker, runtime, loader);
  }
#if GROUP_PMP_ENABLE_SPARK_SCHEDULER
  if (run_task)
    ok = run_task_scheduler_phase(task_master, task_worker, runtime, loader);
#endif
  if (run_scale)
    ok = run_aes_enclave_scaling_phase(
        timeslice_check, aes_scale_worker, runtime, loader);
  if (run_mixed_scale)
    ok = run_mixed_scaling_phase(
        mixed_master, mixed_worker, runtime, loader,
        GROUP_PMP_MIXED_OCALL_PER_TASK);
  if (run_mixed_ocall_stress)
    ok = run_mixed_scaling_phase(
        mixed_master, mixed_worker, runtime, loader,
        GROUP_PMP_MIXED_OCALL_PER_CHUNK_STRESS);
  if (run_sqlite_bench)
    ok = run_sqlite_scaling_phase(
        sqlite_master, sqlite_worker, runtime, loader);
  if (run_rv8_bench)
    ok = run_rv8_scaling_phase(sqlite_master, runtime, loader);
  if (run_kv_bench)
    ok = run_kv_scaling_phase(sqlite_master, runtime, loader);
  if (run_aes_baseline)
    ok = run_aes_fair_comparison_phase(
        aes_enclave_baseline, runtime, loader);
  if (run_aes_diagnostic) {
    ok = run_aes_fair_comparison_phase(
        aes_enclave_baseline, runtime, loader);
    ok = ok && run_yxstm_memory_diagnostic_phase(
        mixed_master, mixed_worker, runtime, loader);
  }
  if (run_acceptance) {
    bool run_acceptance_faults = env_u64(
        "GROUP_PMP_ACCEPTANCE_FAULTS", 1, 0, 1) != 0;
    ok = ok && run_production_lane_queue_phase(
        timeslice_check, timeslice_b, runtime, loader);
    ok = ok && run_active_worker_lease_release_phase(
        timeslice_check, lease_hold, runtime, loader);
    if (run_acceptance_faults) {
      ok = ok && run_ocall_block_phase(
          ocall_blocker, timeslice_check, timeslice_check, runtime, loader);
      ok = ok && run_fault_cleanup_phase(mw_master_fault,
          mw_no_acquire_fault, timeslice_check, runtime, loader);
      ok = ok && run_worker_missing_injection_phase(
          mw_master_dispatch, mw_worker, runtime, loader);
      ok = ok && run_ipi_injection_control_phase(mw_master_dispatch,
          mw_worker, mw_master_aggregate, runtime, loader);
    }
  }

  std::cout << (ok ? "[host] GROUP PMP TEST PASS" :
                      "[host] GROUP PMP TEST FAIL")
            << std::endl;
  return ok ? 0 : 1;
}
