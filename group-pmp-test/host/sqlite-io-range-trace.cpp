#include "sqlite-io-range-trace.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

#include "../eapp/group-pmp-sqlite-shared.h"
#include "../eapp/group-pmp-sqlite-vfs-shared.h"

namespace {

static const volatile char sqlite_io_range_trace_marker[]
    __attribute__((used)) = "keystone-sqlite-io-range-trace-v2";

uint64_t maximum_records() {
  const char* text = std::getenv("GROUP_PMP_SQLITE_IO_RANGE_MAX_RECORDS");
  char* end = nullptr;
  if (!text || !text[0])
    return UINT64_C(262144);
  errno = 0;
  const unsigned long long parsed = std::strtoull(text, &end, 0);
  if (errno || !end || *end || parsed < 1024 || parsed > UINT64_C(4194304))
    return UINT64_C(262144);
  return static_cast<uint64_t>(parsed);
}

}  // namespace

struct SqliteIoRangeTrace::Impl {
  struct Record {
    uint64_t file_id;
    uint64_t offset;
    uint64_t length;
    uint64_t useful_bytes;
    uint64_t member_request_count;
    uint64_t worker_mask;
    int64_t result;
    uint32_t backend;
    uint32_t read;
  };

  Impl()
      : active(false), configured(false), case_id(0), sample_id(0),
        workload(0), worker_count(0), no_extent_mode(0), next_record(0),
        dropped(0), summary_valid(false) {
    std::fill(reinterpret_cast<unsigned char*>(&summary),
              reinterpret_cast<unsigned char*>(&summary) + sizeof(summary),
              0);
  }

  std::atomic<bool> active;
  bool configured;
  std::string path;
  std::ofstream output;
  std::mutex output_mutex;
  uint64_t case_id;
  uint64_t sample_id;
  uint64_t workload;
  uint64_t worker_count;
  uint64_t no_extent_mode;
  std::vector<Record> records;
  std::atomic<uint64_t> next_record;
  std::atomic<uint64_t> dropped;
  SqliteIoRangeSummary summary;
  bool summary_valid;

  void record(uint64_t file_id, uint64_t offset, uint64_t length,
              uint64_t useful_bytes, bool read,
              uint64_t member_request_count, uint64_t worker_mask,
              SqliteIoRangeBackend backend, int64_t result) {
    if (!active.load(std::memory_order_acquire))
      return;
    const uint64_t index = next_record.fetch_add(1, std::memory_order_relaxed);
    if (index >= records.size()) {
      dropped.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    Record& target = records[static_cast<size_t>(index)];
    target.file_id = file_id;
    target.offset = offset;
    target.length = length;
    target.useful_bytes = useful_bytes;
    target.member_request_count = member_request_count;
    target.worker_mask = worker_mask;
    target.result = result;
    target.backend = static_cast<uint32_t>(backend);
    target.read = read ? 1U : 0U;
  }
};

SqliteIoRangeTrace::SqliteIoRangeTrace() : impl_(new Impl()) {}

SqliteIoRangeTrace::~SqliteIoRangeTrace() { delete impl_; }

bool SqliteIoRangeTrace::configureOutput(const char* path) {
  std::lock_guard<std::mutex> lock(impl_->output_mutex);
  impl_->active.store(false, std::memory_order_release);
  impl_->configured = path && path[0];
  impl_->path = impl_->configured ? path : "";
  impl_->output.close();
  impl_->records.clear();
  impl_->summary_valid = false;
  if (!impl_->configured)
    return true;
  impl_->records.resize(static_cast<size_t>(maximum_records()));
  /* Validate and truncate the destination now, but defer compact aggregate
   * output until all randomized samples have been reduced by the runner. */
  impl_->output.open(impl_->path.c_str(), std::ios::out | std::ios::trunc);
  if (!impl_->output.is_open())
    return false;
  impl_->output.close();
  return true;
}

void SqliteIoRangeTrace::beginCase(uint64_t case_id, uint64_t sample_id,
                                   uint64_t workload, uint64_t worker_count,
                                   uint64_t no_extent_mode) {
  impl_->active.store(false, std::memory_order_release);
  impl_->case_id = case_id;
  impl_->sample_id = sample_id;
  impl_->workload = workload;
  impl_->worker_count = worker_count;
  impl_->no_extent_mode = no_extent_mode;
  impl_->next_record.store(0, std::memory_order_relaxed);
  impl_->dropped.store(0, std::memory_order_relaxed);
  impl_->summary_valid = false;
}

void SqliteIoRangeTrace::beginWindow() {
  if (impl_->configured)
    impl_->active.store(true, std::memory_order_release);
}

void SqliteIoRangeTrace::endWindow() {
  impl_->active.store(false, std::memory_order_release);
}

void SqliteIoRangeTrace::recordNoExtent(
    const group_pmp_sqlite_vfs_request& request, int64_t result) {
  if (request.operation != GROUP_PMP_SQLITE_VFS_OP_READ &&
      request.operation != GROUP_PMP_SQLITE_VFS_OP_WRITE)
    return;
  const uint64_t worker_mask = request.worker_index < 64 ?
      (UINT64_C(1) << request.worker_index) : 0;
  impl_->record(request.file_id, request.file_offset, request.length,
                request.length,
                request.operation == GROUP_PMP_SQLITE_VFS_OP_READ, 1,
                worker_mask, SQLITE_IO_RANGE_BACKEND_SQLITE_BLOB, result);
}

void SqliteIoRangeTrace::recordExtent(
    uint64_t file_id, uint64_t offset, uint64_t length,
    uint64_t useful_bytes, bool read, uint64_t member_request_count,
    uint64_t worker_mask, SqliteIoRangeBackend backend, int64_t status) {
  impl_->record(file_id, offset, length, useful_bytes, read,
                member_request_count, worker_mask, backend, status);
}

bool SqliteIoRangeTrace::flushCase() {
  impl_->active.store(false, std::memory_order_release);
  if (!impl_->configured)
    return true;
  std::atomic_thread_fence(std::memory_order_acquire);
  const uint64_t reserved = impl_->next_record.load(std::memory_order_acquire);
  const uint64_t count = std::min<uint64_t>(reserved, impl_->records.size());
  SqliteIoRangeSummary summary = {};
  summary.request_count = count;
  summary.range_start = UINT64_MAX;
  summary.min_request_bytes = UINT64_MAX;
  for (uint64_t index = 0; index < count; ++index) {
    const Impl::Record& record = impl_->records[static_cast<size_t>(index)];
    const uint64_t end = record.offset <=
        std::numeric_limits<uint64_t>::max() - record.length ?
        record.offset + record.length : std::numeric_limits<uint64_t>::max();
    const uint64_t gap = record.length > record.useful_bytes ?
        record.length - record.useful_bytes : 0;
#define SQLITE_RANGE_SATURATING_ADD(target, value)                           \
    do {                                                                      \
      if ((target) <= UINT64_MAX - (value))                                  \
        (target) += (value);                                                  \
      else                                                                    \
        (target) = UINT64_MAX;                                                \
    } while (0)
    SQLITE_RANGE_SATURATING_ADD(summary.total_range_bytes, record.length);
    SQLITE_RANGE_SATURATING_ADD(summary.useful_bytes, record.useful_bytes);
    SQLITE_RANGE_SATURATING_ADD(summary.gap_bytes, gap);
    SQLITE_RANGE_SATURATING_ADD(summary.member_request_count,
                                record.member_request_count);
#undef SQLITE_RANGE_SATURATING_ADD
    summary.range_start = std::min(summary.range_start, record.offset);
    summary.range_end = std::max(summary.range_end, end);
    summary.min_request_bytes =
        std::min(summary.min_request_bytes, record.length);
    summary.max_request_bytes =
        std::max(summary.max_request_bytes, record.length);
    if (record.read)
      ++summary.read_request_count;
    else
      ++summary.write_request_count;
    if (record.result != 0)
      ++summary.failed_request_count;
  }
  if (count == 0) {
    summary.range_start = 0;
    summary.min_request_bytes = 0;
  }
  impl_->summary = summary;
  impl_->summary_valid = true;
  return true;
}

bool SqliteIoRangeTrace::lastSummary(SqliteIoRangeSummary* summary) const {
  if (!summary || !impl_->summary_valid)
    return false;
  *summary = impl_->summary;
  return true;
}

uint64_t SqliteIoRangeTrace::droppedRecords() const {
  return impl_->dropped.load(std::memory_order_relaxed);
}

bool SqliteIoRangeTrace::enabled() const { return impl_->configured; }

SqliteIoRangeTrace& sqlite_io_range_trace() {
  static SqliteIoRangeTrace trace;
  return trace;
}
