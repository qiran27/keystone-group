#include "sqlite-gantt-trace.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <limits>

#include "../eapp/group-pmp-sqlite-shared.h"

namespace {

static const volatile char sqlite_gantt_trace_marker[]
    __attribute__((used)) = "keystone-sqlite-gantt-trace-v4";

constexpr uint64_t kDefaultTraceEvents = UINT64_C(131072);
constexpr uint64_t kMinimumTraceEvents = UINT64_C(4096);
constexpr uint64_t kMaximumTraceEvents = UINT64_C(4194304);
constexpr uint64_t kCriticalTraceReserve = UINT64_C(16384);
constexpr uint64_t kEstimatedEventsPerDataRequest = UINT64_C(12);

uint64_t trace_u64_from_env(const char* name, uint64_t fallback) {
  const char* text = std::getenv(name);
  char* end = nullptr;
  unsigned long long value;

  if (!text || !text[0])
    return fallback;
  errno = 0;
  value = std::strtoull(text, &end, 0);
  if (errno || !end || *end)
    return fallback;
  return static_cast<uint64_t>(value);
}

uint64_t request_bytes_for_workload(uint64_t workload) {
  switch (workload) {
    case GROUP_PMP_SQLITE_FILLSEQ:
    case GROUP_PMP_SQLITE_FILLSEQBATCH:
    case GROUP_PMP_SQLITE_READSEQ:
      return GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
    case GROUP_PMP_SQLITE_READRAND100K:
      return GROUP_PMP_SQLITE_LARGE_VALUE_BYTES;
    case GROUP_PMP_SQLITE_FILLRANDOM:
    case GROUP_PMP_SQLITE_FILLRANDOMBATCH:
    case GROUP_PMP_SQLITE_OVERWRITE:
    case GROUP_PMP_SQLITE_READRANDOM:
      return GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES;
    default:
      return 0;
  }
}

uint64_t ceil_div_u64(uint64_t value, uint64_t divisor) {
  return divisor ? value / divisor + (value % divisor != 0) : 0;
}

uint64_t request_sample_stride(uint64_t workload, uint64_t budget) {
  const uint64_t request_bytes = request_bytes_for_workload(workload);
  const uint64_t total_bytes = trace_u64_from_env(
      "GROUP_PMP_SQLITE_TOTAL_BYTES", 0);

  if (!request_bytes || !total_bytes || !budget)
    return 1;
  const uint64_t requests = ceil_div_u64(total_bytes, request_bytes);
  const uint64_t estimated_events = requests >
          std::numeric_limits<uint64_t>::max() /
              kEstimatedEventsPerDataRequest ?
      std::numeric_limits<uint64_t>::max() :
      requests * kEstimatedEventsPerDataRequest;
  return std::max<uint64_t>(1, ceil_div_u64(estimated_events, budget));
}

uint64_t trace_capacity_from_env() {
  const char* text = std::getenv("GROUP_PMP_SQLITE_GANTT_MAX_EVENTS");
  char* end = nullptr;
  unsigned long long value;

  if (!text || !text[0])
    return kDefaultTraceEvents;
  errno = 0;
  value = std::strtoull(text, &end, 0);
  if (errno || !end || *end || value < kMinimumTraceEvents ||
      value > kMaximumTraceEvents)
    return kDefaultTraceEvents;
  return static_cast<uint64_t>(value);
}

std::atomic<uint64_t> next_completion_id(UINT64_C(1));

const char* trace_io_mode_name(uint64_t mode) {
  switch (mode) {
    case 1: return "sync-no-extent";
    case 2: return "async-no-extent";
    default: return "adaptive-extent";
  }
}

}  // namespace

struct SqliteGanttTrace::Event {
  uint64_t timestamp_ns;
  uint64_t group_id;
  uint64_t sm_hart_id;
  uint64_t eid;
  uint64_t ocall_id;
  uint64_t completion_id;
  uint64_t request_id;
  uint64_t run_id;
  uint64_t worker_index;
  uint64_t request_worker_count;
  uint64_t request_workload;
  uint64_t task_id;
  uint64_t sequence;
  uint64_t file_id;
  uint64_t file_offset;
  uint64_t length;
  uint64_t operation;
  uint64_t buffer_id;
  uint64_t queue_depth;
  uint64_t value;
  int64_t result;
  uint32_t type;
  uint64_t admission[9] = {};

  Event()
      : timestamp_ns(0), group_id(0), sm_hart_id(0), eid(0), ocall_id(0),
        completion_id(0), request_id(0), run_id(0), worker_index(UINT64_MAX),
        request_worker_count(0), request_workload(0), task_id(0), sequence(0),
        file_id(0), file_offset(0), length(0), operation(0), buffer_id(0),
        queue_depth(0), value(0), result(0), type(0) {}
};

struct SqliteGanttTrace::Slot {
  Event event;
  std::atomic<uint64_t> generation;

  Slot() : generation(0) {}
};

uint64_t sqlite_gantt_now_ns() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
}

uint64_t sqlite_gantt_next_completion_id() {
  return next_completion_id.fetch_add(1, std::memory_order_relaxed);
}

SqliteGanttTrace::SqliteGanttTrace()
    : capacity_(static_cast<size_t>(trace_capacity_from_env())),
      slots_(new Slot[capacity_]), next_(0),
      dropped_(0), request_events_stored_(0), sampled_request_events_(0),
      active_(false), generation_(0), origin_ns_(0), case_id_(0),
      sample_id_(0), workload_(0), worker_count_(0), io_mode_(0), group_id_(0),
      request_event_budget_(0), request_sample_stride_(1),
      header_written_(false), neighbor_diagnostic_(false) {}

SqliteGanttTrace::~SqliteGanttTrace() {}

bool SqliteGanttTrace::configureOutput(const char* path) {
  active_.store(false, std::memory_order_release);
  neighbor_diagnostic_ = trace_u64_from_env("GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC", 0) == 1;
  output_path_ = path ? path : "";
  header_written_ = false;
  if (output_path_.empty())
    return true;
  std::ofstream output(output_path_.c_str(), std::ios::out | std::ios::trunc);
  return output.good();
}

void SqliteGanttTrace::beginCase(uint64_t case_id, uint64_t sample_id,
                                 uint64_t workload, uint64_t worker_count,
                                 uint64_t io_mode) {
  active_.store(false, std::memory_order_release);
  ++generation_;
  if (!generation_)
    ++generation_;
  next_.store(0, std::memory_order_relaxed);
  dropped_.store(0, std::memory_order_relaxed);
  request_events_stored_.store(0, std::memory_order_relaxed);
  sampled_request_events_.store(0, std::memory_order_relaxed);
  origin_ns_ = 0;
  group_id_ = 0;
  case_id_ = case_id;
  sample_id_ = sample_id;
  workload_ = workload;
  worker_count_ = worker_count;
  io_mode_ = io_mode;
  const uint64_t reserve = std::min<uint64_t>(
      kCriticalTraceReserve, static_cast<uint64_t>(capacity_) / 4);
  request_event_budget_ = static_cast<uint64_t>(capacity_) - reserve;
  request_sample_stride_ = neighbor_diagnostic_ ? 1 : request_sample_stride(
      workload_, request_event_budget_);
}

void SqliteGanttTrace::beginWindow(uint64_t group_id) {
  if (output_path_.empty())
    return;
  if (neighbor_diagnostic_) {
    const uint64_t workload = trace_u64_from_env("GROUP_PMP_SQLITE_NEIGHBOR_WORKLOAD", 0);
    const uint64_t workers = trace_u64_from_env("GROUP_PMP_SQLITE_NEIGHBOR_WORKERS", 0);
    const uint64_t sample = trace_u64_from_env("GROUP_PMP_SQLITE_NEIGHBOR_SAMPLE", 0);
    if ((workload && workload != workload_) || (workers && workers != worker_count_) ||
        (sample && sample != sample_id_)) return;
  }
  group_id_ = group_id;
  origin_ns_ = sqlite_gantt_now_ns();
  active_.store(true, std::memory_order_release);
  recordPoint(SQLITE_GANTT_CASE_BEGIN, group_id, 0, 0, 0, 0, origin_ns_);
  recordPoint(SQLITE_GANTT_PERF_BEGIN, group_id, 0, 0, 0, 0, origin_ns_);
}

void SqliteGanttTrace::endWindow(bool success) {
  if (!active_.load(std::memory_order_acquire))
    return;
  const uint64_t timestamp = sqlite_gantt_now_ns();
  recordPoint(SQLITE_GANTT_PERF_END, group_id_, 0, 0, 0, 0, timestamp);
  recordPoint(success ? SQLITE_GANTT_CASE_END : SQLITE_GANTT_CASE_ABORT,
              group_id_, 0, 0, 0, success ? 0 : -1, timestamp);
  active_.store(false, std::memory_order_release);
}

bool SqliteGanttTrace::enabled() const {
  return active_.load(std::memory_order_acquire);
}

bool SqliteGanttTrace::neighborDiagnostic() const {
  return neighbor_diagnostic_ && enabled();
}

void SqliteGanttTrace::recordAdmission(
    const struct group_pmp_sqlite_vfs_request* head,
    SqliteNeighborAdmissionReason reason, const uint64_t (&state)[9]) {
  if (!neighborDiagnostic()) return;
  Event event;
  event.type = SQLITE_GANTT_NEIGHBOR_ADMISSION;
  event.result = reason;
  if (head) {
    event.run_id = head->run_id;
    event.worker_index = head->worker_index;
    event.request_id = head->request_id;
    event.buffer_id = head->buffer_id;
    event.sequence = head->sequence;
    event.task_id = head->task_id;
    event.request_workload = head->workload;
    event.operation = head->operation;
  }
  std::copy(state, state + 9, event.admission);
  record(event, 0);
}

void SqliteGanttTrace::recordPlanned(SqliteGanttEventType type,
    const struct group_pmp_sqlite_vfs_request& request, uint64_t completion_id,
    uint64_t offset, uint64_t length, uint64_t plan_id, uint64_t io_id,
    uint64_t timestamp_ns) {
  if (!neighborDiagnostic()) return;
  auto resolved = request;
  resolved.file_offset = offset;
  resolved.length = length;
  // Diagnostic events: queue_depth=opaque plan id, value=physical operation
  // token, result=request phase flags (not an I/O return code).
  recordRequest(type, resolved, completion_id, request.reserved[0], plan_id,
                timestamp_ns, io_id);
}

uint64_t SqliteGanttTrace::droppedEvents() const {
  return dropped_.load(std::memory_order_relaxed);
}

uint64_t SqliteGanttTrace::sampledRequestEvents() const {
  return sampled_request_events_.load(std::memory_order_relaxed);
}

uint64_t SqliteGanttTrace::requestSampleStride() const {
  return request_sample_stride_;
}

bool SqliteGanttTrace::retainRequestEvent(
    const struct group_pmp_sqlite_vfs_request& request) {
  const bool data_request =
      request.operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
      request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE;
  if (data_request && request_sample_stride_ > 1) {
    const uint64_t key = request.request_id ^
        (request.worker_index * UINT64_C(0x9e3779b97f4a7c15));
    if (key % request_sample_stride_ != 0) {
      sampled_request_events_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
  }
  const uint64_t stored = request_events_stored_.fetch_add(
      1, std::memory_order_relaxed);
  if (stored >= request_event_budget_) {
    sampled_request_events_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
  return true;
}

void SqliteGanttTrace::record(const Event& source, uint64_t timestamp_ns) {
  if (!active_.load(std::memory_order_acquire))
    return;
  const uint64_t index = next_.fetch_add(1, std::memory_order_relaxed);
  if (index >= capacity_) {
    dropped_.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  Slot& slot = slots_[static_cast<size_t>(index)];
  slot.event = source;
  slot.event.timestamp_ns = timestamp_ns ? timestamp_ns : sqlite_gantt_now_ns();
  slot.generation.store(generation_, std::memory_order_release);
}

void SqliteGanttTrace::recordRequest(
    SqliteGanttEventType type,
    const struct group_pmp_sqlite_vfs_request& request,
    uint64_t completion_id, int64_t result, uint64_t queue_depth,
    uint64_t timestamp_ns, uint64_t value) {
  if (neighbor_diagnostic_ && type != SQLITE_GANTT_QUEUE_ENQUEUE &&
      type != SQLITE_GANTT_NEIGHBOR_PLAN_READY && type != SQLITE_GANTT_NEIGHBOR_SUBMIT &&
      type != SQLITE_GANTT_IO_COMPLETE && type != SQLITE_GANTT_COMPLETION_PUBLISH)
    return;
  if (!active_.load(std::memory_order_acquire) ||
      !retainRequestEvent(request))
    return;
  Event event;
  event.type = static_cast<uint32_t>(type);
  event.group_id = group_id_;
  event.sm_hart_id = UINT64_C(2) + request.worker_index % UINT64_C(3);
  event.completion_id = completion_id;
  event.request_id = request.request_id;
  event.run_id = request.run_id;
  event.worker_index = request.worker_index;
  event.request_worker_count = request.worker_count;
  event.request_workload = request.workload;
  event.task_id = request.task_id;
  event.sequence = request.sequence;
  event.file_id = request.file_id;
  event.file_offset = request.file_offset;
  event.length = request.length;
  event.operation = request.operation;
  event.buffer_id = request.buffer_id;
  event.queue_depth = queue_depth;
  event.result = result;
  event.value = value;
  record(event, timestamp_ns);
}

void SqliteGanttTrace::recordOcall(
    SqliteGanttEventType type, uint64_t group_id, uint64_t sm_hart_id,
    uint64_t eid, uint64_t ocall_id, uint64_t completion_id, int64_t result,
                   uint64_t timestamp_ns) {
  if (neighbor_diagnostic_) return;
  Event event;
  event.type = static_cast<uint32_t>(type);
  event.group_id = group_id ? group_id : group_id_;
  event.sm_hart_id = sm_hart_id;
  event.eid = eid;
  event.ocall_id = ocall_id;
  event.completion_id = completion_id;
  event.result = result;
  record(event, timestamp_ns);
}

void SqliteGanttTrace::recordPoint(SqliteGanttEventType type,
                                   uint64_t group_id, uint64_t sm_hart_id,
                                   uint64_t eid, uint64_t value, int64_t result,
                                   uint64_t timestamp_ns) {
  Event event;
  event.type = static_cast<uint32_t>(type);
  event.group_id = group_id;
  event.sm_hart_id = sm_hart_id;
  event.eid = eid;
  event.value = value;
  event.result = result;
  record(event, timestamp_ns);
}

const char* SqliteGanttTrace::eventName(uint32_t type) const {
  switch (type) {
    case SQLITE_GANTT_CASE_BEGIN: return "case_begin";
    case SQLITE_GANTT_PERF_BEGIN: return "perf_begin";
    case SQLITE_GANTT_OCALL_HANDLER_BEGIN: return "ocall_handler_begin";
    case SQLITE_GANTT_OCALL_HANDLER_END: return "ocall_handler_end";
    case SQLITE_GANTT_ENCLAVE_BLOCKED: return "enclave_blocked";
    case SQLITE_GANTT_REQUEST_SUBMIT: return "request_submit";
    case SQLITE_GANTT_QUEUE_ENQUEUE: return "queue_enqueue";
    case SQLITE_GANTT_QUEUE_SERVICE_BEGIN: return "queue_service_begin";
    case SQLITE_GANTT_IO_SUBMIT: return "io_submit";
    case SQLITE_GANTT_IO_COMPLETE: return "io_complete";
    case SQLITE_GANTT_METADATA_LOOKUP_BEGIN: return "metadata_lookup_begin";
    case SQLITE_GANTT_METADATA_LOOKUP_END: return "metadata_lookup_end";
    case SQLITE_GANTT_STORAGE_IO_BEGIN: return "storage_io_begin";
    case SQLITE_GANTT_STORAGE_IO_END: return "storage_io_end";
    case SQLITE_GANTT_METADATA_COMMIT_BEGIN: return "metadata_commit_begin";
    case SQLITE_GANTT_METADATA_COMMIT_END: return "metadata_commit_end";
    case SQLITE_GANTT_REQUEST_COMPLETE: return "request_complete";
    case SQLITE_GANTT_COMPLETION_READY: return "completion_ready";
    case SQLITE_GANTT_COMPLETION_PUBLISH: return "completion_publish";
    case SQLITE_GANTT_WAKEUP_REQUEST: return "host_resume_ioctl_begin";
    case SQLITE_GANTT_WAKEUP_COMPLETE: return "host_resume_ioctl_end";
    case SQLITE_GANTT_SM_WAKE: return "sm_wake";
    case SQLITE_GANTT_ENCLAVE_RESUMED: return "enclave_resumed";
    case SQLITE_GANTT_MASTER_WAIT_BEGIN: return "master_wait_begin";
    case SQLITE_GANTT_MASTER_WAKEUP: return "master_wakeup";
    case SQLITE_GANTT_WORKERS_READY: return "workers_ready";
    case SQLITE_GANTT_ENCLAVE_EXIT: return "enclave_exit";
    case SQLITE_GANTT_PERF_END: return "perf_end";
    case SQLITE_GANTT_CASE_END: return "case_end";
    case SQLITE_GANTT_CASE_ABORT: return "case_abort";
    case SQLITE_GANTT_NEIGHBOR_PLAN_READY: return "neighbor_plan_ready";
    case SQLITE_GANTT_NEIGHBOR_SUBMIT: return "neighbor_submit";
    case SQLITE_GANTT_NEIGHBOR_SUBMIT_BATCH: return "neighbor_submit_batch";
    case SQLITE_GANTT_NEIGHBOR_ADMISSION: return "neighbor_admission";
    default: return "unknown";
  }
}

const char* SqliteGanttTrace::operationName(uint64_t operation) const {
  switch (operation) {
    case GROUP_PMP_SQLITE_VFS_OP_RESET: return "reset";
    case GROUP_PMP_SQLITE_VFS_OP_READ: return "read";
    case GROUP_PMP_SQLITE_VFS_OP_WRITE: return "write";
    case GROUP_PMP_SQLITE_VFS_OP_TRUNCATE: return "truncate";
    case GROUP_PMP_SQLITE_VFS_OP_DELETE: return "delete";
    case GROUP_PMP_SQLITE_VFS_OP_SYNC: return "sync";
    default: return "none";
  }
}

bool SqliteGanttTrace::flushCase() {
  if (output_path_.empty())
    return true;
  active_.store(false, std::memory_order_release);
  std::atomic_thread_fence(std::memory_order_acquire);
  std::ofstream output(output_path_.c_str(), std::ios::out | std::ios::app);
  if (!output.good())
    return false;
  if (!header_written_) {
    output << "case_id,sample_id,case_io_mode,case_workload,case_worker_count,"
              "request_sample_stride,request_events_omitted,event_seq,"
              "timestamp_ns,relative_ns,event,group_id,sm_hart_id,lane_id,eid,"
              "ocall_id,completion_id,request_id,run_id,worker_index,"
              "request_worker_count,request_workload,task_id,sequence,file_id,"
              "file_offset,length,operation,buffer_id,queue_depth,value,result";
    if (neighbor_diagnostic_)
      output << ",diagnostic_version,events_dropped,queued_requests,captured_arrivals,"
                "pending_operations,inflight_operations,depth_target,inflight_bytes,"
                "byte_limit,active_plans,admitted_plans";
    output << '\n';
    header_written_ = true;
  }
  const uint64_t count = std::min<uint64_t>(
      next_.load(std::memory_order_acquire), capacity_);
  output << std::setprecision(17);
  for (uint64_t index = 0; index < count; ++index) {
    const Slot& slot = slots_[static_cast<size_t>(index)];
    if (slot.generation.load(std::memory_order_acquire) != generation_)
      continue;
    const Event& event = slot.event;
    const uint64_t relative = event.timestamp_ns >= origin_ns_ ?
        event.timestamp_ns - origin_ns_ : 0;
    const uint64_t lane = event.sm_hart_id >= 2 && event.sm_hart_id <= 4 ?
        event.sm_hart_id - 2 : UINT64_MAX;
    output << case_id_ << ',' << sample_id_ << ','
           << trace_io_mode_name(io_mode_) << ',' << workload_ << ','
           << worker_count_ << ',' << request_sample_stride_ << ','
           << sampled_request_events_.load(std::memory_order_relaxed) << ','
           << index << ',' << event.timestamp_ns << ','
           << relative << ',' << eventName(event.type) << ',' << event.group_id
           << ',' << event.sm_hart_id << ',';
    if (lane == UINT64_MAX)
      output << -1;
    else
      output << lane;
    output << ',' << event.eid << ',' << event.ocall_id << ','
           << event.completion_id << ',' << event.request_id << ','
           << event.run_id << ',';
    if (event.worker_index == UINT64_MAX)
      output << -1;
    else
      output << event.worker_index;
    output << ',' << event.request_worker_count << ',' << event.request_workload
           << ',' << event.task_id << ',' << event.sequence << ','
           << event.file_id << ',' << event.file_offset << ',' << event.length
           << ',' << operationName(event.operation) << ',' << event.buffer_id
           << ',' << event.queue_depth << ',' << event.value << ','
           << event.result;
    if (neighbor_diagnostic_) {
      output << ",2," << dropped_.load(std::memory_order_relaxed);
      for (uint64_t value : event.admission) output << ',' << value;
    }
    output << '\n';
  }
  return output.good();
}

SqliteGanttTrace& sqlite_gantt_trace() {
  static SqliteGanttTrace trace;
  return trace;
}
