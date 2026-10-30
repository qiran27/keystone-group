#ifndef GROUP_PMP_SQLITE_GANTT_TRACE_HPP
#define GROUP_PMP_SQLITE_GANTT_TRACE_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "../eapp/group-pmp-sqlite-vfs-shared.h"

#define GROUP_PMP_SQLITE_GANTT_TRACE_MARKER \
  "keystone-sqlite-gantt-trace-v4"

enum SqliteGanttEventType {
  SQLITE_GANTT_CASE_BEGIN = 1,
  SQLITE_GANTT_PERF_BEGIN,
  SQLITE_GANTT_OCALL_HANDLER_BEGIN,
  SQLITE_GANTT_OCALL_HANDLER_END,
  SQLITE_GANTT_ENCLAVE_BLOCKED,
  SQLITE_GANTT_REQUEST_SUBMIT,
  SQLITE_GANTT_QUEUE_ENQUEUE,
  SQLITE_GANTT_QUEUE_SERVICE_BEGIN,
  SQLITE_GANTT_IO_SUBMIT,
  SQLITE_GANTT_IO_COMPLETE,
  SQLITE_GANTT_METADATA_LOOKUP_BEGIN,
  SQLITE_GANTT_METADATA_LOOKUP_END,
  SQLITE_GANTT_STORAGE_IO_BEGIN,
  SQLITE_GANTT_STORAGE_IO_END,
  SQLITE_GANTT_METADATA_COMMIT_BEGIN,
  SQLITE_GANTT_METADATA_COMMIT_END,
  SQLITE_GANTT_REQUEST_COMPLETE,
  SQLITE_GANTT_COMPLETION_READY,
  SQLITE_GANTT_COMPLETION_PUBLISH,
  SQLITE_GANTT_WAKEUP_REQUEST,
  SQLITE_GANTT_WAKEUP_COMPLETE,
  SQLITE_GANTT_SM_WAKE,
  SQLITE_GANTT_ENCLAVE_RESUMED,
  SQLITE_GANTT_MASTER_WAIT_BEGIN,
  SQLITE_GANTT_MASTER_WAKEUP,
  SQLITE_GANTT_WORKERS_READY,
  SQLITE_GANTT_ENCLAVE_EXIT,
  SQLITE_GANTT_PERF_END,
  SQLITE_GANTT_CASE_END,
  SQLITE_GANTT_CASE_ABORT,
  SQLITE_GANTT_NEIGHBOR_PLAN_READY,
  SQLITE_GANTT_NEIGHBOR_SUBMIT,
  SQLITE_GANTT_NEIGHBOR_SUBMIT_BATCH,
  SQLITE_GANTT_NEIGHBOR_ADMISSION
};

enum SqliteNeighborAdmissionReason {
  SQLITE_NEIGHBOR_ACCEPT = 0,
  SQLITE_NEIGHBOR_NO_ARRIVALS,
  SQLITE_NEIGHBOR_TWO_PLAN_LIMIT,
  SQLITE_NEIGHBOR_NOT_READSEQ,
  SQLITE_NEIGHBOR_SQE_CREDIT,
  SQLITE_NEIGHBOR_BYTE_CREDIT,
  SQLITE_NEIGHBOR_SCOPE,
  SQLITE_NEIGHBOR_NO_PENDING_PLAN,
  SQLITE_NEIGHBOR_INVALID_LENGTH,
  SQLITE_NEIGHBOR_ACTIVE_PLAN_LIMIT,
  SQLITE_NEIGHBOR_BARRIER,
  SQLITE_NEIGHBOR_PENDING_FILLS_CREDIT,
  SQLITE_NEIGHBOR_WRITE_CONFLICT,
  SQLITE_NEIGHBOR_EMPTY_BATCH
};

uint64_t sqlite_gantt_now_ns();
uint64_t sqlite_gantt_next_completion_id();

class SqliteGanttTrace {
 public:
  SqliteGanttTrace();
  ~SqliteGanttTrace();

  bool configureOutput(const char* path);
  void beginCase(uint64_t case_id, uint64_t sample_id,
                 uint64_t workload, uint64_t worker_count,
                 uint64_t io_mode);
  void beginWindow(uint64_t group_id);
  void endWindow(bool success);
  bool flushCase();

  bool enabled() const;
  bool neighborDiagnostic() const;
  // Snapshot columns exist only in the explicitly enabled diagnostic CSV.
  void recordAdmission(const struct group_pmp_sqlite_vfs_request* head,
                       SqliteNeighborAdmissionReason reason,
                       const uint64_t (&state)[9]);
  void recordPlanned(SqliteGanttEventType type,
                     const struct group_pmp_sqlite_vfs_request& request,
                     uint64_t completion_id, uint64_t offset, uint64_t length,
                     uint64_t plan_id, uint64_t io_id, uint64_t timestamp_ns);
  uint64_t droppedEvents() const;
  uint64_t sampledRequestEvents() const;
  uint64_t requestSampleStride() const;

  void recordRequest(SqliteGanttEventType type,
                     const struct group_pmp_sqlite_vfs_request& request,
                     uint64_t completion_id, int64_t result = 0,
                     uint64_t queue_depth = 0, uint64_t timestamp_ns = 0,
                     uint64_t value = 0);
  void recordOcall(SqliteGanttEventType type, uint64_t group_id,
                   uint64_t sm_hart_id, uint64_t eid, uint64_t ocall_id,
                   uint64_t completion_id, int64_t result = 0,
                   uint64_t timestamp_ns = 0);
  void recordPoint(SqliteGanttEventType type, uint64_t group_id = 0,
                   uint64_t sm_hart_id = 0, uint64_t eid = 0,
                   uint64_t value = 0, int64_t result = 0,
                   uint64_t timestamp_ns = 0);

 private:
  struct Event;
  struct Slot;

  void record(const Event& event, uint64_t timestamp_ns);
  bool retainRequestEvent(
      const struct group_pmp_sqlite_vfs_request& request);
  const char* eventName(uint32_t type) const;
  const char* operationName(uint64_t operation) const;

  size_t capacity_;
  std::unique_ptr<Slot[]> slots_;
  std::atomic<uint64_t> next_;
  std::atomic<uint64_t> dropped_;
  std::atomic<uint64_t> request_events_stored_;
  std::atomic<uint64_t> sampled_request_events_;
  std::atomic<bool> active_;
  uint64_t generation_;
  uint64_t origin_ns_;
  uint64_t case_id_;
  uint64_t sample_id_;
  uint64_t workload_;
  uint64_t worker_count_;
  uint64_t io_mode_;
  uint64_t group_id_;
  uint64_t request_event_budget_;
  uint64_t request_sample_stride_;
  std::string output_path_;
  bool header_written_;
  bool neighbor_diagnostic_;
};

SqliteGanttTrace& sqlite_gantt_trace();

#endif
