#ifndef GROUP_PMP_SQLITE_IO_RANGE_TRACE_HPP
#define GROUP_PMP_SQLITE_IO_RANGE_TRACE_HPP

#include <cstddef>
#include <cstdint>

struct group_pmp_sqlite_vfs_request;

static const char KEYSTONE_SQLITE_IO_RANGE_TRACE_MARKER[] =
    "keystone-sqlite-io-range-trace-v2";

struct SqliteIoRangeSummary {
  uint64_t request_count;
  uint64_t member_request_count;
  uint64_t total_range_bytes;
  uint64_t useful_bytes;
  uint64_t gap_bytes;
  uint64_t range_start;
  uint64_t range_end;
  uint64_t min_request_bytes;
  uint64_t max_request_bytes;
  uint64_t read_request_count;
  uint64_t write_request_count;
  uint64_t failed_request_count;
};

enum SqliteIoRangeBackend {
  SQLITE_IO_RANGE_BACKEND_SQLITE_BLOB = 1,
  SQLITE_IO_RANGE_BACKEND_IO_URING = 2,
  SQLITE_IO_RANGE_BACKEND_POSIX_VECTOR = 3,
};

class SqliteIoRangeTrace {
 public:
  SqliteIoRangeTrace();
  ~SqliteIoRangeTrace();

  bool configureOutput(const char* path);
  void beginCase(uint64_t case_id, uint64_t sample_id, uint64_t workload,
                 uint64_t worker_count, uint64_t no_extent_mode);
  void beginWindow();
  void endWindow();
  void recordNoExtent(const group_pmp_sqlite_vfs_request& request,
                      int64_t result);
  void recordExtent(uint64_t file_id, uint64_t offset, uint64_t length,
                    uint64_t useful_bytes, bool read,
                    uint64_t member_request_count, uint64_t worker_mask,
                    SqliteIoRangeBackend backend, int64_t status);
  bool flushCase();
  bool lastSummary(SqliteIoRangeSummary* summary) const;
  uint64_t droppedRecords() const;
  bool enabled() const;

 private:
  struct Impl;
  Impl* impl_;

  SqliteIoRangeTrace(const SqliteIoRangeTrace&);
  SqliteIoRangeTrace& operator=(const SqliteIoRangeTrace&);
};

SqliteIoRangeTrace& sqlite_io_range_trace();

#endif
