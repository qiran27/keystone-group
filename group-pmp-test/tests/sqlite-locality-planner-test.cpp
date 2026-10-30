#include <bits/stdc++.h>
#define private public
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsubobject-linkage"
#include "../host/sqlite-extent-io.cpp"
#pragma GCC diagnostic pop
#undef private
#include "../sqlite-bench-master/sqlite-locality-address.h"

int main() {
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  setenv("GROUP_PMP_SQLITE_CACHE_MODE", "hot", 1);
  unsetenv("GROUP_PMP_SQLITE_CLUSTER_MODE");
  void* allocation = nullptr;
  assert(!posix_memalign(&allocation, 4096, GROUP_PMP_SQLITE_VFS_UTM_BYTES));
  std::unique_ptr<uint8_t, decltype(&free)> utm(static_cast<uint8_t*>(allocation), &free);
  char filename[] = "/tmp/sqlite-locality-plan-XXXXXX";
  const int fd = mkstemp(filename); assert(fd >= 0); unlink(filename);
  std::puts("scope=local-production-planner,no-storage-or-enclave,one-arrived-ring-per-plan,capacity=256");
  std::puts("size_mb,workers,logical_ops,read_host_ops,write_host_ops,read_reduction_pct,write_reduction_pct,read_plan_ns_per_request,write_plan_ns_per_request");
  for (uint64_t mb : {60, 100, 200, 300, 400, 500, 512}) {
    for (uint64_t workers = 1; workers <= 15; ++workers) {
      uint64_t operations[2] = {}, logical[2] = {}, elapsed[2] = {};
      for (unsigned read = 0; read < 2; ++read) {
        SqliteExtentIoService::Impl service(false);
        service.files_[1] = dup(fd); assert(service.files_[1] >= 0);
        const uint64_t total_records = mb * 1000000 / 240;
        for (uint64_t worker = 0, file_base = 0; worker < workers; ++worker) {
          const uint64_t bytes = (total_records / workers + (worker < total_records % workers)) * 240;
          const uint64_t pages = (bytes + 4095) / 4096;
          std::vector<uint8_t> seen(pages, 0);
          auto completion = std::make_shared<SqliteAsyncCompletion>();
          for (uint64_t start = 0; start < pages; start += 256) {
            const size_t n = std::min<uint64_t>(256, pages - start);
            std::vector<Task> tasks(n);
            std::vector<Task*> input;
            for (size_t i = 0; i < n; ++i) {
              const uint64_t page = sqlite_locality_page(start + i, bytes, worker);
              assert(page < pages && !seen[page]); seen[page] = 1;
              Task& t = tasks[i];
              t.utm = utm.get(); t.utm_size = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
              t.completion = completion; t.case_epoch = 1;
              t.request.workload = read ? GROUP_PMP_SQLITE_READRANDOM : GROUP_PMP_SQLITE_FILLRANDOM;
              t.request.operation = read ? GROUP_PMP_SQLITE_VFS_OP_READ : GROUP_PMP_SQLITE_VFS_OP_WRITE;
              t.request.worker_count = workers; t.request.worker_index = worker;
              t.request.run_id = worker + 1; t.request.sequence = start + i + 1;
              t.request.file_id = t.stored_file_id = 1;
              t.request.file_offset = t.storage_offset = file_base + page * 4096;
              t.request.length = t.storage_length = std::min<uint64_t>(4096, bytes - (start + i) * 4096);
              t.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + i * 4096;
              t.request.reserved[0] = GROUP_PMP_SQLITE_STORE_MEASURED;
              input.push_back(&t);
            }
            PipelineBatch plan;
            const uint64_t before = now_ns();
            assert(service.execute_io(input, true, &plan));
            elapsed[read] += now_ns() - before;
            operations[read] += plan.operations.size(); logical[read] += n;
            uint64_t covered = 0;
            for (const auto& group : plan.groups) {
              assert(!group.spans_gap && !group.overlapping && !group.read_buffer);
              uint64_t next = group.offset;
              for (const Task* t : group.tasks) {
                assert(!t->result && t->io_offset == next);
                next += t->io_length; covered += t->io_length;
              }
              assert(next == group.end);
            }
            uint64_t expected = 0;
            for (const Task* t : input) expected += t->request.length;
            assert(covered == expected);
          }
          assert(std::all_of(seen.begin(), seen.end(), [](uint8_t v) { return v == 1; }));
          file_base += ((bytes + 4095) / 4096) * 4096;
        }
      }
      assert(logical[0] == logical[1]);
      std::printf("%llu,%llu,%llu,%llu,%llu,%.3f,%.3f,%llu,%llu\n",
          (unsigned long long)mb, (unsigned long long)workers, (unsigned long long)logical[0],
          (unsigned long long)operations[1], (unsigned long long)operations[0],
          100.0 * (logical[1] - operations[1]) / logical[1],
          100.0 * (logical[0] - operations[0]) / logical[0],
          (unsigned long long)(elapsed[1] / logical[1]), (unsigned long long)(elapsed[0] / logical[0]));
    }
  }
  close(fd);
}
