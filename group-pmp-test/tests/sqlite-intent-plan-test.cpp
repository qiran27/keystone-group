#include <bits/stdc++.h>
#include <dirent.h>
#define private public
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsubobject-linkage"
#include "../host/sqlite-extent-io.cpp"
#pragma GCC diagnostic pop
#undef private

static void reject_future_intents() {
  SqliteExtentIoService::Impl impl(false);
  std::vector<uint8_t> utm(GROUP_PMP_SQLITE_VFS_UTM_BYTES, 0xa5);
  group_pmp_sqlite_intent_plan p = {};
  p.magic = GROUP_PMP_SQLITE_INTENT_MAGIC;
  p.version = GROUP_PMP_SQLITE_INTENT_VERSION;
  p.request_id = p.run_id = p.worker_count = 1;
  p.workload = GROUP_PMP_SQLITE_READRANDOM;
  p.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
  p.count = 3;
  p.flags = GROUP_PMP_SQLITE_STORE_MEASURED;
  p.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
  p.file_span = 12288;
  for (const char* mode : {"adaptive-extent", "async-no-extent", "sync-no-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    assert(!impl.planIntents(p, utm.data(), utm.size()));
    assert(std::all_of(utm.begin(), utm.end(), [](uint8_t x) { return x == 0xa5; }));
  }
  const auto s = impl.snapshot();
  assert(!s.physical_request_count && !s.logical_request_count);
  assert(!s.pipeline[SQLITE_PIPELINE_INTENT_WINDOWS]);
  assert(s.pipeline[SQLITE_PIPELINE_INTENT_REJECTS] == 3);
  puts("online boundary: all modes reject future address lists without touching UTM PASS");
}

// Both arms see only these submitted buffers, with no future address trace.
static void real_online_plans() {
  char dir[] = "/tmp/sqlite-online-cluster-XXXXXX";
  assert(mkdtemp(dir));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", dir, 1);
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  for (uint64_t workload : {GROUP_PMP_SQLITE_FILLSEQ, GROUP_PMP_SQLITE_FILLSEQBATCH,
      GROUP_PMP_SQLITE_FILLRANDOM, GROUP_PMP_SQLITE_FILLRANDOMBATCH, GROUP_PMP_SQLITE_OVERWRITE,
      GROUP_PMP_SQLITE_READSEQ, GROUP_PMP_SQLITE_READRANDOM, GROUP_PMP_SQLITE_READRAND100K})
  for (bool sparse : {false, true}) {
    const bool read = workload == GROUP_PMP_SQLITE_READSEQ ||
        workload == GROUP_PMP_SQLITE_READRANDOM || workload == GROUP_PMP_SQLITE_READRAND100K;
    uint64_t counts[2] = {};
    for (unsigned arm = 0; arm < 2; ++arm) {
      setenv("GROUP_PMP_SQLITE_IO_MODE", arm ? "adaptive-extent" : "async-no-extent", 1);
      SqliteExtentIoService::Impl impl(false);
      impl.online_execution_ = true;
      const int fd = impl.file_for(1);
      assert(fd >= 0);
      std::vector<uint8_t> expected(32768);
      for (size_t i = 0; i < expected.size(); ++i) expected[i] = (i * 17 + i / 4096) & 255;
      assert(pwrite(fd, expected.data(), expected.size(), 0) == (ssize_t)expected.size());
      OnlineClusterFeedback feedback;
      PipelineBatch plan;
      plan.online_feedback = &feedback;
      plan.online_merge = feedback.merging;
      plan.online_epoch = feedback.epoch;
      std::vector<uint8_t> utm(GROUP_PMP_SQLITE_VFS_UTM_BYTES);
      auto completion = std::make_shared<SqliteAsyncCompletion>(1);
      for (uint64_t i : {UINT64_C(1), UINT64_C(0)}) {
        Task t;
        t.utm = utm.data(); t.utm_size = utm.size(); t.completion = completion;
        t.request.file_id = t.stored_file_id = 1;
        t.request.workload = workload;
        t.request.run_id = t.request.worker_count = 1;
        t.request.operation = read ? GROUP_PMP_SQLITE_VFS_OP_READ : GROUP_PMP_SQLITE_VFS_OP_WRITE;
        t.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + i * 4096;
        t.request.file_offset = t.storage_offset = t.io_offset = i * (sparse ? 16384 : 4096);
        t.request.length = t.storage_length = t.io_length = 4096;
        t.request.sequence = t.request.task_id = i + 1;
        if (!read) memcpy(t.data(), expected.data() + t.io_offset, 4096);
        plan.owned.push_back(t);
      }
      for (auto& t : plan.owned) plan.tasks.push_back(&t);
      assert(impl.execute_io(plan.tasks, false, &plan));
      counts[arm] = plan.operations.size();
      assert(counts[arm] == (arm && !sparse ? 1 : 2));
      if (arm && sparse && workload != GROUP_PMP_SQLITE_READRAND100K)
        assert(impl.snapshot().sort_ns == 0);
      std::vector<int> results;
      uint64_t submit_ns = 0, wait_ns = 0;
      assert(impl.ring_.submit(plan.operations, &results, &submit_ns, &wait_ns));
      for (size_t i = 0; i < results.size(); ++i) assert(results[i] == (int)plan.operations[i].expected);
      for (const auto& t : plan.owned) {
        if (read) assert(!memcmp(t.data(), expected.data() + t.io_offset, 4096));
        assert(t.online_merged == (arm && !sparse));
      }
      std::vector<uint8_t> actual(expected.size());
      assert(pread(fd, actual.data(), actual.size(), 0) == (ssize_t)actual.size());
      assert(actual == expected);
      assert(impl.pipeline_depth_.target == 64);
      assert(impl.snapshot().pipeline[SQLITE_PIPELINE_INTENT_WINDOWS] == 0);
    }
    assert(sparse ? counts[0] == counts[1] : counts[1] < counts[0]);
  }
  DIR* d = opendir(dir); assert(d);
  while (dirent* e = readdir(d)) if (e->d_name[0] != '.')
    assert(!unlink((std::string(dir) + "/" + e->d_name).c_str()));
  closedir(d); assert(!rmdir(dir));
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("all eight workloads: Async vs Adaptive, first arrived read/write requests, adjacent 2->1, sparse 2->2, byte equality PASS");
}

static void measured_pipeline() {
  char directory[] = "/tmp/sqlite-online-observe-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  {
    SqliteExtentIoService::Impl impl(false);
    std::vector<uint8_t> utm(GROUP_PMP_SQLITE_VFS_UTM_BYTES);
    const int fd = impl.file_for(1);
    assert(fd >= 0);
    for (unsigned buffer = 0; buffer < 45; ++buffer) {
      auto completion = std::make_shared<SqliteAsyncCompletion>(2);
      std::vector<Task> batch;
      for (unsigned i = 0; i < 2; ++i) {
        Task t;
        t.utm = utm.data(); t.utm_size = utm.size(); t.completion = completion;
        t.enqueue_ns = now_ns();
        t.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
        t.request.workload = GROUP_PMP_SQLITE_FILLRANDOM;
        t.request.run_id = t.request.file_id = t.request.worker_count = 1;
        t.request.sequence = t.request.task_id = t.request.request_id = buffer * 2 + i + 1;
        t.request.file_offset = (buffer * 2 + i) * 4096;
        t.request.reserved[0] = GROUP_PMP_SQLITE_STORE_MEASURED | GROUP_PMP_SQLITE_STORE_RING;
        t.request.reserved[1] = t.request.file_offset;
        t.request.descriptor_id = i;
        t.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + i * 4096;
        t.request.length = 4096;
        memset(t.data(), buffer + 1, 4096);
        batch.push_back(t);
      }
      impl.pipeline_begin(std::move(batch));
      auto& plan = *impl.pipeline_batches_.back();
      assert(plan.online_feedback && plan.online_epoch);
      assert(plan.operations.size() == 1);
      assert(impl.pipeline_refill());
      while (!completion->isComplete()) {
        if (!impl.pipeline_reap()) {
          struct pollfd p{impl.ring_.descriptor(), POLLIN, 0};
          assert(poll(&p, 1, 5000) > 0);
        }
        impl.pipeline_publish();
      }
      impl.pipeline_retire();
      assert(impl.pipeline_batches_.empty());
      std::array<uint8_t, 8192> disk;
      assert(pread(fd, disk.data(), disk.size(), buffer * 8192) == (ssize_t)disk.size());
      for (const auto byte : disk) assert(byte == buffer + 1);
    }
    auto s = impl.snapshot();
    assert(s.logical_request_count == 90 && s.physical_request_count == 45);
    assert(s.pipeline[SQLITE_PIPELINE_ONLINE_BUFFERS] == 45);
    assert(s.pipeline[SQLITE_PIPELINE_ONLINE_WINDOWS] >= 4);
    assert(s.pipeline[SQLITE_PIPELINE_ONLINE_PROBES] == 0);
    assert(s.pipeline[SQLITE_PIPELINE_ONLINE_MERGED_BUFFERS] == 45);
    assert(s.pipeline[SQLITE_PIPELINE_ONLINE_SERVICE_NS_PER_MB] > 0);
    assert(s.pipeline[SQLITE_PIPELINE_ONLINE_PUBLICATION_P95_NS] > 0);
    assert(s.pipeline[SQLITE_PIPELINE_ONLINE_WINDOW_TARGET] == 16);
    assert(s.pipeline[SQLITE_PIPELINE_ONLINE_WINDOW_GROWS] == 1);
    assert(s.pipeline[SQLITE_PIPELINE_ONLINE_EVALUATED_BUFFERS] >= 32);
    assert(s.pipeline[SQLITE_PIPELINE_ONLINE_EVALUATED_BUFFERS] <= 45);
    assert(impl.pipeline_depth_.target == 64 && !impl.pipeline_depth_.probing);
    assert(impl.cipher_cache_.empty() && !s.cache_fill_bytes);
    Task read;
    read.utm = utm.data(); read.utm_size = utm.size();
    read.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    read.request.workload = GROUP_PMP_SQLITE_READRANDOM;
    read.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
    read.storage_length = 4096; read.stored_file_id = 1;
    impl.update_read_cache(read);
    impl.apply_read_cache(read);
    assert(impl.cipher_cache_.empty() && !impl.snapshot().cache_fill_bytes);
    assert(impl.resetPerf() && impl.online_feedback_.empty());
    assert(!impl.snapshot().pipeline[SQLITE_PIPELINE_ONLINE_BUFFERS]);
    assert(!impl.snapshot().pipeline[SQLITE_PIPELINE_ONLINE_WINDOW_TARGET]);
    assert(!impl.snapshot().pipeline[SQLITE_PIPELINE_ONLINE_WINDOW_GROWS]);
  }
  DIR* dir = opendir(directory); assert(dir);
  while (dirent* e = readdir(dir)) if (e->d_name[0] != '.')
    assert(!unlink((std::string(directory) + "/" + e->d_name).c_str()));
  closedir(dir); assert(!rmdir(directory));
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("production observer: measured buffer windows, actual io_uring, no learning gate, fixed depth/cache and reset PASS");
}

static void selection_cost_scope() {
  SqliteExtentIoService::Impl impl(false);
  auto& f = impl.online_feedback_[1];
  PipelineBatch p;
  p.online_feedback = &f;
  p.online_epoch = f.epoch;
  p.online_merge = true;
  p.online_started = 200;
  Task task;
  task.pipeline_owner = &p;
  task.enqueue_ns = 100;
  task.dequeue_ns = 500;
  task.publish_ns = 1200;
  task.storage_length = 1000000;
  task.online_candidate = true;
  std::vector<Task*> tasks{&task};
  for (unsigned i = 0; i < 8; ++i) impl.pipeline_observe_online_buffer(tasks);
  assert(f.last_cost == 1000 && f.last_p95 == 1100);
  assert(f.probes == 0 && f.merging);
  p.online_epoch = f.epoch;
  p.online_merge = true;
  task.enqueue_ns = 250; // A request cannot arrive after its own service start.
  impl.pipeline_observe_online_buffer(tasks);
  assert(f.mixed == 1 && !f.samples);
  puts("online timing: pre-dequeue selection/planning included, queue excluded from cost but included in P95 PASS");
}

int main() {
  setenv("GROUP_PMP_SQLITE_MERGE_READ_SAVED_NS", "1000000000", 1);
  setenv("GROUP_PMP_SQLITE_MERGE_WRITE_SAVED_NS", "1000000000", 1);
  selection_cost_scope();
  reject_future_intents();
  real_online_plans();
  measured_pipeline();
}
