#include <bits/stdc++.h>
#include <dirent.h>
#define private public
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsubobject-linkage"
#include "../host/sqlite-extent-io.cpp"
#pragma GCC diagnostic pop
#undef private

static void depth_feedback() {
  const uint64_t ms = 1000000;
  for (bool adaptive : {false, true}) {
    PipelineDepthFeedback f;
    uint64_t now = 0;
    auto window = [&](uint64_t tail) {
      int action = 0;
      for (unsigned i = 0; i < 16; ++i) {
        const uint64_t submitted = now + 1;
        f.submitted(f.target, true);
        f.completed(now += 2 * ms, submitted, 4096, tail, f.epoch, 1000);
      }
      action = f.evaluate(now, adaptive);
      return action;
    };
    if (adaptive) {
      assert(window(2 * ms) == 1 && f.target == 80 && f.probing);
      assert(window(2 * ms) == -1 && f.target == 64 && !f.probing);
      assert(f.cooldown == 4 && f.failure_streak == 1);
      for (unsigned i = 0; i < 4; ++i)
        assert(window(20 * ms) == 0 && f.target == 64); // Cooldown gates high tails too.
      assert(window(20 * ms) == 0 && f.target == 64);
      assert(window(20 * ms) == -1 && f.target == 48 && f.shrinking);
      assert(window(20 * ms) == 1 && f.target == 64 && f.rejected == 2);
      assert(f.cooldown == 4 && f.failure_streak == 2);
      // A second shrink trial must improve tail without losing throughput.
      for (unsigned i = 0; i < 5; ++i) assert(window(20 * ms) == 0);
      assert(window(20 * ms) == -1 && f.target == 48);
      assert(window(10 * ms) == 0 && f.target == 48 && f.stable == 48);
      assert(f.failure_streak == 0 && f.cooldown == 4);
    } else {
      for (unsigned i = 0; i < 30; ++i) assert(window(100 * ms) == 0);
      assert(f.target == 64 && f.byte_limit == 16000000 && !f.probing);
    }
  }
  PipelineDepthFeedback growth;
  uint64_t now = 0, amount = 4096;
  auto sample_window = [&](bool pressure) {
    for (unsigned i = 0; i < 16; ++i) {
      const uint64_t submitted = now + 1;
      growth.submitted(growth.target, pressure);
      growth.completed(now += 2 * ms, submitted, amount, 2 * ms, growth.epoch, 1000);
    }
    growth.evaluate(now, true);
  };
  sample_window(false);
  assert(growth.target == 64); // Backlog without measured saturation cannot grow.
  sample_window(true);
  assert(growth.target == 80 && growth.probing);
  amount *= 2;
  sample_window(true);
  assert(growth.target == 80 && growth.stable == 80 && !growth.probing);
  for (unsigned i = 0; i < 40; ++i) {
    if (growth.probing) amount *= 2;
    sample_window(true);
    assert(growth.target >= 16 && growth.target <= 128 && growth.byte_limit <= 32000000);
  }
  assert(growth.target == 128);
  PipelineDepthFeedback costly;
  now = 0;
  for (unsigned w = 0; w < 2; ++w) {
    for (unsigned i = 0; i < 16; ++i) {
      const uint64_t submitted = now + 1;
      costly.submitted(costly.target, true);
      costly.completed(now += 2 * ms, submitted, w ? 8192 : 4096,
                       2 * ms, costly.epoch, w ? 100000 : 1000);
    }
    costly.evaluate(now, true);
  }
  assert(costly.target == 64 && costly.rejected == 1); // Throughput alone cannot justify submit CPU inflation.

  PipelineDepthFeedback clean;
  clean.target = 80; clean.stable = 64; clean.probing = true;
  clean.epoch = 2;
  clean.submitted(80, true);
  clean.completed(40 * ms, ms, 4096, ms, 2, 1000);
  clean.settle(41 * ms); // Old-depth buffer publication cannot train a new trial.
  clean.completed(42 * ms, ms, 4096, ms, 1, 1000);
  clean.completed(42 * ms, 40 * ms, 4096, ms, 2, 1000);
  assert(clean.samples == 0 && clean.stale_samples == 1 && clean.transition_samples == 1);
  now = 43 * ms;
  for (unsigned i = 0; i < 16; ++i) {
    const uint64_t submitted = now + 1;
    clean.submitted(4, false); // No producer supply can exercise the trial depth.
    clean.completed(now += 2 * ms, submitted, 4096, ms, 2, 1000);
  }
  assert(clean.evaluate(now, true) == -1 && clean.target == 64);
  assert(clean.unexposed == 1 && !clean.rejected && !clean.probing);

  PipelineDepthFeedback short_run;
  short_run.submitted(8, false);
  for (unsigned i = 0; i < 8; ++i)
    short_run.completed(30 * ms, ms, 2000000, ms, short_run.epoch, 1000);
  assert(!short_run.evaluate(30 * ms, true) && !short_run.windows && !short_run.probes);
  assert(short_run.samples == 8); // Honest insufficient-sample gauge, no forced learning.

  PipelineDepthFeedback backoff;
  now = 0;
  auto backoff_window = [&](uint64_t amount) {
    for (unsigned i = 0; i < 16; ++i) {
      const uint64_t submitted = now + 1;
      backoff.submitted(backoff.target, true);
      backoff.completed(now += 2 * ms, submitted, amount, 2 * ms, backoff.epoch, 1000);
    }
    return backoff.evaluate(now, true);
  };
  uint64_t skipped = 0;
  for (unsigned failure = 1; failure <= 5; ++failure) {
    assert(backoff_window(4096) == 1 && backoff.target == 80);
    assert(backoff_window(4096) == -1 && backoff.target == 64);
    const unsigned expected = 4;
    assert(backoff.cooldown == expected && backoff.rejected == failure);
    const uint64_t probes = backoff.probes, samples = backoff.completed_samples;
    for (unsigned i = 0; i < expected; ++i) {
      assert(!backoff_window(4096) && backoff.target == 64 && !backoff.probing);
      assert(backoff.probes == probes);
    }
    skipped += expected;
    assert(backoff.backoff_skips == skipped);
    assert(backoff.completed_samples > samples); // Serving/learning continues during backoff.
  }
  assert(backoff_window(4096) == 1);
  assert(!backoff_window(8192) && backoff.accepts == 1 && backoff.failure_streak == 0);
  assert(backoff.cooldown == 4 && backoff.stable == 80);
  puts("pipeline depth: buffer samples, clean epochs, exposed trials, fixed Async and cooldown PASS");
  puts("document depth policy: fixed four-window cooldown, continued completions, no forced learning PASS");
}

static void write_service_depth_feedback() {
  const uint64_t ms = 1000000;
  uint64_t now = 100 * ms;
  auto window = [&](PipelineDepthFeedback& f, uint64_t io, uint64_t residual,
                    uint64_t publication, uint64_t amount = 4096, bool adaptive = true) {
    now += io; // Old epoch work has drained; all samples are clean.
    for (unsigned i = 0; i < 16; ++i) {
      now += 2 * ms;
      f.submitted(f.target, true);
      f.completed(now, now - io, amount, publication, f.epoch, 1000,
                  true, io, residual);
    }
    return f.evaluate(now, adaptive);
  };
  for (bool adaptive : {false, true}) {
    PipelineDepthFeedback inline_write;
    for (unsigned w = 0; w < 12; ++w)
      assert(!window(inline_write, 4 * ms, ms / 10, 200 * ms, 4096, adaptive));
    assert(inline_write.target == 64 && !inline_write.probes);
    assert(inline_write.write_guard_windows == (adaptive ? 12U : 0U));
  }
  PipelineDepthFeedback stable;
  assert(!window(stable, 4 * ms, 2 * ms, 40 * ms));
  assert(window(stable, 4 * ms, 2 * ms, 40 * ms) == 1 && stable.target == 80);
  // More bytes/s cannot justify a worse buffer-publication tail.
  assert(window(stable, 4 * ms, 2 * ms, 100 * ms, 8192) == -1);
  assert(stable.target == 64 && stable.rejected == 1);
  PipelineDepthFeedback shrink;
  assert(!window(shrink, 100 * ms, 50 * ms, 500 * ms));
  assert(!window(shrink, 100 * ms, 50 * ms, 500 * ms));
  assert(window(shrink, 100 * ms, 50 * ms, 500 * ms) == -1 && shrink.target == 48);
  // Less upstream queueing alone is NOT a successful physical-depth trial.
  assert(window(shrink, 100 * ms, 50 * ms, 100 * ms) == 1);
  assert(shrink.target == 64 && shrink.rejected == 1);
  PipelineDepthFeedback useful;
  for (unsigned w = 0; w < 3; ++w) window(useful, 100 * ms, 50 * ms, 500 * ms);
  assert(useful.target == 48 && useful.probing);
  assert(!window(useful, 80 * ms, 40 * ms, 500 * ms));
  assert(useful.stable == 48 && useful.accepts == 1);
  puts("write depth: inline-submit/queue guard, two clean windows, real service gain, publication guard, fixed Async PASS");
}

static void adaptive_metadata_updates() {
  char directory[] = "/tmp/sqlite-metadata-update-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  std::vector<std::string> reference;
  for (const char* mode : {"sync-no-extent", "async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    const bool adaptive = std::string(mode) != "sync-no-extent";
    SqliteExtentIoService::Impl impl(false);
    assert(impl.ensure_database_locked());
    auto sql = [&](const char* query) {
      assert(sqlite3_exec(impl.db_, query, nullptr, nullptr, nullptr) == SQLITE_OK);
    };
    auto rows = [&](const char* query) {
      sqlite3_stmt* s = nullptr;
      assert(sqlite3_prepare_v2(impl.db_, query, -1, &s, nullptr) == SQLITE_OK);
      std::vector<std::string> result;
      int rc;
      while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        std::string row;
        for (int c = 0; c < sqlite3_column_count(s); ++c)
          row += std::string(reinterpret_cast<const char*>(sqlite3_column_text(s, c))) + "|";
        result.push_back(row);
      }
      assert(rc == SQLITE_DONE);
      sqlite3_finalize(s);
      return result;
    };
    sql("DELETE FROM extent_index_v3");
    Task a, b;
    a.request = {}; b.request = {};
    a.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
    a.request.workload = GROUP_PMP_SQLITE_OVERWRITE;
    a.request.run_id = 101; a.request.file_id = 1; a.request.worker_count = 2;
    a.request.sequence = 1; a.request.length = 4096; a.request.logical_size = 8192;
    b = a; b.request.worker_index = 1; b.request.file_offset = 4096;
    assert(impl.commit_writes({&a, &b}));
    const auto old_id = rows("SELECT rowid FROM extent_index_v3 WHERE worker_index=0");
    Task older = a, newer = a, missing = a;
    older.request.sequence = 2; older.request.file_offset = 8192;
    newer.request.sequence = 3; newer.request.file_offset = 12288;
    newer.request.task_id = 19; newer.request.tag[0] = 0xa5;
    missing.request.reserved[1] = 4096; missing.request.file_offset = 16384;
    assert(impl.commit_writes({&newer, &missing, &older}));
    const auto new_id = rows("SELECT rowid FROM extent_index_v3 WHERE worker_index=0 AND logical_offset=0");
    assert((old_id == new_id) == adaptive); // No delete/reinsert for Adaptive overwrite.
    const char* snapshot = "SELECT run_id,worker_index,worker_count,workload,task_id,file_id,"
        "logical_offset,file_offset,cipher_length,logical_size,sequence,hex(tag) "
        "FROM extent_index_v3 ORDER BY run_id,worker_index,workload,logical_offset";
    const auto current = rows(snapshot);
    assert(current.size() == 3);
    if (reference.empty()) reference = current; else assert(current == reference);
    assert(rows("SELECT sequence,task_id,file_offset FROM extent_index_v3 WHERE worker_index=0 AND logical_offset=0") ==
        std::vector<std::string>{"3|19|12288|"});
    assert(rows("SELECT sequence FROM extent_index_v3 WHERE worker_index=1") ==
        std::vector<std::string>{"1|"});
    auto before = impl.snapshot();
    assert(before.pipeline[SQLITE_PIPELINE_METADATA_UPSERT_ROWS] == (adaptive ? 5U : 0U));
    assert(before.pipeline[SQLITE_PIPELINE_METADATA_UPSERT_TRANSACTIONS] == (adaptive ? 2U : 0U));
    assert((impl.adaptive_write_statement_ != nullptr) == adaptive);
    sql("CREATE TRIGGER reject_test_update BEFORE INSERT ON extent_index_v3 "
        "WHEN NEW.sequence=9999 BEGIN SELECT RAISE(ABORT,'test fault'); END");
    older.request.sequence = 4; newer.request.sequence = 9999;
    assert(!impl.commit_writes({&older, &newer}));
    assert(rows(snapshot) == current); // Earlier statement in the transaction rolled back too.
    assert(impl.snapshot().commit_count == before.commit_count);
    assert(impl.snapshot().pipeline[SQLITE_PIPELINE_METADATA_UPSERT_ROWS] ==
           before.pipeline[SQLITE_PIPELINE_METADATA_UPSERT_ROWS]);
    sql("DROP TRIGGER reject_test_update");
    older.result = -EIO; newer.superseded = true;
    assert(impl.commit_writes({&older, &newer}));
    assert(rows(snapshot) == current);
    if (adaptive) {
      // Same key, different data file: sequence, not file_id, wins.
      older.result = 0; older.request.file_id = 2;
      newer.superseded = false; newer.request.sequence = 5;
      assert(impl.commit_writes({&newer, &older}));
      assert(rows("SELECT sequence,file_id FROM extent_index_v3 WHERE worker_index=0 AND logical_offset=0") ==
             std::vector<std::string>{"5|1|"});
    }
  }
  DIR* dir = opendir(directory); assert(dir);
  while (dirent* e = readdir(dir))
    if (e->d_name[0] != '.') assert(unlink((std::string(directory) + "/" + e->d_name).c_str()) == 0);
  closedir(dir); assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("metadata UPSERT: shared Async/Adaptive, real SQLite, stable rowid, key isolation, sequence, tags, rollback PASS");
}

static void bounded_completion_drain() {
  for (bool adaptive : {false, true}) {
    unsigned calls = 0;
    std::vector<int> consumed;
    const auto drained = drain_arrived_completions(adaptive, 3, [&]() {
      ++calls;
      return calls == 1 ? std::vector<int>{1} : std::vector<int>{2, 3};
    }, [&](const std::vector<int>& items) {
      consumed.insert(consumed.end(), items.begin(), items.end());
    });
    assert(calls == (adaptive ? 2U : 1U));
    assert(consumed == (adaptive ? std::vector<int>{1, 2, 3} : std::vector<int>{1}));
    assert(drained.extra == (adaptive ? 2U : 0U));
  }
  unsigned calls = 0;
  const auto incomplete = drain_arrived_completions(true, 10, [&]() {
    return ++calls == 1 ? std::vector<int>{1} : std::vector<int>{};
  }, [](const std::vector<int>&) {});
  assert(calls == 2 && incomplete.consumed == 1); // No wait for the other nine.
  puts("bounded CQ drain: arrived during processing included, empty exits, Async unchanged PASS");
}

static void raw_inflight() {
  RawIoUring ring;
  assert(ring.available());
  int pipe_fds[2];
  assert(pipe(pipe_fds) == 0);
  FILE* file = tmpfile();
  assert(file);
  const int fd = fileno(file);
  assert(pwrite(fd, "abc", 3, 0) == 3);
  char slow = 0, fast = 0;
  InlineOneList<iovec> a, b;
  a.push_back({&slow, 1});
  b.push_back({&fast, 1});
  RawIoUring::Operation op;
  op.fd = pipe_fds[0]; op.offset = UINT64_MAX; op.vectors = &a; op.read = true; op.expected = 1;
  int error = 0;
  assert(ring.submitAsync({op}, {1}, &error) == 1 && !error);
  assert(ring.inflight() == 1);
  op.fd = fd; op.offset = 0; op.vectors = &b;
  RawIoUring::SubmitTiming timing;
  assert(ring.submitAsync({op}, {2}, &error, nullptr, nullptr, &timing) == 1 && !error);
  assert(timing.prep_wall_ns > 0 && timing.enter_wall_ns > 0);
  assert(timing.prep_cpu_ns > 0 && timing.enter_cpu_ns > 0);
  auto receive = [&]() {
    for (;;) {
      auto ready = ring.reapAsync();
      if (!ready.empty()) return ready;
      struct pollfd p{ring.descriptor(), POLLIN, 0};
      assert(poll(&p, 1, 5000) > 0);
    }
  };
  auto ready = receive();
  assert(ready.size() == 1 && ready[0].token == 2 && ready[0].result == 1);
  assert(fast == 'a' && ring.inflight() == 1 && !slow);
  // Refill a freed buffer while the older read is still blocked in the kernel.
  op.offset = 1;
  assert(ring.submitAsync({op}, {3}, &error) == 1);
  ready = receive();
  assert(ready.size() == 1 && ready[0].token == 3 && fast == 'b');
  assert(!ring.registerFiles({fd})); // No replacement of live resource tables.
  assert(write(pipe_fds[1], "z", 1) == 1);
  ready = receive();
  assert(ready.size() == 1 && ready[0].token == 1 && slow == 'z' && !ring.inflight());
  op.offset = 1000; // Short I/O is delivered, not retried/replayed.
  assert(ring.submitAsync({op}, {4}, &error) == 1);
  ready = receive();
  assert(ready[0].token == 4 && ready[0].result == 0);
  op.fd = -1;
  assert(ring.submitAsync({op}, {5}, &error) == 1);
  ready = receive();
  assert(ready[0].token == 5 && ready[0].result == -EBADF && !ring.inflight());
  close(pipe_fds[0]); close(pipe_fds[1]); fclose(file);
  puts("real io_uring: blocked A, independent B, B refill before A, short/error CQE PASS");
}

static Task task_for(uint8_t* utm, size_t size, unsigned slot, unsigned descriptor,
                     const std::shared_ptr<SqliteAsyncCompletion>& completion) {
  Task t;
  t.utm = utm; t.utm_size = size; t.completion = completion;
  t.enqueue_ns = t.dequeue_ns = t.io_submit_ns = now_ns();
  t.io_complete_ns = now_ns();
  t.pipeline_depth_epoch = 1;
  t.pipeline_submit_cost = 1000;
  t.storage_length = 16;
  t.stored_sequence = 1;
  t.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
  t.request.workload = GROUP_PMP_SQLITE_READSEQ;
  t.request.ring_slot = t.request.buffer_id = slot;
  t.request.descriptor_id = descriptor;
  t.request.buffer_offset = slot ? GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET : GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
  t.request.buffer_offset += descriptor * 16;
  t.request.length = 16;
  t.request.request_id = slot * 100 + descriptor + 1;
  t.request.reserved[0] = GROUP_PMP_SQLITE_STORE_RING;
  return t;
}

static void overwrite_submit_accounting() {
  char directory[] = "/tmp/sqlite-overwrite-submit-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  setenv("GROUP_PMP_SQLITE_CACHE_MODE", "cold", 1);
  const size_t size = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
  constexpr unsigned workers = 7, requests = workers * 4;
  for (const char* mode : {"async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    SqliteExtentIoService::Impl impl(false);
    const int fd = impl.file_for(1);
    assert(fd >= 0 && impl.ring_.available());
    std::vector<uint8_t> expected(requests * 8192, 0xa5);
    assert(pwrite(fd, expected.data(), expected.size(), 0) ==
           static_cast<ssize_t>(expected.size()));
    assert(fdatasync(fd) == 0);
    assert(posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) == 0);
    std::vector<std::vector<uint8_t>> utms(workers, std::vector<uint8_t>(size));
    std::vector<std::shared_ptr<SqliteAsyncCompletion>> completions;
    std::vector<Task> tasks;
    unsigned wakes = 0;
    for (unsigned worker = 0; worker < workers; ++worker) {
      for (unsigned slot = 0; slot < 2; ++slot) {
        auto completion = std::make_shared<SqliteAsyncCompletion>(2);
        completion->arm([&](bool) { ++wakes; }, worker % 3);
        completions.push_back(completion);
        auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
            utms[worker].data() + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot));
        ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
        ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
        for (unsigned descriptor = 0; descriptor < 2; ++descriptor) {
          const unsigned index = worker * 4 + slot * 2 + descriptor;
          Task t = task_for(utms[worker].data(), size, slot, descriptor, completion);
          t.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
          t.request.workload = GROUP_PMP_SQLITE_OVERWRITE;
          t.request.worker_index = worker;
          t.request.worker_count = workers;
          t.request.run_id = 101 + worker;
          t.request.file_id = 1;
          t.request.file_offset = index * 8192;
          t.request.buffer_offset = (slot ? GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET :
              GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET) + descriptor * 4096;
          t.request.length = 4096;
          t.request.sequence = index + 1;
          t.request.task_id = index + 1;
          t.request.reserved[1] = (slot * 2 + descriptor) * 4096;
          memset(t.data(), 0x31 + index, 4096);
          memset(expected.data() + t.request.file_offset, 0x31 + index, 4096);
          tasks.push_back(t);
        }
      }
    }
    impl.pipeline_begin(std::move(tasks));
    assert(impl.snapshot().physical_request_count == requests);
    // Inject userspace contention, not device latency. The actual enter()
    // duration can vary, so assert the accounting difference, not its speed.
    std::unique_lock<std::mutex> held(impl.ring_mutex_);
    std::promise<void> entered;
    auto started = entered.get_future();
    std::thread submitter([&]() {
      entered.set_value();
      assert(impl.pipeline_refill());
    });
    started.wait();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    held.unlock();
    submitter.join();
    auto stats = impl.snapshot();
    uint64_t inclusive_cost = 0, queue_sum = 0;
    for (const auto& item : impl.flights_) {
      const auto& flight = item.second;
      inclusive_cost += flight.submit_cost;
      assert(flight.submitted && flight.followers.empty());
    }
    for (const auto& plan : impl.pipeline_batches_)
      for (const auto* task : plan->tasks)
        queue_sum += task->io_submit_ns - task->dequeue_ns;
    assert(stats.submit_ns > 0 && stats.disk_io_ns == stats.submit_ns);
    assert(inclusive_cost > stats.submit_ns + UINT64_C(50000000));
    assert(stats.host_dequeue_to_io_submit_ns == queue_sum);
    assert(stats.pipeline[SQLITE_PIPELINE_SQES_ACCEPTED] == requests);
    assert(stats.pipeline[SQLITE_PIPELINE_SUBMITS] == 1);
    while (!impl.flights_.empty()) {
      if (!impl.pipeline_reap()) {
        struct pollfd p{impl.ring_.descriptor(), POLLIN, 0};
        assert(poll(&p, 1, 5000) > 0);
      }
      impl.pipeline_publish();
      impl.pipeline_retire();
    }
    assert(impl.pipeline_batches_.empty() && wakes == workers * 2);
    for (const auto& completion : completions) assert(completion->isComplete());
    assert(!impl.pipeline_publish() && !impl.pipeline_refill());
    std::vector<uint8_t> actual(expected.size());
    assert(pread(fd, actual.data(), actual.size(), 0) == static_cast<ssize_t>(actual.size()));
    assert(actual == expected); // Every overwrite and every untouched gap.
    stats = impl.snapshot();
    assert(stats.logical_request_count == requests && stats.physical_request_count == requests);
    assert(stats.pipeline[SQLITE_PIPELINE_BUFFER_COMPLETIONS] == workers * 2);
  }
  DIR* dir = opendir(directory); assert(dir);
  while (dirent* e = readdir(dir))
    if (e->d_name[0] != '.') assert(unlink((std::string(directory) + "/" + e->d_name).c_str()) == 0);
  closedir(dir); assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("overwrite N=7: submit excludes userspace lock, inclusive feedback preserved, counters/data/wakes PASS");
}

static void independent_buffers(bool measure_read100k = false) {
  SqliteExtentIoService::Impl impl(false);
  ReadMergeFeedback feedback;
  const size_t size = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
  std::vector<uint8_t> utm(size, 0);
  for (unsigned slot = 0; slot < 2; ++slot) {
    auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
        utm.data() + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot));
    ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
    ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
  }
  auto a = std::make_shared<SqliteAsyncCompletion>(2);
  auto b = std::make_shared<SqliteAsyncCompletion>(1);
  unsigned wakes = 0;
  b->arm([&](bool) { ++wakes; }, 0);
  auto gate = std::make_shared<SqliteAsyncCompletion>(1);
  unsigned gate_wakes = 0;
  a->watchAny(gate); b->watchAny(gate);
  gate->arm([&](bool defer) { assert(!defer); ++gate_wakes; }, 0);
  auto plan = std::make_shared<PipelineBatch>();
  plan->started = now_ns();
  plan->owned = {task_for(utm.data(), size, 0, 0, a),
                 task_for(utm.data(), size, 0, 1, a), task_for(utm.data(), size, 1, 0, b)};
  if (measure_read100k) {
    plan->feedback = &feedback;
    for (auto& task : plan->owned) {
      task.request.workload = GROUP_PMP_SQLITE_READRAND100K;
      task.merge_feedback_candidate = true;
      task.merge_feedback_work_ns = 100;
    }
  }
  for (auto& t : plan->owned) plan->tasks.push_back(&t);
  plan->owned[0].pipeline_done = plan->owned[2].pipeline_done = true;
  plan->remaining = 1;
  impl.pipeline_batches_.push_back(plan);
  assert(impl.pipeline_publish());
  assert(!a->isComplete() && b->isComplete() && wakes == 1);
  assert(gate->isComplete() && gate_wakes == 1);
  assert(!plan->owned[0].pipeline_published && plan->owned[2].pipeline_published);
  assert(!impl.pipeline_publish() && wakes == 1);
  const uint64_t first_service = feedback.service_ns;
  if (measure_read100k) assert(feedback.samples == 1 && first_service > 0);
  // B can be reused before A. Retiring the old plan must not read B again.
  memset(utm.data() + GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET, 0x7c, 16);
  auto b2 = std::make_shared<SqliteAsyncCompletion>(1);
  auto next = std::make_shared<PipelineBatch>();
  next->started = now_ns();
  next->owned = {task_for(utm.data(), size, 1, 0, b2)};
  next->tasks = {&next->owned[0]}; next->owned[0].pipeline_done = true;
  impl.pipeline_batches_.push_back(next);
  assert(impl.pipeline_publish() && b2->isComplete() && !a->isComplete());
  if (measure_read100k) assert(feedback.samples == 1 && feedback.service_ns == first_service);
  impl.pipeline_mark_done(plan->owned[1]); plan->remaining = 0;
  assert(impl.pipeline_publish() && a->isComplete());
  assert(gate_wakes == 1);
  impl.pipeline_retire();
  assert(impl.pipeline_batches_.empty());
  assert(utm[GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET] == 0x7c);
  const auto stats = impl.snapshot();
  assert(stats.pipeline[SQLITE_PIPELINE_BUFFER_COMPLETIONS] == 3);
  assert(stats.pipeline[SQLITE_PIPELINE_EARLY_BUFFERS] == 2);
  assert(stats.pipeline[SQLITE_PIPELINE_DEPTH_SAMPLES] == 3);
  assert(!stats.pipeline[SQLITE_PIPELINE_DEPTH_PROBES]);
  if (measure_read100k) {
    assert(feedback.samples == 2);
    assert(stats.pipeline[SQLITE_PIPELINE_READ100K_FEEDBACK_BUFFERS] == 2);
    assert(stats.read100k[SQLITE_READ100K_DISCRETE_BYTES] == 48);
    assert(stats.read100k[SQLITE_READ100K_DISCRETE_SERVICE_NS] == feedback.service_ns);
  }
  puts("per-buffer publication: all own children, early peer, reuse, exactly-once wake PASS");
}

static void arrived_buffer_publication() {
  SqliteExtentIoService::Impl impl(false);
  const size_t size = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
  std::vector<std::vector<uint8_t>> utms(4, std::vector<uint8_t>(size, 0));
  auto plan = std::make_shared<PipelineBatch>();
  plan->started = now_ns();
  std::vector<std::shared_ptr<SqliteAsyncCompletion>> completions;
  unsigned callbacks = 0, flushes = 0;
  for (unsigned i = 0; i < 4; ++i) {
    auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
        utms[i].data() + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(0));
    ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
    ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
    completions.push_back(std::make_shared<SqliteAsyncCompletion>(1));
    completions.back()->arm([&, i](bool defer) {
      assert(i != 3); // No wakeup for the still-in-flight buffer.
      for (unsigned j = 0; j < 3; ++j) {
        assert(completions[j]->isComplete());
        assert(plan->owned[j].publish_ns && plan->owned[j].pipeline_published);
      }
      assert(!completions[3]->isComplete());
      ++callbacks;
      if (!defer) { ++flushes; assert(callbacks == 3); }
    }, i == 2 ? 1 : 0);
    plan->owned.push_back(task_for(utms[i].data(), size, 0, 0, completions.back()));
    plan->owned.back().pipeline_done = i != 3;
  }
  for (auto& task : plan->owned) plan->tasks.push_back(&task);
  plan->remaining = 1;
  impl.pipeline_batches_.push_back(plan);
  assert(impl.pipeline_publish() && callbacks == 3 && flushes == 1);
  assert(!impl.pipeline_publish() && !completions[3]->isComplete());
  const auto stats = impl.snapshot();
  assert(stats.pipeline[SQLITE_PIPELINE_COMPLETION_PUBLICATIONS] == 1);
  assert(stats.pipeline[SQLITE_PIPELINE_COMPLETION_MAX_BUFFERS] == 3);
  assert(stats.pipeline[SQLITE_PIPELINE_WAKE_FLUSH_BATCHES] == 1);
  assert(stats.pipeline[SQLITE_PIPELINE_WAKE_LANES] == 2);
  puts("arrived buffers: statuses before callbacks, one flush, two lanes, unfinished peer not woken PASS");
}

static void write_barriers_and_errors() {
  char directory[] = "/tmp/sqlite-pipeline-errors-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  {
    SqliteExtentIoService::Impl impl(false);
    std::vector<uint8_t> utm(GROUP_PMP_SQLITE_VFS_UTM_BYTES, 0);
    auto old = std::make_shared<SqliteAsyncCompletion>(1);
    auto replacement = std::make_shared<SqliteAsyncCompletion>(1);
    auto plan = std::make_shared<PipelineBatch>();
    plan->started = now_ns();
    plan->owned = {task_for(utm.data(), utm.size(), 0, 0, old),
                   task_for(utm.data(), utm.size(), 1, 0, replacement)};
    for (auto& task : plan->owned) {
      task.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
      task.request.file_id = task.stored_file_id = 1;
      task.request.sequence = task.request.buffer_id + 1;
      task.request.file_offset = 100;
      task.io_complete_ns = 0;
      plan->tasks.push_back(&task);
    }
    plan->owned[0].superseded = plan->owned[0].pipeline_done = true;
    plan->atomic_write_publish = true;
    plan->remaining = 1;
    IoGroup group;
    group.read = false; group.fd = 0; group.file_id = 1;
    group.offset = 100; group.end = 116;
    plan->groups.push_back(std::move(group));
    impl.pipeline_write_ranges_[{1, 100}] = 116;
    const auto& first = plan->owned[0].request;
    impl.pipeline_write_keys_.insert(std::make_tuple(first.run_id,
        first.worker_index, first.workload, first.reserved[1]));
    impl.pipeline_batches_.push_back(plan);

    Task next = plan->owned[1];
    next.request.reserved[1] = 1;
    assert(impl.pipeline_write_conflict({next}));
    next.request.file_offset = 116;
    assert(!impl.pipeline_write_conflict({next})); // Adjacent is not conflicting.
    next.request.reserved[1] = 0;
    assert(impl.pipeline_write_conflict({next})); // Metadata key still owned.
    assert(impl.pipeline_compatible(next));
    next.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    assert(!impl.pipeline_compatible(next));
    next.request.operation = GROUP_PMP_SQLITE_VFS_OP_SYNC;
    assert(!impl.pipeline_compatible(next));

    // An eliminated write depends on its replacement, even across buffers.
    assert(!impl.pipeline_publish());
    assert(!old->isComplete() && !replacement->isComplete());
    impl.pipeline_mark_done(plan->owned[1]);
    plan->owned[1].result = -EIO;
    plan->remaining = 0;
    assert(impl.pipeline_publish());
    assert(old->isComplete() && replacement->isComplete());
    for (const Task& task : plan->owned) {
      assert(task.result == -EIO);
      group_pmp_sqlite_vfs_status status;
      memcpy(&status, utm.data() + status_offset_for_request(task.request), sizeof(status));
      assert(status.result == -EIO && status.state == GROUP_PMP_SQLITE_VFS_STATE_ERROR);
    }
    assert(!impl.pipeline_publish());
    impl.pipeline_retire();
    assert(impl.pipeline_batches_.empty() && impl.pipeline_write_ranges_.empty() &&
           impl.pipeline_write_keys_.empty() && impl.pipeline_compatible(next));
  }
  assert(unlink((std::string(directory) + "/keystone-group-extent-index.db").c_str()) == 0);
  assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("write pipeline: interval/key reservations, read/fsync barriers, replacement failure PASS");
}

static void ready_sequential_plans(bool queued_snapshot = false) {
  char directory[] = "/tmp/sqlite-ready-extents-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  setenv("GROUP_PMP_SQLITE_IO_RANGE_MAX_RECORDS", "1024", 1);
  assert(sqlite_io_range_trace().configureOutput((std::string(directory) + "/ranges.csv").c_str()));
  for (const char* mode : {"async-no-extent", "adaptive-extent"}) {
   for (bool holes : {false, true}) {
    if (queued_snapshot && (holes || std::string(mode) != "adaptive-extent")) continue;
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    SqliteExtentIoService::Impl impl(false);
    const bool adaptive = std::string(mode) == "adaptive-extent";
    // A deliberately high fixed storage latency makes an 8 MB joint CQE
    // profitable in this fixture; the low-latency rejection is tested below.
    impl.ewma_request_latency_ns_.store(100000000);
    for (size_t depth : {16, 48, 64, 128}) {
      impl.pipeline_depth_.target = depth;
      assert(impl.pipeline_logical_target(GROUP_PMP_SQLITE_FILLRANDOM) == 512);
      assert(impl.pipeline_logical_target(GROUP_PMP_SQLITE_READRANDOM) == 512);
    }
    impl.pipeline_depth_.target = 64;
    if (queued_snapshot) impl.adaptive_batch_max_ = 4; // Force two existing plan boundaries, not larger batches.
    auto& trace = sqlite_io_range_trace();
    trace.beginCase(1, 1, GROUP_PMP_SQLITE_FILLSEQ, queued_snapshot ? 4 : 2, adaptive ? 0 : 2);
    trace.beginWindow();
    const size_t size = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
    std::vector<std::vector<uint8_t> > utm(4, std::vector<uint8_t>(size));
    std::vector<std::shared_ptr<SqliteAsyncCompletion> > completions;
    const std::vector<unsigned> order = queued_snapshot ? std::vector<unsigned>{0, 2, 4, 6, 1, 3, 5, 7} :
        std::vector<unsigned>{3, 0, 2, 1};
    for (unsigned i : order) {
      auto completion = std::make_shared<SqliteAsyncCompletion>(1);
      completions.push_back(completion);
      Task task = task_for(utm[i / 2].data(), size, i % 2, 0, completion);
      auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
          task.utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(i % 2));
      ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
      ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
      task.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
      task.request.workload = GROUP_PMP_SQLITE_FILLSEQ;
      task.request.run_id = 1 + i / 2;
      task.request.worker_index = i / 2;
      task.request.worker_count = order.size() / 2;
      task.request.file_id = 1;
      task.request.file_offset = task.request.reserved[1] = (i + (holes && i >= 2 ? 1 : 0)) * 2000000;
      task.request.length = 2000000;
      task.request.sequence = i + 1;
      memset(task.data(), i + 1, 2000000);
      if (queued_snapshot) impl.queue_.push_back(task);
      else impl.pipeline_begin({task});
    }
    if (queued_snapshot) {
      assert(impl.pipeline_admit_ready());
      assert(impl.queue_.empty() && impl.pipeline_batches_.size() == 2);
      assert(impl.flights_.empty());
    }
    assert(impl.pipeline_refill());
    if (queued_snapshot) {
      // Only an already-arrived neighbouring plan is prepared before refill.
      assert(impl.snapshot().pipeline[SQLITE_PIPELINE_SQES_ACCEPTED] == 2);
      assert(impl.snapshot().pipeline[SQLITE_PIPELINE_ADMITTED_PLANS] == 2);
      assert(impl.snapshot().pipeline[SQLITE_PIPELINE_SEQ_LOOKAHEAD_PLANS] == 1);
      assert(!impl.pipeline_admit_ready());
    }
    const unsigned physical = queued_snapshot ? 2 : adaptive ? (holes ? 2 : 1) : 4;
    const unsigned logical = order.size();
    assert(impl.flights_.size() == physical);
    assert(impl.snapshot().physical_request_count == physical);
    assert(impl.snapshot().logical_request_count == logical);
    assert(impl.snapshot().pipeline[SQLITE_PIPELINE_READY_EXTENT_JOINS] == logical - physical);
    assert(impl.snapshot().pipeline[SQLITE_PIPELINE_SQES_ACCEPTED] == physical);
    assert(impl.snapshot().pipeline[SQLITE_PIPELINE_SUBMITS] == 1);
    assert(impl.snapshot().pipeline[SQLITE_PIPELINE_ENTER_CALLS] >= 1);
    if (queued_snapshot) {
      assert(impl.snapshot().pipeline[SQLITE_PIPELINE_SUBMIT_2_4] == 1);
      assert(impl.snapshot().pipeline[SQLITE_PIPELINE_ADMITTED_PLANS] == 2);
    }
    while (!impl.flights_.empty()) {
      const auto sampled = impl.pipeline_depth_.completed_samples;
      if (!impl.pipeline_reap()) {
        struct pollfd p{impl.ring_.descriptor(), POLLIN, 0};
        assert(poll(&p, 1, 5000) > 0);
      }
      assert(impl.pipeline_depth_.completed_samples == sampled);
      impl.pipeline_publish();
      assert(impl.pipeline_depth_.completed_samples ==
          impl.snapshot().pipeline[SQLITE_PIPELINE_BUFFER_COMPLETIONS]);
      impl.pipeline_retire();
    }
    assert(impl.pipeline_batches_.empty());
    assert(impl.pipeline_depth_.completed_samples == logical);
    assert(impl.snapshot().sequential_8mb_extent_count == (adaptive && !holes ? physical : 0));
    assert(impl.inflight_bytes_ == 0);
    for (const auto& completion : completions) assert(completion->isComplete());
    std::vector<uint8_t> data(2000000);
    for (unsigned i = 0; i < logical; ++i) {
      const off_t offset = (i + (holes && i >= 2 ? 1 : 0)) * 2000000;
      assert(pread(impl.files_[1], data.data(), data.size(), offset) == static_cast<ssize_t>(data.size()));
      for (const uint8_t value : data) assert(value == i + 1);
    }
    trace.endWindow();
    assert(trace.flushCase());
    SqliteIoRangeSummary summary{};
    assert(trace.lastSummary(&summary));
    assert(summary.request_count == physical && summary.member_request_count == logical);
    assert(summary.total_range_bytes == logical * 2000000 && summary.gap_bytes == 0);
    assert(summary.max_request_bytes == (adaptive ? (holes ? 4000000 : 8000000) : 2000000));
   }
  }
  // Remove only files created in this test-owned temporary directory.
  assert(sqlite_io_range_trace().configureOutput(nullptr));
  unsetenv("GROUP_PMP_SQLITE_IO_RANGE_MAX_RECORDS");
  DIR* dir = opendir(directory);
  assert(dir);
  while (dirent* entry = readdir(dir)) {
    if (entry->d_name[0] != '.') assert(unlink((std::string(directory) + "/" + entry->d_name).c_str()) == 0);
  }
  closedir(dir);
  assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  setenv("GROUP_PMP_SQLITE_IO_MODE", "async-no-extent", 1);
  puts(queued_snapshot ?
      "queued sequential plans: bounded arrived-neighbour admission, two real 8 MB extents PASS" :
      "ready sequential plans: real 8 MB WRITEV, out-of-order arrivals, buffer feedback and fixed Async PASS");
}

static void missing_neighbor_diagnostics() {
  SqliteExtentIoService::Impl impl(false);
  RawIoUring::Operation op;
  op.offset = 0; op.expected = 2000000; op.read = true;
  impl.pipeline_note_sequential_peer(op, 1);
  Task t;
  t.request.file_id = 1; t.request.file_offset = 2000000;
  t.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
  impl.queue_.push_back(t);
  impl.pipeline_note_sequential_peer(op, 1);
  impl.queue_.clear();
  auto plan = std::make_shared<PipelineBatch>();
  SqliteExtentIoService::Impl::Flight f(plan, 0, 1);
  f.file_id = 1; f.offset = 2000000; f.length = 2000000; f.read = true;
  impl.flights_.emplace(1, std::move(f));
  impl.pipeline_note_sequential_peer(op, 1);
  impl.flights_.clear();
  IoGroup group;
  group.file_id = 1; group.offset = 2000000; group.read = true;
  plan->groups.push_back(std::move(group));
  plan->operations.push_back(op); plan->operation_groups.push_back(0);
  impl.pipeline_batches_.push_back(plan);
  impl.pipeline_note_sequential_peer(op, 1);
  impl.pipeline_batches_.clear();
  auto stats = impl.snapshot();
  assert(stats.pipeline[SQLITE_PIPELINE_SEQ_PEER_ABSENT] == 1);
  assert(stats.pipeline[SQLITE_PIPELINE_SEQ_PEER_QUEUED] == 1);
  assert(stats.pipeline[SQLITE_PIPELINE_SEQ_PEER_INFLIGHT] == 1);
  assert(stats.pipeline[SQLITE_PIPELINE_SEQ_PEER_READY_UNJOINED] == 1);
  puts("sequential neighbor classification: absent/queued/inflight/ready-ineligible PASS");
}

static void sequential_lookahead_guards() {
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  SqliteExtentIoService::Impl impl(false);
  auto plan = std::make_shared<PipelineBatch>();
  plan->owned.resize(1);
  Task& first = plan->owned[0];
  first.case_epoch = 1;
  first.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
  first.request.workload = GROUP_PMP_SQLITE_READSEQ;
  first.request.file_id = 1;
  first.request.worker_count = 2;
  IoGroup group;
  group.file_id = 1; group.offset = 0; group.end = 2000000;
  group.policy = IoPlanningPolicy::kSequentialContiguous;
  group.tasks = {&first};
  plan->groups.push_back(std::move(group));
  plan->operations.resize(1); plan->operation_groups = {0};
  plan->operations[0].expected = 2000000;
  impl.pipeline_batches_.push_back(plan);
  Task peer = first;
  peer.request.file_offset = 2000000;
  peer.request.length = 2000000;
  impl.queue_ = {peer};
  assert(impl.pipeline_arrived_sequential_peer(1));
  assert(impl.pipeline_arrived_readseq_share(1));
  assert(!impl.pipeline_arrived_readseq_share(0));
  impl.queue_.front().request.file_offset += 17;
  assert(impl.pipeline_arrived_readseq_share(1)); // Co-submit need not imply merging.
  impl.queue_.front() = peer;
  impl.pipeline_depth_.target = 1;
  assert(!impl.pipeline_arrived_readseq_share(1));
  impl.pipeline_depth_.target = 64;
  impl.inflight_bytes_ = impl.pipeline_depth_.byte_limit - 3999999;
  assert(!impl.pipeline_arrived_readseq_share(1));
  impl.inflight_bytes_ = 0;
  assert(!impl.pipeline_arrived_sequential_peer(0)); // Later arrivals excluded.
  plan->next = 1;
  assert(!impl.pipeline_arrived_sequential_peer(1)); // In-flight requests immutable.
  plan->next = 0;
  impl.inflight_bytes_ = impl.pipeline_depth_.byte_limit;
  assert(!impl.pipeline_arrived_sequential_peer(1));
  impl.inflight_bytes_ = 0;
  for (unsigned boundary = 0; boundary < 6; ++boundary) {
    Task other = peer;
    if (boundary == 0) other.case_epoch++;
    if (boundary == 1) other.request.file_id++;
    if (boundary == 2) other.request.operation = GROUP_PMP_SQLITE_VFS_OP_SYNC;
    if (boundary == 3) other.request.reserved[0] |= GROUP_PMP_SQLITE_STORE_PREFILL;
    if (boundary == 4) other.request.file_offset++; // A hole is not a candidate.
    if (boundary == 5) other.request.length = 8000000;
    impl.queue_ = {other};
    assert(!impl.pipeline_arrived_sequential_peer(1));
    if (boundary < 4) {
      impl.queue_.push_back(peer);
      assert(!impl.pipeline_arrived_sequential_peer(2)); // No barrier bypass.
      assert(!impl.pipeline_arrived_readseq_share(2));
    }
  }
  impl.queue_ = {peer};
  setenv("GROUP_PMP_SQLITE_IO_MODE", "async-no-extent", 1);
  assert(impl.pipeline_arrived_sequential_peer(1));
  assert(impl.pipeline_arrived_readseq_share(1));
  impl.queue_.clear(); impl.pipeline_batches_.clear();
  puts("sequential lookahead: bounded snapshot, no holes/barrier/epoch bypass, Async unchanged PASS");
}

static void admission_and_budget_diagnostics() {
  SqliteExtentIoService::Impl impl(false);
  Task t;
  t.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
  t.request.workload = GROUP_PMP_SQLITE_READSEQ;
  t.request.file_id = 1;
  impl.queue_ = {t, t, t};
  auto arrived = impl.take_ready_batch_locked(64, true, 2);
  assert(arrived.size() == 2 && impl.queue_.size() == 1);
  impl.queue_.clear(); // Later arrivals are not needed to close a snapshot.

  auto plan = std::make_shared<PipelineBatch>();
  RawIoUring::Operation op;
  op.expected = 2000000;
  plan->operations.push_back(op);
  IoGroup group;
  group.policy = IoPlanningPolicy::kSequentialContiguous;
  group.tasks.push_back(&t);
  plan->groups.push_back(std::move(group));
  plan->operation_groups.push_back(0);
  impl.pipeline_batches_.push_back(plan);
  impl.flights_.emplace(1, SqliteExtentIoService::Impl::Flight(plan, 0, 1));
  impl.inflight_bytes_ = impl.pipeline_depth_.byte_limit;
  assert(!impl.pipeline_refill());
  assert(impl.snapshot().pipeline[SQLITE_PIPELINE_BYTE_LIMITED] == 1);
  assert(!impl.pipeline_depth_.pressure); // Byte budget is not SQE credit pressure.
  impl.pipeline_depth_.target = 1;
  assert(!impl.pipeline_refill());
  assert(impl.snapshot().pipeline[SQLITE_PIPELINE_CREDIT_LIMITED] == 1);
  assert(impl.pipeline_depth_.pressure);
  assert(plan->next == 0 && impl.snapshot().pipeline[SQLITE_PIPELINE_SQES_ACCEPTED] == 0);
  impl.flights_.clear(); impl.pipeline_batches_.clear(); impl.inflight_bytes_ = 0;
  puts("admission snapshot boundary, separate byte/SQE limits and no artificial enter PASS");
}

static void low_gain_merge_retirement() {
  SqliteExtentIoService::Impl impl(false);
  ReadMergeFeedback feedback;
  for (unsigned i = 0; i < 4; ++i) feedback.observe(2000000, 10000000);
  assert(feedback.merging && feedback.epoch == 1);
  for (unsigned i = 0; i < 5; ++i) {
    auto plan = std::make_shared<PipelineBatch>();
    plan->started = now_ns() - 10000000;
    plan->feedback = &feedback; plan->merged = true;
    plan->feedback_epoch = feedback.epoch;
    plan->useful = 2000000;
    plan->owned.resize(1);
    auto& task = plan->owned.front();
    task.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    task.pipeline_owner = plan.get();
    task.merge_feedback_candidate = true;
    task.storage_length = 2000000;
    task.dequeue_ns = plan->started;
    task.io_complete_ns = plan->started + 9000000;
    task.publish_ns = plan->started + 10000000;
    task.enqueue_ns = plan->started;
    task.pipeline_done = task.pipeline_published = true;
    plan->tasks = {&task};
    impl.pipeline_batches_.push_back(plan);
  }
  // Publication samples each completed buffer while plans may still be live.
  for (const auto& plan : impl.pipeline_batches_)
    impl.pipeline_observe_read_buffer(plan->tasks, plan->started + 20000000);
  impl.pipeline_retire();
  assert(impl.pipeline_batches_.empty());
  assert(!feedback.merging && feedback.epoch == 2 && feedback.failures == 1);
  assert(feedback.cooldown == 8 && feedback.samples == 0);
  const auto stats = impl.snapshot();
  assert(stats.read100k[SQLITE_READ100K_MERGED_BATCHES] == 5);
  assert(stats.read100k[SQLITE_READ100K_MERGED_SERVICE_NS] == 50000000);
  assert(stats.pipeline[SQLITE_PIPELINE_READ100K_RELEASE_NS] == 5000000);
  assert(stats.read100k[SQLITE_READ100K_BACKOFFS] == 1);
  assert(stats.pipeline[SQLITE_PIPELINE_READ100K_FEEDBACK_BUFFERS] == 5);
  assert(stats.pipeline[SQLITE_PIPELINE_READ100K_FEEDBACK_STALE] == 1);
  // The fifth already-issued plan keeps its result but cannot train a new epoch.
  puts("read100k publication: buffer service window, no retirement resampling, stale epoch guarded PASS");
}

static void producer_ack_reservation() {
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  SqliteExtentIoService::Impl impl(false); // No storage progress is possible.
  constexpr unsigned workers = 15;
  const size_t count = GROUP_PMP_SQLITE_VFS_BATCH_MAX;
  const size_t bytes = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
  std::vector<std::vector<uint8_t> > utms(workers, std::vector<uint8_t>(bytes));
  auto submit = [&](unsigned worker, unsigned slot, size_t n) {
    auto completion = std::make_shared<SqliteAsyncCompletion>(n);
    std::vector<group_pmp_sqlite_vfs_request> requests;
    for (size_t i = 0; i < n; ++i) {
      auto task = task_for(utms[worker].data(), bytes, slot, i, completion);
      task.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
      task.request.workload = GROUP_PMP_SQLITE_FILLRANDOM;
      task.request.worker_index = worker;
      task.request.worker_count = workers;
      requests.push_back(task.request);
    }
    return impl.submitBatch(requests.data(), n, utms[worker].data(), bytes, completion);
  };
  // The old global write-depth gate stalled here after just a few workers,
  // even though all remaining producers still owned unused UTM slots.
  auto producers = std::async(std::launch::async, [&] {
    for (unsigned w = 0; w < workers; ++w)
      for (unsigned slot = 0; slot < 2; ++slot)
        if (!submit(w, slot, count)) return false;
    return true;
  });
  const bool prompt = producers.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
  if (!prompt) {
    { std::lock_guard<std::mutex> lock(impl.queue_mutex_); impl.stopping_ = true; }
    impl.condition_.notify_all();
  }
  const bool accepted = producers.get();
  assert(prompt && accepted);
  assert(impl.queue_.size() == workers * 2 * count);
  assert(!impl.snapshot().pipeline[SQLITE_PIPELINE_ADMISSION_WAIT_COUNT]);
  assert(impl.pipeline_depth_.target == 64 && impl.pipeline_batches_.empty());
  assert(!impl.snapshot().pipeline[SQLITE_PIPELINE_SQES_ACCEPTED]);

  // Beyond the finite producer reservation, admission still blocks. A short
  // tail does not shrink the reservation while earlier full rings are queued.
  auto extra = std::async(std::launch::async, [&] { return submit(0, 0, 1); });
  assert(extra.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
  { std::lock_guard<std::mutex> lock(impl.queue_mutex_); impl.queue_.pop_front(); }
  impl.condition_.notify_all();
  assert(extra.wait_for(std::chrono::seconds(5)) == std::future_status::ready && extra.get());
  auto cancelled = std::async(std::launch::async, [&] { return submit(0, 0, 1); });
  assert(cancelled.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
  { std::lock_guard<std::mutex> lock(impl.queue_mutex_); impl.stopping_ = true; }
  impl.condition_.notify_all();
  assert(cancelled.wait_for(std::chrono::seconds(5)) == std::future_status::ready && !cancelled.get());
  const auto stats = impl.snapshot();
  assert(stats.pipeline[SQLITE_PIPELINE_ADMISSION_WAIT_COUNT] == 2);
  assert(stats.pipeline[SQLITE_PIPELINE_ADMISSION_WAIT_NS] >=
         stats.pipeline[SQLITE_PIPELINE_ADMISSION_WAIT_MAX_NS]);
  setenv("GROUP_PMP_SQLITE_IO_MODE", "async-no-extent", 1);
  puts("producer ACK: 15x2 rings accepted without storage progress; bounded overflow, tail and shutdown PASS");
}

static void incremental_completion_checks(bool read100k = false) {
  for (const char* mode : {"async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    SqliteExtentIoService::Impl impl(false);
    std::vector<uint8_t> utm(GROUP_PMP_SQLITE_VFS_UTM_BYTES, 0);
    auto completion = std::make_shared<SqliteAsyncCompletion>(256);
    unsigned wakes = 0;
    completion->arm([&](bool) { ++wakes; }, 0);
    for (unsigned p = 0; p < 4; ++p) {
      auto plan = std::make_shared<PipelineBatch>();
      plan->started = now_ns();
      for (unsigned i = 0; i < 64; ++i)
        plan->owned.push_back(task_for(utm.data(), utm.size(), 0, p * 64 + i, completion));
      if (read100k)
        for (auto& task : plan->owned) {
          task.request.workload = GROUP_PMP_SQLITE_READRAND100K;
          task.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
        }
      for (auto& task : plan->owned) plan->tasks.push_back(&task);
      plan->remaining = 64;
      impl.pipeline_batches_.push_back(plan);
      assert(!impl.pipeline_publish());
      // Completed descriptors in earlier plans cannot release an incomplete
      // producer ring. Later fragments have not even been admitted yet.
      for (Task* task : plan->tasks) {
        impl.pipeline_mark_done(*task);
        impl.pipeline_mark_done(*task); // Idempotent duplicate notification.
        --plan->remaining;
      }
      if (p < 3) assert(!impl.pipeline_publish() && !completion->isComplete());
    }
    // Cached groups, not 256 descriptor scans, are checked on each idle turn.
    const uint64_t indexed = impl.snapshot().pipeline[SQLITE_PIPELINE_COMPLETION_INDEXED_TASKS];
    assert(indexed == 256);
    assert(impl.pipeline_publish() && completion->isComplete() && wakes == 1);
    assert(impl.snapshot().pipeline[SQLITE_PIPELINE_DEPTH_SAMPLES] == 1);
    assert(impl.pipeline_depth_.submit_ns == 256000);
    assert(!impl.pipeline_depth_.probes); // 256 descriptors remain one buffer sample.
    const auto checks_before = impl.snapshot().pipeline[SQLITE_PIPELINE_COMPLETION_BUFFER_CHECKS];
    for (unsigned i = 0; i < 64; ++i) assert(!impl.pipeline_publish());
    if (read100k) {
      assert(impl.snapshot().pipeline[SQLITE_PIPELINE_COMPLETION_BUFFER_CHECKS] == checks_before);
      assert(impl.snapshot().pipeline[SQLITE_PIPELINE_READ100K_PUBLISH_IDLE_SKIPS] >= 64);
    } else assert(impl.snapshot().pipeline[SQLITE_PIPELINE_READ100K_PUBLISH_IDLE_SKIPS] == 0);
    assert(impl.snapshot().pipeline[SQLITE_PIPELINE_COMPLETION_INDEXED_TASKS] == indexed);
    for (const auto& plan : impl.pipeline_batches_)
      for (const Task* task : plan->tasks) assert(task->pipeline_published);
    impl.pipeline_retire();
    assert(impl.pipeline_batches_.empty() && wakes == 1);
  }
  setenv("GROUP_PMP_SQLITE_IO_MODE", "async-no-extent", 1);
  puts("completion index: split ring across four plans, exactly-once children/wake, no repeated descriptor scans PASS");
}

static void cross_worker_collection_guards() {
  for (const char* mode : {"async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    SqliteExtentIoService::Impl impl(false);
    Task a, b;
    a.case_epoch = 7;
    a.request.file_id = 1;
    a.request.worker_count = 2;
    a.request.workload = GROUP_PMP_SQLITE_READRANDOM;
    a.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    a.request.run_id = 101;
    b = a;
    b.request.worker_index = 1;
    b.request.run_id = 102;
    impl.queue_ = {a, b};
    auto batch = impl.take_ready_batch_locked(512, true, 2);
    assert(batch.size() == 2);
    impl.queue_.clear();

    for (unsigned boundary = 0; boundary < 6; ++boundary) {
      Task other = b;
      if (boundary == 0) ++other.case_epoch;
      if (boundary == 1) ++other.request.file_id;
      if (boundary == 2) ++other.request.worker_count;
      if (boundary == 3) ++other.request.workload;
      if (boundary == 4) other.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
      if (boundary == 5) other.request.reserved[0] = GROUP_PMP_SQLITE_STORE_PREFILL;
      impl.queue_ = {a, other, b};
      batch = impl.take_ready_batch_locked(512, true, 3);
      assert(batch.size() == 1 && impl.queue_.size() == 2);
      assert(!same_planning_scope(a, other));
    }
    for (uint64_t op : {GROUP_PMP_SQLITE_VFS_OP_SYNC, GROUP_PMP_SQLITE_VFS_OP_RESET,
                       GROUP_PMP_SQLITE_VFS_OP_DELETE, GROUP_PMP_SQLITE_VFS_OP_TRUNCATE}) {
      Task control = a;
      control.request.operation = op;
      impl.queue_ = {a, control, b};
      batch = impl.take_ready_batch_locked(512, true, 3);
      assert(batch.size() == 1 && impl.queue_.front().request.operation == op);
    }
    impl.queue_ = {a, b};
    batch = impl.take_ready_batch_locked(512, true, 1);
    assert(batch.size() == 1 && impl.queue_.size() == 1); // Snapshot, not a collection delay.
    Task next_run = b;
    ++next_run.request.run_id;
    impl.queue_ = {a, b, next_run};
    batch = impl.take_ready_batch_locked(512, true, 3);
    assert(batch.size() == 2 && impl.queue_.size() == 1); // Not merely the first worker's run fence.
    impl.queue_.clear();
    batch = impl.take_ready_batch_locked(512, true);
    assert(batch.empty());
  }
  puts("cross-worker collector: shared Async/Adaptive, file/epoch/phase/operation fences, arrived snapshot PASS");
}

static void cross_worker_real_io() {
  char directory[] = "/tmp/sqlite-cross-worker-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  setenv("GROUP_PMP_SQLITE_CACHE_MODE", "cold", 1);
  const size_t size = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
  uint8_t* utms[2];
  size_t sizes[2] = {size, size};
  for (auto& utm : utms) assert(posix_memalign(reinterpret_cast<void**>(&utm), 4096, size) == 0);
  for (unsigned variant = 0; variant < 3; ++variant) {
    const char* mode = variant ? "adaptive-extent" : "async-no-extent";
    setenv("GROUP_PMP_SQLITE_CLUSTER_MODE", variant == 1 ? "plan-only" : "merge", 1);
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    const bool adaptive = variant == 2;
    // Writes stay disjoint. Duplicate reads are independently authorized by
    // per-worker SQLite index entries, not by sharing a worker's lookup key.
    for (unsigned scenario = 0; scenario < 5; ++scenario) {
      SqliteExtentIoService::Impl impl(false);
      for (auto utm : utms) memset(utm, 0, size);
      const bool registered = impl.prepareCase(1, utms, sizes, 2);
      if (registered) assert(impl.case_epoch_ == 1);
      const bool write = scenario == 0;
      const bool duplicate = scenario == 2;
      const uint64_t length = scenario == 3 ? 100000 : 4096;
      const uint64_t workload = write ? GROUP_PMP_SQLITE_FILLRANDOM :
          scenario == 3 ? GROUP_PMP_SQLITE_READRAND100K : GROUP_PMP_SQLITE_READRANDOM;
      // The first adjacent pair straddles the decimal 4 MB bucket boundary.
      const uint64_t base = scenario == 4 ? UINT64_C(3997696) : 0;
      const uint64_t offsets[4] = {base, base + (duplicate ? 0 : length),
          base + (duplicate ? length : 8 * length), base + (duplicate ? 8 * length : 9 * length)};
      const int fd = impl.file_for(1);
      assert(fd >= 0);
      std::vector<uint8_t> disk(base + 10 * length);
      for (size_t i = 0; i < disk.size(); ++i) disk[i] = static_cast<uint8_t>((i / length) + 0x31);
      assert(pwrite(fd, disk.data(), disk.size(), 0) == static_cast<ssize_t>(disk.size()));
      std::vector<Task> tasks;
      std::vector<std::shared_ptr<SqliteAsyncCompletion> > completions;
      std::array<unsigned, 4> wakes{};
      for (unsigned i = 0; i < 4; ++i) {
        const unsigned worker = i % 2, slot = i / 2;
        auto completion = std::make_shared<SqliteAsyncCompletion>(1);
        completion->arm([&, i](bool) { ++wakes[i]; }, worker);
        Task task = task_for(utms[worker], size, slot, 0, completion);
        task.case_epoch = impl.case_epoch_;
        task.request.run_id = 101 + worker;
        task.request.worker_index = worker;
        task.request.worker_count = 2;
        task.request.file_id = 1;
        task.request.workload = workload;
        task.request.file_offset = offsets[i];
        task.request.length = length;
        task.request.logical_size = disk.size();
        task.request.sequence = slot + 1; // Not globally ordered across workers.
        task.request.task_id = i + 1;
        task.request.reserved[1] = i * length;
        task.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
        tasks.push_back(task);
        completions.push_back(completion);
        auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
            task.utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot));
        ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
        ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
        memset(task.data(), write ? i + 0x51 : 0xa5, length);
      }
      std::vector<Task*> pointers;
      for (auto& task : tasks) pointers.push_back(&task);
      if (!write) {
        assert(impl.commit_writes(pointers)); // Untimed metadata fixture.
        for (auto& task : tasks) task.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
      }
      assert(impl.resetPerf());
      impl.ewma_request_latency_ns_.store(2000000);
      impl.merge_plan_cost_ns_ = impl.merge_completion_cost_ns_ = 1000;
      if (scenario == 3) impl.read_merge_feedback_[0].merging = true;
      for (unsigned i : {2, 0, 3, 1}) impl.queue_.push_back(tasks[i]);
      while (!impl.queue_.empty()) {
        auto batch = impl.take_ready_batch_locked(512, true, impl.queue_.size());
        assert(!batch.empty());
        impl.pipeline_begin(std::move(batch));
      }
      assert(impl.pipeline_refill());
      const uint64_t expected = adaptive ? 2 : 4;
      assert(impl.snapshot().logical_request_count == 4);
      assert(impl.snapshot().physical_request_count == expected);
      assert(impl.snapshot().pipeline[SQLITE_PIPELINE_SQES_ACCEPTED] == expected);
      while (!impl.flights_.empty()) {
        if (!impl.pipeline_reap()) {
          struct pollfd poller{impl.ring_.descriptor(), POLLIN, 0};
          assert(poll(&poller, 1, 5000) > 0);
        }
        impl.pipeline_publish();
        impl.pipeline_retire();
      }
      assert(impl.pipeline_batches_.empty() && impl.inflight_bytes_ == 0);
      auto stats = impl.snapshot();
      assert(stats.cross_worker_extent_count == (adaptive ? (duplicate ? 1 : 2) : 0));
      if (variant && scenario == 3)
        assert(stats.pipeline[SQLITE_PIPELINE_READ100K_BUFFER_BOUNDARIES] == 2);
      assert(stats.deduplicated_request_count == (adaptive && duplicate ? 1 : 0));
      assert(stats.physical_io_bytes == (duplicate && adaptive ? 3 : 4) * length);
      assert(stats.pipeline[SQLITE_PIPELINE_CROSS_WORKER_PLAN_BATCHES] == (variant ? 1 : 0));
      assert(stats.pipeline[SQLITE_PIPELINE_CROSS_WORKER_PLAN_REQUESTS] == (variant ? 4 : 0));
      assert(stats.cache_fill_ns == 0 && stats.cache_fill_bytes == 0);
      if (!variant) {
        assert(stats.random_precheck_ns == 0 && stats.sort_ns == 0 && stats.cluster_ns == 0);
      }
      assert(stats.pipeline[SQLITE_PIPELINE_BUFFER_PUBLISH_SAMPLES] == 4);
      assert(stats.pipeline[SQLITE_PIPELINE_BUFFER_PUBLISH_P95_NS] > 0);
      assert(stats.pipeline[SQLITE_PIPELINE_CLUSTER_PLAN_ONLY_BATCHES] == (variant == 1 ? 1 : 0));
      assert(stats.pipeline[SQLITE_PIPELINE_CLUSTER_PLANNED_SAVINGS] == (variant ? 2 : 0));
      printf("ablation: variant=%u scenario=%u logical=%llu host_ops=%llu copies=%llu submit_calls=%llu publish_p95_ns=%llu\n",
          variant, scenario, (unsigned long long)stats.logical_request_count,
          (unsigned long long)stats.physical_request_count, (unsigned long long)stats.utm_copy_ns,
          (unsigned long long)stats.pipeline[SQLITE_PIPELINE_ENTER_CALLS],
          (unsigned long long)stats.pipeline[SQLITE_PIPELINE_BUFFER_PUBLISH_P95_NS]);
      // Cache admission belongs to the existing mode policy. Adjacency must
      // add no extent bounce/scatter copy on top of that separately timed fill.
      if (!duplicate) assert(stats.utm_copy_ns == stats.cache_fill_ns);
      if (registered) assert(stats.registered_buffer_operations > 0);
      for (unsigned i = 0; i < 4; ++i) {
        const Task& task = tasks[i];
        assert(completions[i]->isComplete() && wakes[i] == 1);
        auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
            task.utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(task.request.ring_slot));
        assert(ring->completion_count == 1);
        auto* status = reinterpret_cast<group_pmp_sqlite_vfs_status*>(
            task.utm + status_offset_for_request(task.request));
        assert(status->request_id == task.request.request_id && status->result == 0);
        if (!write) assert(memcmp(task.data(), disk.data() + offsets[i], length) == 0);
        else {
          std::vector<uint8_t> data(length);
          assert(pread(fd, data.data(), length, offsets[i]) == static_cast<ssize_t>(length));
          for (auto value : data) assert(value == i + 0x51);
        }
      }
      // A repeated publish pass must not double-increment another worker's ring.
      assert(!impl.pipeline_publish());
      for (auto count : wakes) assert(count == 1);
    }
  }
  for (auto utm : utms) free(utm);
  DIR* dir = opendir(directory);
  assert(dir);
  while (dirent* entry = readdir(dir))
    if (entry->d_name[0] != '.') assert(unlink((std::string(directory) + "/" + entry->d_name).c_str()) == 0);
  closedir(dir);
  assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("cross-worker io_uring: random write/read/duplicate/100KB, independent UTM/CQE/wake, Async unchanged PASS");
}

static void arrived_local_candidates() {
  for (const char* mode : {"async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    const bool adaptive = std::string(mode) == "adaptive-extent";
    for (bool adjacent : {false, true}) {
      SqliteExtentIoService::Impl impl(false);
      for (unsigned w = 0; w < 3; ++w) {
        auto completion = std::make_shared<SqliteAsyncCompletion>(256);
        for (unsigned i = 0; i < 256; ++i) {
          Task t;
          t.case_epoch = 7; t.completion = completion;
          t.request.run_id = 101 + w / 2; t.request.worker_index = w / 2;
          t.request.worker_count = 2; t.request.file_id = 1;
          t.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
          t.request.workload = GROUP_PMP_SQLITE_READRANDOM;
          t.request.length = 4096;
          t.request.file_offset = w * 16000000 + i * 16384;
          if (adjacent && w == 2 && !i) t.request.file_offset = 4096;
          impl.queue_.push_back(t);
        }
      }
      auto original = impl.queue_;
      auto batch = impl.take_ready_batch_locked(512, true, 512);
      assert(batch.size() == 512 && impl.queue_.size() == 256); // No future arrivals.
      impl.queue_ = original;
      batch = impl.take_ready_batch_locked(512, true, 1024);
      assert(batch.size() == 512);
      const auto stats = impl.snapshot();
      assert(stats.pipeline[SQLITE_PIPELINE_ARRIVED_EXTEND_REQUESTS] == 0);
      if (!adaptive) {
        assert(!stats.pipeline[SQLITE_PIPELINE_ARRIVED_PROBE_CHECKS]);
        assert(!stats.pipeline[SQLITE_PIPELINE_MERGE_RELEASE_REJECTS]);
      } else {
        assert(stats.pipeline[SQLITE_PIPELINE_ARRIVED_PROBE_CHECKS] <= 8192);
        for (unsigned guard = 0; guard < 5; ++guard) {
          impl.queue_ = original;
          if (guard == 0) impl.queue_[512].request.operation = GROUP_PMP_SQLITE_VFS_OP_SYNC;
          if (guard == 1) ++impl.queue_[512].case_epoch;
          if (guard == 2) impl.queue_[512].request.reserved[0] = GROUP_PMP_SQLITE_STORE_PREFILL;
          if (guard == 3) impl.queue_[512].request.worker_index = 0; // Same worker, different run.
          if (guard == 4) impl.queue_.pop_back(); // Never take an incomplete buffer.
          batch = impl.take_ready_batch_locked(512, true, 1024);
          assert(batch.size() == 512);
        }
      }
    }
  }
  puts("arrived prefix: identical 512-request bound, no candidate-dependent admission, epoch/run/control fences PASS");
}

static void buffer_release_cost() {
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  SqliteExtentIoService::Impl impl(false);
  Task a, b;
  a.completion = std::make_shared<SqliteAsyncCompletion>(1);
  b.completion = std::make_shared<SqliteAsyncCompletion>(1);
  a.io_length = b.io_length = 2000000;
  b.io_offset = 2000000;
  IoGroup group;
  group.offset = 0; group.end = group.useful_bytes = group.release_floor_bytes = 2000000;
  group.tasks = {&a}; group.read = true;
  group.policy = IoPlanningPolicy::kSequentialContiguous;
  impl.ewma_bandwidth_bytes_per_sec_.store(200000000);
  impl.ewma_request_latency_ns_.store(80000);
  impl.merge_delay_budget_ns_ = 1000000;
  uint64_t gap = 0;
  assert(!impl.merge_within_budget(group, b, 4000000, &gap));
  assert(impl.snapshot().pipeline[SQLITE_PIPELINE_MERGE_RELEASE_REJECTS] == 1);
  assert(impl.snapshot().pipeline[SQLITE_PIPELINE_MERGE_RELEASE_PENALTY_NS] == 10000000);
  impl.merge_delay_budget_ns_ = 20000000;
  assert(impl.merge_within_budget(group, b, 4000000, &gap));
  impl.ewma_request_latency_ns_.store(80000);
  impl.merge_delay_budget_ns_ = 1000000;
  b.completion = a.completion;
  assert(impl.merge_within_budget(group, b, 4000000, &gap)); // No new independent-owner wait.
  group.read = false;
  b.io_offset += 4096;
  assert(!impl.merge_within_budget(group, b, 4004096, &gap)); // Never write a hole.
  b.io_offset = 2000000;
  b.io_length = 80;
  b.completion = std::make_shared<SqliteAsyncCompletion>(1);
  assert(!impl.merge_within_budget(group, b, 2000080, &gap));
  impl.merge_delay_budget_ns_ = 20000000;
  assert(impl.merge_within_budget(group, b, 2000080, &gap));
  puts("release cost: independent-owner growth charged, budget-bounded/same-buffer accepted, write holes rejected PASS");
}

static void packed_tail_real_io() {
  char directory[] = "/tmp/sqlite-packed-tail-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  for (const char* mode : {"async-no-extent", "adaptive-extent"}) {
    const bool adaptive = std::string(mode) == "adaptive-extent";
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    for (const bool costly : {false, true}) {
      SqliteExtentIoService::Impl impl(false);
      impl.ewma_request_latency_ns_.store(costly ? 100000000 : 1000);
      impl.ewma_bandwidth_bytes_per_sec_.store(200000000);
      const size_t size = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
      std::vector<std::vector<uint8_t> > utm(3, std::vector<uint8_t>(size));
      std::vector<std::shared_ptr<SqliteAsyncCompletion> > completions;
      const uint64_t offsets[] = {0, 2000000, 2000080, 6000080};
      const uint64_t lengths[] = {2000000, 80, 2000000, 2000000};
      std::vector<Task> later;
      for (unsigned i = 0; i < 4; ++i) {
        auto completion = std::make_shared<SqliteAsyncCompletion>(1);
        completions.push_back(completion);
        const unsigned worker = i < 2 ? 0 : i - 1;
        const unsigned slot = i == 1 ? 1 : 0;
        Task t = task_for(utm[worker].data(), size, slot, 0, completion);
        auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
            t.utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot));
        ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
        ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
        t.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
        t.request.workload = GROUP_PMP_SQLITE_FILLSEQ;
        t.request.file_id = 1;
        t.request.worker_index = worker; t.request.worker_count = 3;
        t.request.run_id = worker + 1;
        t.request.file_offset = offsets[i]; t.request.length = lengths[i];
        t.request.reserved[1] = offsets[i]; t.request.sequence = i + 1;
        memset(t.data(), 0x31 + i, lengths[i]);
        if (!i) impl.pipeline_begin({t});
        else later.push_back(t);
      }
      impl.pipeline_begin(std::move(later));
      auto plan = impl.pipeline_batches_.back();
      // Model a valid arrived plan whose unrelated interval is at its head.
      // The payload/group references stay fixed, just as after metadata resolution.
      const size_t last = plan->operations.size() - 1;
      std::swap(plan->operations[0], plan->operations[last]);
      std::swap(plan->operation_groups[0], plan->operation_groups[last]);
      assert(impl.pipeline_refill());
      while (!impl.flights_.empty()) {
        if (!impl.pipeline_reap()) {
          struct pollfd p{impl.ring_.descriptor(), POLLIN, 0};
          assert(poll(&p, 1, 5000) > 0);
        }
        impl.pipeline_publish(); impl.pipeline_retire();
      }
      assert(impl.pipeline_batches_.empty());
      const auto stats = impl.snapshot();
      assert(stats.logical_request_count == 4);
      assert(stats.physical_request_count == (adaptive ? 2 : 4));
      if (adaptive) {
        assert(stats.pipeline[SQLITE_PIPELINE_SEQ_NONHEAD_JOINS] > 0);
        assert(stats.pipeline[SQLITE_PIPELINE_SEQ_TAIL_JOINS] > 0);
      }
      if (!adaptive) assert(stats.pipeline[SQLITE_PIPELINE_SEQ_LOCAL_CHECKS] == 0);
      for (auto& c : completions) assert(c->isComplete());
      std::vector<uint8_t> data(2000000);
      for (unsigned i = 0; i < 4; ++i) {
        assert(pread(impl.files_[1], data.data(), lengths[i], offsets[i]) ==
            static_cast<ssize_t>(lengths[i]));
        for (uint64_t b = 0; b < lengths[i]; ++b) assert(data[b] == 0x31 + i);
      }
      assert(stats.physical_io_bytes == 6000080 && stats.useful_io_bytes == 6000080);
    }
  }
  DIR* dir = opendir(directory); assert(dir);
  while (dirent* e = readdir(dir))
    if (e->d_name[0] != '.') assert(unlink((std::string(directory) + "/" + e->d_name).c_str()) == 0);
  closedir(dir); assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("packed-tail WRITEV: actual offsets, non-head peer, holes excluded, release guard, fixed Async PASS");
}

static void cross_boundary_real_io() {
  char directory[] = "/tmp/sqlite-boundary-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  const size_t size = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
  std::vector<std::vector<uint8_t> > utm(2, std::vector<uint8_t>(size));
  for (const char* mode : {"async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
      const bool read = scenario != 0;
      const bool misleading_hint = scenario == 2;
      SqliteExtentIoService::Impl impl(false);
      const int fd = impl.file_for(1);
      assert(fd >= 0);
      std::vector<uint8_t> disk(8 * 4096);
      for (size_t i = 0; i < disk.size(); ++i) disk[i] = 0x65 + i / 4096;
      assert(pwrite(fd, disk.data(), disk.size(), 0) == static_cast<ssize_t>(disk.size()));
      std::vector<Task> tasks;
      std::vector<std::shared_ptr<SqliteAsyncCompletion> > completions;
      unsigned wakes[2] = {0, 0};
      for (unsigned w = 0; w < 2; ++w) {
        auto completion = std::make_shared<SqliteAsyncCompletion>(2);
        completion->arm([&, w](bool) { ++wakes[w]; }, w);
        completions.push_back(completion);
        auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
            utm[w].data() + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(0));
        memset(ring, 0, sizeof(*ring));
        ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
        ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
        for (unsigned i = 0; i < 2; ++i) {
          Task t = task_for(utm[w].data(), size, 0, i, completion);
          t.case_epoch = 1; t.request.run_id = 101 + w;
          t.request.worker_count = 2; t.request.worker_index = w;
          t.request.file_id = 1; t.request.sequence = i + 1;
          t.request.workload = read ? GROUP_PMP_SQLITE_READRANDOM : GROUP_PMP_SQLITE_FILLRANDOM;
          t.request.file_offset = (i * 4 + w * (misleading_hint ? 2 : 1)) * 4096;
          t.request.reserved[1] = i * 4096;
          t.request.length = 4096; t.request.logical_size = disk.size();
          t.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + i * 4096;
          t.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
          memset(t.data(), 0x31 + w * 2 + i, 4096);
          tasks.push_back(t);
        }
      }
      std::vector<Task*> ptrs;
      for (auto& t : tasks) ptrs.push_back(&t);
      if (read) {
        assert(impl.commit_writes(ptrs));
        for (auto& t : tasks) {
          t.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
          if (misleading_hint && t.request.worker_index) t.request.file_offset -= 4096;
        }
      }
      impl.ewma_request_latency_ns_.store(2000000);
      for (const auto& t : tasks) impl.queue_.push_back(t);
      const size_t arrived = impl.queue_.size();
      auto batch = impl.take_ready_batch_locked(2, true, arrived);
      assert(batch.size() == 2); // Same admission fence, even if the next buffer has neighbours.
      impl.pipeline_begin(std::move(batch));
      impl.pipeline_begin(impl.take_ready_batch_locked(2, true, 2));
      assert(impl.queue_.empty());
      assert(impl.pipeline_refill());
      while (!impl.flights_.empty()) {
        if (!impl.pipeline_reap()) {
          struct pollfd p{impl.ring_.descriptor(), POLLIN, 0};
          assert(poll(&p, 1, 5000) > 0);
        }
        impl.pipeline_publish(); impl.pipeline_retire();
      }
      const auto stats = impl.snapshot();
      assert(stats.logical_request_count == 4);
      const unsigned physical = 4; // Sparse 4 KB plans do not acquire another whole buffer.
      assert(stats.physical_request_count == physical);
      assert(stats.pipeline[SQLITE_PIPELINE_SQES_ACCEPTED] == physical);
      assert(stats.pipeline[SQLITE_PIPELINE_SUBMITS] == 1);
      assert(stats.pipeline[SQLITE_PIPELINE_ENTER_CALLS] >= 1);
      assert(stats.pipeline[SQLITE_PIPELINE_ARRIVED_EXTEND_REQUESTS] == 0);
      assert(stats.physical_io_bytes == 16384 && stats.logical_request_count == 4);
      assert(stats.cross_worker_extent_count == 0);
      for (unsigned w = 0; w < 2; ++w) {
        assert(completions[w]->isComplete() && wakes[w] == 1);
        for (unsigned i = 0; i < 2; ++i) {
          const auto& t = tasks[w * 2 + i];
          if (read) {
            const size_t actual_offset = t.request.file_offset + (misleading_hint && w ? 4096 : 0);
            assert(memcmp(t.data(), disk.data() + actual_offset, 4096) == 0);
          }
          else {
            std::array<uint8_t, 4096> result;
            assert(pread(fd, result.data(), result.size(), t.request.file_offset) == 4096);
            assert(memcmp(result.data(), t.data(), 4096) == 0);
          }
        }
      }
      assert(!impl.pipeline_publish() && impl.pipeline_batches_.empty());
    }
  }
  DIR* dir = opendir(directory); assert(dir);
  while (dirent* e = readdir(dir))
    if (e->d_name[0] != '.') assert(unlink((std::string(directory) + "/" + e->d_name).c_str()) == 0);
  closedir(dir); assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("real sparse cross-boundary read/write: shared two-request fence, four I/Os, one submit, no extra buffer admitted PASS");
}

static void bounded_plan_boundaries() {
  char directory[] = "/tmp/sqlite-planned-boundaries-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  setenv("GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC", "1", 1);
  auto& trace = sqlite_gantt_trace();
  const std::string trace_path = std::string(directory) + "/neighbors.csv";
  assert(trace.configureOutput(trace_path.c_str()));
  uint64_t case_id = 0;
  for (const char* mode : {"async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    const bool adaptive = std::string(mode) == "adaptive-extent";
    // No pressure, SQE pressure, byte pressure, sparse/phase/4KiB exclusions.
    for (unsigned scenario = 0; scenario < 6; ++scenario) {
      const bool pressure = scenario != 0;
      const bool small = scenario == 5;
      const uint64_t length = small ? 4096 : 100000;
      const uint64_t workload = small ? GROUP_PMP_SQLITE_READRANDOM : GROUP_PMP_SQLITE_READRAND100K;
      trace.beginCase(++case_id, 1, workload, 3, adaptive ? 0 : 2);
      trace.beginWindow(1);
      SqliteExtentIoService::Impl impl(false);
      impl.ewma_request_latency_ns_.store(100000000);
      impl.ewma_bandwidth_bytes_per_sec_.store(200000000);
      const size_t size = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
      std::vector<std::vector<uint8_t> > utm(3, std::vector<uint8_t>(size));
      std::vector<Task> tasks;
      unsigned wakes[3] = {};
      for (unsigned w = 0; w < 3; ++w) {
        auto c = std::make_shared<SqliteAsyncCompletion>(1);
        c->arm([&, w](bool) { ++wakes[w]; }, w);
        Task t = task_for(utm[w].data(), size, 0, 0, c);
        auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
            utm[w].data() + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(0));
        ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
        ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
        t.case_epoch = scenario == 4 && w == 1 ? 2 : 1;
        t.request.run_id = 101 + w; t.request.worker_count = 3; t.request.worker_index = w;
        t.request.workload = workload; t.request.file_id = 1;
        t.request.file_offset = (w == 2 ? 8 : scenario == 3 ? w * 3 : w) * length;
        t.request.reserved[1] = t.request.file_offset;
        t.request.length = length; t.request.logical_size = 10 * length;
        t.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
        tasks.push_back(t);
      }
      const int fd = impl.file_for(1);
      std::vector<uint8_t> disk(10 * length);
      for (size_t b = 0; b < disk.size(); ++b) disk[b] = static_cast<uint8_t>(b / length + 31);
      assert(pwrite(fd, disk.data(), disk.size(), 0) == static_cast<ssize_t>(disk.size()));
      assert(impl.commit_writes({&tasks[0], &tasks[1], &tasks[2]}));
      for (Task& t : tasks) {
        t.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
        // Read hint deliberately differs from the database's real offset.
        t.request.file_offset += 32;
      }
      auto begin = [&](unsigned w) {
        auto& t = tasks[w]; t.enqueue_ns = now_ns();
        trace.recordRequest(SQLITE_GANTT_QUEUE_ENQUEUE, t.request, t.completion->trace_id, 0, 0, t.enqueue_ns);
        impl.pipeline_begin({t});
      };
      auto drain = [&]() {
        while (!impl.flights_.empty()) {
          if (!impl.pipeline_reap()) {
            struct pollfd p{impl.ring_.descriptor(), POLLIN, 0};
            assert(poll(&p, 1, 5000) > 0);
          }
          impl.pipeline_publish(); impl.pipeline_retire();
        }
      };
      if (pressure) {
        impl.pipeline_depth_.target = scenario == 2 ? 64 : 1;
        impl.pipeline_depth_.byte_limit = scenario == 2 ? length : 16000000;
        begin(2); assert(impl.pipeline_refill());
      }
      begin(0); begin(1);
      if (pressure) {
        assert(!impl.pipeline_refill()); // Existing flights, no synthetic delay.
        for (const auto& plan : impl.pipeline_batches_)
          if (plan->next < plan->operations.size())
            assert(plan->boundary_backpressure == (adaptive && !small));
        drain();
        impl.pipeline_depth_.target = 64;
        impl.pipeline_depth_.byte_limit = 16000000;
      }
      assert(impl.pipeline_refill());
      drain();
      const bool joined = adaptive && (scenario == 1 || scenario == 2);
      const auto stats = impl.snapshot();
      assert(stats.physical_request_count == UINT64_C(2) + pressure - joined);
      assert(stats.pipeline[SQLITE_PIPELINE_BOUNDARY_CROSS_PLAN_JOINS] == (joined ? 1 : 0));
      assert(stats.sequential_extent_count == 0); // 100KB merges are not sequential extents.
      if (small || !adaptive) {
        assert(stats.pipeline[SQLITE_PIPELINE_BOUNDARY_SNAPSHOTS] == 0);
        assert(stats.pipeline[SQLITE_PIPELINE_BOUNDARY_PROBES] == 0);
        assert(stats.pipeline[SQLITE_PIPELINE_BOUNDARY_MATCH_NS] == 0);
      }
      for (unsigned w = 0; w < (pressure ? 3 : 2); ++w) {
        assert(tasks[w].completion->isComplete() && wakes[w] == 1);
        assert(!memcmp(tasks[w].data(), disk.data() + tasks[w].request.file_offset - 32, length));
      }
      assert(impl.pipeline_batches_.empty());
      trace.endWindow(true); assert(trace.flushCase());
      assert(trace.droppedEvents() == 0 && trace.sampledRequestEvents() == 0);
    }
  }
  // The audit consumes actual resolved offsets, not untrusted read hints.
  assert(std::system(("python3 analyze-sqlite-neighbors.py " + trace_path +
                     " --output " + directory + "/audit.json").c_str()) == 0);
  unsetenv("GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC");
  assert(trace.configureOutput(nullptr));
  DIR* dir = opendir(directory); assert(dir);
  while (dirent* e = readdir(dir))
    if (e->d_name[0] != '.') assert(unlink((std::string(directory) + "/" + e->d_name).c_str()) == 0);
  closedir(dir); assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("policy41 boundaries: natural SQE/byte pressure, resolved 100KB 2->1, no-pressure/sparse/epoch/fixed-Async fences, zero 4KB probes, real trace audit PASS");
}

static void read_ready_boundary_regression() {
  char directory[] = "/tmp/sqlite-ready-read-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  setenv("GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC", "1", 1);
  auto& trace = sqlite_gantt_trace();
  const std::string trace_path = std::string(directory) + "/ready-read.csv";
  assert(trace.configureOutput(trace_path.c_str()));
  uint64_t case_id = 0;
  for (const char* mode : {"async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    const bool adaptive = std::string(mode) == "adaptive-extent";
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
      const bool small = scenario == 2;
      const uint64_t length = small ? 100000 : 2000000;
      const unsigned count = small ? 2 : 5;
      trace.beginCase(++case_id, 1, small ? GROUP_PMP_SQLITE_READRAND100K : GROUP_PMP_SQLITE_READSEQ,
          count, adaptive ? 0 : 2);
      trace.beginWindow(1);
      const bool joint_admission = !small;
      SqliteExtentIoService::Impl impl(false);
      impl.adaptive_batch_max_ = 1; // Expose a plan boundary without extra requests.
      impl.ewma_request_latency_ns_.store(100000000);
      std::vector<std::vector<uint8_t> > utm(count, std::vector<uint8_t>(GROUP_PMP_SQLITE_VFS_UTM_BYTES));
      std::vector<Task> tasks;
      unsigned wakes[5] = {};
      for (unsigned w = 0; w < count; ++w) {
        auto completion = std::make_shared<SqliteAsyncCompletion>(1);
        completion->arm([&, w](bool) { ++wakes[w]; }, w);
        Task t = task_for(utm[w].data(), utm[w].size(), 0, 0, completion);
        auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
            t.utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(0));
        ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
        ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
        t.case_epoch = 1; t.request.run_id = 300 + w;
        t.request.worker_index = w; t.request.worker_count = count;
        t.request.workload = small ? GROUP_PMP_SQLITE_READRAND100K : GROUP_PMP_SQLITE_READSEQ;
        t.request.file_id = 1; t.request.length = length;
        t.request.file_offset = (w == 4 ? (scenario == 0 ? 1 : 11) : w * 3) * length;
        t.request.reserved[1] = w * length;
        t.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
        tasks.push_back(t);
      }
      std::vector<uint8_t> disk(12 * length, 0x72);
      const int fd = impl.file_for(1);
      assert(pwrite(fd, disk.data(), disk.size(), 0) == static_cast<ssize_t>(disk.size()));
      std::vector<Task*> ptrs;
      for (auto& t : tasks) ptrs.push_back(&t);
      assert(impl.commit_writes(ptrs));
      for (Task& t : tasks) {
        t.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
        // Actual adjacent ranges exist even though hints look distant.
        t.request.file_offset += (t.request.worker_index + 1) * 100 * length;
        t.enqueue_ns = now_ns(); impl.queue_.push_back(t);
        trace.recordRequest(SQLITE_GANTT_QUEUE_ENQUEUE, t.request, t.completion->trace_id, 0, 0, t.enqueue_ns);
      }
      if (joint_admission) {
        SqliteNeighborAdmissionReason reason = SQLITE_NEIGHBOR_ACCEPT;
        assert(!impl.pipeline_arrived_readseq_share(count, &reason));
        assert(reason == SQLITE_NEIGHBOR_NO_PENDING_PLAN);
        const auto target = impl.pipeline_depth_.target;
        impl.pipeline_depth_.target = 0;
        assert(!impl.pipeline_arrived_readseq_share(count, &reason));
        assert(reason == SQLITE_NEIGHBOR_SQE_CREDIT);
        impl.pipeline_depth_.target = target;
        const auto bytes = impl.pipeline_depth_.byte_limit;
        impl.pipeline_depth_.byte_limit = 0;
        assert(!impl.pipeline_arrived_readseq_share(count, &reason));
        assert(reason == SQLITE_NEIGHBOR_BYTE_CREDIT);
        impl.pipeline_depth_.byte_limit = bytes;
      }
      assert(impl.pipeline_admit_ready());
      assert(impl.pipeline_batches_.size() == (joint_admission ? 2 : 1));
      assert(impl.queue_.size() == (joint_admission ? 0 : count - (!small ? 4 : 1)));
      assert(impl.pipeline_refill());
      const uint64_t checks = impl.snapshot().pipeline[SQLITE_PIPELINE_COMPLETION_BUFFER_CHECKS];
      for (unsigned i = 0; i < 16; ++i) assert(!impl.pipeline_publish());
      const uint64_t repeated = impl.snapshot().pipeline[SQLITE_PIPELINE_COMPLETION_BUFFER_CHECKS] - checks;
      if (small) assert(repeated == 1);
      printf("ready-read diagnosis: policy=%llu adaptive=%d scenario=%u first_plans=%zu repeated_checks=%llu\n",
          static_cast<unsigned long long>(kGroupPmpSqliteExtentIoPolicyVersion), adaptive,
          scenario, impl.pipeline_batches_.size(), static_cast<unsigned long long>(repeated));
      while (!impl.pipeline_batches_.empty() || !impl.queue_.empty()) {
        if (!impl.flights_.empty() && !impl.pipeline_reap()) {
          struct pollfd p{impl.ring_.descriptor(), POLLIN, 0}; assert(poll(&p, 1, 5000) > 0);
          continue;
        }
        impl.pipeline_publish(); impl.pipeline_retire();
        impl.pipeline_admit_ready(); impl.pipeline_refill();
      }
      const auto stats = impl.snapshot();
      assert(stats.pipeline[SQLITE_PIPELINE_SUBMITS] == (joint_admission ? 1 : !small ? 2 : count));
      assert(stats.physical_request_count == count - (adaptive && joint_admission && scenario == 0 ? 1 : 0));
      assert(stats.pipeline[SQLITE_PIPELINE_SEQ_READ_READY_ADMISSIONS] == (joint_admission ? 1 : 0));
      assert(stats.pipeline[SQLITE_PIPELINE_SEQ_READ_SHARED_SUBMITS] == (joint_admission ? 1 : 0));
      assert(stats.pipeline[SQLITE_PIPELINE_READ100K_VECTOR_PREPARATIONS] == (small ? count : 0));
      for (unsigned w = 0; w < count; ++w) {
        assert(tasks[w].completion->isComplete() && wakes[w] == 1);
        assert(!memcmp(tasks[w].data(), disk.data(), length));
      }
      trace.endWindow(true); assert(trace.flushCase());
      assert(trace.droppedEvents() == 0 && trace.sampledRequestEvents() == 0);
    }
  }
  const std::string audit_path = std::string(directory) + "/audit.json";
  assert(std::system(("python3 analyze-sqlite-neighbors.py " + trace_path + " --output " + audit_path).c_str()) == 0);
  if (const char* output = std::getenv("GROUP_PMP_TEST_DIAG_DIR")) {
    for (const auto& input : {trace_path, audit_path}) {
      std::ifstream source(input, std::ios::binary);
      std::ofstream dest(std::string(output) + (input == trace_path ? "/ready-read.csv" : "/ready-read-audit.json"), std::ios::binary);
      dest << source.rdbuf(); assert(source.good() && dest.good());
    }
  }
  unsetenv("GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC");
  assert(trace.configureOutput(nullptr));
  DIR* dir = opendir(directory); assert(dir);
  while (dirent* e = readdir(dir))
    if (e->d_name[0] != '.') assert(unlink((std::string(directory) + "/" + e->d_name).c_str()) == 0);
  closedir(dir); assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("read-ready boundary reproduction: resolved offsets, separate plans, fixed Async, independent publication PASS");
}

static void registered_contiguous_vector_fold() {
  SqliteExtentIoService::Impl impl(false);
  std::array<uint8_t, 16384> utm{};
  impl.registered_utm_buffers_.push_back({utm.data(), 8192});
  impl.utm_buffers_registered_ = true;
  InlineOneList<iovec> adjacent;
  adjacent.push_back({utm.data(), 4096});
  adjacent.push_back({utm.data() + 4096, 4096});
  impl.fold_contiguous_vectors(&adjacent, 8192);
  assert(adjacent.size() == 1 && adjacent[0].iov_len == 8192);
  assert(impl.fixed_buffer_for_vectors(adjacent) == 0);

  InlineOneList<iovec> gap;
  gap.push_back({utm.data(), 4096});
  gap.push_back({utm.data() + 8192, 4096});
  impl.fold_contiguous_vectors(&gap, 8192);
  assert(gap.size() == 2 && impl.fixed_buffer_for_vectors(gap) == -1);

  InlineOneList<iovec> outside;
  outside.push_back({utm.data() + 4096, 4096});
  outside.push_back({utm.data() + 8192, 4096});
  impl.fold_contiguous_vectors(&outside, 8192);
  assert(outside.size() == 2);
  puts("registered contiguous FIXED fold and gap/region guards PASS");
}

int main() {
  PublicationHistogram histogram;
  assert(histogram.snapshot() == std::make_pair(UINT64_C(0), UINT64_C(0)));
  for (unsigned i = 1; i <= 100; ++i) histogram.record(i * 1000);
  const auto percentile = histogram.snapshot();
  assert(percentile.first == 100 && percentile.second >= 95000 && percentile.second <= 100937);
  histogram.reset();
  histogram.record(UINT64_MAX);
  assert(histogram.snapshot().second == UINT64_MAX);
  histogram.reset();
  assert(!histogram.snapshot().first);
  write_service_depth_feedback();
  registered_contiguous_vector_fold();
  assert(sqlite_io_path_probe(5) == 0);
  // Safety/ownership fixtures use an explicitly high fixed-operation cost.
  // Production defaults are evaluated separately by the planner study/probe.
  setenv("GROUP_PMP_SQLITE_MERGE_READ_SAVED_NS", "1000000000", 1);
  setenv("GROUP_PMP_SQLITE_MERGE_WRITE_SAVED_NS", "1000000000", 1);
  adaptive_metadata_updates();
  bounded_completion_drain();
  setenv("GROUP_PMP_SQLITE_IO_MODE", "async-no-extent", 1);
  depth_feedback();
  raw_inflight();
  overwrite_submit_accounting();
  setenv("GROUP_PMP_SQLITE_IO_MODE", "async-no-extent", 1);
  independent_buffers();
  independent_buffers(true);
  arrived_buffer_publication();
  write_barriers_and_errors();
  ready_sequential_plans();
  ready_sequential_plans(true);
  missing_neighbor_diagnostics();
  sequential_lookahead_guards();
  admission_and_budget_diagnostics();
  low_gain_merge_retirement();
  producer_ack_reservation();
  incremental_completion_checks();
  incremental_completion_checks(true);
  cross_worker_collection_guards();
  cross_worker_real_io();
  arrived_local_candidates();
  buffer_release_cost();
  packed_tail_real_io();
  cross_boundary_real_io();
  bounded_plan_boundaries();
  read_ready_boundary_regression();
}
