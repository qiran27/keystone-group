#include <bits/stdc++.h>
#include <cassert>
/* Expose internals only in this test TU. Execute the real planner synchronously
 * so cross-worker adjacency tests do not depend on host thread timing. */
#define private public
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsubobject-linkage"
#include "../host/sqlite-extent-io.cpp"
#pragma GCC diagnostic pop
#undef private

static void check_io_clock(const SqliteIoPerfSnapshot& stats) {
  assert(stats.disk_io_ns >= stats.completion_wait_ns);
  assert(stats.disk_io_ns >= stats.submit_ns);
  if (!stats.posix_fallback_operations)
    assert(stats.disk_io_ns == stats.submit_ns + stats.completion_wait_ns);
}

static Task overlap_write(uint64_t file, uint64_t sequence, uint64_t start,
                          uint64_t length) {
  Task task;
  task.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
  task.request.workload = GROUP_PMP_SQLITE_OVERWRITE;
  task.request.file_id = task.stored_file_id = file;
  task.request.sequence = sequence;
  task.request.file_offset = task.storage_offset = task.io_offset = start;
  task.request.length = task.storage_length = task.io_length = length;
  return task;
}

static void reset_overlap_stats(SqliteExtentIoService::Impl& service) {
  assert(service.resetPerf());
  const auto stats = service.snapshot();
  assert(stats.write_overlap_checks == 0);
  assert(stats.write_overlap_check_ns == 0);
  assert(stats.write_disjoint_batches == 0);
  assert(stats.write_overlap_batches == 0);
  assert(stats.deduplicated_request_count == 0);
  assert(stats.random_sparse_fast_batches == 0 && stats.random_precheck_ns == 0);
  assert(stats.readseq_initial_requests == 0 && stats.readseq_refill_peer_io_requests == 0);
}

static void test_sparse_precheck() {
  SparsePagePrecheck precheck;
  std::mt19937 random(0x73706172);
  uint64_t checks = 0;
  std::vector<Task> storage(512);
  std::vector<Task*> tasks;
  for (size_t i = 0; i < storage.size(); ++i) {
    storage[i] = overlap_write(1, i + 1, i * 16384, 4096);
    tasks.push_back(&storage[i]);
  }
  for (unsigned repeat = 0; repeat < 32; ++repeat) {
    std::shuffle(tasks.begin(), tasks.end(), random);
    assert(precheck.inspect(tasks, 1100, &checks) == SparsePagePrecheck::kSparse);
    assert(checks < tasks.size() * 24);
  }
  auto inspect_pair = [&](Task a, Task b, uint64_t amp = 1100) {
    std::vector<Task*> pair{&a, &b};
    return precheck.inspect(pair, amp, &checks);
  };
  Task a = overlap_write(1, 1, 0, 4096);
  Task b = overlap_write(1, 2, 4096, 4096);
  assert(inspect_pair(a, b) == SparsePagePrecheck::kCandidate);
  assert(inspect_pair(b, a) == SparsePagePrecheck::kCandidate);
  assert(inspect_pair(a, a) == SparsePagePrecheck::kCandidate);
  b = overlap_write(1, 2, 8192, 4096);
  assert(inspect_pair(a, b) == SparsePagePrecheck::kSparse);
  Task packed = b;
  packed.storage_offset = packed.io_offset = 8192 - 80;
  assert(inspect_pair(a, packed) == SparsePagePrecheck::kInconclusive);
  // Layout v3 keeps the short tail out of the full-page permutation.
  packed.storage_offset = packed.io_offset = 8192;
  assert(inspect_pair(a, packed) == SparsePagePrecheck::kSparse);
  assert(inspect_pair(a, b, 1499) == SparsePagePrecheck::kSparse);
  assert(inspect_pair(a, b, 1500) == SparsePagePrecheck::kInconclusive);
  for (unsigned kind = 0; kind < 7; ++kind) {
    Task odd = b;
    if (kind == 0) odd.storage_length = odd.io_length = 16;
    if (kind == 1) ++odd.io_offset;
    if (kind == 2) odd.stored_file_id = 2;
    if (kind == 3) odd.io_length = 0;
    if (kind == 4) odd.io_offset = odd.storage_offset = UINT64_MAX - 4095;
    if (kind == 5) odd.result = -EIO;
    if (kind == 6) odd.superseded = true;
    assert(inspect_pair(a, odd) == SparsePagePrecheck::kInconclusive);
  }
  // Probe-budget exhaustion is inconclusive, never a disjoint certificate.
  for (auto& entry : precheck.entries_) {
    entry.generation = precheck.generation_ + 1;
    entry.page = UINT64_MAX;
  }
  assert(precheck.inspect(tasks, 1100, &checks) == SparsePagePrecheck::kInconclusive);
  precheck.generation_ = UINT64_MAX;
  assert(precheck.inspect(tasks, 1100, &checks) == SparsePagePrecheck::kSparse);
  for (unsigned trial = 0; trial < 128; ++trial) {
    bool candidate = false;
    for (size_t i = 0; i < storage.size(); ++i) {
      storage[i] = overlap_write(1, i, (random() % 8192) * UINT64_C(4096), 4096);
      for (size_t j = 0; j < i; ++j) {
        uint64_t x = storage[i].io_offset, y = storage[j].io_offset;
        if ((x > y ? x - y : y - x) <= 4096)
          candidate = true;
      }
    }
    std::vector<Task*> candidates, isolated;
    auto result = precheck.inspect(tasks, 1100, &checks, &candidates, &isolated);
    assert(result != SparsePagePrecheck::kSparse || !candidate);
    assert(result != SparsePagePrecheck::kCandidate || candidate);
    if (result != SparsePagePrecheck::kInconclusive) {
      assert(candidates.size() + isolated.size() == tasks.size());
      for (const auto* task : tasks) {
        bool local = false;
        for (const auto* other : tasks) {
          if (other == task) continue;
          const uint64_t a = task->io_offset, b = other->io_offset;
          local |= (a > b ? a - b : b - a) <= 4096;
        }
        assert(local == (std::find(candidates.begin(), candidates.end(), task) !=
                            candidates.end()));
      }
    } else {
      assert(candidates.empty() && isolated.empty());
    }
  }
  for (size_t i = 0; i < storage.size(); ++i)
    storage[i] = overlap_write(1, i, i * 16384, 4096);
  storage[1] = overlap_write(1, 1, 4096, 4096);
  for (unsigned repeat = 0; repeat < 32; ++repeat) {
    std::vector<Task*> candidates, isolated;
    std::shuffle(tasks.begin(), tasks.end(), random);
    assert(precheck.inspect(tasks, 1100, &checks, &candidates, &isolated) ==
           SparsePagePrecheck::kCandidate);
    assert(candidates.size() == 2 && isolated.size() == 510);
    assert(checks < tasks.size() * 24);
  }
  for (unsigned repeat = 0; repeat < 32; ++repeat) {
    for (size_t i = 0; i < storage.size(); ++i)
      storage[i] = overlap_write(1, i, (i < 128 ? i : i * 4) * 4096, 4096);
    std::shuffle(tasks.begin(), tasks.end(), random);
    std::vector<Task*> ordered;
    size_t candidates = 0;
    assert(precheck.order_pages(tasks, &checks, &ordered, &candidates));
    assert(candidates == 128 && ordered.size() == 512);
    for (size_t i = 0; i < candidates; ++i) assert(ordered[i]->io_offset == i * 4096);
    assert(std::set<Task*>(ordered.begin(), ordered.end()).size() == tasks.size());
    storage[1].io_offset = storage[1].storage_offset = 0;
    assert(!precheck.order_pages(tasks, &checks, &ordered, &candidates));
  }
  puts("sparse certificate and direct chain emission: shuffled chains, isolated pages, duplicates, bounds PASS");
}

static void test_interval_candidates() {
  SparsePagePrecheck precheck;
  std::mt19937 random(22);
  uint64_t checks = 0;
  std::vector<Task> storage(512);
  std::vector<Task*> tasks, candidates, isolated;
  for (size_t i = 0; i < storage.size(); ++i) {
    storage[i] = overlap_write(1, i, i * UINT64_C(1048576), 100000);
    storage[i].request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    tasks.push_back(&storage[i]);
  }
  for (size_t round = 0; round < 20; ++round) {
    std::shuffle(tasks.begin(), tasks.end(), random);
    assert(precheck.inspect_intervals(tasks, &checks, &candidates, &isolated) ==
        SparsePagePrecheck::kSparse);
    assert(candidates.empty() && isolated.size() == 512 && checks < 20000);
  }
  storage[1].io_offset = storage[1].storage_offset = 100000;
  for (size_t round = 0; round < 20; ++round) {
    std::shuffle(tasks.begin(), tasks.end(), random);
    assert(precheck.inspect_intervals(tasks, &checks, &candidates, &isolated) ==
        SparsePagePrecheck::kCandidate);
    assert(candidates.size() == 2 && isolated.size() == 510);
  }
  storage[1].io_offset = storage[1].storage_offset = 104000;
  assert(precheck.inspect_intervals(tasks, &checks, &candidates, &isolated) ==
      SparsePagePrecheck::kCandidate);
  assert(candidates.size() == 2);
  for (size_t round = 0; round < 40; ++round) {
    for (Task& task : storage) {
      task.io_offset = task.storage_offset = (random() % 16000) * UINT64_C(10000);
      task.io_length = 16 + (random() % 100000);
    }
    const auto result = precheck.inspect_intervals(tasks, &checks, &candidates, &isolated);
    if (result == SparsePagePrecheck::kInconclusive) continue;
    for (const Task* a : isolated)
      for (const Task* b : tasks)
        if (a != b)
          assert(a->io_offset > b->io_offset + b->io_length ||
                 b->io_offset > a->io_offset + a->io_length);
  }
  storage[0].io_offset = UINT64_MAX - 16;
  storage[0].io_length = 32;
  assert(precheck.inspect_intervals(tasks, &checks, &candidates, &isolated) ==
      SparsePagePrecheck::kInconclusive);
  assert(candidates.empty() && isolated.empty());
  puts("100 KB interval candidates: bounded sparse/adjacent/overlap/overflow PASS");
}

static bool check_write_overlap_case(SqliteExtentIoService::Impl& service,
                                      std::vector<Task> storage) {
  const std::vector<Task> original = storage;
  std::vector<bool> eligible(storage.size(), false);
  std::vector<bool> superseded(storage.size(), false);
  std::vector<int> results(storage.size());
  size_t valid_writes = 0;
  for (size_t i = 0; i < original.size(); ++i) {
    const Task& task = original[i];
    results[i] = task.result;
    superseded[i] = task.superseded;
    if (task.result || task.superseded ||
        task.request.operation != GROUP_PMP_SQLITE_VFS_OP_WRITE)
      continue;
    if (task.storage_length > UINT64_MAX - task.storage_offset) {
      results[i] = -EOVERFLOW;
      continue;
    }
    eligible[i] = true;
    ++valid_writes;
  }
  // Original semantics: one strictly newer write must cover the entire range.
  // Consult the immutable input, never the planner's sorted or filtered output.
  uint64_t removed = 0;
  for (size_t i = 0; i < original.size(); ++i) {
    if (!eligible[i])
      continue;
    const Task& older = original[i];
    for (size_t j = 0; j < original.size(); ++j) {
      if (!eligible[j])
        continue;
      const Task& newer = original[j];
      if (newer.stored_file_id == older.stored_file_id &&
          newer.request.sequence > older.request.sequence &&
          newer.storage_offset <= older.storage_offset &&
          newer.storage_offset + newer.storage_length >=
              older.storage_offset + older.storage_length) {
        superseded[i] = true;
        ++removed;
        break;
      }
    }
  }
  bool had_overlap = false, remaining_overlap = false;
  for (size_t i = 0; i < original.size(); ++i) {
    for (size_t j = i + 1; j < original.size(); ++j) {
      if (!eligible[i] || !eligible[j])
        continue;
      const Task& a = original[i];
      const Task& b = original[j];
      if (a.stored_file_id == b.stored_file_id &&
          a.storage_offset < b.storage_offset + b.storage_length &&
          b.storage_offset < a.storage_offset + a.storage_length) {
        had_overlap = true;
        if (!superseded[i] && !superseded[j])
          remaining_overlap = true;
      }
    }
  }
  std::vector<Task*> tasks;
  for (auto& task : storage)
    tasks.push_back(&task);
  const auto before = service.snapshot();
  const uint64_t started = now_ns();
  const bool actual_overlap = service.eliminate_fully_overwritten_writes(tasks);
  const uint64_t elapsed = now_ns() - started;
  assert(actual_overlap == remaining_overlap);
  assert(tasks.size() == storage.size());
  for (size_t i = 0; i < storage.size(); ++i) {
    assert(storage[i].result == results[i]);
    assert(storage[i].superseded == superseded[i]);
    assert(storage[i].io_length ==
           (eligible[i] && superseded[i] ? 0 : original[i].io_length));
  }
  const auto after = service.snapshot();
  assert(after.deduplicated_request_count ==
         before.deduplicated_request_count + removed);
  assert(after.write_overlap_batches ==
         before.write_overlap_batches + (had_overlap ? 1 : 0));
  assert(after.write_disjoint_batches ==
         before.write_disjoint_batches + (valid_writes && !had_overlap ? 1 : 0));
  assert(after.write_overlap_checks >= before.write_overlap_checks);
  if (valid_writes)
    assert(after.write_overlap_checks > before.write_overlap_checks);
  assert(after.write_overlap_check_ns >= before.write_overlap_check_ns);
  assert(after.write_overlap_check_ns - before.write_overlap_check_ns <= elapsed);
  return actual_overlap;
}

static void test_write_overlap_planner(SqliteExtentIoService::Impl& service) {
  reset_overlap_stats(service);
  std::mt19937 random(0x6f766572);
  constexpr size_t count = 512;
  for (bool multiple_files : {false, true}) {
    std::vector<Task> storage;
    for (size_t i = 0; i < count; ++i) {
      const uint64_t file = multiple_files ? i % 4 : 0;
      const uint64_t start = multiple_files ? (i / 4) * 16 : i * 32;
      storage.push_back(overlap_write(file, random(), start, 16));
    }
    std::shuffle(storage.begin(), storage.end(), random);
    for (unsigned repeat = 0; repeat < 2; ++repeat) {
      const auto before = service.snapshot();
      assert(!check_write_overlap_case(service, storage));
      const auto after = service.snapshot();
      // Only interval/tree checks count, not sorting comparisons.
      assert(after.write_overlap_checks - before.write_overlap_checks < 4 * count);
      assert(after.write_disjoint_batches == before.write_disjoint_batches + 1);
    }
  }
  assert(service.snapshot().write_overlap_check_ns > 0);
  assert(service.snapshot().write_disjoint_batches == 4);
  assert(service.snapshot().write_overlap_batches == 0);
  puts("512-write shuffled disjoint/touching batches and bounded overlap checks PASS");

  reset_overlap_stats(service);
  assert(!check_write_overlap_case(service, {}));
  assert(!check_write_overlap_case(service, {overlap_write(0, 0, 0, 16)}));
  assert(!check_write_overlap_case(service, {
      overlap_write(1, 1, 32, 16), overlap_write(1, 3, 0, 128),
      overlap_write(1, 2, 16, 64)}));
  assert(service.snapshot().deduplicated_request_count == 2);
  // Equal sequences, including identical ranges and nested ranges, stay live.
  Task duplicate = overlap_write(1, UINT64_MAX, 0, 64);
  Task same_sequence = duplicate;
  duplicate.request.request_id = 1;
  same_sequence.request.request_id = 99;
  assert(check_write_overlap_case(service, {
      same_sequence, overlap_write(1, UINT64_MAX, 16, 16), duplicate}));
  assert(check_write_overlap_case(service, {
      overlap_write(1, UINT64_MAX - 1, 0, 64), same_sequence, duplicate}));
  assert(!check_write_overlap_case(service, {
      overlap_write(1, UINT64_MAX, 0, 64), overlap_write(1, 0, 0, 64)}));
  // Crossing intervals overlap, but neither covers the other. Touching does not.
  assert(check_write_overlap_case(service, {
      overlap_write(1, 2, 32, 64), overlap_write(1, 1, 0, 64)}));
  assert(!check_write_overlap_case(service, {
      overlap_write(1, 9, 64, 32), overlap_write(1, 3, 0, 32),
      overlap_write(1, 1, 32, 32), overlap_write(1, 7, 128, 16)}));
  // A union of newer writes is not a single fully covering write.
  assert(check_write_overlap_case(service, {
      overlap_write(1, 1, 0, 64), overlap_write(1, 2, 0, 32),
      overlap_write(1, 3, 32, 32)}));
  // The covering prefix maximum need not belong to the newest/nearest write.
  assert(check_write_overlap_case(service, {
      overlap_write(1, 5, 0, 128), overlap_write(1, 9, 16, 8),
      overlap_write(1, 2, 32, 16)}));
  assert(check_write_overlap_case(service, {
      overlap_write(1, 1, 0, 128), overlap_write(1, 9, 16, 8),
      overlap_write(1, 2, 32, 16)}));
  // Separate files and separate overlap components must not share tree state.
  assert(!check_write_overlap_case(service, {
      overlap_write(UINT64_MAX, 9, 0, 128), overlap_write(0, 1, 16, 16)}));
  assert(!check_write_overlap_case(service, {
      overlap_write(1, 9, 0, 64), overlap_write(1, 1, 16, 16),
      overlap_write(1, 2, 256, 64), overlap_write(1, 1, 272, 16),
      overlap_write(2, 0, 16, 16)}));
  // End == UINT64_MAX is valid; a wrapping end must never cover another task.
  assert(!check_write_overlap_case(service, {
      overlap_write(1, 1, UINT64_MAX - 16, 8),
      overlap_write(1, 2, UINT64_MAX - 32, 32)}));
  assert(!check_write_overlap_case(service, {
      overlap_write(1, 9, UINT64_MAX - 3, 8),
      overlap_write(1, 1, UINT64_MAX - 2, 1), overlap_write(1, 0, 0, 1)}));
  assert(!check_write_overlap_case(service, {
      overlap_write(1, UINT64_MAX, UINT64_MAX, 1)}));
  std::vector<Task> ignored;
  for (uint64_t sequence : {UINT64_C(0), UINT64_C(9)}) {
    Task task = overlap_write(1, sequence, 0, sequence ? 128 : 8);
    task.result = -EIO;
    ignored.push_back(task);
    task.result = 0;
    task.superseded = true;
    ignored.push_back(task);
    task.superseded = false;
    task.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    ignored.push_back(task);
  }
  assert(!check_write_overlap_case(service, ignored));
  ignored.push_back(overlap_write(1, 1, 0, 64));
  assert(!check_write_overlap_case(service, ignored));
  puts("strict-sequence coverage, duplicates, partial overlap, files and overflow PASS");

  reset_overlap_stats(service);
  constexpr size_t trials = 256;
  for (size_t trial = 0; trial < trials; ++trial) {
    std::vector<Task> storage;
    const size_t size = trial % 16 == 0 ? count : 1 + random() % 96;
    for (size_t i = 0; i < size; ++i) {
      uint64_t file = random() % 4;
      if (file == 3)
        file = UINT64_MAX;
      uint64_t sequence = random() % 12;
      if (sequence == 11)
        sequence = UINT64_MAX;
      uint64_t start = (random() % 32) * 16;
      if (trial % 3 == 1)
        start += UINT64_MAX - 2048;
      else if (trial % 3 == 2)
        start = i * 1024;
      Task task = overlap_write(file, sequence, start, 1 + random() % 512);
      if (i && random() % 4 == 0) {
        task = storage[random() % storage.size()];
        if (random() % 2)
          task.request.sequence = sequence;
      }
      if (i % 31 == 30) {
        task.storage_offset = UINT64_MAX - 3;
        task.storage_length = 8;
      }
      // Deliberately disagree with storage fields; only request.sequence orders
      // writes, not stored_sequence or request_id.
      task.request.file_id = 77;
      task.request.file_offset = random();
      task.request.length = 1;
      task.request.request_id = random();
      task.stored_sequence = UINT64_MAX - task.request.sequence;
      storage.push_back(task);
    }
    std::shuffle(storage.begin(), storage.end(), random);
    check_write_overlap_case(service, storage);
  }
  const auto stats = service.snapshot();
  assert(stats.write_overlap_batches > 0 && stats.write_disjoint_batches > 0);
  assert(stats.write_overlap_batches + stats.write_disjoint_batches == trials);
  assert(stats.deduplicated_request_count > 0 && stats.write_overlap_check_ns > 0);
  reset_overlap_stats(service);
  puts("256 deterministic write-overlap batches match brute-force coverage PASS");
}

static void test_write_overlap_contents(SqliteExtentIoService::Impl& service,
                                        uint8_t* const utms[2], size_t utm_size) {
  constexpr size_t page = 4096;
  constexpr uint64_t base = UINT64_C(8388608);
  for (bool partial : {false, true}) {
    Task initial = overlap_write(1, 0, base, 6 * page);
    initial.utm = utms[0];
    initial.utm_size = utm_size;
    initial.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
    memset(initial.data(), 0x5a, initial.storage_length);
    std::vector<Task*> tasks = {&initial};
    assert(service.execute_io(tasks));
    assert(initial.result == 0);
    reset_overlap_stats(service);

    // Newer starts earlier and arrives first: offset/input order would corrupt
    // the shared bytes if the partial-overlap ordered-write fallback is skipped.
    Task newer = overlap_write(1, 20, base + page, (partial ? 3 : 4) * page);
    Task older = overlap_write(1, 10, base + 2 * page, (partial ? 3 : 2) * page);
    size_t buffer = 0;
    for (Task* task : {&newer, &older}) {
      task->utm = utms[0];
      task->utm_size = utm_size;
      task->request.run_id = 1;
      task->request.worker_index = 0;
      task->request.worker_count = 2;
      task->request.buffer_offset = buffer++ ? GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET :
          GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
      memset(task->data(), task == &newer ? 0xb2 : 0xa1, task->storage_length);
    }
    tasks = {&newer, &older};
    assert(service.execute_io(tasks));
    assert(newer.result == 0 && older.result == 0);
    assert(!newer.superseded && older.superseded == !partial);
    assert(older.io_length == (partial ? older.storage_length : 0));
    const auto stats = service.snapshot();
    assert(stats.logical_request_count == 2);
    assert(stats.physical_request_count == (partial ? 2 : 1));
    assert(stats.physical_io_bytes == (partial ? 6 : 4) * page);
    assert(stats.deduplicated_request_count == (partial ? 0 : 1));
    assert(stats.write_overlap_batches == 1 && stats.write_disjoint_batches == 0);
    assert(stats.write_overlap_checks > 0);

    std::vector<uint8_t> expected(6 * page, 0x5a), actual(expected.size());
    std::fill(expected.begin() + page, expected.begin() + (partial ? 4 : 5) * page,
              0xb2);
    if (partial)
      std::fill(expected.begin() + 4 * page, expected.begin() + 5 * page, 0xa1);
    // Read the actual file independently of the service's read/cache planner.
    const int fd = service.file_for(1);
    assert(fd >= 0);
    assert(pread(fd, actual.data(), actual.size(), base) ==
           static_cast<ssize_t>(actual.size()));
    assert(actual == expected);

    // Different workers have no shared sequence clock. Never treat a higher
    // number from another owner as permission to supersede these writes.
    newer.pipeline_done = older.pipeline_done = false;
    newer.superseded = older.superseded = false;
    older.request.worker_index = 1;
    older.request.run_id = 2;
    tasks = {&newer, &older};
    assert(service.execute_io(tasks));
    assert(newer.result == -ESTALE && older.result == -ESTALE);
    assert(!newer.superseded && !older.superseded);
    assert(pread(fd, actual.data(), actual.size(), base) ==
           static_cast<ssize_t>(actual.size()));
    assert(actual == expected);
  }
  reset_overlap_stats(service);
  puts("same-owner write sequences, cross-owner overlap rejection and file guards PASS");
}

static void test_local_planner_contents(SqliteExtentIoService::Impl& service,
                                         uint8_t* const utms[2], size_t bytes) {
  constexpr size_t count = 512, page = 4096;
  constexpr uint64_t base = UINT64_C(16777216);
  std::vector<Task> storage(count);
  std::vector<Task*> tasks;
  for (size_t i = 0; i < count; ++i) {
    Task& t = storage[i];
    t = overlap_write(1, i + 1, base + i * 16384, page);
    t.utm = utms[i / 256];
    t.utm_size = bytes;
    t.request.worker_index = i / 256;
    t.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + (i % 256) * page;
    memset(t.data(), static_cast<int>(i % 251 + 1), page);
    tasks.push_back(&t);
  }
  storage[1].request.file_offset = base + page;
  std::mt19937 random(19);
  std::shuffle(tasks.begin(), tasks.end(), random);
  assert(service.resetPerf() && service.execute_io(tasks));
  auto stats = service.snapshot();
  assert(stats.logical_request_count == 512 && stats.physical_request_count == 511);
  assert(stats.random_local_candidate_requests == 2 && stats.random_sparse_fast_requests == 510);
  assert(stats.random_local_plan_batches == 1);
  assert(stats.write_overlap_checks == 2 * count - 1);
  std::array<uint8_t, page> actual;
  for (size_t i = 0; i < count; ++i) {
    assert(storage[i].result == 0);
    assert(pread(service.file_for(1), actual.data(), page, storage[i].request.file_offset) == page);
    assert(std::all_of(actual.begin(), actual.end(), [i](uint8_t b) {
      return b == i % 251 + 1;
    }));
  }
  // Coverage validation is common; only neighbor clustering is Adaptive-only.
  storage[2].request.file_offset = base;
  assert(service.resetPerf() && service.execute_io(tasks));
  stats = service.snapshot();
  assert(storage[0].superseded && !storage[2].superseded);
  assert(stats.deduplicated_request_count == 1 && stats.physical_request_count == 510);
  assert(stats.random_local_candidate_requests == 3 && stats.random_sparse_fast_requests == 509);
  assert(pread(service.file_for(1), actual.data(), page, base) == page);
  assert(actual.front() == 3 && actual.back() == 3);
  // Equal-sequence conflicts cannot be hidden by the local partition.
  storage[0].superseded = false;
  storage[2].request.sequence = storage[0].request.sequence;
  assert(service.resetPerf() && service.execute_io(tasks));
  stats = service.snapshot();
  assert(storage[0].result == -ESTALE && storage[2].result == -ESTALE);
  for (size_t i = 1; i < count; ++i)
    if (i != 2) assert(storage[i].result == 0);
  assert(stats.random_local_candidate_requests == 3 && stats.random_sparse_fast_requests == 509);
  assert(stats.logical_request_count == 512 && stats.physical_request_count == 510);
  // The common legality path conservatively orders a batch with unresolved
  // overlaps in both modes; clustering must not bypass that sequence barrier.
  assert(stats.io_uring_submissions == 0 && stats.sparse_io_count == 510);
  assert(pread(service.file_for(1), actual.data(), page, base) == page);
  assert(actual.front() == 3 && actual.back() == 3);
  assert(service.resetPerf());
  puts("512-page local plan: two candidates, 510 isolated, overwrite/sequence contents PASS");
}

static void test_cache_admission(SqliteExtentIoService::Impl& service,
                                  uint8_t* utm, size_t bytes) {
  assert(service.resetPerf());
  Task base;
  base.utm = utm;
  base.utm_size = bytes;
  base.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
  base.request.workload = GROUP_PMP_SQLITE_READRANDOM;
  base.request.run_id = 1;
  base.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
  base.stored_file_id = 1;
  base.stored_sequence = 1;
  base.storage_length = 4096;
  for (unsigned i = 0; i < 256; ++i) {
    Task task = base;
    task.storage_offset = i * 16384;
    service.apply_read_cache(task);
    assert(!task.cache_satisfied && !task.cache_partial);
    memset(task.data(), 0x5a, 4096);
    service.update_read_cache(task);
  }
  auto stats = service.snapshot();
  assert(stats.cache_full_hit_count == 0 && stats.cache_partial_hit_count == 0);
  assert(stats.cache_admission_disables == 1);
  assert(stats.cache_fill_bytes == 127 * 4096);
  assert(stats.cache_fill_skipped_bytes == 129 * 4096);
  assert(stats.cache_fill_ns == stats.utm_copy_ns);
  assert(service.cipher_cache_.size() == 1);
  assert(service.cipher_cache_.begin()->second.ciphertext.empty());
  // Shadow metadata detects a new local phase while payload filling is off.
  base.storage_offset = 255 * 16384;
  for (unsigned i = 0; i < 128; ++i) {
    Task task = base;
    service.apply_read_cache(task);
    assert(!task.cache_satisfied);
    service.update_read_cache(task);
  }
  assert(service.snapshot().cache_admission_reenables == 1);
  Task hit = base;
  memset(hit.data(), 0, 4096);
  service.apply_read_cache(hit);
  assert(hit.cache_satisfied && hit.io_length == 0);
  assert(std::all_of(hit.data(), hit.data() + 4096,
                     [](uint8_t b) { return b == 0x5a; }));
  for (unsigned change = 0; change < 3; ++change) {
    Task stale = base;
    if (change == 0) ++stale.request.run_id;
    if (change == 1) ++stale.stored_sequence;
    if (change == 2) ++stale.stored_file_id;
    service.apply_read_cache(stale);
    assert(!stale.cache_satisfied && !stale.cache_partial);
  }
  service.invalidate_file_cache(1);
  assert(service.cipher_cache_.empty() && service.cache_admission_.count(1) == 0);
  assert(service.resetPerf());
  // Async keeps its original cache behavior; only adaptive learns admission.
  setenv("GROUP_PMP_SQLITE_IO_MODE", "async-no-extent", 1);
  for (unsigned i = 0; i < 256; ++i) {
    Task task = base;
    task.storage_offset = i * 16384;
    service.apply_read_cache(task);
    service.update_read_cache(task);
  }
  assert(service.snapshot().cache_admission_disables == 0);
  assert(service.snapshot().cache_fill_bytes == 256 * 4096);
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  assert(service.resetPerf());
  puts("cache: zero-hit fill suppression, shadow re-enable, epochs and async isolation PASS");
}

static int feedback_window(WriteBatchFeedback& feedback, size_t completed,
                           size_t queued, uint64_t bytes, uint64_t duration,
                           uint64_t tail, size_t minimum = 128,
                           size_t maximum = 512) {
  assert(feedback.samples == 0);
  const size_t before = feedback.target;
  int action = 0;
  for (unsigned sample = 0; sample < 4; ++sample) {
    action = feedback.observe(completed, queued, bytes, duration, tail,
                              minimum, maximum);
    if (sample < 3) {
      assert(action == 0 && feedback.target == before);
      assert(feedback.samples == sample + 1);
    }
    assert(feedback.target >= minimum && feedback.target <= maximum);
  }
  assert(feedback.samples == 0 && feedback.bytes == 0);
  assert(feedback.service_ns == 0 && feedback.tail_ns == 0);
  assert(!feedback.saturated);
  return action;
}

static void test_write_batch_feedback() {
  constexpr uint64_t ms = UINT64_C(1000000);
  WriteBatchFeedback feedback;
  feedback.reset(128, 512);
  assert(feedback.target == 256 && feedback.stable_target == 256);
  assert(feedback.observe(0, 512, 1000000, 10 * ms, 20 * ms, 128, 512) == 0);
  assert(feedback.observe(256, 512, 0, 10 * ms, 20 * ms, 128, 512) == 0);
  assert(feedback.observe(256, 512, 1000000, 0, 20 * ms, 128, 512) == 0);
  assert(feedback.samples == 0 && feedback.bytes == 0 && !feedback.probing);
  assert(feedback_window(feedback, 256, 512, 1000000, 10 * ms, 20 * ms) == 1);
  assert(feedback.target == 320 && feedback.stable_target == 256);
  assert(feedback.probing && feedback.reference_rate == 100000000);
  // More bytes take proportionally longer: batch size alone is not a gain.
  assert(feedback_window(feedback, 320, 512, 1250000, 12500000, 20 * ms) == -1);
  assert(feedback.target == 256 && !feedback.probing && feedback.cooldown == 8);
  for (unsigned window = 0; window < 8; ++window) {
    assert(feedback_window(feedback, 256, 512, 1000000, 10 * ms, 20 * ms) == 0);
    assert(feedback.target == 256 && !feedback.probing);
    assert(feedback.cooldown == 7 - window);
  }
  assert(feedback_window(feedback, 256, 512, 1000000, 10 * ms, 20 * ms) == 1);

  feedback.reset(128, 512);
  assert(feedback_window(feedback, 256, 512, 1000000, 10 * ms, 20 * ms) == 1);
  assert(feedback_window(feedback, 320, 512, 1050000, 10 * ms, 25 * ms) == 0);
  assert(feedback.target == 320 && feedback.stable_target == 320);
  assert(!feedback.probing && feedback.cooldown == 2);
  assert(feedback_window(feedback, 320, 512, 1050000, 10 * ms, 25 * ms) == 0);
  assert(feedback.target == 320 && feedback.cooldown == 1);
  for (unsigned failure = 0; failure < 3; ++failure) {
    feedback.reset(128, 512);
    assert(feedback_window(feedback, 256, 512, 1000000, 10 * ms, 20 * ms) == 1);
    const uint64_t bytes = failure == 0 ? 1049999 : 1100000;
    const uint64_t tail = failure == 0 ? 20 * ms :
        (failure == 1 ? 25 * ms + 1 : 80 * ms + 1);
    assert(feedback_window(feedback, 320, 512, bytes, 10 * ms, tail) == -1);
    assert(feedback.target == 256 && feedback.stable_target == 256);
    assert(!feedback.probing && feedback.cooldown == 8);
  }
  feedback.reset(128, 512);
  assert(feedback_window(feedback, 256, 512, 1000000, 10 * ms, 80 * ms) == 0);
  assert(feedback.target == 256 && !feedback.probing);
  assert(feedback_window(feedback, 256, 512, 1000000, 10 * ms, 80 * ms + 1) == -1);
  assert(feedback.target == 128 && feedback.stable_target == 128);
  assert(!feedback.probing && feedback.cooldown == 8);
  assert(feedback_window(feedback, 128, 512, 1000000, 10 * ms, 81 * ms) == 0);
  assert(feedback.target == 128);
  feedback.reset(128, 512);
  // Shrink on worsening real throughput/tail even below the absolute budget.
  assert(feedback_window(feedback, 256, 0, 1000000, 10 * ms, 20 * ms) == 0);
  assert(feedback_window(feedback, 256, 0, 1000000, 12 * ms, 26 * ms) == -1);
  assert(feedback.target == 128 && feedback.cooldown == 8);
  for (unsigned idle = 0; idle < 3; ++idle) {
    feedback.reset(128, 512);
    const size_t completed = idle == 1 ? 255 : 256;
    const size_t queued = idle == 0 ? 0 : (idle == 1 ? 512 : 255);
    for (unsigned window = 0; window < 3; ++window)
      assert(feedback_window(feedback, completed, queued,
                             1000000, 10 * ms, 20 * ms) == 0);
    assert(feedback.target == 256 && !feedback.probing);
  }
  feedback.reset(320, 512);
  assert(feedback.target == 320);
  assert(feedback_window(feedback, 320, 512, 1000000, 10 * ms, 81 * ms,
                         320, 512) == 0);
  feedback.reset(128, 300);
  assert(feedback_window(feedback, 256, 512, 1000000, 10 * ms, 20 * ms,
                         128, 300) == 1);
  assert(feedback.target == 300);
  assert(feedback_window(feedback, 300, 512, 1100000, 10 * ms, 20 * ms,
                         128, 300) == 0);
  for (unsigned window = 0; window < 4; ++window)
    assert(feedback_window(feedback, 300, 512, 1100000, 10 * ms, 20 * ms,
                           128, 300) == 0);
  assert(feedback.target == 300 && !feedback.probing);
  for (size_t fixed : {128, 512}) {
    feedback.reset(fixed, fixed);
    assert(feedback.target == fixed && feedback.stable_target == fixed);
    assert(feedback_window(feedback, fixed, 1024, 1000000, 10 * ms, 20 * ms,
                           fixed, fixed) == 0);
    assert(feedback_window(feedback, fixed, 1024, 1000000, 10 * ms, 81 * ms,
                           fixed, fixed) == 0);
  }
  assert(producer_admission_limit(1) == 2 * GROUP_PMP_SQLITE_VFS_BATCH_MAX);
  assert(producer_admission_limit(15) == 30 * GROUP_PMP_SQLITE_VFS_BATCH_MAX);
  assert(producer_admission_limit(64) == kQueueDepth);
  assert(producer_admission_limit(UINT64_MAX) == kQueueDepth);
  puts("write feedback windows, probe gain/tail thresholds, cooldown and admission bounds PASS");
}

static void test_bounded_write_admission(SqliteExtentIoService::Impl& service,
                                         uint8_t* const utms[2], size_t utm_size) {
  constexpr size_t count = 256, producers = 4, rounds = 4, length = 64;
  static_assert(GROUP_PMP_SQLITE_VFS_BATCH_MAX >= count, "256-write submissions");
  const size_t saved_minimum = service.adaptive_batch_min_;
  const size_t saved_maximum = service.adaptive_batch_max_;
  // Pin feedback while measuring admission, so host speed cannot change bounds.
  service.adaptive_batch_min_ = service.adaptive_batch_max_ = 256;
  for (uint64_t advertised_workers : {UINT64_C(2), UINT64_C(64)}) {
    reset_overlap_stats(service);
    std::promise<void> start;
    const std::shared_future<void> ready = start.get_future().share();
    std::vector<std::future<void>> submitters;
    for (size_t producer = 0; producer < producers; ++producer) {
      submitters.push_back(std::async(std::launch::async, [&, producer, ready] {
        const size_t worker = producer / 2, slot = producer % 2;
        uint8_t* const utm = utms[worker];
        const uint64_t payload_offset = slot ? GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET :
            GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
        auto* ring = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
            utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot));
        memset(ring, 0, sizeof(*ring));
        ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
        ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
        std::vector<group_pmp_sqlite_vfs_request> requests(count);
        memset(utm + payload_offset, static_cast<int>(producer + 1), count * length);
        ready.wait();
        for (size_t round = 0; round < rounds; ++round) {
          for (size_t i = 0; i < count; ++i) {
            auto& request = requests[i];
            const uint64_t id = (round * producers + producer) * count + i + 1;
            request.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
            request.version = GROUP_PMP_SQLITE_VFS_VERSION;
            request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
            request.workload = GROUP_PMP_SQLITE_FILLRANDOMBATCH;
            request.run_id = worker + 1;
            request.worker_index = worker;
            request.worker_count = advertised_workers;
            request.request_id = request.task_id = request.sequence = id;
            request.file_id = 1;
            request.file_offset = (id - 1) * length;
            request.length = request.logical_size = length;
            request.buffer_id = request.ring_slot = slot;
            request.descriptor_id = i;
            request.buffer_offset = payload_offset + i * length;
            request.reserved[0] = GROUP_PMP_SQLITE_STORE_RING;
            request.reserved[1] = request.file_offset;
          }
          auto completion = std::make_shared<SqliteAsyncCompletion>(count);
          assert(service.submitBatch(requests.data(), count, utm, utm_size, completion));
          completion->wait();
          assert(completion->isComplete());
          assert(__atomic_load_n(&ring->completion_count, __ATOMIC_ACQUIRE) ==
                 (round + 1) * count);
          for (const auto& request : requests) {
            const auto* status = reinterpret_cast<const group_pmp_sqlite_vfs_status*>(
                utm + status_offset_for_request(request));
            assert(status->state == GROUP_PMP_SQLITE_VFS_STATE_DONE);
            assert(status->result == 0 && status->request_id == request.request_id);
            assert(status->sequence == request.sequence && status->length == length);
          }
        }
      }));
    }
    start.set_value();
    for (auto& submitter : submitters) {
      assert(submitter.wait_for(std::chrono::seconds(30)) == std::future_status::ready);
      submitter.get();
    }
    {
      std::unique_lock<std::mutex> lock(service.queue_mutex_);
      assert(service.condition_.wait_for(lock, std::chrono::seconds(30), [&] {
        return service.queue_.empty() && !service.processing_batch_;
      }));
    }
    const auto stats = service.snapshot();
    assert(stats.queue_depth_peak >= count && stats.queue_depth_peak <= 1024);
    assert(stats.task_count == producers * rounds * count);
    assert(stats.batch_count == producers * rounds);
    assert(stats.logical_request_count == producers * rounds * count);
    assert(stats.physical_io_bytes == producers * rounds * count * length);
    assert(stats.deduplicated_request_count == 0 && stats.write_overlap_batches == 0);
    assert(service.write_queue_depth_.load() >= 128 && service.write_queue_depth_.load() <= 1024);
    assert(stats.pipeline[SQLITE_PIPELINE_BUFFER_COMPLETIONS] == producers * rounds);
    assert(stats.pipeline[SQLITE_PIPELINE_INFLIGHT_PEAK] <= 128);
  }
  service.adaptive_batch_min_ = saved_minimum;
  service.adaptive_batch_max_ = saved_maximum;
  reset_overlap_stats(service);
  puts("concurrent writes: bounded latency-controlled admission and per-buffer completions PASS");
}

static void test_read_pair_enqueue(uint8_t* utm, size_t utm_size) {
  SqliteExtentIoService service;
  group_pmp_sqlite_vfs_request requests[2] = {};
  std::shared_ptr<SqliteAsyncCompletion> completions[2] = {
      std::make_shared<SqliteAsyncCompletion>(1),
      std::make_shared<SqliteAsyncCompletion>(1)};
  for (size_t i = 0; i < 2; ++i) {
    auto& request = requests[i];
    request.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    request.version = GROUP_PMP_SQLITE_VFS_VERSION;
    request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    request.workload = GROUP_PMP_SQLITE_READSEQ;
    request.run_id = 999;
    request.worker_count = 1;
    request.file_id = 1;
    request.request_id = request.task_id = i + 1;
    request.buffer_id = request.ring_slot = i;
    request.buffer_offset = i ? GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET :
        GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
    request.length = request.logical_size = 1;
    request.reserved[0] = GROUP_PMP_SQLITE_STORE_RING;
  }
  const uint64_t second_offset = requests[1].buffer_offset;
  requests[1].buffer_offset = utm_size;
  assert(!service.submitReadPair(requests, utm, utm_size, completions));
  assert(service.snapshot().batch_count == 0);
  assert(service.snapshot().queue_depth_peak == 0);
  assert(!completions[0]->isComplete() && !completions[1]->isComplete());
  requests[1].buffer_offset = second_offset;
  assert(service.submitReadPair(requests, utm, utm_size, completions));
  {
    std::unique_lock<std::mutex> lock(service.impl_->queue_mutex_);
    assert(service.impl_->condition_.wait_for(lock, std::chrono::seconds(30), [&] {
      return service.impl_->queue_.empty() && !service.impl_->processing_batch_;
    }));
  }
  const auto stats = service.snapshot();
  // The high-water mark is recorded under the enqueue lock before notification.
  assert(stats.batch_count == 1 && stats.queue_depth_peak == 2);
  assert(stats.task_count == 2 && stats.physical_request_count == 0);
  for (size_t i = 0; i < 2; ++i) {
    assert(completions[i]->isComplete());
    const auto* status = reinterpret_cast<const group_pmp_sqlite_vfs_status*>(
        utm + status_offset_for_request(requests[i]));
    // No metadata exists for this run; only enqueue/completion behavior is tested.
    assert(status->state == GROUP_PMP_SQLITE_VFS_STATE_ERROR);
    assert(status->result == -ENOENT && status->request_id == requests[i].request_id);
  }
  assert(service.resetPerf());
  puts("read-pair atomic admission, invalid-second rejection and independent completions PASS");
}

static void test_drain_and_snapshot() {
  SqliteExtentIoService service;
  auto& impl = *service.impl_;
  SqliteAsyncCompletion completion(1);
  std::promise<void> published, store_final, final_stored, become_idle, drain_started;
  auto published_event = published.get_future();
  auto store_final_gate = store_final.get_future();
  auto final_stored_event = final_stored.get_future();
  auto become_idle_gate = become_idle.get_future();
  auto drain_started_event = drain_started.get_future();
  {
    std::lock_guard<std::mutex> lock(impl.queue_mutex_);
    assert(impl.queue_.empty() && !impl.processing_batch_);
    // Model a dequeued batch; the actual worker remains idle on an empty queue.
    impl.processing_batch_ = true;
  }
  impl.task_count_.store(5, std::memory_order_relaxed);
  impl.batch_count_.store(3, std::memory_order_relaxed);
  impl.physical_io_bytes_.store(8192, std::memory_order_relaxed);
  impl.write_disjoint_batches_.store(3, std::memory_order_relaxed);
  auto finalizer = std::async(std::launch::async, [&] {
    completion.completeOne();
    published.set_value();
    store_final_gate.wait();
    impl.task_count_.fetch_add(2, std::memory_order_relaxed);
    impl.write_service_ns_.store(9000000, std::memory_order_relaxed);
    impl.max_batch_service_ns_.store(4000000, std::memory_order_relaxed);
    impl.max_completion_latency_ns_.store(6000000, std::memory_order_relaxed);
    impl.window_last_completion_ns_.store(123456789, std::memory_order_relaxed);
    final_stored.set_value();
    become_idle_gate.wait();
    {
      std::lock_guard<std::mutex> lock(impl.queue_mutex_);
      impl.processing_batch_ = false;
    }
    impl.condition_.notify_all();
  });
  assert(published_event.wait_for(std::chrono::seconds(30)) ==
         std::future_status::ready);
  assert(completion.isComplete() && completion.publishedAtNs() != 0);
  const auto early = service.snapshot();
  assert(early.task_count == 5 && early.window_last_completion_ns == 0);
  auto drained = std::async(std::launch::async, [&] {
    drain_started.set_value();
    return service.drainAndSnapshot();
  });
  assert(drain_started_event.wait_for(std::chrono::seconds(30)) ==
         std::future_status::ready);
  // Gates, not host execution speed, keep both publication stages incomplete.
  assert(drained.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout);
  store_final.set_value();
  assert(final_stored_event.wait_for(std::chrono::seconds(30)) ==
         std::future_status::ready);
  assert(service.snapshot().task_count == 7);
  assert(drained.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout);
  become_idle.set_value();
  assert(finalizer.wait_for(std::chrono::seconds(30)) == std::future_status::ready);
  finalizer.get();
  assert(drained.wait_for(std::chrono::seconds(30)) == std::future_status::ready);
  const auto final = drained.get();
  const auto check_final = [](const SqliteIoPerfSnapshot& stats) {
    assert(stats.task_count == 7 && stats.batch_count == 3);
    assert(stats.physical_io_bytes == 8192 && stats.write_disjoint_batches == 3);
    assert(stats.write_service_ns == 9000000);
    assert(stats.max_batch_service_ns == 4000000);
    assert(stats.max_completion_latency_ns == 6000000);
    assert(stats.window_last_completion_ns == 123456789);
  };
  check_final(final);
  // Neither public nor Impl draining may reset already accumulated counters.
  check_final(service.snapshot());
  check_final(impl.drainAndSnapshot());
  check_final(service.snapshot());
  puts("drain snapshot waits beyond completion publication and preserves final counters PASS");
}

static void test_read_merge_feedback() {
  const auto window = [](ReadMergeFeedback& feedback, uint64_t bytes,
                          uint64_t duration) {
    int action = 0;
    const unsigned count = 4;
    for (unsigned i = 0; i < count; ++i)
      action = feedback.observe(bytes, duration);
    return action;
  };
  ReadMergeFeedback feedback;
  assert(!feedback.merging);
  assert(feedback.observe(0, 10) == 0 && feedback.samples == 0);
  assert(feedback.observe(10, 0) == 0 && feedback.samples == 0);
  assert(window(feedback, 2000000, 10000000) == 1 && feedback.merging);
  // Fewer physical operations are not evidence of lower service cost.
  assert(window(feedback, 2000000, 11000000) == -1 && !feedback.merging);
  for (unsigned i = 0; i < 8; ++i)
    assert(window(feedback, 2000000, 10000000) == 0 && !feedback.merging);
  assert(window(feedback, 2000000, 10000000) == 1 && feedback.merging);
  assert(window(feedback, 2000000, 8000000) == 0 && feedback.merging);
  // Eventually refresh the discrete reference, even after a successful trial.
  for (unsigned i = 0; i < 7; ++i)
    assert(window(feedback, 2000000, 8000000) == 0);
  assert(!feedback.merging);
  assert(window(feedback, 2000000, 10000000) == 1);
  // Larger useful batches do not create artificial tail regressions.
  assert(window(feedback, 4000000, 14000000) == 0);
  assert(window(feedback, 2000000, 14000000) == -1);
  ReadMergeFeedback costly;
  for (unsigned i = 0; i < 4; ++i) costly.observe(2000000, 10000000, 100000);
  assert(costly.merging && costly.epoch == 1);
  // Less storage wait cannot justify a large increase in planning/copy/publish work.
  for (unsigned i = 0; i < 4; ++i) costly.observe(2000000, 8000000, 1000000);
  assert(!costly.merging && costly.epoch == 2);
  ReadMergeFeedback delayed_release;
  for (unsigned i = 0; i < 4; ++i)
    delayed_release.observe(2000000, 10000000, 100000, 20000);
  assert(delayed_release.merging);
  // Faster media alone must not hide a slower buffer publication/notification.
  for (unsigned i = 0; i < 4; ++i)
    delayed_release.observe(2000000, 8000000, 100000, 500000);
  assert(!delayed_release.merging && delayed_release.cooldown == 8);
  ReadMergeFeedback slower_tail;
  for (unsigned i = 0; i < 4; ++i) slower_tail.observe(2000000, 10000000);
  for (unsigned i = 0; i < 3; ++i) slower_tail.observe(2000000, 7000000);
  slower_tail.observe(2000000, 12000000);
  assert(!slower_tail.merging); // Mean improves, worst buffer release is 20% later.
  ReadMergeFeedback no_gain;
  for (unsigned failure = 1; failure <= 5; ++failure) {
    assert(window(no_gain, 2000000, 10000000) == 1);
    for (unsigned i = 0; i < 3; ++i)
      assert(!no_gain.observe(2000000, 10000000) && no_gain.merging);
    assert(no_gain.observe(2000000, 10000000) == -1 && !no_gain.merging);
    const unsigned expected = 8;
    assert(no_gain.cooldown == expected && no_gain.samples == 0);
    for (unsigned i = 0; i < expected; ++i)
      assert(!window(no_gain, 2000000, 10000000) && !no_gain.merging);
  }
  assert(window(no_gain, 2000000, 10000000) == 1);
  assert(!window(no_gain, 2000000, 8000000) && no_gain.merging && !no_gain.failures);
  assert(read_merge_class(20, 2000000, 20, false) !=
         read_merge_class(20, 2000000, 20, true));
  assert(read_merge_class(20, 2000000, 20, false) ==
         read_merge_class(200, 20000000, 200, false));
  for (auto policy : {IoPlanningPolicy::kSequentialContiguous,
                      IoPlanningPolicy::kReadRand100kAdjacent}) {
    assert(collection_window(true, policy, 500) == 0);
    assert(collection_window(false, policy, 50) == 50);
  }
  assert(collection_window(true, IoPlanningPolicy::kRandomReadClustered, 50) == 50);
  puts("read100k measured-cost backoff/probe and arrived-only large reads PASS");
}

static void test_merge_cost(SqliteExtentIoService::Impl& service) {
  const uint64_t bandwidth = service.ewma_bandwidth_bytes_per_sec_.load();
  const uint64_t latency = service.ewma_request_latency_ns_.load();
  const uint64_t copy = service.copy_bandwidth_;
  const uint64_t plan = service.merge_plan_cost_ns_;
  const uint64_t completion = service.merge_completion_cost_ns_;
  const uint64_t budget = service.merge_delay_budget_ns_;
  const uint64_t adaptive_gap = service.adaptive_gap_bytes_.load();
  const uint64_t saved_read = service.read_saved_op_ns_;
  service.read_saved_op_ns_ = 10000000; // Exercise safety limits independently of benefit.
  service.ewma_bandwidth_bytes_per_sec_.store(100000000);
  service.ewma_request_latency_ns_.store(0);
  service.copy_bandwidth_ = 100000000;
  service.merge_delay_budget_ns_ = 500000;
  service.merge_plan_cost_ns_ = service.merge_completion_cost_ns_ = 1000;
  IoGroup group;
  group.read = true;
  group.policy = IoPlanningPolicy::kReadRand100kAdjacent;
  group.end = group.useful_bytes = 100000;
  Task first, task;
  first.io_length = 100000;
  group.tasks = {&first};
  task.io_offset = task.io_length = 100000;
  uint64_t gap = 1;
  assert(service.merge_within_budget(group, task, 200000, &gap) && gap == 0);
  service.read_merge_feedback_[0].reference_cost = 1;
  assert(service.merge_within_budget(group, task, 200000, &gap)); // Retired time-savings gate.
  service.read_merge_feedback_.erase(0);
  service.merge_plan_cost_ns_ = 300000;
  assert(!service.merge_within_budget(group, task, 200000, &gap));
  service.merge_plan_cost_ns_ = 1000;
  service.merge_completion_cost_ns_ = 300000;
  assert(!service.merge_within_budget(group, task, 200000, &gap));
  service.merge_completion_cost_ns_ = 1000;
  task.io_offset = 50000;
  assert(!service.merge_within_budget(group, task, 150000, &gap)); // Whole fan-out copy exceeds budget.
  service.copy_bandwidth_ = 10000000000ULL;
  assert(service.merge_within_budget(group, task, 150000, &gap));
  group.overlapping = true;
  group.useful_bytes = 1000000;
  task.io_offset = 100000;
  service.copy_bandwidth_ = 20000000;
  assert(!service.merge_within_budget(group, task, 200000, &gap));
  task.io_offset = 100016;
  assert(!service.merge_within_budget(group, task, 200016, &gap)); // Release budget rejects even a small hole.
  service.merge_delay_budget_ns_ = 50000000;
  service.copy_bandwidth_ = 100000000;
  group.overlapping = false;
  group.useful_bytes = 100000;
  service.adaptive_gap_bytes_.store(4096);
  task.io_offset = 104000;
  assert(service.merge_within_budget(group, task, 204000, &gap) && gap == 4000);
  task.io_offset = 108000;
  assert(!service.merge_within_budget(group, task, 208000, &gap)); // 100 KB gap cap.
  group.policy = IoPlanningPolicy::kRandomReadClustered;
  group.end = 200000;
  group.gap_bytes = 100000;
  task.io_offset = 200000;
  task.io_length = 100000;
  // Logical overlap cannot conceal 100 KB of holes from amplification accounting.
  assert(!service.merge_within_budget(group, task, 300000, &gap));
  group.gap_bytes = 0;
  assert(service.merge_within_budget(group, task, 300000, &gap));
  assert(!service.merge_within_budget(group, task, service.merge_limit_ + 1, &gap));
  group.read = false;
  task.io_offset = 200016;
  assert(!service.merge_within_budget(group, task, 300016, &gap));
  task.io_offset = 100000;
  assert(!service.merge_within_budget(group, task, 200000, &gap)); // Write overlap is handled by sequence, not union.
  service.ewma_bandwidth_bytes_per_sec_.store(bandwidth);
  service.ewma_request_latency_ns_.store(latency);
  service.copy_bandwidth_ = copy;
  service.merge_plan_cost_ns_ = plan;
  service.merge_completion_cost_ns_ = completion;
  service.merge_delay_budget_ns_ = budget;
  service.adaptive_gap_bytes_.store(adaptive_gap);
  service.read_saved_op_ns_ = saved_read;
  assert(service.snapshot().pipeline[SQLITE_PIPELINE_CLUSTER_DELAY_REJECTS] >= 4);
  assert(service.snapshot().pipeline[SQLITE_PIPELINE_CLUSTER_AMP_REJECTS] >= 1);
  group = IoGroup(); group.read = true; group.end = group.useful_bytes = 4096;
  group.tasks = {&first}; first.io_length = 4096;
  task.io_offset = task.io_length = 4096;
  service.read_saved_op_ns_ = 0;
  assert(!service.merge_within_budget(group, task, 8192, &gap));
  service.read_saved_op_ns_ = 1000000;
  assert(service.merge_within_budget(group, task, 8192, &gap));
  service.read_saved_op_ns_ = saved_read;
  puts("merge admission: net benefit, whole-extent delay, unique-byte amplification, write safety PASS");
}

static void test_release_order(SqliteExtentIoService::Impl& service,
                               uint8_t* const utms[2], size_t bytes) {
  for (bool read : {false, true}) {
    size_t first_buffer_last[3] = {};
    for (unsigned mode = 0; mode < 3; ++mode) {
      setenv("GROUP_PMP_SQLITE_IO_MODE", mode ? "adaptive-extent" : "async-no-extent", 1);
      setenv("GROUP_PMP_SQLITE_CLUSTER_MODE", mode == 1 ? "plan-only" : "merge", 1);
      std::array<Task, 16> storage;
      std::vector<Task*> tasks;
      auto a = std::make_shared<SqliteAsyncCompletion>(8);
      auto b = std::make_shared<SqliteAsyncCompletion>(8);
      for (size_t i = 0; i < storage.size(); ++i) {
        Task& t = storage[i];
        t.utm = utms[i / 8]; t.utm_size = bytes;
        t.request.run_id = i / 8 + 1; t.request.worker_index = i / 8;
        t.request.worker_count = 2; t.request.sequence = i + 1;
        t.request.file_id = t.stored_file_id = 1;
        t.request.operation = read ? GROUP_PMP_SQLITE_VFS_OP_READ : GROUP_PMP_SQLITE_VFS_OP_WRITE;
        t.request.workload = read ? GROUP_PMP_SQLITE_READRANDOM : GROUP_PMP_SQLITE_FILLRANDOM;
        // Early buffer has a late isolated tail; later buffer has more pairs.
        const size_t page = i < 2 ? i : i < 8 ? i * 8 : 100 + (i - 8) / 2 * 8 + i % 2;
        t.request.file_offset = t.storage_offset = page * 4096;
        t.request.length = t.storage_length = t.request.logical_size = 4096;
        t.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + (i % 8) * 4096;
        t.completion = i < 8 ? a : b;
        tasks.push_back(&t);
      }
      PipelineBatch plan;
      assert(service.resetPerf() && service.execute_io(tasks, true, &plan));
      assert(plan.operations.size() == (mode == 2 ? 11 : 16));
      std::array<bool, 16> seen{};
      size_t previous = 0;
      for (size_t g = 0; g < plan.groups.size(); ++g) {
        size_t earliest = 16;
        uint64_t end = 0;
        for (const Task* t : plan.groups[g].tasks) {
          const size_t index = t - storage.data();
          assert(!seen[index]); seen[index] = true;
          earliest = std::min(earliest, index);
          assert(!end || t->io_offset == end);
          end = t->io_offset + t->io_length;
          if (index < 8) first_buffer_last[mode] = g + 1;
        }
        assert(!g || earliest > previous); previous = earliest;
      }
      assert(std::all_of(seen.begin(), seen.end(), [](bool present) { return present; }));
    }
    assert(first_buffer_last[0] == 8 && first_buffer_last[1] == 8 && first_buffer_last[2] == 7);
  }
  unsetenv("GROUP_PMP_SQLITE_CLUSTER_MODE");
  puts("merged submission: arrival order, early isolated tail, plan-only fairness, unique ownership PASS");
}

static void test_calibrated_read_bypass(SqliteExtentIoService::Impl& service,
                                        uint8_t* utm, size_t bytes) {
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  const bool old_calibrated = service.merge_calibrated_;
  const uint64_t old_read_fixed = service.calibrated_saved_ns_[1][0];
  const uint64_t old_read_vector = service.calibrated_saved_ns_[1][1];
  const uint64_t old_write_fixed = service.calibrated_saved_ns_[0][0];
  const uint64_t old_write_vector = service.calibrated_saved_ns_[0][1];
  service.merge_calibrated_ = true;
  service.calibrated_saved_ns_[1][0] = service.calibrated_saved_ns_[1][1] = 0;
  service.calibrated_saved_ns_[0][0] = 1000000;
  service.calibrated_saved_ns_[0][1] = 0;
  std::array<Task, 4> storage;
  std::vector<Task*> tasks;
  for (size_t i = 0; i < storage.size(); ++i) {
    Task& t = storage[i];
    t.utm = utm; t.utm_size = bytes;
    t.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    t.request.workload = GROUP_PMP_SQLITE_READRANDOM;
    t.request.run_id = 301; t.request.worker_index = 0;
    t.request.file_id = t.stored_file_id = 1;
    t.request.task_id = t.request.sequence = i + 1;
    t.request.file_offset = t.storage_offset = t.io_offset = i * 4096;
    t.request.length = t.storage_length = t.io_length = 4096;
    t.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + i * 4096;
    tasks.push_back(&t);
  }
  PipelineBatch plan;
  assert(service.resetPerf() && service.execute_io(tasks, true, &plan));
  auto stats = service.snapshot();
  assert(plan.operations.size() == tasks.size());
  assert(stats.pipeline[SQLITE_PIPELINE_CALIBRATION_SKIPPED_BATCHES] == 1);
  assert(stats.pipeline[SQLITE_PIPELINE_CALIBRATION_SKIPPED_REQUESTS] == tasks.size());
  assert(stats.pipeline[SQLITE_PIPELINE_CANDIDATE_SCAN_NS] == 0 && stats.cluster_ns == 0);
  assert(stats.pipeline[SQLITE_PIPELINE_RELEASE_ORDER_MOVES] == 0);
  for (size_t i = 0; i < plan.groups.size(); ++i)
    assert(plan.groups[i].tasks.size() == 1 && plan.groups[i].tasks.front() == tasks[i]);

  storage.back().request.length = storage.back().storage_length = storage.back().io_length = 240;
  plan = PipelineBatch{};
  assert(service.resetPerf() && service.execute_io(tasks, true, &plan));
  stats = service.snapshot();
  assert(stats.pipeline[SQLITE_PIPELINE_CALIBRATION_SKIPPED_BATCHES] == 0);
  assert(stats.pipeline[SQLITE_PIPELINE_CALIBRATION_ZERO_REJECTS] >= 1);

  for (auto& t : storage) {
    t.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
    t.request.workload = GROUP_PMP_SQLITE_FILLRANDOM;
    t.request.length = t.storage_length = t.io_length = 4096;
  }
  plan = PipelineBatch{};
  assert(service.resetPerf() && service.execute_io(tasks, true, &plan));
  stats = service.snapshot();
  assert(plan.operations.size() < tasks.size());
  assert(stats.pipeline[SQLITE_PIPELINE_CALIBRATION_SKIPPED_BATCHES] == 0);
  assert(stats.pipeline[SQLITE_PIPELINE_CLUSTER_PLANNED_SAVINGS] > 0);

  service.merge_calibrated_ = old_calibrated;
  service.calibrated_saved_ns_[1][0] = old_read_fixed;
  service.calibrated_saved_ns_[1][1] = old_read_vector;
  service.calibrated_saved_ns_[0][0] = old_write_fixed;
  service.calibrated_saved_ns_[0][1] = old_write_vector;
  assert(service.resetPerf());
  puts("calibrated random read bypass, short tail, fixed write merge PASS");
}

static void test_metadata_batch(SqliteExtentIoService::Impl& service) {
  for (const char* mode : {"async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    std::vector<Task> store(129);
    std::vector<Task*> tasks;
    for (size_t i = 0; i < store.size(); ++i) {
      Task& t = store[i];
      t.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
      t.request.run_id = 900 + i % 2;
      t.request.worker_index = i % 3; t.request.worker_count = 3;
      t.request.workload = i % 2 ? GROUP_PMP_SQLITE_READSEQ : GROUP_PMP_SQLITE_READRANDOM;
      t.request.task_id = i + 1; t.request.file_id = i % 3 + 1;
      t.request.reserved[1] = i * 4096; t.request.file_offset = (store.size() - i) * 4096;
      t.request.length = t.request.logical_size = i == 128 ? 240 : 4096;
      t.request.sequence = i + 7;
      memset(t.request.tag, static_cast<int>(i), sizeof(t.request.tag));
      tasks.push_back(&t);
    }
    assert(service.commit_writes(tasks));
    for (auto& t : store) t.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    std::reverse(tasks.begin(), tasks.end());
    // Duplicate keys must each return a row, with results mapped by input slot.
    Task duplicate = store[0], missing = store[1], stale = store[2], skip = store[3];
    missing.request.run_id = 9999; stale.request.task_id = 9999; skip.result = -EIO;
    tasks.insert(tasks.end(), {&duplicate, &missing, &stale, &skip});
    assert(service.resetPerf() && service.resolve_reads(tasks));
    const auto stats = service.snapshot();
    assert(stats.pipeline[SQLITE_PIPELINE_METADATA_LOOKUP_BATCHES] == 3);
    assert(stats.pipeline[SQLITE_PIPELINE_METADATA_LOOKUP_ROWS] == 132);
    for (auto& t : store) {
      assert(t.result == 0 && t.storage_length == t.request.length);
      assert(t.storage_offset == t.request.file_offset && t.stored_file_id == t.request.file_id);
      assert(t.stored_sequence == t.request.sequence);
      assert(!memcmp(t.stored_tag, t.request.tag, sizeof(t.stored_tag)));
    }
    assert(duplicate.result == 0 && missing.result == -ENOENT && stale.result == -ESTALE && skip.result == -EIO);
    assert(sqlite3_get_autocommit(service.db_));
    sqlite3_progress_handler(service.db_, 1, [](void*) { return 1; }, nullptr);
    assert(!service.resolve_reads(tasks));
    sqlite3_progress_handler(service.db_, 0, nullptr, nullptr);
    assert(sqlite3_get_autocommit(service.db_));
    assert(service.resolve_reads(tasks));
    assert(service.resetPerf());
  }
  puts("common batch metadata: 64-key chunks, tail, duplicate/missing/stale, error recovery PASS");
}

static void test_calibration_profile() {
  char path[] = "/tmp/sqlite-profile-test-XXXXXX";
  int fd = mkstemp(path); assert(fd >= 0);
  FILE* output = fdopen(fd, "w"); assert(output);
  fprintf(output, "keystone-mixed-calibration-v1 %llu %llu %llu %u 0 1200 3400 0\n",
      (unsigned long long)kGroupPmpSqliteExtentIoPolicyVersion,
      (unsigned long long)kGroupPmpSqliteCommonPathVersion,
      (unsigned long long)GROUP_PMP_SQLITE_VFS_BATCH_MAX,
      static_cast<unsigned>(configured_cache_mode()));
  assert(!fclose(output));
  setenv("GROUP_PMP_SQLITE_MERGE_PROFILE", path, 1);
  {
    SqliteExtentIoService::Impl service(false);
    assert(service.merge_calibrated_ && service.resetPerf());
    assert(service.snapshot().pipeline[SQLITE_PIPELINE_MERGE_CALIBRATED] == 1);
    assert(service.calibrated_saved_ns_[0][0] == 0 && service.calibrated_saved_ns_[0][1] == 1200);
    assert(service.calibrated_saved_ns_[1][0] == 3400 && service.calibrated_saved_ns_[1][1] == 0);
  }
  output = fopen(path, "a"); assert(output); fputs("stale", output); fclose(output);
  bool rejected = false;
  try { SqliteExtentIoService::Impl service(false); }
  catch (const std::runtime_error&) { rejected = true; }
  assert(rejected);
  unsetenv("GROUP_PMP_SQLITE_MERGE_PROFILE"); unlink(path);
  puts("mixed calibration: strict profile contract, zero disables, reset preserves profile PASS");
}

static void test_paired_publication_guard() {
  std::vector<CalibrationPublicationPair> pairs(93);
  for (auto& pair : pairs) {
    pair.discrete[0] = pair.discrete[1] = 1000;
    pair.merged[0] = pair.merged[1] = 1100;
  }
  auto guard = paired_publication_guard(pairs);
  assert(guard.windows == 3 && !guard.persistent);
  for (size_t i = 0; i < 31; ++i) pairs[i].merged[0] = 1200;
  guard = paired_publication_guard(pairs);
  assert(guard.bad_windows[0] == 1 && !guard.persistent);
  for (size_t i = 31; i < 62; ++i) pairs[i].merged[0] = 1200;
  guard = paired_publication_guard(pairs);
  assert(guard.bad_windows[0] == 2 && guard.persistent);
  for (auto& pair : pairs) pair.merged[0] = 1100;
  for (size_t i = 31; i < 93; ++i) pairs[i].merged[1] = 1200;
  guard = paired_publication_guard(pairs);
  assert(guard.bad_windows[1] == 2 && guard.persistent);
  puts("mixed calibration: paired per-buffer 10% guard requires persistent tail regression PASS");
}

int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--probe") return sqlite_io_path_probe(20);
  if ((argc == 3 || argc == 4) && std::string(argv[1]) == "--calibrate") {
    const unsigned iterations = argc == 4 ? static_cast<unsigned>(std::strtoul(argv[2], nullptr, 10)) : 15;
    const char* profile = argv[argc - 1];
    assert(iterations >= 15 && iterations <= 1000);
    const int result = sqlite_io_mixed_batch_probe(iterations, profile);
    if (result) return result;
    setenv("GROUP_PMP_SQLITE_MERGE_PROFILE", profile, 1);
    SqliteExtentIoService::Impl service(false);
    assert(service.merge_calibrated_);
    puts("real mixed calibration: profile generated and loaded PASS");
    return 0;
  }
  // These fixtures test merge correctness and safety independent of device cost.
  // The net-benefit unit cases and locality/probe executables test that policy.
  setenv("GROUP_PMP_SQLITE_MERGE_READ_SAVED_NS", "1000000000", 1);
  setenv("GROUP_PMP_SQLITE_MERGE_WRITE_SAVED_NS", "1000000000", 1);
  test_paired_publication_guard();
  test_interval_candidates();
  test_read_merge_feedback();
  test_sparse_precheck();
  char directory[] = "/tmp/sqlite-extent-regression-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  setenv("GROUP_PMP_SQLITE_CACHE_MODE", "cold", 1);
  test_write_batch_feedback();
  test_drain_and_snapshot();
  constexpr size_t bytes = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
  uint8_t* utms[2] = {nullptr, nullptr};
  size_t sizes[2] = {bytes, bytes};
  for (auto& utm : utms) {
    assert(posix_memalign(reinterpret_cast<void**>(&utm), 4096, bytes) == 0);
    memset(utm, 0, bytes);
  }
  {
    SqliteExtentIoService::Impl service;
    test_merge_cost(service);
    test_release_order(service, utms, bytes);
    test_metadata_batch(service);
    test_calibration_profile();
    test_write_overlap_planner(service);
    bool registered = service.prepareCase(1, utms, sizes, 2);
    test_calibrated_read_bypass(service, utms[0], bytes);
    test_bounded_write_admission(service, utms, bytes);
    std::vector<Task> storage(4);
    std::vector<Task*> tasks;
    for (size_t i = 0; i < storage.size(); ++i) {
      Task& task = storage[i];
      task.utm = utms[i / 2];
      task.utm_size = bytes;
      task.request.run_id = 1;
      task.request.worker_index = i / 2;
      task.request.worker_count = 2;
      task.request.buffer_id = i % 2;
      task.request.buffer_offset = i % 2 ?
          GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET :
          GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
      task.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
      task.request.workload = GROUP_PMP_SQLITE_READSEQ;
      task.request.file_id = 1;
      task.request.sequence = i + 1;
      task.request.file_offset = i * 2000000;
      task.request.length = 2000000;
      memset(task.data(), static_cast<int>(i + 1), 2000000);
      tasks.push_back(&task);
    }
    // Exercise the real collector with distinct worker run_ids and offsets
    // arriving out of order. A SYNC must remain a collection barrier.
    {
      std::lock_guard<std::mutex> lock(service.queue_mutex_);
      for (size_t i : {3, 0, 2, 1}) {
        Task task = storage[i];
        task.request.run_id = 100 + task.request.worker_index;
        service.queue_.push_back(std::move(task));
      }
      auto batch = service.take_ready_batch_locked(4);
      assert(batch.size() == 4 && service.queue_.empty());
      tasks.clear();
      for (auto& task : batch)
        tasks.push_back(&task);
      assert(service.execute_io(tasks));
      assert(service.snapshot().sequential_8mb_extent_count == 1);
      Task first = storage[0], barrier = first, second = storage[2];
      barrier.request.operation = GROUP_PMP_SQLITE_VFS_OP_SYNC;
      service.queue_.push_back(first);
      service.queue_.push_back(barrier);
      service.queue_.push_back(second);
      batch = service.take_ready_batch_locked(4);
      assert(batch.size() == 1 && service.queue_.size() == 2);
      assert(service.queue_.front().request.operation == GROUP_PMP_SQLITE_VFS_OP_SYNC);
      batch = service.take_ready_batch_locked(4);
      assert(batch.size() == 1 && service.queue_.size() == 1);
      batch = service.take_ready_batch_locked(4);
      assert(batch.size() == 1 && service.queue_.empty());
      service.queue_.push_back(first);
      batch = service.take_ready_batch_locked(4);
      assert(batch.size() == 1 && service.queue_.empty());
      first.request.workload = second.request.workload = GROUP_PMP_SQLITE_READRANDOM;
      first.request.run_id = 101;
      second.request.run_id = 102;
      service.queue_.push_back(first);
      service.queue_.push_back(second);
      batch = service.take_ready_batch_locked(512);
      assert(batch.size() == 2 && service.queue_.empty());
      service.queue_.clear();
    }
    puts("ready-only cross-run collector, control barriers and random policy PASS");
    assert(service.resetPerf());
    tasks.clear();
    for (auto& task : storage)
      tasks.push_back(&task);
    assert(service.execute_io(tasks));
    auto stats = service.snapshot();
    assert(stats.logical_request_count == 4 && stats.physical_request_count == 1);
    assert(stats.physical_io_bytes == 8000000);
    assert(stats.sequential_8mb_extent_count == 1);
    assert(stats.cross_worker_extent_count == 1);
    check_io_clock(stats);
    assert(service.resetPerf());
    for (auto& task : storage) {
      assert(task.result == 0);
      task.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
      memset(task.data(), 0, 2000000);
      const uint64_t flags[] = {GROUP_PMP_SQLITE_READSEQ_INITIAL,
          GROUP_PMP_SQLITE_READSEQ_PEER_IO, GROUP_PMP_SQLITE_READSEQ_PEER_READY,
          GROUP_PMP_SQLITE_READSEQ_PEER_IDLE};
      task.request.reserved[0] = flags[&task - storage.data()];
    }
    assert(service.execute_io(tasks));
    stats = service.snapshot();
    assert(stats.physical_request_count == 1 && stats.merged_io_count > 0);
    assert(stats.sequential_8mb_extent_count == 1);
    assert(stats.cross_worker_extent_count == 1);
    assert(stats.direct_io_operations == 0);
    assert(stats.utm_copy_ns == 0);
    assert(stats.readseq_initial_requests == 1);
    assert(stats.readseq_refill_peer_io_requests == 1);
    assert(stats.readseq_refill_peer_ready_requests == 1);
    assert(stats.readseq_refill_peer_idle_requests == 1);
    assert(stats.random_sparse_fast_batches == 0);
    assert(service.cipher_cache_.empty());
    if (registered)
      assert(stats.registered_buffer_operations > 0);
    for (size_t i = 0; i < storage.size(); ++i) {
      assert(storage[i].result == 0);
      for (size_t j = 0; j < 2000000; ++j)
        assert(storage[i].data()[j] == i + 1);
    }
    check_io_clock(stats);
    puts("8 MB cross-worker readv/writev, direct UTM payload and API clock PASS");

    // The following fixtures exercise the legacy standalone planner. Production
    // Adaptive uses the online pipeline and does not populate this cache.
    service.online_execution_ = false;
    assert(service.resetPerf());
    service.invalidate_all_cache();
    storage.assign(20, Task());
    tasks.clear();
    for (size_t i = 0; i < storage.size(); ++i) {
      Task& task = storage[i];
      task.utm = utms[0];
      task.utm_size = bytes;
      task.request.run_id = 1;
      task.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
      task.request.workload = GROUP_PMP_SQLITE_READRAND100K;
      task.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + i * 100000;
      task.storage_length = 100000;
      task.storage_offset = i * 100000;
      task.stored_file_id = 1;
      task.stored_sequence = i + 1;
      tasks.push_back(&task);
    }
    assert(service.execute_io(tasks));
    assert(service.cipher_cache_.size() == 1);
    const auto& cached = service.cipher_cache_.begin()->second;
    assert(cached.offset == 1900000 && cached.length == 100000);
    assert(cached.sequence == 20 && cached.ciphertext.empty());
    assert(service.snapshot().cache_admission_disables == 1);
    assert(service.snapshot().cache_fill_bytes == 0);
    for (const auto& task : storage)
      assert(task.result == 0);
    puts("100 KB exact packing and last-entry-only ciphertext cache PASS");

    stats = service.snapshot();
    assert(stats.read100k[SQLITE_READ100K_DISCRETE_BATCHES] == 0);
    assert(stats.read100k[SQLITE_READ100K_MERGED_BATCHES] == 1);
    assert(stats.read100k[SQLITE_READ100K_DISCRETE_BYTES] == 0);
    assert(stats.physical_request_count == 1);
    assert(stats.pipeline[SQLITE_PIPELINE_READ100K_DISCRETE_PLAN_BYPASSES] == 0);
    service.invalidate_all_cache();
    assert(service.execute_io(tasks));
    stats = service.snapshot();
    assert(stats.physical_request_count == 2);
    assert(stats.read100k[SQLITE_READ100K_MERGED_BATCHES] == 2);
    assert(stats.read100k[SQLITE_READ100K_MERGED_BYTES] == 4000000);
    assert(stats.read100k[SQLITE_READ100K_MERGED_SERVICE_NS] > 0);
    for (auto* task : tasks)
      assert(task->result == 0 && task->data()[0] == 1);
    assert(service.resetPerf());
    assert(service.read_merge_feedback_.empty());
    for (const auto value : service.snapshot().read100k)
      assert(value == 0);
    service.recordWakeupTimeline(100, 200, 300, 330);
    assert(service.snapshot().host_resume_ioctl_ns == 30);
    assert(service.snapshot().publish_to_host_resume_request_ns == 200);
    puts("read100k real discrete/merged contents, counters, reset and Host ioctl clock PASS");

    assert(service.resetPerf());
    service.invalidate_all_cache();
    for (size_t i = 0; i < storage.size(); ++i) {
      Task& task = storage[i];
      task.request.workload = GROUP_PMP_SQLITE_READRANDOM;
      task.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + i * 4096;
      task.storage_length = 4096;
      task.storage_offset = i * 16384;
    }
    assert(service.execute_io(tasks));
    stats = service.snapshot();
    assert(stats.logical_request_count == 20 && stats.physical_request_count == 20);
    assert(stats.physical_io_bytes == 20 * 4096);
    assert(stats.random_sparse_fast_batches == 1);
    assert(stats.random_sparse_fast_requests == 20 && stats.sort_ns == 0);
    assert(stats.random_planned_batches == 0 && stats.random_precheck_fallbacks == 0);
    assert(stats.random_precheck_ns > 0);
    assert(workload_batch_target(GROUP_PMP_SQLITE_READRANDOM, 512, 1024) == 512);
    check_io_clock(stats);
    puts("sparse 4 KB discrete I/O path unchanged PASS");
    for (auto& task : storage) {
      task.request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
      task.request.workload = GROUP_PMP_SQLITE_FILLRANDOM;
      task.request.file_id = task.stored_file_id;
      task.request.file_offset = task.storage_offset;
      task.request.length = task.storage_length;
      task.request.sequence = task.stored_sequence;
      memset(task.data(), 0x61 + (&task - storage.data()), 4096);
    }
    assert(service.resetPerf() && service.execute_io(tasks));
    stats = service.snapshot();
    assert(stats.random_sparse_fast_batches == 1 && stats.sort_ns == 0);
    assert(stats.write_disjoint_batches == 1 && stats.write_overlap_batches == 0);
    // Both modes validate write ownership/coverage before optional clustering.
    // Disjoint ranges require two linear scans, not pairwise comparisons.
    assert(stats.write_overlap_checks == 2 * tasks.size() - 1);
    assert(stats.write_overlap_check_ns > 0 && stats.random_precheck_ns > 0);
    std::array<uint8_t, 4096> page;
    for (size_t i = 0; i < storage.size(); ++i) {
      assert(pread(service.file_for(1), page.data(), page.size(),
                   storage[i].storage_offset) == 4096);
      assert(std::all_of(page.begin(), page.end(), [i](uint8_t value) {
        return value == 0x61 + i;
      }));
    }
    // Locality changes must trigger the full planner on the very next batch.
    storage[1].request.file_offset = 4096;
    assert(service.resetPerf() && service.execute_io(tasks));
    stats = service.snapshot();
    assert(stats.random_sparse_fast_batches == 0 && stats.random_planned_batches == 1);
    assert(stats.random_precheck_fallbacks == 0);
    assert(stats.random_local_plan_batches == 1);
    assert(stats.random_local_candidate_requests == 2);
    assert(stats.random_sparse_fast_requests == 18);
    assert(stats.merged_io_count == 1 && stats.physical_request_count == 19);
    // Equal read ranges with different destinations still deduplicate safely.
    service.invalidate_all_cache();
    tasks.resize(3);
    for (size_t i = 0; i < tasks.size(); ++i) {
      auto& task = *tasks[i];
      task.request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
      task.request.workload = GROUP_PMP_SQLITE_READRANDOM;
      task.storage_offset = i == 2 ? 4096 : 0;
    }
    assert(service.resetPerf() && service.execute_io(tasks));
    stats = service.snapshot();
    assert(stats.deduplicated_request_count == 1 && stats.physical_request_count == 1);
    assert(stats.random_planned_batches == 1);
    assert(memcmp(tasks[0]->data(), tasks[1]->data(), 4096) == 0);
    assert(tasks[0]->data()[0] == 0x61 && tasks[2]->data()[0] == 0x62);
    // Async baseline remains discrete and does not acquire the adaptive gate.
    setenv("GROUP_PMP_SQLITE_IO_MODE", "async-no-extent", 1);
    service.invalidate_all_cache();
    assert(service.resetPerf() && service.execute_io(tasks));
    stats = service.snapshot();
    assert(stats.physical_request_count == 3 && stats.merged_io_count == 0);
    assert(stats.random_sparse_fast_batches == 0 && stats.random_precheck_ns == 0);
    setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
    puts("sparse writes, immediate locality changes, duplicate reads and async isolation PASS");
    std::cout << "registered=" << registered
              << " io_uring_submissions=" << stats.io_uring_submissions
              << " posix_fallback_operations=" << stats.posix_fallback_operations
              << std::endl;
    test_write_overlap_contents(service, utms, bytes);
    test_local_planner_contents(service, utms, bytes);
    test_cache_admission(service, utms[0], bytes);
  }
  test_read_pair_enqueue(utms[0], bytes);
  for (auto utm : utms)
    free(utm);
  std::string data_path = std::string(directory) + "/keystone-cipher-0000000000000001.bin";
  assert(unlink(data_path.c_str()) == 0);
  std::string database_path = std::string(directory) + "/keystone-group-extent-index.db";
  assert(unlink(database_path.c_str()) == 0);
  assert(rmdir(directory) == 0);
}
