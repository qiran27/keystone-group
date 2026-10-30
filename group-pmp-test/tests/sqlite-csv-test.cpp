#include <cassert>
#include <future>
#include <limits>
#include <sstream>
#define main group_pmp_unused_runner_main
#include "../host/group-pmp-test-runner.cpp"
#undef main

// In-memory edge transport; the OCALL handler and asynchronous service are real.
uintptr_t _shared_start;
size_t _shared_len;
static size_t test_return_offset = sizeof(struct edge_call);

int edge_call_args_ptr(struct edge_call* call, uintptr_t* ptr, size_t* size) {
  const size_t offset = call->call_arg_offset;
  *size = call->call_arg_size;
  if (offset >= _shared_len || offset > UINTPTR_MAX - _shared_start ||
      *size > _shared_len - offset ||
      *size > UINTPTR_MAX - (_shared_start + offset))
    return -1;
  *ptr = _shared_start + offset;
  return 0;
}

uintptr_t edge_call_data_ptr() { return _shared_start + test_return_offset; }

int edge_call_setup_ret(struct edge_call* call, void* data, size_t size) {
  const uintptr_t ptr = reinterpret_cast<uintptr_t>(data);
  if (ptr < _shared_start || ptr - _shared_start > _shared_len ||
      size > _shared_len - (ptr - _shared_start) || size > UINTPTR_MAX - ptr)
    return -1;
  call->return_data.call_ret_offset = ptr - _shared_start;
  call->return_data.call_ret_size = size;
  return 0;
}

struct PairedReadOcall {
  std::vector<uint64_t> storage;
  group_pmp_sqlite_vfs_ring_pair_doorbell pair;
  size_t shared_size;

  PairedReadOcall() : storage(GROUP_PMP_SQLITE_VFS_UTM_BYTES / sizeof(uint64_t)),
                      pair(), shared_size(GROUP_PMP_SQLITE_VFS_UTM_BYTES) {
    for (size_t slot = 0; slot < 2; ++slot) {
      auto& bell = pair.rings[slot];
      bell.magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
      bell.version = GROUP_PMP_SQLITE_VFS_VERSION;
      bell.generation = 10 + slot;
      bell.producer = bell.count = 1;
      bell.flags = GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY;
      bell.ring_slot = slot;
      bell.batch_request_id = 500 + slot;
      auto& header = ring(slot);
      header.magic = bell.magic;
      header.version = bell.version;
      header.generation = bell.generation;
      header.producer = 1;
      auto& req = request(slot);
      req.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
      req.version = GROUP_PMP_SQLITE_VFS_VERSION;
      req.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
      req.request_id = 100 + slot;
      req.run_id = 41;
      req.worker_count = 1;
      req.workload = req.file_id = GROUP_PMP_SQLITE_READSEQ;
      req.buffer_id = req.ring_slot = slot;
      req.buffer_offset = slot ? GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET :
                                 GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
      req.length = GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
      req.logical_size = 2 * GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
      req.file_offset = req.reserved[1] = slot * GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
      req.sequence = req.task_id = slot + 1;
      req.reserved[0] = GROUP_PMP_SQLITE_STORE_RING |
          GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY | GROUP_PMP_SQLITE_STORE_MEASURED;
    }
  }

  uint8_t* utm() { return reinterpret_cast<uint8_t*>(storage.data()); }
  group_pmp_sqlite_vfs_ring_header& ring(size_t slot) {
    return *reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
        utm() + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot));
  }
  group_pmp_sqlite_vfs_request& request(size_t slot) {
    return *reinterpret_cast<group_pmp_sqlite_vfs_request*>(
        utm() + GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET_FOR_SLOT(slot));
  }
  group_pmp_sqlite_vfs_status& status(size_t slot) {
    return *reinterpret_cast<group_pmp_sqlite_vfs_status*>(
        utm() + GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET_FOR_SLOT(slot));
  }
  edge_call& invoke(const void* args, size_t size) {
    _shared_start = reinterpret_cast<uintptr_t>(utm());
    _shared_len = shared_size;
    auto& call = *reinterpret_cast<edge_call*>(utm());
    call = {};
    call.call_id = GROUP_PMP_SQLITE_VFS_OCALL_ID;
    call.call_arg_offset = sizeof(call);
    call.call_arg_size = size;
    call.return_data.call_status = CALL_STATUS_ERROR;
    std::memcpy(utm() + sizeof(call), args, size);
    sqlite_dispatched_completion.reset();
    group_pmp_sqlite_async_vfs(&call);
    return call;
  }
};

static void check_intent_ocall() {
  SqliteIoPerfSnapshot perf;
  perf.completion_wait_ocall_count = 7;
  assert(sqlite_expected_host_ocalls(11, perf) == 18);
  perf.pipeline[SQLITE_PIPELINE_INTENT_WINDOWS] = 3;
  assert(sqlite_expected_host_ocalls(11, perf) == 21);
  assert(!perf.logical_request_count && !perf.physical_request_count && !perf.batch_count);
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  PairedReadOcall transport;
  group_pmp_sqlite_intent_plan p = {};
  p.magic = GROUP_PMP_SQLITE_INTENT_MAGIC;
  p.version = GROUP_PMP_SQLITE_INTENT_VERSION;
  p.request_id = 39;
  p.run_id = p.worker_count = 1;
  p.workload = GROUP_PMP_SQLITE_READRANDOM;
  p.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
  p.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
  p.count = 3;
  p.flags = GROUP_PMP_SQLITE_STORE_MEASURED;
  p.file_span = 12288;
  const group_pmp_sqlite_io_intent input[] = {{8192,4096},{0,4096},{4096,4096}};
  memcpy(transport.utm() + p.buffer_offset, input, sizeof(input));
  auto& call = transport.invoke(&p, sizeof(p));
  assert(call.return_data.call_status == CALL_STATUS_OK);
  assert(call.return_data.call_ret_size == sizeof(group_pmp_sqlite_intent_ack));
  group_pmp_sqlite_intent_ack ack;
  memcpy(&ack, transport.utm() + call.return_data.call_ret_offset, sizeof(ack));
  assert(ack.magic == p.magic && ack.version == p.version && ack.request_id == 39 &&
         ack.count == 3 && ack.status != 0);
  assert(!memcmp(input, transport.utm() + p.buffer_offset, sizeof(input)));
  assert(!sqlite_dispatched_completion);
  // The packet is the same size as WAIT_ANY; its distinct magic must select planning.
  static_assert(sizeof(p) == sizeof(group_pmp_sqlite_vfs_wait_any), "packet size fixture");
  p.count = GROUP_PMP_SQLITE_INTENT_MAX + 1;
  auto& invalid = transport.invoke(&p, sizeof(p));
  memcpy(&ack, transport.utm() + invalid.return_data.call_ret_offset, sizeof(ack));
  assert(ack.status != 0 && !sqlite_dispatched_completion);
  puts("obsolete intent OCALL: real handler rejects future plan, no UTM mutation or deferred completion PASS");
}

static void check_pair_counts_and_flags() {
  for (const char* mode : {"adaptive-extent", "async-no-extent", "sync-no-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    for (uint64_t workload = 0; workload <= GROUP_PMP_SQLITE_READRAND100K; ++workload) {
      const bool paired = std::strcmp(mode, "sync-no-extent") != 0 &&
          workload == GROUP_PMP_SQLITE_READSEQ;
      const bool intent = false;
      assert(sqlite_worker_diagnostic_flags(workload, GROUP_PMP_MIXED_DIAG_MEMORY) ==
          (GROUP_PMP_MIXED_DIAG_MEMORY | (paired ? GROUP_PMP_SQLITE_PAIRED_READS : 0) |
           (intent ? GROUP_PMP_SQLITE_INTENT_LOOKAHEAD : 0)));
      assert(sqlite_ring_counts_valid(workload, 0, 0, 0));
      assert(sqlite_ring_counts_valid(workload, 3, 3, 3));
      assert(sqlite_ring_counts_valid(workload, 3, 4, 4) == paired);
      assert(sqlite_ring_counts_valid(workload, 3, 6, 6) == paired);
      assert(!sqlite_ring_counts_valid(workload, 3, 7, 7));
      assert(!sqlite_ring_counts_valid(workload, 3, 2, 2));
      assert(!sqlite_ring_counts_valid(workload, 3, 2, 3));
      assert(!sqlite_ring_counts_valid(workload, 0, 1, 1));
      assert(sqlite_ring_counts_valid(workload, 3, 4, 3) == !paired);
      assert(sqlite_ring_counts_valid(workload, UINT64_MAX, UINT64_MAX, UINT64_MAX));
      assert(sqlite_ring_counts_valid(workload, UINT64_MAX / 2 + 1,
                                      UINT64_MAX, UINT64_MAX) == paired);
    }
  }
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  puts("Paired READSEQ counts and config flag; nonpaired strict accounting PASS");
}

static void check_pair_rejections() {
  const auto reject = [](const std::function<void(PairedReadOcall&)>& change,
                          unsigned long expected = CALL_STATUS_ERROR) {
    PairedReadOcall test;
    change(test);
    const group_pmp_sqlite_vfs_ring_header headers[] = {test.ring(0), test.ring(1)};
    const auto before = sqlite_async_io_service().snapshot();
    const auto entries = sqlite_detached_completions.size();
    auto& call = test.invoke(&test.pair, sizeof(test.pair));
    assert(call.return_data.call_status == expected);
    assert(sqlite_detached_completions.size() == entries);
    for (size_t slot = 0; slot < 2; ++slot)
      assert(std::memcmp(&test.ring(slot), &headers[slot], sizeof(headers[slot])) == 0);
    const auto after = sqlite_async_io_service().snapshot();
    assert(after.batch_count == before.batch_count && after.task_count == before.task_count);
  };
  for (const char* mode : {"sync-no-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    reject([](PairedReadOcall&) {});
  }
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  for (size_t slot = 0; slot < 2; ++slot) {
    struct BellChange { uint64_t group_pmp_sqlite_vfs_ring_doorbell::*field; uint64_t value; };
    for (const auto& change : std::initializer_list<BellChange>{
        {&group_pmp_sqlite_vfs_ring_doorbell::magic, 0},
        {&group_pmp_sqlite_vfs_ring_doorbell::version, 0},
        {&group_pmp_sqlite_vfs_ring_doorbell::generation, 0},
        {&group_pmp_sqlite_vfs_ring_doorbell::count, 0},
        {&group_pmp_sqlite_vfs_ring_doorbell::count, 2},
        {&group_pmp_sqlite_vfs_ring_doorbell::producer, 2},
        {&group_pmp_sqlite_vfs_ring_doorbell::flags, 0},
        {&group_pmp_sqlite_vfs_ring_doorbell::ring_slot, 2},
        {&group_pmp_sqlite_vfs_ring_doorbell::batch_request_id, 0}})
      reject([=](PairedReadOcall& test) { test.pair.rings[slot].*change.field = change.value; });
    for (auto field : {&group_pmp_sqlite_vfs_ring_header::magic,
                       &group_pmp_sqlite_vfs_ring_header::version,
                       &group_pmp_sqlite_vfs_ring_header::generation,
                       &group_pmp_sqlite_vfs_ring_header::producer,
                       &group_pmp_sqlite_vfs_ring_header::consumer,
                       &group_pmp_sqlite_vfs_ring_header::completion_count,
                       &group_pmp_sqlite_vfs_ring_header::flags,
                       &group_pmp_sqlite_vfs_ring_header::completed_time_ticks})
      reject([=](PairedReadOcall& test) { ++(test.ring(slot).*field); });
    struct RequestChange { uint64_t group_pmp_sqlite_vfs_request::*field; uint64_t value; };
    for (const auto& change : std::initializer_list<RequestChange>{
        {&group_pmp_sqlite_vfs_request::magic, 0},
        {&group_pmp_sqlite_vfs_request::version, 0},
        {&group_pmp_sqlite_vfs_request::operation, GROUP_PMP_SQLITE_VFS_OP_WRITE},
        {&group_pmp_sqlite_vfs_request::workload, GROUP_PMP_SQLITE_READRANDOM},
        {&group_pmp_sqlite_vfs_request::request_id, 0},
        {&group_pmp_sqlite_vfs_request::run_id, 0},
        {&group_pmp_sqlite_vfs_request::worker_count, 0},
        {&group_pmp_sqlite_vfs_request::worker_index, 1},
        {&group_pmp_sqlite_vfs_request::file_id, 0},
        {&group_pmp_sqlite_vfs_request::buffer_id, 1 - slot},
        {&group_pmp_sqlite_vfs_request::ring_slot, 1 - slot},
        {&group_pmp_sqlite_vfs_request::descriptor_id, 1},
        {&group_pmp_sqlite_vfs_request::length, 0},
        {&group_pmp_sqlite_vfs_request::length, GROUP_PMP_SQLITE_VFS_BUFFER_BYTES + 1},
        {&group_pmp_sqlite_vfs_request::buffer_offset, UINT64_MAX},
        {&group_pmp_sqlite_vfs_request::file_offset, UINT64_MAX},
        {&group_pmp_sqlite_vfs_request::sequence, 0},
        {&group_pmp_sqlite_vfs_request::task_id, 0}})
      reject([=](PairedReadOcall& test) { test.request(slot).*change.field = change.value; });
    for (uint64_t flags : std::initializer_list<uint64_t>{UINT64_C(0), GROUP_PMP_SQLITE_STORE_RING,
                           GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY,
                           UINT64_C(1) << 63})
      reject([=](PairedReadOcall& test) { test.request(slot).reserved[0] = flags; });
    reject([=](PairedReadOcall& test) {
      test.request(slot).reserved[0] |= GROUP_PMP_SQLITE_STORE_BLOCK_ON_COMPLETE;
    });
    reject([=](PairedReadOcall& test) {
      test.request(slot).reserved[1] += GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
    });
  }
  reject([](PairedReadOcall& test) { test.pair.rings[1].ring_slot = 0; });
  for (auto field : {&group_pmp_sqlite_vfs_request::run_id,
                     &group_pmp_sqlite_vfs_request::worker_count,
                     &group_pmp_sqlite_vfs_request::file_id})
    reject([=](PairedReadOcall& test) { ++(test.request(1).*field); });
  reject([](PairedReadOcall& test) {
    test.request(0).worker_count = test.request(1).worker_count = 2;
    test.request(1).worker_index = 1;
  });
  reject([](PairedReadOcall& test) { test.request(1).request_id = test.request(0).request_id; });
  reject([](PairedReadOcall& test) {
    test.request(1).sequence = test.request(1).task_id = 1;
    test.request(1).reserved[1] = 0;
  });
  reject([](PairedReadOcall& test) { test.request(1).buffer_offset = test.request(0).buffer_offset; });
  reject([](PairedReadOcall& test) { --test.shared_size; });
  reject([](PairedReadOcall& test) { test.shared_size = sizeof(edge_call) + 64; },
         CALL_STATUS_BAD_OFFSET);
  test_return_offset = GROUP_PMP_SQLITE_VFS_UTM_BYTES - 64;
  reject([](PairedReadOcall&) {}, CALL_STATUS_BAD_PTR);
  test_return_offset = sizeof(edge_call);
  for (size_t slot = 0; slot < 2; ++slot) {
    PairedReadOcall test;
    auto key = test.request(slot);
    key.request_id = test.pair.rings[slot].batch_request_id + 10;
    auto pending = std::make_shared<SqliteAsyncCompletion>(1);
    assert(sqlite_store_detached_completion(key, pending));
    reject([](PairedReadOcall&) {});
    assert(sqlite_detached_completions.begin()->second == pending);
    sqlite_clear_detached_completions();
  }
  puts("Paired OCALL malformed headers/requests, bounds, keys and occupied slots PASS");
}

static void check_pair_reservation_cleanup() {
  const std::array<SqliteDetachedCompletionKey, 2> keys = {{{41, 0, 500, 0}, {41, 0, 500, 1}}};
  group_pmp_sqlite_vfs_request other_key = {};
  other_key.run_id = 41;
  other_key.worker_index = 1;
  other_key.request_id = 900;
  auto other_worker = std::make_shared<SqliteAsyncCompletion>(1);
  assert(sqlite_store_detached_completion(other_key, other_worker));
  std::array<std::shared_ptr<SqliteAsyncCompletion>, 2> first = {{
      std::make_shared<SqliteAsyncCompletion>(1), std::make_shared<SqliteAsyncCompletion>(1)}};
  auto second = first;
  assert(sqlite_store_detached_read_pair(keys, first));
  assert(sqlite_detached_completions.size() == 3);
  first[0]->completeOne();
  assert(first[0]->isComplete() && !first[1]->isComplete());
  assert(!sqlite_store_detached_read_pair(keys, first));
  first[1]->completeOne();
  for (auto& completion : second)
    completion = std::make_shared<SqliteAsyncCompletion>(1);
  assert(sqlite_store_detached_read_pair(keys, second));
  assert(sqlite_detached_completions.size() == 3);
  sqlite_remove_detached_read_pair(keys, first);
  assert(sqlite_detached_completions.size() == 3);
  sqlite_remove_detached_read_pair(keys, second);
  assert(sqlite_detached_completions.size() == 1);
  assert(sqlite_detached_completions.begin()->second == other_worker);
  second[1] = second[0];
  assert(!sqlite_store_detached_read_pair(keys, second));
  sqlite_clear_detached_completions();
  puts("Pair reservation: two slots, independent completion and exact rollback PASS");
}

static void check_pair_round_trip(uint64_t tail_bytes) {
  PairedReadOcall test;
  test.request(1).length = tail_bytes;
  test.request(0).logical_size = test.request(1).logical_size =
      GROUP_PMP_SQLITE_VFS_BUFFER_BYTES + tail_bytes;
  auto& service = sqlite_async_io_service();
  std::array<group_pmp_sqlite_vfs_request, 2> writes;
  for (size_t slot = 0; slot < 2; ++slot) {
    writes[slot] = test.request(slot);
    writes[slot].operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
    writes[slot].reserved[0] = GROUP_PMP_SQLITE_STORE_PREFILL;
    std::memset(writes[slot].tag, 0x70 + slot, sizeof(writes[slot].tag));
    std::memset(test.utm() + writes[slot].buffer_offset, 0xa0 + slot, writes[slot].length);
  }
  auto written = std::make_shared<SqliteAsyncCompletion>(2);
  assert(service.submitBatch(writes.data(), 2, test.utm(), test.shared_size, written));
  written->wait();
  assert(service.resetPerf());
  for (size_t slot = 0; slot < 2; ++slot)
    std::memset(test.utm() + writes[slot].buffer_offset, 0, writes[slot].length);
  if (tail_bytes < GROUP_PMP_SQLITE_VFS_BUFFER_BYTES) {
    // Ring slot is part of the detached key, even with one shared batch ID.
    test.pair.rings[1].batch_request_id = test.pair.rings[0].batch_request_id;
    std::swap(test.pair.rings[0], test.pair.rings[1]);
  }
  auto& call = test.invoke(&test.pair, sizeof(test.pair));
  assert(call.return_data.call_status == CALL_STATUS_OK);
  assert(call.return_data.call_ret_size == sizeof(group_pmp_sqlite_vfs_ring_pair_ack));
  assert(!sqlite_dispatched_completion);
  group_pmp_sqlite_vfs_ring_pair_ack ack;
  std::memcpy(&ack, test.utm() + call.return_data.call_ret_offset, sizeof(ack));
  assert(sqlite_detached_completions.size() == 2);
  std::array<std::shared_ptr<SqliteAsyncCompletion>, 2> completions;
  for (size_t index = 0; index < 2; ++index) {
    const auto& bell = test.pair.rings[index];
    assert(ack.rings[index].magic == bell.magic && ack.rings[index].version == bell.version);
    assert(ack.rings[index].generation == bell.generation && ack.rings[index].accepted == 1);
    assert(ack.rings[index].status == 0 && ack.rings[index].consumer == 1);
    assert(ack.rings[index].ring_slot == bell.ring_slot);
    assert(ack.rings[index].batch_request_id == bell.batch_request_id);
    assert(test.ring(bell.ring_slot).consumer == 1);
    group_pmp_sqlite_vfs_wait wait = {GROUP_PMP_SQLITE_VFS_MAGIC,
        GROUP_PMP_SQLITE_VFS_VERSION, 41, 0, bell.batch_request_id, bell.ring_slot, 0};
    const SqliteDetachedCompletionKey key = {41, 0, bell.batch_request_id, bell.ring_slot};
    completions[index] = sqlite_detached_completions.at(key);
    auto& waited = test.invoke(&wait, sizeof(wait));
    assert(waited.return_data.call_status == CALL_STATUS_OK);
    assert(sqlite_dispatched_completion == completions[index] ||
           (!sqlite_dispatched_completion && completions[index]->isComplete()));
    assert(sqlite_detached_completions.size() == 1 - index);
  }
  assert(completions[0] != completions[1]);
  for (const auto& completion : completions)
    completion->wait();
  const auto completed_snapshot = service.drainAndSnapshot();
  assert(completed_snapshot.batch_count == 1 && completed_snapshot.task_count == 2);
  for (size_t slot = 0; slot < 2; ++slot) {
    assert(test.ring(slot).completion_count == 1);
    const auto& status = test.status(slot);
    assert(status.state == GROUP_PMP_SQLITE_VFS_STATE_DONE && status.result == 0);
    assert(status.request_id == writes[slot].request_id && status.length == writes[slot].length);
    assert(status.sequence == writes[slot].sequence);
    assert(std::memcmp(status.tag, writes[slot].tag, sizeof(status.tag)) == 0);
    const uint8_t* cipher = test.utm() + writes[slot].buffer_offset;
    assert(std::all_of(cipher, cipher + writes[slot].length,
                      [=](uint8_t value) { return value == 0xa0 + slot; }));
    assert(std::all_of(cipher + writes[slot].length,
                      cipher + GROUP_PMP_SQLITE_VFS_BUFFER_BYTES,
                      [](uint8_t value) { return value == 0; }));
  }
  assert(service.resetPerf());
  sqlite_dispatched_completion.reset();
  service.cleanup_case(1, GROUP_PMP_SQLITE_READSEQ);
  puts("Runner paired OCALL: one enqueue, two ACKs/waits and ciphertext-only buffers PASS");
}

static void check_async_submission_before_completion() {
  PairedReadOcall test;
  auto& service = sqlite_async_io_service();
  std::array<group_pmp_sqlite_vfs_request, 2> writes;
  for (size_t slot = 0; slot < 2; ++slot) {
    writes[slot] = test.request(slot);
    writes[slot].operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
    writes[slot].reserved[0] = GROUP_PMP_SQLITE_STORE_PREFILL;
    std::memset(test.utm() + writes[slot].buffer_offset, 0xb0 + slot, writes[slot].length);
  }
  auto prepared = std::make_shared<SqliteAsyncCompletion>(2);
  assert(service.submitBatch(writes.data(), 2, test.utm(), test.shared_size, prepared));
  (void)service.drainAndSnapshot();
  assert(prepared->isComplete());

  // Hold the service thread, not the edge dispatcher. No requested READ can finish.
  std::promise<void> blocked, release;
  auto reached = blocked.get_future();
  auto resume = release.get_future();
  auto gate = std::make_shared<SqliteAsyncCompletion>(1);
  gate->arm([&](bool) { blocked.set_value(); resume.wait(); }, 0);
  auto control = writes[0];
  control.operation = GROUP_PMP_SQLITE_VFS_OP_SYNC;
  control.request_id = 900;
  control.length = 0;
  control.reserved[0] = 0;
  assert(service.submit(control, test.utm(), test.shared_size, gate));
  assert(reached.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
  for (size_t slot = 0; slot < 2; ++slot) {
    auto& call = test.invoke(&test.pair.rings[slot], sizeof(test.pair.rings[slot]));
    assert(call.return_data.call_status == CALL_STATUS_OK);
    assert(call.return_data.call_ret_size == sizeof(group_pmp_sqlite_vfs_ring_ack));
    assert(!sqlite_dispatched_completion);
    assert(test.ring(slot).consumer == 1 && test.ring(slot).completion_count == 0);
    assert(sqlite_submission_timing.count == 1);
#if defined(__riscv)
    assert(test.ring(slot).host_received_ticks && test.ring(slot).host_ack_ticks);
#else
    // No cross-hart rdtime domain on the x86 regression host.
    assert(test.ring(slot).host_received_ticks == 0 && test.ring(slot).host_ack_ticks == 0);
#endif
    assert(test.ring(slot).host_resume_request_ticks == 0);
    sqlite_submission_timing.requestResume(sqlite_io_time_ticks());
    assert(test.ring(slot).host_resume_request_ticks >= test.ring(slot).host_ack_ticks);
  }
  assert(sqlite_detached_completions.size() == 2);
  for (const auto& entry : sqlite_detached_completions)
    assert(!entry.second->isComplete());
  release.set_value();
  (void)service.drainAndSnapshot();
  for (size_t slot = 0; slot < 2; ++slot) {
    assert(test.ring(slot).completion_count == 1);
    assert(test.status(slot).state == GROUP_PMP_SQLITE_VFS_STATE_DONE);
    assert(test.status(slot).result == 0);
  }
  sqlite_clear_detached_completions();
  assert(service.resetPerf());
  service.cleanup_case(1, GROUP_PMP_SQLITE_READSEQ);
  puts("Async ACK precedes held I/O; second buffer accepted while first is pending PASS");
}

static void check_paired_ocall() {
  char directory[] = "/tmp/sqlite-paired-ocall-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  setenv("GROUP_PMP_SQLITE_CACHE_MODE", "hot", 1);
  // The production service chooses its loop once per process. Start it under
  // an async mode before exercising invalid Sync packets in this shared test.
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  check_pair_round_trip(16);
  check_pair_counts_and_flags();
  check_pair_rejections();
  check_pair_reservation_cleanup();
  check_pair_round_trip(GROUP_PMP_SQLITE_VFS_BUFFER_BYTES);
  check_pair_round_trip(16);
  check_async_submission_before_completion();
  setenv("GROUP_PMP_SQLITE_IO_MODE", "async-no-extent", 1);
  check_pair_round_trip(GROUP_PMP_SQLITE_VFS_BUFFER_BYTES);
  check_pair_round_trip(16);
  check_async_submission_before_completion();
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  for (const char* name : {"keystone-group-extent-index.db", "keystone-group-extent-index.db-wal",
                           "keystone-group-extent-index.db-shm", "keystone-cipher-0000000000000006.bin"}) {
    const std::string path = std::string(directory) + "/" + name;
    assert(unlink(path.c_str()) == 0 || errno == ENOENT);
  }
  assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
}

template <typename Service>
static void check_published_legacy_drain(
    Service& service, const group_pmp_sqlite_vfs_request& request,
    std::vector<uint64_t>& storage) {
  const auto before = service.drainAndSnapshot();
  std::promise<void> published, release, drain_entered;
  auto publication = published.get_future();
  auto resume = release.get_future();
  auto entered = drain_entered.get_future();
  auto completion = std::make_shared<SqliteAsyncCompletion>(1);
  // Hold process() after publication but before worker_loop's final accounting.
  completion->arm([&](bool) {
    published.set_value();
    resume.wait();
  }, request.worker_index % GROUP_PMP_MIXED_LANES);
  auto* utm = reinterpret_cast<uint8_t*>(storage.data());
  assert(service.submit(request, utm, storage.size() * sizeof(uint64_t), completion));
  assert(publication.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
  const uint64_t published_at = sqlite_perf_now_ns();
  assert(completion->isComplete());
  const auto live = service.snapshot();
  assert(live.task_count == before.task_count);
  assert(live.batch_count == before.batch_count + 1);
  assert(live.window_last_completion_ns == before.window_last_completion_ns);
  auto draining = std::async(std::launch::async, [&] {
    drain_entered.set_value();
    return service.drainAndSnapshot();
  });
  assert(entered.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
  assert(draining.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
  release.set_value();
  assert(draining.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
  const auto final = draining.get();
  assert(final.task_count == before.task_count + 1);
  assert(final.batch_count == before.batch_count + 1);
  const uint64_t data = request.operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
      request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE;
  assert(final.logical_request_count == before.logical_request_count + data);
  assert(final.physical_request_count == before.physical_request_count + data);
  assert(final.sparse_io_count == before.sparse_io_count + data);
  assert(final.window_first_enqueue_ns && final.window_last_completion_ns >= published_at);
  assert(final.critical_path_ns == final.window_last_completion_ns - final.window_first_enqueue_ns);
  assert(final.max_batch_service_ns && final.max_completion_latency_ns);
  if (request.operation == GROUP_PMP_SQLITE_VFS_OP_READ)
    assert(final.read_service_ns > before.read_service_ns);
  else
    assert(final.control_service_ns > before.control_service_ns);
  const auto repeated = service.drainAndSnapshot();
  assert(repeated.task_count == final.task_count && repeated.batch_count == final.batch_count);
  assert(repeated.read_service_ns == final.read_service_ns);
  assert(repeated.write_service_ns == final.write_service_ns);
  assert(repeated.control_service_ns == final.control_service_ns);
  assert(repeated.queue_wait_ns == final.queue_wait_ns);
  assert(repeated.window_first_enqueue_ns == final.window_first_enqueue_ns);
  assert(repeated.window_last_completion_ns == final.window_last_completion_ns);
  assert(repeated.max_batch_service_ns == final.max_batch_service_ns);
  assert(repeated.max_completion_latency_ns == final.max_completion_latency_ns);
  const auto* status = reinterpret_cast<const group_pmp_sqlite_vfs_status*>(
      utm + sqlite_status_offset_for_request(request));
  assert(status->state == GROUP_PMP_SQLITE_VFS_STATE_DONE && status->result == 0);
}

static void check_sync_event_dispatch(bool ring) {
  setenv("GROUP_PMP_SQLITE_IO_MODE", "sync-no-extent", 1);
  auto& service = sqlite_no_extent_io_service();
  PairedReadOcall gate_storage;
  auto control = gate_storage.request(0);
  control.operation = GROUP_PMP_SQLITE_VFS_OP_SYNC;
  control.request_id = 900;
  control.length = control.reserved[0] = 0;
  std::promise<void> blocked, release;
  auto reached = blocked.get_future();
  auto resume = release.get_future();
  auto gate = std::make_shared<SqliteAsyncCompletion>(1);
  gate->arm([&](bool) { blocked.set_value(); resume.wait(); }, 0);
  assert(service.submit(control, gate_storage.utm(), gate_storage.shared_size, gate));
  assert(reached.wait_for(std::chrono::seconds(5)) == std::future_status::ready);

  std::array<PairedReadOcall, 2> workers;
  std::array<std::shared_ptr<SqliteAsyncCompletion>, 2> completions;
  std::atomic<unsigned> resumed{0};
  for (size_t i = 0; i < workers.size(); ++i) {
    auto& worker = workers[i];
    auto& request = worker.request(0);
    request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
    request.worker_count = 11;
    request.worker_index = i;
    request.length = 16;
    request.reserved[0] = GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY |
        GROUP_PMP_SQLITE_STORE_PREFILL | (ring ? GROUP_PMP_SQLITE_STORE_RING : 0);
    std::memset(worker.utm() + request.buffer_offset, 0xa0 + i, request.length);
    auto dispatched = std::async(std::launch::async, [&worker, &request, ring] {
      const void* args = ring ? static_cast<void*>(&worker.pair.rings[0]) :
                                static_cast<void*>(&request);
      auto& call = worker.invoke(args, ring ? sizeof(worker.pair.rings[0]) : sizeof(request));
      assert(call.return_data.call_status == CALL_STATUS_OK);
      return sqlite_dispatched_completion;
    });
    bool returned = dispatched.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
    if (!returned) {
      release.set_value();
      (void)dispatched.get();
      assert(returned && "sync submit blocks Host event dispatcher on storage");
    }
    completions[i] = dispatched.get();
    assert(completions[i] && !completions[i]->isComplete());
    completions[i]->arm([&](bool) { ++resumed; }, i + 2);
    assert(resumed == 0); // Worker ACK must still wait for real I/O completion.
  }
  release.set_value();
  (void)service.drainAndSnapshot();
  assert(resumed == 2);
  for (size_t i = 0; i < workers.size(); ++i) {
    auto& worker = workers[i];
    const auto& request = worker.request(0);
    group_pmp_sqlite_vfs_wait wait = {GROUP_PMP_SQLITE_VFS_MAGIC,
        GROUP_PMP_SQLITE_VFS_VERSION, request.run_id, i,
        ring ? worker.pair.rings[0].batch_request_id : request.request_id, 0, 0};
    auto& call = worker.invoke(&wait, sizeof(wait));
    assert(call.return_data.call_status == CALL_STATUS_OK);
    assert(!sqlite_dispatched_completion); // Never re-arm the consumed one-shot wakeup.
    assert(completions[i]->isComplete() && resumed == 2);
    if (ring)
      assert(worker.ring(0).completion_count == 1);
    auto& duplicate = worker.invoke(&wait, sizeof(wait));
    assert(duplicate.return_data.call_status == CALL_STATUS_ERROR);
  }
  sqlite_clear_detached_completions();
  service.cleanup_case(11, GROUP_PMP_SQLITE_READSEQ);
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  puts("Sync submit: Host accepts peer events while storage held, worker waits, late WAIT no lost wake PASS");
}

static void check_legacy_drain() {
  {
    GroupWarmupDiagnostics diagnostics;
    const auto started = std::chrono::steady_clock::now();
    {
      GroupWarmupWatchdog watcher(diagnostics, 1, 11);
      diagnostics.mark(GroupWarmupDiagnostics::MAIN, "wait-driver-event", 7, 23);
      assert(diagnostics.enabled.load());
      assert(diagnostics.stages[GroupWarmupDiagnostics::MAIN].request.load() == 23);
    }
    assert(!diagnostics.enabled.load());
    assert(std::chrono::steady_clock::now() - started < std::chrono::seconds(2));
    puts("Warmup observer: stage publication and immediate teardown (no 10s delay) PASS");
  }
  char directory[] = "/tmp/sqlite-legacy-drain-XXXXXX";
  assert(mkdtemp(directory));
  setenv("GROUP_PMP_SQLITE_STORAGE_DIR", directory, 1);
  setenv("GROUP_PMP_SQLITE_CACHE_MODE", "hot", 1);
  std::vector<uint64_t> storage((GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + 16) / sizeof(uint64_t));
  auto* utm = reinterpret_cast<uint8_t*>(storage.data());
  group_pmp_sqlite_vfs_request request = {};
  request.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
  request.version = GROUP_PMP_SQLITE_VFS_VERSION;
  request.operation = GROUP_PMP_SQLITE_VFS_OP_RESET;
  request.request_id = request.worker_count = request.task_id = request.sequence = 1;
  request.run_id = 91;
  request.workload = request.file_id = GROUP_PMP_SQLITE_READSEQ;
  request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
  {
    SqliteAsyncIoService service(0, true);
    check_published_legacy_drain(service, request, storage);
  }
  {
    SqliteNoExtentIoService service;
    request.operation = GROUP_PMP_SQLITE_VFS_OP_SYNC;
    request.request_id = 2;
    check_published_legacy_drain(service, request, storage);
    request.worker_count = GROUP_PMP_MIXED_LANES;
    request.length = request.logical_size = 16;
    request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
    request.reserved[0] = GROUP_PMP_SQLITE_STORE_MEASURED | GROUP_PMP_SQLITE_STORE_TXN_END;
    for (uint64_t lane = 0; lane < GROUP_PMP_MIXED_LANES; ++lane) {
      request.worker_index = lane;
      request.request_id = 10 + lane;
      std::memset(utm + request.buffer_offset, 0xa0 + lane, request.length);
      auto completion = std::make_shared<SqliteAsyncCompletion>(1);
      assert(service.submit(request, utm, storage.size() * sizeof(uint64_t), completion));
      (void)service.drainAndSnapshot();
      assert(completion->isComplete());
    }
    request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    request.reserved[0] = GROUP_PMP_SQLITE_STORE_MEASURED;
    for (uint64_t lane = 0; lane < GROUP_PMP_MIXED_LANES; ++lane) {
      request.worker_index = lane;
      request.request_id = 20 + lane;
      std::memset(utm + request.buffer_offset, 0, request.length);
      check_published_legacy_drain(service, request, storage);
      assert(std::all_of(utm + request.buffer_offset,
                        utm + request.buffer_offset + request.length,
                        [=](uint8_t value) { return value == 0xa0 + lane; }));
    }
    const auto final = service.drainAndSnapshot();
    assert(final.task_count == 1 + 2 * GROUP_PMP_MIXED_LANES);
    assert(final.batch_count == final.task_count);
    assert(final.logical_request_count == 2 * GROUP_PMP_MIXED_LANES);
    assert(final.physical_request_count == final.logical_request_count);
    assert(final.sparse_io_count == final.logical_request_count);
    assert(final.physical_io_bytes == 32 * GROUP_PMP_MIXED_LANES);
    assert(final.useful_io_bytes == final.physical_io_bytes);
    assert(final.commit_count && final.read_service_ns &&
           final.write_service_ns && final.control_service_ns);
    setenv("GROUP_PMP_SQLITE_CACHE_MODE", "cold", 1);
    assert(service.resetPerf());
    const auto cleared = service.drainAndSnapshot();
    assert(!cleared.task_count && !cleared.logical_request_count &&
           !cleared.physical_request_count && !cleared.sparse_io_count);
    assert(!cleared.physical_io_bytes && !cleared.useful_io_bytes);
    request.file_offset = 16; // A failed data request still counts as an attempted I/O.
    request.request_id = 100;
    auto failed = std::make_shared<SqliteAsyncCompletion>(1);
    assert(service.submit(request, utm, storage.size() * sizeof(uint64_t), failed));
    const auto failure = service.drainAndSnapshot();
    assert(failed->isComplete() && failure.task_count == 1);
    assert(failure.logical_request_count == 1 && failure.physical_request_count == 1);
    assert(failure.physical_io_bytes == 16 && !failure.useful_io_bytes);
    const auto* status = reinterpret_cast<const group_pmp_sqlite_vfs_status*>(
        utm + sqlite_status_offset_for_request(request));
    assert(status->result == -ENOENT);
  }
  check_sync_event_dispatch(false);
  check_sync_event_dispatch(true);
  for (const char* name : {"keystone-group-ciphertext.db", "keystone-group-ciphertext.db-wal",
                           "keystone-group-ciphertext.db-shm"}) {
    const std::string path = std::string(directory) + "/" + name;
    assert(unlink(path.c_str()) == 0 || errno == ENOENT);
  }
  assert(rmdir(directory) == 0);
  unsetenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  puts("Legacy terminal drain: publication race, writer/all readers, live snapshot and no reset PASS");
  puts("Sync data counts: controls excluded, writer/readers aggregated, reset and failed I/O counted PASS");
}

static std::vector<std::string> fields(const std::string& line) {
  std::vector<std::string> result;
  size_t start = 0;
  for (;;) {
    size_t end = line.find(',', start);
    result.push_back(line.substr(start, end - start));
    if (end == std::string::npos)
      return result;
    start = end + 1;
  }
}

struct CsvMetricExpectation {
  const char* column;
  uint64_t MixedRunMetrics::*field;
  uint64_t value;
  const char* csv_value;
};

static const CsvMetricExpectation policy17_metrics[] = {
    {"write_overlap_check_seconds", &MixedRunMetrics::sqlite_write_overlap_check_ns,
     UINT64_C(125000000), "0.125"},
    {"write_overlap_checks", &MixedRunMetrics::sqlite_write_overlap_checks,
     UINT64_C(4294967301), "4294967301"},
    {"write_disjoint_batches", &MixedRunMetrics::sqlite_write_disjoint_batches,
     23, "23"},
    {"write_overlap_batches", &MixedRunMetrics::sqlite_write_overlap_batches,
     7, "7"},
    {"adaptive_write_grow_count", &MixedRunMetrics::sqlite_adaptive_write_grow_count,
     3, "3"},
    {"adaptive_write_shrink_count", &MixedRunMetrics::sqlite_adaptive_write_shrink_count,
     5, "5"},
    {"adaptive_write_hold_count", &MixedRunMetrics::sqlite_adaptive_write_hold_count,
     11, "11"},
    {"sequential_ready_single_batches",
     &MixedRunMetrics::sqlite_sequential_ready_single_batches, 13, "13"},
    {"sequential_ready_multi_batches",
     &MixedRunMetrics::sqlite_sequential_ready_multi_batches, 17, "17"},
    {"sequential_ready_adjacent_pairs",
     &MixedRunMetrics::sqlite_sequential_ready_adjacent_pairs, 19, "19"},
    {"sequential_ready_nonadjacent_pairs",
     &MixedRunMetrics::sqlite_sequential_ready_nonadjacent_pairs, 29, "29"},
    {"random_sparse_fast_batches", &MixedRunMetrics::sqlite_random_sparse_fast_batches, 31, "31"},
    {"random_sparse_fast_requests", &MixedRunMetrics::sqlite_random_sparse_fast_requests, 32, "32"},
    {"random_planned_batches", &MixedRunMetrics::sqlite_random_planned_batches, 33, "33"},
    {"random_precheck_fallbacks", &MixedRunMetrics::sqlite_random_precheck_fallbacks, 34, "34"},
    {"random_precheck_ns", &MixedRunMetrics::sqlite_random_precheck_ns, 35, "35"},
    {"readseq_initial_requests", &MixedRunMetrics::sqlite_readseq_initial_requests, 36, "36"},
    {"readseq_refill_peer_io_requests", &MixedRunMetrics::sqlite_readseq_refill_peer_io_requests, 37, "37"},
    {"readseq_refill_peer_ready_requests", &MixedRunMetrics::sqlite_readseq_refill_peer_ready_requests, 38, "38"},
    {"readseq_refill_peer_idle_requests", &MixedRunMetrics::sqlite_readseq_refill_peer_idle_requests, 39, "39"},
    {"random_local_plan_batches", &MixedRunMetrics::sqlite_random_local_plan_batches, 40, "40"},
    {"random_local_candidate_requests", &MixedRunMetrics::sqlite_random_local_candidate_requests, 41, "41"},
    {"cache_fill_bytes", &MixedRunMetrics::sqlite_cache_fill_bytes, 42, "42"},
    {"cache_fill_ns", &MixedRunMetrics::sqlite_cache_fill_ns, 43, "43"},
    {"cache_fill_skipped_bytes", &MixedRunMetrics::sqlite_cache_fill_skipped_bytes, 44, "44"},
    {"cache_admission_disables", &MixedRunMetrics::sqlite_cache_admission_disables, 45, "45"},
    {"cache_admission_reenables", &MixedRunMetrics::sqlite_cache_admission_reenables, 46, "46"},
};

struct PipelineMetricExpectation {
  const char* column;
  uint64_t group_pmp_sqlite_pipeline_timing::*field;
  double scale;
};
static const PipelineMetricExpectation pipeline_metrics[] = {
    {"pipeline_doorbell_count", &group_pmp_sqlite_pipeline_timing::doorbell_count, 1.0},
    {"pipeline_doorbell_ack_seconds", &group_pmp_sqlite_pipeline_timing::doorbell_ack_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_doorbell_ack_max_us", &group_pmp_sqlite_pipeline_timing::doorbell_ack_max_ticks, 1e6 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_completion_to_consume_count", &group_pmp_sqlite_pipeline_timing::completion_to_consume_count, 1.0},
    {"pipeline_completion_to_consume_seconds", &group_pmp_sqlite_pipeline_timing::completion_to_consume_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_completion_to_consume_max_us", &group_pmp_sqlite_pipeline_timing::completion_to_consume_max_ticks, 1e6 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_completion_timestamp_invalid", &group_pmp_sqlite_pipeline_timing::completion_timestamp_invalid, 1.0},
    {"pipeline_ack_to_consume_seconds", &group_pmp_sqlite_pipeline_timing::ack_to_consume_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_ack_to_consume_max_us", &group_pmp_sqlite_pipeline_timing::ack_to_consume_max_ticks, 1e6 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_buffer_consume_count", &group_pmp_sqlite_pipeline_timing::buffer_consume_count, 1.0},
    {"pipeline_buffer_consume_seconds", &group_pmp_sqlite_pipeline_timing::buffer_consume_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_buffer_consume_max_us", &group_pmp_sqlite_pipeline_timing::buffer_consume_max_ticks, 1e6 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_buffer_refill_count", &group_pmp_sqlite_pipeline_timing::buffer_refill_count, 1.0},
    {"pipeline_buffer_refill_seconds", &group_pmp_sqlite_pipeline_timing::buffer_refill_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_buffer_refill_max_us", &group_pmp_sqlite_pipeline_timing::buffer_refill_max_ticks, 1e6 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_request_prepare_seconds", &group_pmp_sqlite_pipeline_timing::request_prepare_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_submission_timing_count", &group_pmp_sqlite_pipeline_timing::submission_timing_count, 1.0},
    {"pipeline_submission_timestamp_invalid", &group_pmp_sqlite_pipeline_timing::submission_timestamp_invalid, 1.0},
    {"pipeline_submit_to_host_seconds", &group_pmp_sqlite_pipeline_timing::submit_to_host_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_submit_to_host_max_us", &group_pmp_sqlite_pipeline_timing::submit_to_host_max_ticks, 1e6 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_host_to_ack_seconds", &group_pmp_sqlite_pipeline_timing::host_to_ack_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_host_to_ack_max_us", &group_pmp_sqlite_pipeline_timing::host_to_ack_max_ticks, 1e6 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_ack_to_resume_request_seconds", &group_pmp_sqlite_pipeline_timing::ack_to_resume_request_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_ack_to_resume_request_max_us", &group_pmp_sqlite_pipeline_timing::ack_to_resume_request_max_ticks, 1e6 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_resume_request_to_return_seconds", &group_pmp_sqlite_pipeline_timing::resume_request_to_return_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"pipeline_resume_request_to_return_max_us", &group_pmp_sqlite_pipeline_timing::resume_request_to_return_max_ticks, 1e6 / static_cast<double>(riscv_timebase_hz())},
    {"wait_timing_count", &group_pmp_sqlite_pipeline_timing::wait_timing_count, 1.0},
    {"wait_timestamp_invalid", &group_pmp_sqlite_pipeline_timing::wait_timestamp_invalid, 1.0},
    {"wait_submit_to_host_seconds", &group_pmp_sqlite_pipeline_timing::wait_submit_to_host_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"wait_host_to_resume_seconds", &group_pmp_sqlite_pipeline_timing::wait_host_to_resume_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"wait_resume_to_return_seconds", &group_pmp_sqlite_pipeline_timing::wait_resume_to_return_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"wait_resume_to_return_max_us", &group_pmp_sqlite_pipeline_timing::wait_resume_to_return_max_ticks, 1e6 / static_cast<double>(riscv_timebase_hz())},
    {"wait_oncpu_seconds", &group_pmp_sqlite_pipeline_timing::wait_oncpu_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"wait_offcpu_seconds", &group_pmp_sqlite_pipeline_timing::wait_offcpu_ticks, 1.0 / static_cast<double>(riscv_timebase_hz())},
    {"wait_clock_invalid", &group_pmp_sqlite_pipeline_timing::wait_clock_invalid, 1.0},
};

static void check_policy17_medians() {
  for (size_t count : {1, 2, 3, 4, 5}) {
    std::vector<MixedRunMetrics> samples(count);
    for (size_t i = 0; i < count; ++i) {
      auto& sample = samples[i];
      sample.worker_count = sample.active_lanes = sample.lane_depth[0] = 1;
      sample.slot_dispatches = sample.slot_aggregates = 1;
      sample.seconds = i + 1;
      sample.mb_per_sec = 60.0 / sample.seconds;
      size_t column = 0;
      for (const auto& expected : policy17_metrics) {
        // Rotate each field to exercise independent nearest-rank medians.
        sample.*expected.field = expected.value * ((i + column + 1) % count + 1);
        ++column;
      }
      for (const auto& expected : pipeline_metrics) {
        sample.pipeline.*expected.field = ((i + column + 1) % count + 1) * 100;
        ++column;
      }
    }
    MixedRunMetrics aggregate = {};
    assert(aggregate_mixed_samples(samples, &aggregate));
    assert(aggregate.sample_count == count);
    for (const auto& expected : policy17_metrics)
      assert(aggregate.*expected.field == expected.value * ((count + 1) / 2));
    for (const auto& expected : pipeline_metrics)
      assert(aggregate.pipeline.*expected.field == 100 * ((count + 1) / 2));
  }
  puts("Policy17 metrics: single, odd and even nearest-rank medians PASS");
}

static void check_sample_validation() {
  MixedRunMetrics sample = {};
  sample.worker_count = 5;
  sample.active_lanes = 3;
  sample.lane_depth[0] = sample.lane_depth[1] = 2;
  sample.lane_depth[2] = 1;
  sample.slot_dispatches = sample.slot_aggregates = 5;
  sample.digest = UINT64_C(18446744073709551000);
  sample.seconds = 1.0;
  sample.mb_per_sec = 60.0;
  MixedRunMetrics aggregate = {};
  std::vector<MixedRunMetrics> samples(5, sample);
  for (size_t i = 0; i < samples.size(); ++i) {
    samples[i].worker_ocalls = 100 + i;
    samples[i].vfs_ring_doorbell_count = 30 + i;
    samples[i].vfs_wait_count = i;
    samples[i].seconds = i + 1.0;
    samples[i].mb_per_sec = 60.0 / samples[i].seconds;
  }
  assert(aggregate_mixed_samples(samples, &aggregate));
  assert(aggregate.sample_count == 5 && aggregate.digest == sample.digest);
  assert(aggregate.seconds == 3 && aggregate.seconds_p95 == 5);
  assert(aggregate.seconds_min == 1 && aggregate.seconds_max == 5);
  assert(aggregate.mb_per_sec == 20 && aggregate.mb_per_sec_p95 == 60);
  const auto reject = [&](const char* field,
                           const std::function<void(MixedRunMetrics&)>& change) {
    auto invalid = samples;
    change(invalid[2]);
    std::ostringstream errors;
    assert(!aggregate_mixed_samples(invalid, &aggregate, &errors));
    assert(errors.str().find(std::string("sample=3 field=") + field) !=
        std::string::npos);
    std::ostringstream early_errors;
    assert(!validate_mixed_sample(invalid[2], invalid[0], 2, &early_errors));
    assert(errors.str() == early_errors.str());
    return errors.str();
  };
  const auto digest_error = reject("digest", [](MixedRunMetrics& value) {
    ++value.digest;
  });
  assert(digest_error.find("actual=18446744073709551001") != std::string::npos);
  assert(digest_error.find("expected=18446744073709551000") != std::string::npos);
  reject("slot_aggregates", [](MixedRunMetrics& value) { --value.slot_aggregates; });
  reject("slot_dispatches", [](MixedRunMetrics& value) { ++value.slot_dispatches; });
  reject("worker_count", [](MixedRunMetrics& value) { --value.worker_count; });
  reject("active_lanes", [](MixedRunMetrics& value) { --value.active_lanes; });
  reject("ocall_mode", [](MixedRunMetrics& value) { ++value.ocall_mode; });
  reject("lane_depth[1]", [](MixedRunMetrics& value) { ++value.lane_depth[1]; });
  reject("seconds", [](MixedRunMetrics& value) { value.seconds = 0; });
  reject("seconds", [](MixedRunMetrics& value) {
    value.seconds = std::numeric_limits<double>::quiet_NaN();
  });
  reject("mb_per_sec", [](MixedRunMetrics& value) {
    value.mb_per_sec = std::numeric_limits<double>::infinity();
  });
  sample.slot_dispatches = sample.slot_aggregates = 0;
  std::ostringstream errors;
  assert(!validate_mixed_sample(sample, sample, 0, &errors));
  assert(errors.str().find("slot_dispatches_minimum") != std::string::npos);
  puts("five-sample aggregation: order-independent results, strict invariants and early diagnostics PASS");
}

static MixedRunMetrics model_random_rings(const MixedWorkload& workload, bool planned,
                                         uint64_t batch = GROUP_PMP_SQLITE_VFS_BATCH_MAX) {
  MixedRunMetrics metric = {};
  const uint64_t chunk = 4096;
  const uint64_t cap = std::min(GROUP_PMP_SQLITE_INTENT_MAX,
                                GROUP_PMP_SQLITE_INTENT_WINDOW_BYTES / chunk);
  // Simulate producer window and ring boundaries instead of repeating the quotient formula.
  for (uint64_t worker = 0; worker < workload.worker_count; ++worker) {
    uint64_t remaining = workload.assigned_bytes[worker];
    while (remaining) {
      uint64_t window_bytes = planned ? std::min(remaining, cap * chunk) : remaining;
      remaining -= window_bytes;
      if (planned) ++metric.sqlite_io_pipeline[SQLITE_PIPELINE_INTENT_WINDOWS];
      while (window_bytes) {
        ++metric.vfs_ring_doorbell_count;
        for (uint64_t i = 0; i < batch && window_bytes; ++i) {
          window_bytes -= std::min(window_bytes, chunk);
          ++metric.vfs_ring_request_count;
          if (planned) ++metric.sqlite_io_pipeline[SQLITE_PIPELINE_INTENT_REQUESTS];
        }
      }
    }
  }
  return metric;
}

static void check_random_window_accounting() {
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  setenv("GROUP_PMP_SQLITE_TOTAL_BYTES", "512000000", 1);
  MixedWorkload workload;
  assert(build_mixed_workload(1, GROUP_PMP_MIXED_OCALL_PER_TASK, &workload,
                              GROUP_PMP_SQLITE_READRANDOM));
  auto metric = model_random_rings(workload, false);
  const uint64_t expected_doorbells = (125000 + GROUP_PMP_SQLITE_VFS_BATCH_MAX - 1) /
      GROUP_PMP_SQLITE_VFS_BATCH_MAX;
  assert(metric.vfs_ring_request_count == 125000 && metric.vfs_ring_doorbell_count == expected_doorbells);
  assert(metric.sqlite_io_pipeline[SQLITE_PIPELINE_INTENT_WINDOWS] == 0);
  assert((metric.vfs_ring_request_count + GROUP_PMP_SQLITE_VFS_BATCH_MAX - 1) /
      GROUP_PMP_SQLITE_VFS_BATCH_MAX == expected_doorbells);
  std::ostringstream errors;
  assert(check_sqlite_random_ring_result(metric, workload, errors) && errors.str().empty());
  const auto reject = [&](MixedRunMetrics bad) {
    std::ostringstream diagnostic;
    assert(!check_sqlite_random_ring_result(bad, workload, diagnostic));
    assert(diagnostic.str().find("expected_doorbells=" + std::to_string(expected_doorbells)) != std::string::npos);
  };
  auto bad = metric; ++bad.vfs_ring_doorbell_count; reject(bad);
  bad = metric; --bad.vfs_ring_doorbell_count; reject(bad);
  bad = metric; --bad.vfs_ring_request_count; reject(bad);
  bad = metric; ++bad.sqlite_io_pipeline[SQLITE_PIPELINE_INTENT_WINDOWS]; reject(bad);
  bad = metric; --bad.sqlite_io_pipeline[SQLITE_PIPELINE_INTENT_REQUESTS]; reject(bad);
  const uint64_t window = GROUP_PMP_SQLITE_INTENT_WINDOW_BYTES / 4096;
  for (const char* mode : {"sync-no-extent", "async-no-extent", "adaptive-extent"}) {
    const bool planned = false;
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    workload = {};
    workload.worker_count = 1;
    workload.workload_id = GROUP_PMP_SQLITE_READRANDOM;
    for (uint64_t count : {UINT64_C(1), UINT64_C(256), UINT64_C(257), window - 1,
                           window, window + 1, window * 2, window * 2 + 1}) {
      for (uint64_t tail : {UINT64_C(16), UINT64_C(4096)}) {
        workload.assigned_bytes[0] = (count - 1) * 4096 + tail;
        metric = model_random_rings(workload, planned);
        assert(check_sqlite_random_ring_result(metric, workload, errors));
      }
    }
    for (const char* bytes : {"60000000", "512000000"}) {
      setenv("GROUP_PMP_SQLITE_TOTAL_BYTES", bytes, 1);
      for (uint64_t n = 1; n <= 15; ++n)
        for (uint64_t id : {UINT64_C(3), UINT64_C(4), UINT64_C(5), UINT64_C(7)}) {
          assert(build_mixed_workload(n, GROUP_PMP_MIXED_OCALL_PER_TASK, &workload, id));
          metric = model_random_rings(workload, planned);
          assert(check_sqlite_random_ring_result(metric, workload, errors));
        }
    }
  }
  setenv("GROUP_PMP_SQLITE_TOTAL_BYTES", "1000000", 1);
  setenv("GROUP_PMP_SQLITE_IO_MODE", "adaptive-extent", 1);
  setenv("GROUP_PMP_SECURITY_NONCE", "123", 1);
  for (uint64_t n : {UINT64_C(1), UINT64_C(4)}) {
    for (uint64_t id : {GROUP_PMP_SQLITE_FILLRANDOM, GROUP_PMP_SQLITE_READRANDOM}) {
      assert(build_mixed_workload(n, GROUP_PMP_MIXED_OCALL_PER_TASK, &workload, id));
      metric = model_random_rings(workload, false, GROUP_PMP_SECURITY_BATCH_REQUESTS);
      assert(check_sqlite_random_ring_result(metric, workload, errors));
      auto corrupt = metric;
      ++corrupt.vfs_ring_doorbell_count;
      assert(!check_sqlite_random_ring_result(corrupt, workload, errors));
      corrupt = model_random_rings(workload, false);
      assert(!check_sqlite_random_ring_result(corrupt, workload, errors));
      unsetenv("GROUP_PMP_SECURITY_NONCE");
      assert(!check_sqlite_random_ring_result(metric, workload, errors));
      assert(check_sqlite_random_ring_result(corrupt, workload, errors));
      setenv("GROUP_PMP_SECURITY_NONCE", "123", 1);
    }
  }
  unsetenv("GROUP_PMP_SECURITY_NONCE");
  unsetenv("GROUP_PMP_SQLITE_TOTAL_BYTES");
  unsetenv("GROUP_PMP_SQLITE_IO_MODE");
  puts("online ring accounting: normal and compact security batches, corrupt counters rejected PASS");
}

static void check_submission_ack() {
  std::array<group_pmp_sqlite_vfs_request, 256> requests = {};
  for (size_t i = 0; i < requests.size(); ++i) {
    requests[i].buffer_offset = 4096 + i * 4096;
    requests[i].length = 4096;
  }
  assert(sqlite_submission_buffers_disjoint(requests.data(), requests.size()));
  std::reverse(requests.begin(), requests.end());
  assert(sqlite_submission_buffers_disjoint(requests.data(), requests.size()));
  requests[64].buffer_offset = requests[63].buffer_offset + 16;
  assert(!sqlite_submission_buffers_disjoint(requests.data(), requests.size()));
  requests[64].buffer_offset = UINT64_MAX - 8;
  assert(!sqlite_submission_buffers_disjoint(requests.data(), requests.size()));
  assert(!sqlite_submission_buffers_disjoint(requests.data(), 257));
  group_pmp_sqlite_vfs_ring_header rings[2] = {};
  SqliteSubmissionTiming timing;
  timing.begin(110);
  timing.accept(&rings[0]);
  timing.accept(&rings[1]);
  timing.publishAck(130);
  // Both accepted buffers may still be in I/O when the CPU resumes.
  assert(rings[0].completion_count == 0 && rings[1].completion_count == 0);
  timing.requestResume(140);
  for (const auto& ring : rings) {
    group_pmp_sqlite_pipeline_timing stats = {};
    group_pmp_sqlite_pipeline_submission(&stats, 100, ring.host_received_ticks,
        ring.host_ack_ticks, ring.host_resume_request_ticks, 200);
    assert(stats.submission_timing_count == 1);
    assert(stats.submit_to_host_ticks + stats.host_to_ack_ticks +
        stats.ack_to_resume_request_ticks + stats.resume_request_to_return_ticks == 100);
  }
  timing.begin(220);
  timing.acceptWait(&rings[0]);
  timing.publishAck(230);
  timing.requestResume(240);
  assert(rings[0].wait_host_received_ticks == 220);
  assert(rings[0].wait_host_ack_ticks == 230);
  assert(rings[0].wait_host_resume_request_ticks == 240);
  assert(rings[0].host_received_ticks == 110 && rings[0].host_ack_ticks == 130);
  assert(rings[0].host_resume_request_ticks == 140); // WAIT preserves submit timing.
  assert(rings[1].wait_host_received_ticks == 0);
  timing.begin(310);
  timing.publishAck(330);
  timing.requestResume(340);
  assert(rings[0].wait_host_resume_request_ticks == 240); // No stale control ring.
  timing.begin(410);
  timing.accept(&rings[0]);
  timing.publishAck(430);
  timing.requestResume(440);
  assert(rings[0].host_resume_request_ticks == 440); // New submission resets WAIT mode.
  assert(rings[0].wait_host_resume_request_ticks == 240);
  puts("submission ACK: packed/reordered overlap checks, ordered stages and ownership PASS");
}

static void check_wait_any() {
  for (unsigned winner = 0; winner < 2; ++winner) {
    for (unsigned early = 0; early < 3; ++early) {
      PairedReadOcall transport;
      group_pmp_sqlite_vfs_wait_any packet = {};
      std::array<std::shared_ptr<SqliteAsyncCompletion>, 2> buffers;
      sqlite_clear_detached_completions();
      for (unsigned i = 0; i < 2; ++i) {
        buffers[i] = std::make_shared<SqliteAsyncCompletion>(1);
        packet.buffers[i] = {GROUP_PMP_SQLITE_VFS_MAGIC,
            GROUP_PMP_SQLITE_VFS_VERSION, 41, 0, 500 + i, i, 0};
        const SqliteDetachedCompletionKey key = {41, 0, 500 + i, i};
        sqlite_detached_completions.emplace(key, buffers[i]);
      }
      auto invalid = packet;
      invalid.buffers[1].request_id++;
      assert(transport.invoke(&invalid, sizeof(invalid)).return_data.call_status == CALL_STATUS_ERROR);
      assert(buffers[0]->any_waiters.empty()); // Atomic validation of both IDs.
      if (early == 1) buffers[winner]->completeOne();
      assert(transport.invoke(&packet, sizeof(packet)).return_data.call_status == CALL_STATUS_OK);
      auto gate = sqlite_dispatched_completion;
      const auto* ack = reinterpret_cast<const group_pmp_sqlite_vfs_ack*>(
          transport.utm() + sizeof(edge_call));
      assert(ack->request_id == 500 && !ack->status);
      unsigned wakes = 0;
      if (early != 1) {
        assert(gate && !gate->isComplete());
        if (early == 2) buffers[winner]->completeOne();
        gate->arm([&](bool) { ++wakes; }, 2);
        if (early == 0) buffers[winner]->completeOne();
        assert(gate->isComplete() && wakes == 1);
      } else {
        assert(!gate); // Ready before WAIT: return directly, do not rearm.
      }
      const unsigned other = 1 - winner;
      assert(!buffers[other]->isComplete());
      // Waiting on the loser later remains legal; it is not erased by ANY.
      auto losing = sqlite_take_detached_completion(packet.buffers[other]);
      assert(losing == buffers[other]);
      unsigned loser_wakes = 0;
      losing->arm([&](bool) { ++loser_wakes; }, 2);
      losing->completeOne();
      assert(loser_wakes == 1 && wakes == (early == 1 ? 0U : 1U));
      sqlite_dispatched_completion.reset();
      sqlite_clear_detached_completions();
    }
  }
  puts("WAIT_ANY: either buffer, early/late completion, atomic IDs, no duplicate wake PASS");
}

static void check_file_layout_all_scales() {
  setenv("GROUP_PMP_SQLITE_TOTAL_BYTES", "1000000", 1);
  for (unsigned w : {GROUP_PMP_SQLITE_FILLRANDOM,GROUP_PMP_SQLITE_READRANDOM}) {
    for (unsigned n : {1U,4U}) {
      MixedWorkload work;
      assert(build_mixed_workload(n,GROUP_PMP_MIXED_OCALL_PER_TASK,&work,w));
      uint64_t total=0;
      for(unsigned i=0;i<n;++i) {
        assert(work.assigned_bytes[i]>=100000);
        assert(work.assigned_bytes[i]>4*GROUP_PMP_SECURITY_BATCH_REQUESTS*4096);
        total+=work.assigned_bytes[i];
      }
      assert(total==999840 && total==work.total_bytes);
    }
  }
  setenv("GROUP_PMP_SQLITE_TOTAL_BYTES", "60000000", 1);
  for (unsigned w = 1; w <= 8; ++w) {
    for (unsigned n = 1; n <= 64; ++n) {
      std::vector<uint64_t> reference;
      for (const char* mode : {"sync-no-extent", "async-no-extent", "adaptive-extent"}) {
        setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
        MixedWorkload work;
        assert(build_mixed_workload(n, GROUP_PMP_MIXED_OCALL_PER_TASK, &work, w));
        uint64_t packed = 0, aligned = 0;
        std::vector<uint64_t> spans;
        for (unsigned i = 0; i < n; ++i) {
          assert(work.assigned_bytes[i] % group_pmp_sqlite_value_size(w) == 0);
          const auto span = group_pmp_sqlite_file_span(w, work.assigned_bytes[i], 0);
          if (group_pmp_sqlite_page_random(w)) {
            assert(span % 4096 == 0 && span >= work.assigned_bytes[i]);
            assert(span - work.assigned_bytes[i] < 4096);
          } else assert(span == work.assigned_bytes[i]);
          spans.push_back(span);
          packed += span;
          aligned += group_pmp_sqlite_file_span(w, span, 1);
        }
        if (group_pmp_sqlite_page_random(w))
          assert(packed >= work.total_bytes && packed - work.total_bytes < n * 4096);
        else assert(packed == work.total_bytes && packed == 60000000);
        assert(aligned >= packed && aligned % 4096 == 0);
        if (!group_pmp_sqlite_is_random(w)) assert(aligned < packed + n * 4096);
        if (reference.empty()) reference = spans;
        else assert(reference == spans);
      }
    }
  }
  unsetenv("GROUP_PMP_SQLITE_TOTAL_BYTES");
  unsetenv("GROUP_PMP_SQLITE_IO_MODE");
  puts("Host file layout: 1..64 workers, 8 workloads, identical three-mode assignments, tight sequential and page-aligned random spans PASS");
}

static void check_security_fault_evidence() {
  group_pmp_security_probe record = {GROUP_PMP_SECURITY_PROBE_MAGIC, 1, 0x1234000, 2, 1};
  SecurityGuestEvent terminal;
  terminal.eid = 4100;
  terminal.error = Error::Success;
  terminal.event = KEYSTONE_GROUP_EVENT_EXIT;
  terminal.retval = uintptr_t(-1);
  assert(security_access_denied(record, 1, 2, 4100, terminal));
  for (uintptr_t ordinary : {uintptr_t(0), uintptr_t(93), uintptr_t(94), uintptr_t(97)}) {
    terminal.retval = ordinary;
    assert(!security_access_denied(record, 1, 2, 4100, terminal));
  }
  terminal.error = Error::EnclaveFatalFault;
  terminal.event = KEYSTONE_GROUP_EVENT_FAULT;
  assert(security_access_denied(record, 1, 2, 4100, terminal));
  assert(!security_access_denied(record, 1, 2, 4101, terminal));
  assert(!security_access_denied(record, 2, 2, 4100, terminal));
  assert(!security_access_denied(record, 1, 1, 4100, terminal));
  record.attempted = 0;
  assert(!security_access_denied(record, 1, 2, 4100, terminal));
  record.attempted = 1;
  terminal.error = Error::DeviceError;
  assert(!security_access_denied(record, 1, 2, 4100, terminal));
  terminal.error = Error::EnclaveFatalFault;
  terminal.event = KEYSTONE_GROUP_EVENT_NONE;
  assert(!security_access_denied(record, 1, 2, 4100, terminal));
  puts("Security denial evidence: matched EID/event/attempt required; setup failure and ordinary exit reject PASS");
}

static void check_security_ocall_identity() {
  std::array<uint8_t, SECURITY_AEAD_PROGRESS_OFFSET + sizeof(security_aead_progress)> utm = {};
  security_aead_progress progress = {SECURITY_AEAD_PROGRESS_MAGIC, SECURITY_AEAD_GCM, 0, 0, SECURITY_AEAD_KAT_STARTED};
  security_aead_progress sampled = {};
  std::memcpy(utm.data() + SECURITY_AEAD_PROGRESS_OFFSET, &progress, sizeof(progress));
  assert(security_aead_progress_snapshot(utm.data(), utm.size(), &sampled));
  assert(sampled.stage == SECURITY_AEAD_KAT_STARTED);
  assert(std::string(security_aead_stage_name(sampled.stage)) == "kat-started");
  assert(!security_aead_progress_snapshot(nullptr, utm.size(), &sampled));
  assert(!security_aead_progress_snapshot(utm.data(), utm.size() - 1, &sampled));
  assert(!security_aead_progress_snapshot(utm.data(), utm.size(), nullptr));
  for (uint64_t stage : {UINT64_C(0), UINT64_MAX}) {
    progress.stage = stage;
    std::memcpy(utm.data() + SECURITY_AEAD_PROGRESS_OFFSET, &progress, sizeof(progress));
    assert(!security_aead_progress_snapshot(utm.data(), utm.size(), &sampled));
  }
  progress.stage = SECURITY_AEAD_KAT_STARTED;
  progress.magic = 0;
  std::memcpy(utm.data() + SECURITY_AEAD_PROGRESS_OFFSET, &progress, sizeof(progress));
  assert(!security_aead_progress_snapshot(utm.data(), utm.size(), &sampled));
  struct edge_call header = {};
  header.call_id = SECURITY_AEAD_OCALL;
  for (uint64_t token : {UINT64_C(9), UINT64_C(107), UINT64_C(108), UINT64_MAX}) {
    assert(security_aead_ocall_identity_valid(token, &header, sizeof(header)));
    assert(header.call_id == SECURITY_AEAD_OCALL);
  }
  assert(!security_aead_ocall_identity_valid(0, &header, sizeof(header)));
  assert(!security_aead_ocall_identity_valid(107, nullptr, sizeof(header)));
  assert(!security_aead_ocall_identity_valid(107, &header, sizeof(header) - 1));
  for (uint64_t call : {UINT64_C(0), UINT64_C(1), UINT64_C(17), UINT64_MAX}) {
    header.call_id = call;
    assert(!security_aead_ocall_identity_valid(107, &header, sizeof(header)));
  }
  puts("Security AEAD OCALL identity: opaque resume tokens 107/108 accepted only with SDK edge slot 9 PASS");
}

int main() {
  {
    setenv("GROUP_PMP_MOTIVATION_SYSTEM","1",1);
    setenv("GROUP_PMP_SQLITE_TOTAL_BYTES","500000000",1);
    MixedWorkload one,three;
    assert(build_mixed_workload(1,GROUP_PMP_MIXED_OCALL_PER_TASK,&one,GROUP_PMP_SQLITE_READSEQ));
    assert(build_mixed_workload(3,GROUP_PMP_MIXED_OCALL_PER_TASK,&three,GROUP_PMP_SQLITE_READSEQ));
    assert(one.total_bytes==499999920 && one.total_bytes==three.total_bytes);
    for(const char* n:{"1","3"}) {
      setenv("GROUP_PMP_MOTIVATION_WORKERS",n,1);
      assert(sqlite_selected_worker_count(3)==1);
      assert(sqlite_worker_count_selected(std::strtoull(n,nullptr,10)));
      assert(!sqlite_worker_count_selected(2));
      assert(sqlite_selected_workload_count()==1 && sqlite_workload_selected(GROUP_PMP_SQLITE_READSEQ));
    }
    unsetenv("GROUP_PMP_MOTIVATION_SYSTEM");unsetenv("GROUP_PMP_MOTIVATION_WORKERS");
    unsetenv("GROUP_PMP_SQLITE_TOTAL_BYTES");
    assert(sqlite_selected_worker_count(3)==3);
    puts("Extent-I/O real-system selector: exactly N=1/3, actual READSEQ builder, fixed total across lane partitions, normal selection unchanged PASS");
  }
  check_security_ocall_identity();
  check_security_fault_evidence();
  setenv("GROUP_PMP_SQLITE_ADDRESS_MODE", "locality-random-v1", 1);
  for (const char* mode : {"sync-no-extent", "async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    assert(std::string(sqlite_address_mode_name()) == "locality-random-v1");
    for (uint64_t workload = 1; workload <= 8; ++workload)
      assert(!(sqlite_worker_diagnostic_flags(workload, 0) & UINT64_C(16)));
  }
  check_random_window_accounting();
  check_intent_ocall();
  check_file_layout_all_scales();
  check_sample_validation();
  check_submission_ack();
  assert(kSqliteCsvSchemaVersion == 44);
  check_paired_ocall();
  check_wait_any();
  check_legacy_drain();
  check_policy17_medians();
  {
    MixedRunMetrics metric = {};
    metric.sqlite_logical_request_count = 36;
    metric.sqlite_physical_request_count = 36;
    metric.io_trace_request_count = 36;
    metric.io_trace_max_request_bytes = 2000000;
    std::ostringstream diagnostics;
    assert(check_sqlite_sequential_io_result(metric, GROUP_PMP_SQLITE_READSEQ,
                                              11, diagnostics));
    assert(diagnostics.str().find("[WARN]") != std::string::npos);
    assert(diagnostics.str().find("sample_retained=1") != std::string::npos);
    assert(metric.sqlite_merged_io_count == 0); // Never fabricate a merge.
    metric.sqlite_merged_io_count = 1;
    metric.sqlite_physical_request_count = 35;
    metric.io_trace_max_request_bytes = 4000000;
    diagnostics.str("");
    assert(check_sqlite_sequential_io_result(metric, GROUP_PMP_SQLITE_READSEQ,
                                              11, diagnostics));
    assert(diagnostics.str().empty());
    metric.io_trace_max_request_bytes = 8000001;
    assert(!check_sqlite_sequential_io_result(metric, GROUP_PMP_SQLITE_READSEQ,
                                               11, diagnostics));
    metric.io_trace_max_request_bytes = 8000000;
    metric.io_trace_failed_request_count = 1;
    assert(!check_sqlite_sequential_io_result(metric, GROUP_PMP_SQLITE_READSEQ,
                                               11, diagnostics));
    metric.io_trace_failed_request_count = 0;
    metric.sqlite_physical_request_count = 37;
    assert(!check_sqlite_sequential_io_result(metric, GROUP_PMP_SQLITE_READSEQ,
                                               11, diagnostics));
    puts("sequential no-merge sample retained; invalid I/O still rejected PASS");
  }
  std::vector<std::vector<MixedRunMetrics> > results(9,
      std::vector<MixedRunMetrics>(2));
  std::vector<SqliteNoExtentBaseline> baselines(9);
  SqliteNoExtentScaleBaselines scales(9,
      std::vector<SqliteNoExtentBaseline>(2));
  for (size_t w = 1; w <= 8; ++w) {
    auto& value = results[w][1];
    value.worker_count = value.active_lanes = value.sample_count = 1;
    value.lane_depth[0] = 1;
    value.seconds = value.seconds_min = value.seconds_max = value.seconds_p95 = 2;
    value.mb_per_sec = 30;
    value.total_bytes = value.bytes_per_enclave = 60000000;
    value.sqlite_disk_io_ns = 1000000000;
    value.sqlite_completion_wait_ns = 100000000;
    value.sqlite_storage_sync_ns = 200000000;
    value.sqlite_completion_wakeup_count = 4;
    value.sqlite_host_resume_ioctl_ns = 40000;
    value.sqlite_wakeup_eligible_to_host_resume_request_ns = 4000000;
    value.vfs_crypto_io_overlap_ratio = 0.25;
    value.worker_aes_time_ticks = riscv_timebase_hz();
    value.aes_elapsed_time_ticks = value.worker_aes_time_ticks * 3;
    value.enclave_aes_mb_per_sec = 60;
    for (const auto& expected : policy17_metrics)
      value.*expected.field = w == GROUP_PMP_SQLITE_READRAND100K ? 0 : expected.value;
    for (const auto& expected : pipeline_metrics)
      value.pipeline.*expected.field = w * riscv_timebase_hz();
    for (size_t i = 0; i < value.sqlite_read100k.size(); ++i)
      value.sqlite_read100k[i] = 11 + i;
    for (size_t i = 0; i < value.sqlite_io_pipeline.size(); ++i)
      value.sqlite_io_pipeline[i] = 31 + i;
  }
  char name[] = "/tmp/sqlite-csv-regression-XXXXXX";
  int fd = mkstemp(name);
  assert(fd >= 0);
  close(fd);
  setenv("GROUP_PMP_SQLITE_CACHE_MODE", "cold", 1);
  for (const char* mode : {"adaptive-extent", "async-no-extent", "sync-no-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    assert(write_sqlite_scaling_csv(name, results, 1, baselines, scales,
                                    "unavailable", baselines, scales,
                                    "unavailable", 1100));
    std::ifstream csv(name);
    std::string line;
    assert(static_cast<bool>(std::getline(csv, line)));
    auto header = fields(line);
    assert(header.size() == 272 + SQLITE_PIPELINE_METRICS);
    assert(header[1] == "address_mode");
    assert(header[266] == "io_pipeline_submits");
    assert(header[280] == "io_pipeline_tail_ewma_ns");
    assert(header[281] == "io_pipeline_logical_target");
    assert(header.back() == "cipher");
    assert(header[190] == "request_queue_wait_mean_us");
    assert(header[191] == "host_resume_ioctl_mean_us");
    size_t column = 192;
    for (const auto& expected : policy17_metrics)
      assert(header[column++] == expected.column);
    for (const auto& expected : pipeline_metrics)
      if (std::strncmp(expected.column, "wait_", 5) != 0)
        assert(header[column++] == expected.column);
    assert(header[column++] == "worker_submit_resume_mean_us");
    assert(header[column++] == "worker_resume_timing_scope");
    assert(header[column++] == "host_resume_timing_scope");
    const char* merge_columns[] = {"read100k_discrete_batches", "read100k_merged_batches",
        "read100k_discrete_bytes", "read100k_merged_bytes", "read100k_discrete_service_ns",
        "read100k_merged_service_ns", "read100k_merge_backoffs", "read100k_merge_probes"};
    for (const char* expected : merge_columns)
      assert(header[column++] == expected);
    for (const char* expected : {"wait_timing_count", "wait_timestamp_invalid",
        "wait_submit_to_host_seconds", "wait_host_to_resume_seconds",
        "wait_resume_to_return_seconds", "wait_resume_to_return_max_us",
        "wait_oncpu_seconds", "wait_offcpu_seconds", "wait_clock_invalid",
        "wait_timing_scope"})
      assert(header[column++] == expected);
    assert(column == 266);
    for (const char* name : sqlite_pipeline_metric_names)
      assert(header[column++] == std::string("io_pipeline_") + name);
    assert(header[column++] == "file_layout_version");
    assert(header[column++] == "common_path_version");
    assert(header[column++] == "descriptor_limit");
    assert(header[column++] == "cluster_mode");
    assert(header[column++] == "io_pipeline_version");
    assert(header[column++] == "cipher");
    assert(column == header.size());
    assert(std::set<std::string>(header.begin(), header.end()).size() == header.size());
    size_t rows = 0;
    while (std::getline(csv, line)) {
      auto values = fields(line);
      assert(values.size() == header.size());
      std::map<std::string, std::string> row;
      for (size_t i = 0; i < header.size(); ++i)
        row[header[i]] = values[i];
      assert(row["io_mode"] == mode);
      assert(row["address_mode"] == "locality-random-v1");
      assert(row["io_policy_version"] ==
          (std::strcmp(mode, "sync-no-extent") == 0 ? "1" :
           std::strcmp(mode, "async-no-extent") == 0 ? "2" : "51"));
      for (size_t i = 0; i < SQLITE_READ100K_METRICS; ++i)
        assert(std::stoull(row[merge_columns[i]]) == 11 + i);
      assert(row["worker_resume_timing_scope"] ==
          "submit-ocall-host-request-to-worker-return-includes-runnable-queue-not-wait-ocall");
      assert(row["host_resume_timing_scope"] == (std::strcmp(mode, "sync-no-extent") ?
          "completion-backed-host-resume-ioctl-only" : "unavailable-sync-service"));
      assert(std::fabs(std::stod(row["worker_submit_resume_mean_us"]) -
          1e6 / riscv_timebase_hz()) < 1e-6);
      assert(!row.count("ready_to_resume_mean_us"));
      assert(!row.count("sm_wake_to_enclave_resume_seconds"));
      assert(row.count("host_resume_ioctl_seconds"));
      assert(std::stod(row["host_resume_ioctl_mean_us"]) == 10);
      assert(row["wait_timing_scope"] ==
          "ring-completion-wait-ocall-offcpu-includes-blocked-and-runnable-queue");
      for (const auto& expected : pipeline_metrics) {
        const double value = (rows + 1) * riscv_timebase_hz() * expected.scale;
        assert(std::fabs(std::stod(row[expected.column]) - value) < 1e-6);
      }
      for (const auto& expected : policy17_metrics)
        assert(row[expected.column] ==
            (row["workload"] == "readrand100k" ? "0" : expected.csv_value));
      assert(row["io_api_seconds"] == "1");
      assert(row["io_completion_wait_seconds"] == "0.1");
      assert(row["storage_sync_seconds"] == "0.2");
      assert(row["vfs_crypto_io_overlap_ratio"] == "0.25");
      assert(row["aes_oncpu_seconds"] == "1");
      assert(row["aes_elapsed_seconds"] == "3");
      assert(row["aes_descheduled_seconds"] == "2");
      assert(row["aes_oncpu_mb_per_sec"] == "60");
      assert(row["aes_timing_scope"] == "sm-member-runtime-crypto-boundaries");
      assert(row["cache_contract"] ==
          "buffered-fdatasync-fadvise-after-prefill");
      assert(row["io_pipeline_submits"] == "31");
      assert(row["io_pipeline_tail_ewma_ns"] == "45");
      assert(row["io_pipeline_logical_target"] == "46");
      assert(row["io_pipeline_ready_extent_joins"] == "50");
      assert(row["io_pipeline_version"] == "25");
      assert(row["cipher"] == "aes-ecb-128");
      assert(row["common_path_version"] == "3");
      assert(row["descriptor_limit"] == std::to_string(GROUP_PMP_SQLITE_VFS_BATCH_MAX));
      assert(row["cluster_mode"] == sqlite_cluster_mode_name());
      assert(row["file_layout_version"] == "3");
      for (size_t i = 0; i < SQLITE_PIPELINE_METRICS; ++i)
        assert(std::stoull(row[std::string("io_pipeline_") + sqlite_pipeline_metric_names[i]]) == 31 + i);
      assert(row["io_timing_scope"] == (std::strcmp(mode, "sync-no-extent") ?
          "submit-syscalls+reactor-io-wait-excludes-planning-copy-metadata" : "unavailable-sqlite-internal"));
      ++rows;
    }
    assert(rows == 8);
    csv.close();
    if (std::strcmp(mode, "adaptive-extent") != 0) {
      std::vector<SqliteNoExtentBaseline> loaded;
      SqliteNoExtentScaleBaselines loaded_scales;
      assert(load_sqlite_no_extent_baselines(name, mode, 1, &loaded, &loaded_scales));
      for (const char* cipher : {"aes-gcm-128", "chacha20-poly1305"}) {
        setenv("GROUP_PMP_BENCH_CIPHER", cipher, 1);
        assert(!load_sqlite_no_extent_baselines(name, mode, 1, &loaded, &loaded_scales));
      }
      unsetenv("GROUP_PMP_BENCH_CIPHER");
      assert(load_sqlite_no_extent_baselines(name, mode, 1, &loaded, &loaded_scales));
      assert(loaded[1].available && loaded[1].total_bytes == 60000000);
      std::ifstream input(name);
      std::ostringstream text; text << input.rdbuf(); input.close();
      std::string old = text.str();
      auto wrong_stream = old;
      wrong_stream.replace(wrong_stream.find("locality-random-v1"),
                           std::strlen("locality-random-v1"), "incompatible-stream");
      { std::ofstream out(name); out << wrong_stream; }
      assert(!load_sqlite_no_extent_baselines(name, mode, 1, &loaded, &loaded_scales));
      std::string diagnostic = old;
      const auto timing = diagnostic.find("master-first-dispatch-to-final-aggregate");
      assert(timing != std::string::npos);
      diagnostic.insert(timing, "diagnostic-neighbor-trace-");
      { std::ofstream out(name); out << diagnostic; }
      assert(!load_sqlite_no_extent_baselines(name, mode, 1, &loaded, &loaded_scales));
      const std::string common = std::to_string(kGroupPmpSqliteCommonPathVersion);
      const std::string trailer = ",3," + common + "," + std::to_string(GROUP_PMP_SQLITE_VFS_BATCH_MAX) +
          ",off," + std::to_string(kGroupPmpSqlitePipelineVersion) + ",aes-ecb-128\n";
      const std::string stale = ",2," + common + "," + std::to_string(GROUP_PMP_SQLITE_VFS_BATCH_MAX) +
          ",off," + std::to_string(kGroupPmpSqlitePipelineVersion) + ",aes-ecb-128\n";
      for (const auto& contract : {std::string(",3,0,") + std::to_string(GROUP_PMP_SQLITE_VFS_BATCH_MAX) + ",off,",
          std::string(",3,") + common + "," + std::to_string(GROUP_PMP_SQLITE_VFS_BATCH_MAX == 256 ? 488 : 256) + ",off,",
          std::string(",3,") + common + "," + std::to_string(GROUP_PMP_SQLITE_VFS_BATCH_MAX) + ",plan-only,"}) {
        auto mismatch = old;
        mismatch.replace(mismatch.find(trailer), trailer.size(), contract +
            std::to_string(kGroupPmpSqlitePipelineVersion) + ",aes-ecb-128\n");
        { std::ofstream out(name); out << mismatch; }
        assert(!load_sqlite_no_extent_baselines(name, mode, 1, &loaded, &loaded_scales));
      }
      size_t position = 0;
      unsigned mutated = 0;
      while ((position = old.find(trailer, position)) != std::string::npos) {
        old.replace(position, trailer.size(), stale);
        position += stale.size();
        ++mutated;
      }
      assert(mutated == 8);
      std::ofstream output(name); output << old; output.close();
      assert(!load_sqlite_no_extent_baselines(name, mode, 1, &loaded, &loaded_scales));
    }
  }
  setenv("GROUP_PMP_SQLITE_WORKLOAD_SET", "random-pair", 1);
  setenv("GROUP_PMP_SQLITE_IO_MODE", "async-no-extent", 1);
  assert(sqlite_selected_workload_count() == 2);
  assert(sqlite_workload_selected(GROUP_PMP_SQLITE_FILLRANDOM));
  assert(sqlite_workload_selected(GROUP_PMP_SQLITE_READRANDOM));
  assert(!sqlite_workload_selected(GROUP_PMP_SQLITE_FILLSEQ));
  assert(write_sqlite_scaling_csv(name, results, 1, baselines, scales,
                                  "unavailable", baselines, scales,
                                  "unavailable", 1100));
  std::vector<SqliteNoExtentBaseline> selected_baselines;
  SqliteNoExtentScaleBaselines selected_scales;
  assert(load_sqlite_no_extent_baselines(name, "async-no-extent", 1,
                                         &selected_baselines, &selected_scales));
  assert(selected_baselines[GROUP_PMP_SQLITE_FILLRANDOM].available);
  assert(selected_baselines[GROUP_PMP_SQLITE_READRANDOM].available);
  assert(!selected_baselines[GROUP_PMP_SQLITE_FILLSEQ].available);
  assert(write_sqlite_io_summary_csv(name, results, 1, baselines, scales,
                                      baselines, scales, 1100));
  assert(csv_has_uniform_columns(name, 2));
  assert(sqlite_selected_worker_count(4) == 4);
  setenv("GROUP_PMP_SECURITY_WORKER_SET", "1,4", 1);
  assert(sqlite_selected_worker_count(4) == 2);
  std::vector<uint64_t> selected_workers;
  for (uint64_t workers = 1; workers <= 4; ++workers)
    if (sqlite_worker_count_selected(workers)) selected_workers.push_back(workers);
  assert((selected_workers == std::vector<uint64_t>{1, 4}));
  for (uint64_t workload = 1; workload <= GROUP_PMP_SQLITE_WORKLOAD_COUNT; ++workload) {
    results[workload].resize(5);
    results[workload][4] = results[workload][1];
    scales[workload].resize(5);
    scales[workload][4] = scales[workload][1];
  }
  for (const char* mode : {"sync-no-extent", "async-no-extent", "adaptive-extent"}) {
    setenv("GROUP_PMP_SQLITE_IO_MODE", mode, 1);
    assert(write_sqlite_scaling_csv(name, results, 4, baselines, scales,
                                    "unavailable", baselines, scales, "unavailable", 1100));
    assert(csv_has_uniform_columns(name, 4));
    std::ifstream selected_csv(name);
    std::string line;
    assert(static_cast<bool>(std::getline(selected_csv, line)));
    const auto header = fields(line);
    auto worker_column = std::find(header.begin(), header.end(), "worker_count");
    assert(worker_column != header.end());
    while (std::getline(selected_csv, line)) {
      const auto row = fields(line);
      const auto& count = row[worker_column - header.begin()];
      assert(count == "1" || count == "4");
    }
    assert(write_sqlite_io_summary_csv(name, results, 4, baselines, scales,
                                        baselines, scales, 1100));
    assert(csv_has_uniform_columns(name, 4));
  }
  setenv("GROUP_PMP_SECURITY_WORKER_SET", "1,2,4", 1);
  assert(sqlite_selected_worker_count(4) == 0);
  unsetenv("GROUP_PMP_SECURITY_WORKER_SET");
  assert(sqlite_selected_worker_count(4) == 4);
  unsetenv("GROUP_PMP_SQLITE_WORKLOAD_SET");
  unlink(name);
  puts("CSV: schema44, policies 51/2/1, shared execution and descriptor contract, 8 workloads, "
       "planning/refill metrics and on-CPU timing scope PASS");
}
