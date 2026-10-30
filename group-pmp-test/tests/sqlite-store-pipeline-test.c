#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "shared/eyrie_call.h"
#include "shared/sm_call.h"

/* Mock only the enclave boundary; keep the production ring and real AES. */
#define __SYSCALL_H__
static uintptr_t utm_query_direct(struct keystone_utm_direct_info*, size_t);
int ocall(unsigned long, void*, size_t, void*, size_t);
int copy_to_shared_utm(uintptr_t, const void*, size_t);
static int test_random_key(uint8_t* key, size_t length) {
  for (size_t i = 0; i < length; ++i) key[i] = (uint8_t)(i * 7 + 1);
  return 0;
}
#define BENCHMARK_TEST_RANDOM test_random_key
#include "../sqlite-bench-master/keystone_enclave_store.c"
static unsigned test_cipher;
static int corrupt_aead;
static uint8_t aead_disk[8000000], aead_tags[4096][16];
static uint64_t aead_sequences[4096];
#ifdef GROUP_PMP_KV_WORKER
/* Test-only ciphertext backing store: production never decrypts on Host. */
static uint8_t kv_mock_disk[8000000];
static void copy_template(uint8_t* output, uint64_t offset, uint64_t length) {
  assert(kv_record_make(output, (size_t)length, kv_key_for_offset(offset),
                        (uint32_t)store_config.worker_index, 0) == 0);
}
#endif

static uint8_t test_utm[GROUP_PMP_SQLITE_VFS_UTM_BYTES]
    __attribute__((aligned(4096)));
int copy_to_shared_utm(uintptr_t offset, const void* data, size_t length) {
  if(offset > sizeof(test_utm) || length > sizeof(test_utm)-offset) return -1;
  memcpy(test_utm+offset,data,length);
  return 0;
}
static uint8_t host_plain[GROUP_PMP_SQLITE_VFS_BUFFER_BYTES];
static unsigned pending[2], completion_mode, peak_buffers;
static uint64_t doorbells, descriptors, largest_batch, mock_waits;
static uint64_t pair_doorbells, submitted_rings, first_wait_descriptors;
static uint64_t first_wait_consumed_bytes;
static uint64_t any_waits;
static int first_submit_peer_untouched;
static uint64_t slot_submissions[2], slot_waits[2], reuse_with_peer[2];
static uint64_t accepted_generation[2], accepted_id[2], cipher_hash[2];
static unsigned cipher_valid[2];
static uint64_t readseq_initial, readseq_peer_io, readseq_peer_ready, readseq_peer_idle;
static int bad_pair_ack, bad_ack_field, fail_submit;
static int bad_intent;
static int wait_clock_fault;
static uint64_t intent_calls, intent_coverage[9000], intent_sequences[9000];
static int track_intents;
static struct keystone_member_exec_clock test_clock = {2, 1, 1, 0, 0, 1};
static uint64_t clock_now;
static struct keystone_member_exec_clock* republish_clock;
static uint64_t clock_read_time(void) {
  if (republish_clock) {
    // Model a switch-out/resume interrupt partway through the snapshot.
    republish_clock->sequence += 2;
    republish_clock->runtime_ticks = 500;
    republish_clock->resume_ticks = 5000;
    republish_clock = 0;
    clock_now = 5001;
  }
  return clock_now;
}

static void test_exec_clock(void) {
  struct keystone_exec_clock_sample before, after;
  struct keystone_member_exec_clock clock = {2, 1, 7, 100, 1000, 1};
  clock_now = 1010;
  assert(keystone_exec_clock_read(&clock, clock_read_time, &before) == 0);
  // 10 ticks running, 4000 descheduled, then 10 running after resume.
  clock.sequence = 4;
  clock.runtime_ticks = 120;
  clock.resume_ticks = 5020;
  clock_now = 5030;
  assert(keystone_exec_clock_read(&clock, clock_read_time, &after) == 0);
  assert(after.runtime_ticks - before.runtime_ticks == 20);
  assert(after.wall_ticks - before.wall_ticks == 4020);
  clock.sequence = 5;
  assert(keystone_exec_clock_read(&clock, clock_read_time, &after) != 0);
  clock.sequence = 6;
  clock.running = 0;
  assert(keystone_exec_clock_read(&clock, clock_read_time, &after) != 0);
  clock.running = 1;
  clock.version = 0;
  assert(keystone_exec_clock_read(&clock, clock_read_time, &after) != 0);
  clock.version = KEYSTONE_EXEC_CLOCK_VERSION;
  clock.runtime_ticks = 100;
  clock.resume_ticks = 1000;
  clock_now = 1010;
  republish_clock = &clock;
  assert(keystone_exec_clock_read(&clock, clock_read_time, &after) == 0);
  assert(after.runtime_ticks == 501 && after.wall_ticks == 5001);
  clock.generation = 0;
  assert(keystone_exec_clock_read(&clock, clock_read_time, &after) != 0);
  puts("SM execution clock: off-CPU exclusion, publication and version checks PASS");
}

static void test_locality_page_permutation(void) {
  const uint64_t pages[] = {14649, 24414, 48828, 73242, 97656, 122070, 125000};
  store_config.worker_index = 3;
  store_config.workload = GROUP_PMP_SQLITE_READRANDOM;
  for (size_t n = 0; n < sizeof(pages) / sizeof(pages[0]); ++n) {
    const uint64_t count = pages[n];
    uint8_t* seen = calloc((size_t)count, 1);
    assert(seen);
    store_task_bytes = count * GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES;
    for (uint64_t i = 0; i < count; ++i) {
      const uint64_t page = extent_key(i * GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES);
      assert(page < count && !seen[page]);
      seen[page] = 1;
    }
    for (uint64_t i = 0; i < count; ++i) assert(seen[i]);
    free(seen);
  }
  store_task_bytes = pages[0] * GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES - 16;
  store_config.file_base = 0;
  store_config.direct_layout = 0;
  packed_tail_index = extent_key(store_task_bytes -
      store_task_bytes % GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES);
  packed_tail_gap = GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES -
      store_task_bytes % GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES;
  uint8_t* seen = calloc((size_t)pages[0], 1);
  assert(seen);
  for (uint64_t i = 0; i < pages[0]; ++i) {
    const uint64_t offset = extent_file_offset(i *
        GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES);
    assert(offset % GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES == 0);
    assert(offset / GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES < pages[0]);
    assert(!seen[offset / GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES]);
    seen[offset / GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES] = 1;
  }
  assert(extent_file_offset((pages[0] - 1) *
      GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES) ==
      (pages[0] - 1) * GROUP_PMP_SQLITE_VFS_RANDOM_PAGE_BYTES);
  free(seen);
  puts("locality random 4 KB permutation: unique, bounded, seven sizes PASS");
}

static uintptr_t utm_query_direct(struct keystone_utm_direct_info* info,
                                   size_t length) {
  assert(length == sizeof(*info));
  memset(info, 0, sizeof(*info));
  info->abi_version = KEYSTONE_UTM_DIRECT_ABI_VERSION;
  info->struct_size = sizeof(*info);
  info->flags = KEYSTONE_UTM_DIRECT_FLAG_READ | KEYSTONE_UTM_DIRECT_FLAG_WRITE |
      KEYSTONE_UTM_DIRECT_FLAG_NX;
  info->data_utm_offset = GROUP_PMP_SQLITE_VFS_CONTROL_BYTES;
  info->data_va = (uintptr_t)test_utm + info->data_utm_offset;
  info->data_size = sizeof(test_utm) - info->data_utm_offset;
  return 0;
}

static uint64_t payload_hash(unsigned slot) {
  const uint8_t* payload = test_utm + buffer_offset(slot);
  uint64_t hash = UINT64_C(1469598103934665603);
  for (size_t i = 0; i < GROUP_PMP_SQLITE_VFS_BUFFER_BYTES; ++i) {
    hash ^= payload[i];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static void complete_ring(unsigned slot) {
  struct group_pmp_sqlite_vfs_ring_header* ring =
      (void*)(test_utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot));
  struct group_pmp_sqlite_vfs_request* requests =
      (void*)(test_utm + GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET_FOR_SLOT(slot));
  assert(pending[slot]);
  assert(ring->generation == accepted_generation[slot]);
  for (uint64_t i = 0; i < ring->producer; ++i) {
    struct group_pmp_sqlite_vfs_request* request = requests + i;
    struct group_pmp_sqlite_vfs_status* status =
        (void*)(test_utm + status_offset(slot, i));
    assert(payload_range_matches(request->buffer_id, request->buffer_offset,
                                  request->length));
    if (store_config.cipher_algorithm != BENCHMARK_AES_ECB) {
      const size_t k = request->task_id - 1;
      assert(k < 4096 && request->file_offset + request->length <= sizeof(aead_disk));
      if (request->operation == GROUP_PMP_SQLITE_VFS_OP_READ) {
        memcpy(test_utm + request->buffer_offset, aead_disk + request->file_offset, request->length);
        memcpy(status->tag, aead_tags[k], 16);
        if (corrupt_aead == 1) test_utm[request->buffer_offset] ^= 1;
        if (corrupt_aead == 2) status->tag[0] ^= 1;
      } else {
        memcpy(aead_disk + request->file_offset, test_utm + request->buffer_offset, request->length);
        memcpy(aead_tags[k], request->tag, 16);
        aead_sequences[k] = request->sequence;
      }
    } else if (request->operation == GROUP_PMP_SQLITE_VFS_OP_READ) {
#ifdef GROUP_PMP_KV_WORKER
      assert(request->file_offset + request->length <= sizeof(kv_mock_disk));
      memcpy(test_utm + request->buffer_offset, kv_mock_disk + request->file_offset,
             request->length);
#else
      copy_template(host_plain, request->reserved[1], request->length);
      assert(group_pmp_crypto_transform(&crypto_context,
          GROUP_PMP_CRYPTO_ENCRYPT, host_plain,
          test_utm + request->buffer_offset, request->length) == 0);
      assert(memcmp(host_plain, test_utm + request->buffer_offset, 16) != 0);
#endif
    } else {
      assert(group_pmp_crypto_transform(&crypto_context,
          GROUP_PMP_CRYPTO_DECRYPT, test_utm + request->buffer_offset,
          host_plain, request->length) == 0);
#ifdef GROUP_PMP_KV_WORKER
      uint32_t version = (request->reserved[0] & GROUP_PMP_SQLITE_STORE_MEASURED) &&
          store_config.workload == GROUP_PMP_SQLITE_OVERWRITE ? 1 : 0;
      assert(kv_record_check(host_plain, request->length, kv_key_for_offset(request->reserved[1]),
                              (uint32_t)store_config.worker_index, version, NULL) == 0);
      assert(request->file_offset + request->length <= sizeof(kv_mock_disk));
      memcpy(kv_mock_disk + request->file_offset, test_utm + request->buffer_offset,
             request->length);
#else
      assert(validate_plain_sample(host_plain, request->reserved[1],
                                    request->length, NULL) == 0);
#endif
    }
    status->magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    status->version = GROUP_PMP_SQLITE_VFS_VERSION;
    status->request_id = request->request_id;
    status->state = GROUP_PMP_SQLITE_VFS_STATE_DONE;
    status->result = 0;
    status->length = request->length;
    status->sequence = request->sequence;
    if (store_config.cipher_algorithm && request->operation == GROUP_PMP_SQLITE_VFS_OP_READ) {
      status->sequence = aead_sequences[request->task_id - 1];
      if (corrupt_aead == 3) ++status->sequence;
    }
  }
  ring->completed_time_ticks = 150;
  __atomic_store_n(&ring->completion_count, ring->producer, __ATOMIC_RELEASE);
  pending[slot] = 0;
  if (requests[0].operation == GROUP_PMP_SQLITE_VFS_OP_READ) {
    cipher_hash[slot] = payload_hash(slot);
    cipher_valid[slot] = 1;
  }
}

static void accept_ring(const struct group_pmp_sqlite_vfs_ring_doorbell* bell,
                        struct group_pmp_sqlite_vfs_ring_ack* ack) {
  unsigned slot = (unsigned)bell->ring_slot;
  assert(slot < 2 && !pending[slot]);
  const struct store_batch* batch = &store_batches[slot];
  struct group_pmp_sqlite_vfs_ring_header* ring =
      (void*)(test_utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(slot));
  const struct group_pmp_sqlite_vfs_request* requests =
      (void*)(test_utm + GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET_FOR_SLOT(slot));
  assert(bell->magic == GROUP_PMP_SQLITE_VFS_RING_MAGIC);
  assert(bell->version == GROUP_PMP_SQLITE_VFS_VERSION);
  assert(bell->flags == GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY);
  assert(bell->count && bell->count <= GROUP_PMP_SQLITE_VFS_BATCH_MAX);
  assert(bell->producer == bell->count);
  assert(bell->generation && bell->generation != accepted_generation[slot]);
  assert(bell->batch_request_id && bell->batch_request_id != accepted_id[slot]);
  assert(batch->pending && batch->detached && batch->count == bell->count);
  assert(batch->request_id == bell->batch_request_id);
  assert(batch->generation == bell->generation && batch->ring_slot == slot);
  assert(ring->magic == bell->magic && ring->version == bell->version);
  assert(ring->generation == bell->generation && ring->completion_count == 0);
  assert(__atomic_load_n(&ring->producer, __ATOMIC_ACQUIRE) == bell->count);
  if (!submitted_rings && requests[0].operation == GROUP_PMP_SQLITE_VFS_OP_WRITE) {
    first_submit_peer_untouched = 1;
    for (uint64_t i = 0; i < GROUP_PMP_SQLITE_VFS_BUFFER_BYTES; ++i)
      if (test_utm[buffer_offset(1 - slot) + i] != 0xa5)
        first_submit_peer_untouched = 0;
  }
  for (uint64_t i = 0; i < bell->count; ++i) {
    if (track_intents) {
      const uint64_t logical = requests[i].reserved[1] / chunk_bytes();
      assert(logical < 9000 && !intent_coverage[logical]++);
      assert(requests[i].file_offset == extent_file_offset(requests[i].reserved[1]));
      assert(requests[i].task_id == logical + 1);
      intent_sequences[logical] = requests[i].sequence;
    }
    const struct group_pmp_sqlite_vfs_status* status =
        (void*)(test_utm + status_offset(slot, i));
    assert(requests[i].ring_slot == slot && requests[i].descriptor_id == i);
    assert(requests[i].request_id == batch->descriptors[i].request_id);
    assert(status->state == GROUP_PMP_SQLITE_VFS_STATE_PENDING);
    assert(status->request_id == requests[i].request_id);
    if (requests[i].operation == GROUP_PMP_SQLITE_VFS_OP_READ)
      assert(requests[i].buffer_id == slot);
    const uint64_t diagnostic = requests[i].reserved[0] &
        GROUP_PMP_SQLITE_READSEQ_DIAGNOSTICS;
    if (requests[i].operation == GROUP_PMP_SQLITE_VFS_OP_READ &&
        requests[i].workload == GROUP_PMP_SQLITE_READSEQ) {
      assert(diagnostic && !(diagnostic & (diagnostic - 1)));
      if (diagnostic == GROUP_PMP_SQLITE_READSEQ_INITIAL) ++readseq_initial;
      if (diagnostic == GROUP_PMP_SQLITE_READSEQ_PEER_IO) ++readseq_peer_io;
      if (diagnostic == GROUP_PMP_SQLITE_READSEQ_PEER_READY) ++readseq_peer_ready;
      if (diagnostic == GROUP_PMP_SQLITE_READSEQ_PEER_IDLE) ++readseq_peer_idle;
    } else {
      assert(!diagnostic);
    }
  }
  /* Enclave decryption/reuse must leave the previous ciphertext untouched. */
  if (requests[0].operation == GROUP_PMP_SQLITE_VFS_OP_WRITE)
    cipher_valid[slot] = 0;
  if (cipher_valid[slot] && requests[0].operation == GROUP_PMP_SQLITE_VFS_OP_READ)
    assert(payload_hash(slot) == cipher_hash[slot]);
  if (slot_submissions[slot] && pending[1 - slot])
    ++reuse_with_peer[slot];
  ++slot_submissions[slot];
  accepted_generation[slot] = bell->generation;
  accepted_id[slot] = bell->batch_request_id;
  pending[slot] = 1;
  if (pending[0] + pending[1] > peak_buffers)
    peak_buffers = pending[0] + pending[1];
  ++submitted_rings;
  descriptors += bell->count;
  if (bell->count > largest_batch)
    largest_batch = bell->count;
  ring->consumer = bell->count;
  memset(ack, 0, sizeof(*ack));
  ack->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
  ack->version = GROUP_PMP_SQLITE_VFS_VERSION;
  ack->generation = bell->generation;
  ack->accepted = ack->consumer = bell->count;
  ack->ring_slot = slot;
  ack->batch_request_id = bell->batch_request_id;
}

static void maybe_complete_ring(unsigned slot) {
  if (completion_mode == 2 || (completion_mode == 1 && slot == 1) ||
      (completion_mode == 3 && slot == 0))
    complete_ring(slot);
}

static void corrupt_ack(struct group_pmp_sqlite_vfs_ring_ack* ack) {
  switch (bad_ack_field) {
    case 0: ++ack->magic; break;
    case 1: ++ack->version; break;
    case 2: ++ack->generation; break;
    case 3: --ack->accepted; break;
    case 4: ack->status = -1; break;
    case 5: --ack->consumer; break;
    case 6: ack->ring_slot ^= 1; break;
    case 7: ++ack->batch_request_id; break;
    default: assert(0);
  }
}

int ocall(unsigned long id, void* data, size_t length, void* output,
           size_t output_length) {
  assert(id == GROUP_PMP_SQLITE_VFS_OCALL_ID);
  if (length == sizeof(struct group_pmp_sqlite_intent_plan) &&
      ((struct group_pmp_sqlite_intent_plan*)data)->magic == GROUP_PMP_SQLITE_INTENT_MAGIC) {
    const struct group_pmp_sqlite_intent_plan* p = data;
    struct group_pmp_sqlite_intent_ack* ack = output;
    assert(output_length == sizeof(*ack) && p->count <= GROUP_PMP_SQLITE_INTENT_MAX);
    assert(p->buffer_id < 2 && !pending[p->buffer_id]);
    assert(!store_batches[p->buffer_id].pending);
    cipher_valid[p->buffer_id] = 0;
    uint32_t* order = (void*)(test_utm + p->buffer_offset);
    // Deliberately consume the short tail first to exercise non-linear progress.
    for (uint64_t i = 0; i < p->count; ++i) order[i] = (uint32_t)(p->count - i - 1);
    if (bad_intent == 1) order[0] = (uint32_t)p->count;
    if (bad_intent == 2) order[0] = order[1];
    *ack = (struct group_pmp_sqlite_intent_ack){p->magic, p->version,
        p->request_id + (bad_intent == 3), p->count, 0};
    ++intent_calls;
    return 0;
  }
  if (length == sizeof(struct group_pmp_sqlite_vfs_ring_pair_doorbell)) {
    const struct group_pmp_sqlite_vfs_ring_pair_doorbell* bell = data;
    struct group_pmp_sqlite_vfs_ring_pair_ack* ack = output;
    assert(output_length == sizeof(*ack));
    assert(paired_reads && store_config.workload == GROUP_PMP_SQLITE_READSEQ);
    assert(!pending[0] && !pending[1]);
    assert(store_batches[0].pending && store_batches[1].pending);
    assert(bell->rings[0].ring_slot < 2 && bell->rings[1].ring_slot < 2);
    assert(bell->rings[0].ring_slot != bell->rings[1].ring_slot);
    assert(bell->rings[0].generation != bell->rings[1].generation);
    assert(bell->rings[0].batch_request_id != bell->rings[1].batch_request_id);
    const struct group_pmp_sqlite_vfs_request* requests[2];
    for (unsigned i = 0; i < 2; ++i) {
      assert(bell->rings[i].count == 1);
      requests[i] = (void*)(test_utm +
          GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET_FOR_SLOT(
              bell->rings[i].ring_slot));
      assert(requests[i]->operation == GROUP_PMP_SQLITE_VFS_OP_READ);
      assert(requests[i]->descriptor_id == 0);
      assert(requests[i]->buffer_id == bell->rings[i].ring_slot);
    }
    assert(requests[0]->file_offset + requests[0]->length ==
        requests[1]->file_offset);
    assert(requests[0]->reserved[1] + requests[0]->length ==
        requests[1]->reserved[1]);
    assert(!(requests[0]->reserved[0] & GROUP_PMP_SQLITE_STORE_TXN_END));
    assert(!(requests[1]->reserved[0] & GROUP_PMP_SQLITE_STORE_TXN_BEGIN));
    ++doorbells;
    ++pair_doorbells;
    /* Validate/accept both before either completion can be published. */
    accept_ring(&bell->rings[0], &ack->rings[0]);
    accept_ring(&bell->rings[1], &ack->rings[1]);
    assert(pending[0] && pending[1]);
    for (unsigned i = 0; i < 2; ++i)
      maybe_complete_ring((unsigned)bell->rings[i].ring_slot);
    if (bad_pair_ack >= 0)
      corrupt_ack(&ack->rings[bad_pair_ack]);
    return fail_submit ? -1 : 0;
  }
  if (length == sizeof(struct group_pmp_sqlite_vfs_ring_doorbell)) {
    const struct group_pmp_sqlite_vfs_ring_doorbell* bell = data;
    struct group_pmp_sqlite_vfs_ring_ack* ack = output;
    unsigned slot = (unsigned)bell->ring_slot;
    assert(output_length == sizeof(*ack));
    ++doorbells;
    accept_ring(bell, ack);
    maybe_complete_ring(slot);
    if (wait_clock_fault == 1) test_clock.version = 0;
    return fail_submit ? -1 : 0;
  }
  const int any = length == sizeof(struct group_pmp_sqlite_vfs_wait_any);
  assert(any || length == sizeof(struct group_pmp_sqlite_vfs_wait));
  const struct group_pmp_sqlite_vfs_wait* request = data;
  struct group_pmp_sqlite_vfs_ack* ack = output;
  assert(output_length == sizeof(*ack));
  assert(request->buffer_id < 2);
  assert(request->request_id == accepted_id[request->buffer_id]);
  if (!mock_waits) {
    first_wait_descriptors = descriptors;
    first_wait_consumed_bytes = store_stats.read_bytes;
  }
  ++mock_waits;
  ++slot_waits[request->buffer_id];
  unsigned completed_slot = (unsigned)request->buffer_id;
  if (any) {
    ++any_waits;
    const struct group_pmp_sqlite_vfs_wait_any* pair = data;
    const unsigned other = (unsigned)pair->buffers[1].buffer_id;
    assert(other < 2 && other != completed_slot && pending[other]);
    assert(pair->buffers[1].request_id == accepted_id[other]);
    if (completion_mode == 4) completed_slot = other;
  }
  complete_ring(completed_slot);
  memset(ack, 0, sizeof(*ack));
  ack->magic = GROUP_PMP_SQLITE_VFS_MAGIC;
  ack->version = GROUP_PMP_SQLITE_VFS_VERSION;
  ack->request_id = request->request_id;
  if (wait_clock_fault == 1) test_clock.version = KEYSTONE_EXEC_CLOCK_VERSION;
  if (wait_clock_fault == 2) test_clock.version = 0;
  return 0;
}

static void configure_case(uint64_t workload, uint64_t bytes, unsigned mode,
                           int enable_pair) {
  struct group_pmp_sqlite_vfs_config config = {0};
  config.cipher_algorithm = test_cipher;
  memset(test_utm, 0xa5, sizeof(test_utm));
  pending[0] = pending[1] = peak_buffers = 0;
  doorbells = descriptors = largest_batch = mock_waits = 0;
  pair_doorbells = submitted_rings = first_wait_descriptors = 0;
  first_wait_consumed_bytes = 0;
  any_waits = 0;
  first_submit_peer_untouched = 0;
  readseq_initial = readseq_peer_io = readseq_peer_ready = readseq_peer_idle = 0;
  memset(slot_submissions, 0, sizeof(slot_submissions));
  memset(slot_waits, 0, sizeof(slot_waits));
  memset(reuse_with_peer, 0, sizeof(reuse_with_peer));
  memset(accepted_generation, 0, sizeof(accepted_generation));
  memset(accepted_id, 0, sizeof(accepted_id));
  memset(cipher_valid, 0, sizeof(cipher_valid));
  bad_pair_ack = -1;
  bad_ack_field = fail_submit = 0;
  completion_mode = mode;
  config.run_id = 1;
  config.worker_count = 1;
  config.workload = workload;
  assert(keystone_enclave_store_configure(&config, bytes) == 0);
  assert(!paired_reads);
  if (enable_pair >= 0)
    assert(keystone_enclave_store_set_paired_reads(enable_pair) == 0);
  assert(paired_reads == (enable_pair > 0 && workload == GROUP_PMP_SQLITE_READSEQ));
}

static void check_utm(void) {
  for (unsigned slot = 0; slot < 2; ++slot)
    if (cipher_valid[slot])
      assert(payload_hash(slot) == cipher_hash[slot]);
  for (size_t i = 0; i < GROUP_PMP_SQLITE_VFS_CONTROL_BYTES; ++i)
    assert(test_utm[i] == 0xa5);
  for (unsigned slot = 0; slot < 2; ++slot)
    for (size_t i = buffer_offset(slot) + GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
         i < buffer_offset(slot) + GROUP_PMP_SQLITE_VFS_BUFFER_SPAN; ++i)
      assert(test_utm[i] == 0xa5);
}

static void run_case(uint64_t workload, uint64_t bytes, unsigned mode,
                      uint64_t expected_batch, int enable_pair) {
  uint64_t digest = 0;
  configure_case(workload, bytes, mode, enable_pair);
  uint64_t chunk = chunk_bytes();
  assert(transfer_range(0, bytes, group_pmp_sqlite_is_read(workload),
                        GROUP_PMP_SQLITE_STORE_MEASURED, &digest) == 0);
  assert(!pending[0] && !pending[1]);
  assert(descriptors == (bytes + chunk - 1) / chunk);
  assert(largest_batch == expected_batch);
  uint64_t expected_pairs = paired_reads && bytes > chunk ? 1 : 0;
  if (workload == GROUP_PMP_SQLITE_READSEQ) {
    assert(readseq_initial == 1 + expected_pairs);
    assert(readseq_initial + readseq_peer_io + readseq_peer_ready +
           readseq_peer_idle == descriptors);
    if (expected_pairs && descriptors > 2) {
      if (mode == 2)
        assert(readseq_peer_ready == descriptors - 2 && readseq_peer_io == 0);
      else
        assert(readseq_peer_io == descriptors - 2 && readseq_peer_ready == 0);
      assert(readseq_peer_idle == 0);
    }
  }
  assert(pair_doorbells == expected_pairs);
  assert(submitted_rings == (descriptors + expected_batch - 1) / expected_batch);
  assert(doorbells == submitted_rings - expected_pairs);
  assert(store_stats.submit_count == descriptors);
  assert(store_stats.ring_request_count == descriptors);
  assert(store_stats.batch_submit_count == doorbells);
  assert(store_stats.ring_doorbell_count == doorbells);
  assert(store_stats.completion_batch_count == doorbells + expected_pairs);
  assert(store_stats.buffer_reuses == submitted_rings);
  assert(store_stats.wait_count == mock_waits);
  assert(store_stats.read_bytes + store_stats.write_bytes == bytes);
  assert(store_stats.yield_count == 0);
  assert(store_stats.pipeline.doorbell_count == doorbells);
  assert(store_stats.pipeline.buffer_consume_count == submitted_rings);
  assert(store_stats.pipeline.completion_to_consume_count +
      store_stats.pipeline.completion_timestamp_invalid == submitted_rings);
  if (mode == 0 && submitted_rings > 1)
    assert(peak_buffers == 2);
  if (mode == 2) {
    assert(mock_waits == 0);
    assert(store_stats.completion_local_reaps == submitted_rings);
  }
  if (expected_pairs) {
    assert(largest_batch == 1 && store_stats.queue_depth_peak == 2);
    if (mode == 0) {
      assert(first_wait_descriptors == 2);
      assert(mock_waits == descriptors);
      if (descriptors > 2)
        assert(reuse_with_peer[0] > 0);
    }
    if ((mode == 1 || mode == 3) && descriptors > 2) {
      unsigned fast_slot = mode == 1 ? 1 : 0;
      assert(first_wait_descriptors == descriptors && mock_waits == 1);
      assert(slot_waits[fast_slot] == 0 && slot_submissions[1 - fast_slot] == 1);
      assert(reuse_with_peer[fast_slot] == descriptors - 2);
    }
  }
  check_utm();
  printf("store: workload=%llu mode=%u paired=%d bytes=%llu requests=%llu "
         "doorbells=%llu completions=%llu PASS\n",
      (unsigned long long)workload, mode, enable_pair, (unsigned long long)bytes,
      (unsigned long long)descriptors, (unsigned long long)doorbells,
      (unsigned long long)store_stats.completion_batch_count);
  keystone_enclave_store_destroy();
}

static void test_overlap_clock(void) {
  struct group_pmp_sqlite_vfs_config config = {0};
  config.run_id = config.worker_count = 1;
  config.workload = GROUP_PMP_SQLITE_READRAND100K;
  assert(keystone_enclave_store_configure(&config, 4000000) == 0);
  struct store_batch* peer = &store_batches[1];
  peer->pending = 1;
  peer->submitted_ticks = 90;
  peer->generation = 7;
  peer->count = 1;
  struct group_pmp_sqlite_vfs_ring_header* ring =
      (void*)(test_utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(1));
  memset(ring, 0, sizeof(*ring));
  ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
  ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
  ring->generation = 7;
  ring->producer = 1;
  account_crypto_overlap(0, 100, 200);
  assert(store_stats.crypto_io_overlap_ticks == 100);
  ring->completion_count = 1;
  ring->completed_time_ticks = 150;
  account_crypto_overlap(0, 100, 200);
  assert(store_stats.crypto_io_overlap_ticks == 150);
  ring->completed_time_ticks = 80;
  account_crypto_overlap(0, 100, 200);
  assert(store_stats.crypto_io_overlap_ticks == 150);
  assert(store_stats.crypto_io_sample_ticks == 300);
  ring->generation = 8;
  assert(!batch_completion_ready(1));
  keystone_enclave_store_destroy();
}

static void test_consumption_clock(void) {
  uint64_t drain_digest = 0;
  configure_case(GROUP_PMP_SQLITE_READRAND100K, 4000000, 1, 1);
  assert(transfer_range(0, 4000000, 1, GROUP_PMP_SQLITE_STORE_MEASURED,
                        &drain_digest) == 0);
  assert(first_wait_consumed_bytes == 2000000);
  assert(mock_waits == 1 && store_stats.read_bytes == 4000000);
  check_utm();
  keystone_enclave_store_destroy();
  puts("final drain consumes completed peer before blocking; ciphertext unchanged PASS");
  configure_case(GROUP_PMP_SQLITE_READRAND100K, 4000000, 4, 0);
  assert(transfer_range(0, 4000000, 1, GROUP_PMP_SQLITE_STORE_MEASURED,
                        &drain_digest) == 0);
  assert(any_waits == 1 && mock_waits == 2 && store_stats.read_bytes == 4000000);
  assert(slot_waits[0] == 2 && slot_waits[1] == 0); // Late B completion wins the first WAIT_ANY.
  check_utm();
  keystone_enclave_store_destroy();
  configure_case(GROUP_PMP_SQLITE_READSEQ, 4000000, 0, 1);
  struct store_batch* batch = &store_batches[0];
  struct group_pmp_sqlite_vfs_ring_header* ring =
      (void*)(test_utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(0));
  batch->pending = 1;
  batch->submitted_ticks = 100;
  batch->ack_ticks = 150;
  batch->generation = 7;
  batch->count = 1;
  memset(ring, 0, sizeof(*ring));
  ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
  ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
  ring->generation = 7;
  ring->producer = ring->completion_count = 1;
  ring->completed_time_ticks = 120; // Host completed before acceptance ACK.
  account_completion_consumption(0, 200);
  assert(store_stats.pipeline.completion_to_consume_ticks == 80);
  assert(store_stats.pipeline.ack_to_consume_ticks == 50);
  ring->completed_time_ticks = 210;
  account_completion_consumption(0, 230);
  assert(store_stats.pipeline.completion_to_consume_count == 2);
  assert(store_stats.pipeline.completion_to_consume_ticks == 100);
  assert(store_stats.pipeline.completion_to_consume_max_ticks == 80);
  assert(store_stats.pipeline.ack_to_consume_ticks == 130);
  assert(store_stats.pipeline.ack_to_consume_max_ticks == 80);
  for (unsigned bad = 0; bad < 4; ++bad) {
    ring->generation = bad == 3 ? 8 : 7;
    ring->completed_time_ticks = bad == 0 ? 0 : bad == 1 ? 99 :
                                bad == 2 ? UINT64_MAX : 210;
    account_completion_consumption(0, 230);
  }
  assert(store_stats.pipeline.completion_timestamp_invalid == 4);
  assert(store_stats.pipeline.completion_to_consume_ticks == 100);
  assert(batch->pending); // No diagnostic can release ownership.
  account_ring_submission(300, 350, 1);
  account_ring_submission(400, 410, 1);
  assert(store_stats.pipeline.doorbell_count == 2);
  assert(store_stats.pipeline.doorbell_ack_ticks == 60);
  assert(store_stats.pipeline.doorbell_ack_max_ticks == 50);
  struct group_pmp_sqlite_pipeline_timing total = store_stats.pipeline;
  group_pmp_sqlite_pipeline_add(&total, &store_stats.pipeline);
  assert(total.doorbell_ack_ticks == 120 && total.doorbell_ack_max_ticks == 50);
  ring->generation = batch->generation;
  ring->host_received_ticks = 110;
  ring->host_ack_ticks = 130;
  ring->host_resume_request_ticks = 140;
  account_submission_stages(0, 100, 200);
  assert(store_stats.pipeline.submission_timing_count == 1);
  assert(store_stats.pipeline.submit_to_host_ticks == 10);
  assert(store_stats.pipeline.host_to_ack_ticks == 20);
  assert(store_stats.pipeline.ack_to_resume_request_ticks == 10);
  assert(store_stats.pipeline.resume_request_to_return_ticks == 60);
  assert(batch->pending); // An acceptance ACK never frees ciphertext ownership.
  for (unsigned bad = 0; bad < 5; ++bad) {
    ring->generation = bad == 4 ? batch->generation + 1 : batch->generation;
    ring->host_received_ticks = bad == 0 ? 99 : 110;
    ring->host_ack_ticks = bad == 1 ? 109 : 130;
    ring->host_resume_request_ticks = bad == 2 ? 0 : bad == 3 ? 201 : 140;
    account_submission_stages(0, 100, 200);
  }
  assert(store_stats.pipeline.submission_timestamp_invalid == 5);
  assert(store_stats.pipeline.submission_timing_count == 1);
  total = store_stats.pipeline;
  group_pmp_sqlite_pipeline_add(&total, &store_stats.pipeline);
  assert(total.submit_to_host_ticks == 20 && total.submit_to_host_max_ticks == 10);
  assert(total.resume_request_to_return_ticks == 120 &&
         total.resume_request_to_return_max_ticks == 60);
  group_pmp_sqlite_pipeline_wait(&store_stats.pipeline, 100, 110, 120, 150, 200);
  group_pmp_sqlite_pipeline_wait(&store_stats.pipeline, 300, 310, 320, 350, 390);
  assert(store_stats.pipeline.wait_timing_count == 2);
  assert(store_stats.pipeline.wait_submit_to_host_ticks == 20);
  assert(store_stats.pipeline.wait_host_to_resume_ticks == 80);
  assert(store_stats.pipeline.wait_resume_to_return_ticks == 90);
  assert(store_stats.pipeline.wait_resume_to_return_max_ticks == 50);
  for (unsigned bad = 0; bad < 5; ++bad)
    group_pmp_sqlite_pipeline_wait(&store_stats.pipeline, 100,
        bad == 0 ? 0 : bad == 1 ? 99 : 110,
        bad == 2 ? 109 : 120, bad == 3 ? 119 : bad == 4 ? 201 : 150, 200);
  assert(store_stats.pipeline.wait_timestamp_invalid == 5);
  assert(store_stats.pipeline.wait_timing_count == 2 && batch->pending);
  total = store_stats.pipeline;
  group_pmp_sqlite_pipeline_add(&total, &store_stats.pipeline);
  assert(total.wait_timing_count == 4 && total.wait_timestamp_invalid == 10);
  assert(total.wait_resume_to_return_ticks == 180 &&
         total.wait_resume_to_return_max_ticks == 50);
  memset(store_batches, 0, sizeof(store_batches));
  buffer_consumed_ticks[0] = 999;
  assert(keystone_enclave_store_begin_measurement() == 0);
  assert(buffer_consumed_ticks[0] == 0 && store_stats.pipeline.doorbell_count == 0);
  assert(store_stats.pipeline.submission_timing_count == 0);
  assert(store_stats.pipeline.wait_timing_count == 0);
  keystone_enclave_store_destroy();
  puts("pipeline clock: ACK, completion/consume, max aggregation, reset and untrusted timestamps PASS");
}

static void test_read_digest_completion_order(void) {
  const uint64_t workloads[] = {GROUP_PMP_SQLITE_READSEQ,
      GROUP_PMP_SQLITE_READRANDOM, GROUP_PMP_SQLITE_READRAND100K};
  for (size_t i = 0; i < sizeof(workloads) / sizeof(workloads[0]); ++i) {
    const uint64_t bytes = workloads[i] == GROUP_PMP_SQLITE_READRANDOM ?
        UINT64_C(2100016) : UINT64_C(8100016);
    uint64_t expected = 0;
    for (unsigned mode = 0; mode < 5; ++mode) {
      uint64_t digest = UINT64_C(1469598103934665603);
      configure_case(workloads[i], bytes, mode, 1);
      assert(transfer_range(0, bytes, 1, GROUP_PMP_SQLITE_STORE_MEASURED,
                            &digest) == 0);
      assert(store_stats.read_bytes == bytes);
      assert(!pending[0] && !pending[1]);
      check_utm();
      if (!mode)
        expected = digest;
      if (digest != expected)
        fprintf(stderr, "read digest depends on completion order: workload=%llu "
            "mode=%u expected=%llu actual=%llu\n",
            (unsigned long long)workloads[i], mode,
            (unsigned long long)expected, (unsigned long long)digest);
      assert(digest == expected);
      keystone_enclave_store_destroy();
    }
  }
  puts("read digest: five completion orders, partial tail, all read workloads PASS");
}

static void test_read_digest_validation(void) {
  uint8_t sample[64];
  uint64_t first = 7, second = 7, repeated = 7;
  configure_case(GROUP_PMP_SQLITE_READSEQ, 4000000, 0, 1);
  copy_template(sample, 0, sizeof(sample));
  assert(validate_plain_sample(sample, 0, sizeof(sample), &first) == 0);
  assert(validate_plain_sample(sample, 0, sizeof(sample), &repeated) == 0);
  assert(validate_plain_sample(sample, 0, sizeof(sample), &repeated) == 0);
  assert(repeated != first && repeated != 7); // Duplicate samples do not XOR away.
  copy_template(sample, STORE_TEMPLATE_BYTES, sizeof(sample));
  assert(validate_plain_sample(sample, STORE_TEMPLATE_BYTES,
                                sizeof(sample), &second) == 0);
  assert(first != second); // Identical bytes at a different offset are distinct.
  second = 7;
  assert(validate_plain_sample(sample, 0, 32, &second) == 0);
  assert(first != second);
  for (size_t i = 0; i < sizeof(sample); ++i) {
    if (i >= 16 && i < sizeof(sample) - 16)
      continue;
    uint64_t unchanged = first;
    sample[i] ^= 1;
    assert(validate_plain_sample(sample, 0, sizeof(sample), &unchanged) != 0);
    assert(unchanged == first);
    sample[i] ^= 1;
  }
  assert(validate_plain_sample(sample, 0, 15, &first) != 0);
  keystone_enclave_store_destroy();
  puts("read digest: offset/length binding and corrupt edge rejection PASS");
}

static void test_pair_boundaries(void) {
  const uint64_t chunk = GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
  uint64_t digest = 0;
  configure_case(GROUP_PMP_SQLITE_READSEQ, 2 * chunk, 0, 1);
  /* A partial chunk and its contiguous tail are already known in this range. */
  assert(transfer_range(chunk - 16, 32, 1,
                        GROUP_PMP_SQLITE_STORE_MEASURED, &digest) == 0);
  assert(pair_doorbells == 1 && doorbells == 1 && descriptors == 2);
  assert(first_wait_descriptors == 2 && store_stats.read_bytes == 32);
  assert(store_stats.completion_batch_count == 2);
  check_utm();
  keystone_enclave_store_destroy();

  configure_case(GROUP_PMP_SQLITE_READSEQ, 2 * chunk, 0, 1);
  /* Do not defer a known single chunk in anticipation of another packet. */
  assert(transfer_range(chunk - 16, 16, 1,
                        GROUP_PMP_SQLITE_STORE_MEASURED, &digest) == 0);
  assert(doorbells == 1 && first_wait_descriptors == 1 && pair_doorbells == 0);
  assert(transfer_range(chunk, 16, 1,
                        GROUP_PMP_SQLITE_STORE_MEASURED, &digest) == 0);
  assert(doorbells == 2 && pair_doorbells == 0);
  check_utm();
  keystone_enclave_store_destroy();

  configure_case(GROUP_PMP_SQLITE_READSEQ, 2 * chunk, 0, 1);
  assert(transfer_range(0, 2 * chunk, 0,
                        GROUP_PMP_SQLITE_STORE_PREFILL, &digest) == 0);
  assert(doorbells == 2 && pair_doorbells == 0 && largest_batch == 1);
  assert(store_stats.write_bytes == 2 * chunk);
  assert(store_stats.completion_batch_count == 2);
  check_utm();
  keystone_enclave_store_destroy();
  puts("paired readseq: partial chunks, packet boundaries and prefill isolation PASS");
}

static void test_pair_prepare_failure(void) {
  struct group_pmp_sqlite_vfs_request requests[2] = {{0}};
  const int reads[2] = {1, 1};
  const uint64_t offsets[2] = {0, 16};
  configure_case(GROUP_PMP_SQLITE_READSEQ, 4000000, 0, 1);
  for (unsigned i = 0; i < 2; ++i) {
    requests[i].operation = GROUP_PMP_SQLITE_VFS_OP_READ;
    requests[i].length = 16;
    requests[i].buffer_id = i;
    requests[i].buffer_offset = buffer_offset(i);
  }
  requests[1].buffer_offset = buffer_offset(0);
  assert(submit_read_pair(requests, reads, offsets, 0) != 0);
  assert(!doorbells && !pending[0] && !pending[1]);
  assert(!store_batches[0].pending && !store_batches[1].pending);
  const struct group_pmp_sqlite_vfs_ring_header* ring =
      (void*)(test_utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(0));
  assert(ring->producer == 0);
  assert(!store_stats.batch_submit_count && !store_stats.ring_request_count);
  keystone_enclave_store_destroy();
  puts("paired readseq: failed second preparation publishes neither ring PASS");
}

static void test_pair_ack_failures(void) {
  const uint64_t chunk = GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
  for (int slot = 0; slot < 2; ++slot) {
    for (int field = 0; field < 8; ++field) {
      uint64_t digest = 0;
      configure_case(GROUP_PMP_SQLITE_READSEQ, 2 * chunk, 0, 1);
      bad_pair_ack = slot;
      bad_ack_field = field;
      assert(transfer_range(chunk - 16, 32, 1,
                            GROUP_PMP_SQLITE_STORE_MEASURED, &digest) != 0);
      assert(keystone_enclave_store_last_error() == 2002);
      assert(pending[0] && pending[1]);
      assert(store_batches[0].pending && store_batches[1].pending);
      assert(store_stats.batch_submit_count == 1);
      assert(store_stats.ring_doorbell_count == 1);
      assert(store_stats.ring_request_count == 2);
      assert(store_stats.completion_batch_count == 0 && !mock_waits);
      assert(wait_batch(0, &digest) == 0);
      assert(!store_batches[0].pending && store_batches[1].pending && pending[1]);
      assert(store_stats.completion_batch_count == 1);
      assert(wait_batch(1, &digest) == 0);
      assert(store_stats.completion_batch_count == 2);
      check_utm();
      keystone_enclave_store_destroy();
    }
  }
  for (int enable_pair = 0; enable_pair < 2; ++enable_pair) {
    configure_case(GROUP_PMP_SQLITE_READSEQ, 2 * chunk, 0, enable_pair);
    fail_submit = 1;
    assert(transfer_range(chunk - 16, enable_pair ? 32 : 16, 1,
                          GROUP_PMP_SQLITE_STORE_MEASURED, NULL) != 0);
    assert(keystone_enclave_store_last_error() == 2002);
    assert(store_batches[0].pending && pending[0]);
    assert(store_batches[1].pending == enable_pair);
    assert(doorbells == 1 && store_stats.batch_submit_count == 1);
    assert(store_stats.ring_doorbell_count == 1);
    assert(store_stats.ring_request_count == (uint64_t)(1 + enable_pair));
    assert(wait_all(NULL) == 0);
    check_utm();
    keystone_enclave_store_destroy();
  }
  puts("paired readseq: both ACK identities and transport failures retain ownership PASS");
}

static void test_packed_file_layout(void) {
  for (uint64_t workload = 1; workload <= 8; ++workload) {
    for (uint64_t direct = 0; direct < 2; ++direct) {
      uint64_t base = 0, logical = 0;
      const uint64_t unit = group_pmp_sqlite_value_size(workload);
      const uint64_t units = UINT64_C(60000000) / unit;
      for (uint64_t worker = 0; worker < 15; ++worker) {
        struct group_pmp_sqlite_vfs_config config = {0};
        const uint64_t bytes = (units / 15 + (worker < units % 15)) * unit;
        uint64_t offsets[2048] = {0}, lengths[2048] = {0};
        config.run_id = worker + 1;
        config.worker_index = worker; config.worker_count = 15;
        config.workload = workload; config.file_base = base;
        config.logical_base = logical; config.direct_layout = direct;
        assert(keystone_enclave_store_configure(&config, bytes) == 0);
        const uint64_t chunk = chunk_bytes();
        const uint64_t count = (bytes + chunk - 1) / chunk;
        assert(count <= 2048);
        for (uint64_t offset = 0; offset < bytes; offset += chunk) {
          const uint64_t key = extent_key(offset);
          assert(key < count && !lengths[key]);
          offsets[key] = extent_file_offset(offset);
          lengths[key] = bytes - offset < chunk ? bytes - offset : chunk;
          assert(!(offsets[key] % 16) && !(lengths[key] % 16));
          if (!direct && group_pmp_sqlite_page_random(workload)) {
            assert(offsets[key] % 4096 == 0);
            if (lengths[key] != 4096)
              assert(offsets[key] == base + (bytes / 4096) * 4096);
          }
        }
        /* Order by actual storage address; the short tail no longer occupies
         * its original random permutation slot in buffered 4 KB workloads. */
        for (uint64_t i = 1; i < count; ++i) {
          uint64_t j = i;
          while (j && offsets[j] < offsets[j - 1]) {
            uint64_t tmp = offsets[j]; offsets[j] = offsets[j - 1]; offsets[j - 1] = tmp;
            tmp = lengths[j]; lengths[j] = lengths[j - 1]; lengths[j - 1] = tmp;
            --j;
          }
        }
        uint64_t cursor = base;
        for (uint64_t i = 0; i < count; ++i) {
          assert(lengths[i]);
          if (!direct) assert(offsets[i] == cursor);
          else assert(offsets[i] >= cursor);
          cursor = offsets[i] + lengths[i];
        }
        const uint64_t span = group_pmp_sqlite_file_span(workload, bytes, direct);
        assert(cursor <= base + span);
        if (!direct) assert(cursor == base + bytes);
        if (direct || group_pmp_sqlite_page_random(workload)) {
          assert(!(base % 4096) && !(span % 4096));
          if (!direct) assert(span - bytes < 4096);
        }
        base += span; logical += bytes;
        keystone_enclave_store_destroy();
      }
      assert(logical == 60000000);
      if (!direct && !group_pmp_sqlite_page_random(workload)) assert(base == 60000000);
      if (!direct && group_pmp_sqlite_page_random(workload))
        assert(base >= 60000000 && base - 60000000 < 15 * 4096);
    }
  }
  assert(!group_pmp_sqlite_file_span(0, 16, 0));
  assert(!group_pmp_sqlite_file_span(1, 17, 0));
  assert(!group_pmp_sqlite_file_span(1, 16, 2));
  assert(!group_pmp_sqlite_file_span(3, UINT64_MAX - 15, 1));

  const uint64_t small_sizes[] = {16, 4080, 4096, 4112, 8192, 8208};
  for (unsigned i = 0; i < sizeof(small_sizes) / sizeof(small_sizes[0]); ++i) {
    struct group_pmp_sqlite_vfs_config config = {0};
    config.run_id = 1; config.worker_count = 1;
    config.workload = GROUP_PMP_SQLITE_READRANDOM; config.file_base = 4096;
    const uint64_t bytes = small_sizes[i];
    assert(keystone_enclave_store_configure(&config, bytes) == 0);
    const uint64_t span = group_pmp_sqlite_file_span(config.workload, bytes, 0);
    assert(span >= bytes && span - bytes < 4096);
    for (uint64_t offset = 0; offset < bytes; offset += 4096) {
      const uint64_t physical = extent_file_offset(offset);
      assert(physical % 4096 == 0 && physical < config.file_base + span);
      if (bytes - offset < 4096)
        assert(physical == config.file_base + (bytes / 4096) * 4096);
    }
    keystone_enclave_store_destroy();
    config.file_base += 16;
    assert(keystone_enclave_store_configure(&config, bytes) != 0);
  }

  for (unsigned direct = 0; direct < 2; ++direct) {
    uint64_t digest = 0;
    configure_case(GROUP_PMP_SQLITE_FILLSEQ, 4000080, 4, 0);
    struct group_pmp_sqlite_vfs_config config = store_config;
    keystone_enclave_store_destroy();
    config.file_base = direct ? 4001792 : 4000080;
    config.direct_layout = direct;
    assert(keystone_enclave_store_configure(&config, 4000080) == 0);
    assert(chunk_bytes() == (direct ? 1998848 : 2000000));
    assert(transfer_range(0, 4000080, 0, GROUP_PMP_SQLITE_STORE_MEASURED, &digest) == 0);
    assert(first_submit_peer_untouched); // Never encrypt both before submitting.
    assert(descriptors == 3 && pair_doorbells == 0);
    assert(store_stats.write_bytes == 4000080);
    check_utm();
    keystone_enclave_store_destroy();
    config.file_base++;
    assert(keystone_enclave_store_configure(&config, 4000080) != 0);
    config.file_base = UINT64_C(0x7ffffffffffffff0);
    assert(keystone_enclave_store_configure(&config, 4000080) != 0);
  }
  puts("file layout: 8 workloads, 15 owners, page-aligned random slots and separate tails, direct alignment, immediate first write PASS");
}

static void test_intent_lookahead(void) {
  for (uint64_t workload = 3; workload <= 8; ++workload) {
    if (!group_pmp_sqlite_is_random(workload)) continue;
    for (unsigned mode = 0; mode < 5; ++mode) {
      uint64_t expected_digest = 0, actual_digest = 0;
      const uint64_t bytes = workload == GROUP_PMP_SQLITE_READRAND100K ? 2100016 : 33000016;
      configure_case(workload, bytes, mode, -1);
      assert(!intent_lookahead);
      assert(transfer_range(0, bytes, group_pmp_sqlite_is_read(workload),
          GROUP_PMP_SQLITE_STORE_MEASURED, &expected_digest) == 0);
      keystone_enclave_store_destroy();
      configure_case(workload, bytes, mode, -1);
      assert(keystone_enclave_store_set_intent_lookahead(1) != 0);
      assert(keystone_enclave_store_set_intent_lookahead(0) == 0);
      memset(intent_coverage, 0, sizeof(intent_coverage));
      memset(intent_sequences, 0, sizeof(intent_sequences));
      intent_calls = 0; track_intents = 1;
      assert(transfer_range(0, bytes, group_pmp_sqlite_is_read(workload),
          GROUP_PMP_SQLITE_STORE_MEASURED, &actual_digest) == 0);
      track_intents = 0;
      const uint64_t count = (bytes + chunk_bytes() - 1) / chunk_bytes();
      assert(descriptors == count && intent_calls == 0 && actual_digest == expected_digest);
      for (uint64_t i = 0; i < count; ++i)
        assert(intent_coverage[i] == 1 && intent_sequences[i] == i + 1);
      assert(!pending[0] && !pending[1]);
      check_utm();
      keystone_enclave_store_destroy();
    }
  }
  for (bad_intent = 1; bad_intent <= 3; ++bad_intent) {
    configure_case(GROUP_PMP_SQLITE_READRANDOM, 8192, 0, -1);
    assert(keystone_enclave_store_set_intent_lookahead(1) != 0);
    intent_calls = 0;
    assert(transfer_range(0, 8192, 1, GROUP_PMP_SQLITE_STORE_MEASURED, NULL) == 0);
    assert(descriptors == 2 && !intent_calls && !pending[0] && !pending[1]);
    keystone_enclave_store_destroy();
  }
  bad_intent = 0;
  // The board's 512 MB case excludes the final incomplete 240-byte record.
  configure_case(GROUP_PMP_SQLITE_READRANDOM, UINT64_C(511999920), 4, -1);
  intent_calls = 0;
  assert(keystone_enclave_store_set_intent_lookahead(0) == 0);
  uint64_t digest = 0;
  assert(transfer_range(0, UINT64_C(511999920), 1,
      GROUP_PMP_SQLITE_STORE_MEASURED, &digest) == 0);
  const uint64_t expected_doorbells = (125000 + GROUP_PMP_SQLITE_VFS_BATCH_MAX - 1) /
      GROUP_PMP_SQLITE_VFS_BATCH_MAX;
  assert(descriptors == 125000 && doorbells == expected_doorbells && intent_calls == 0);
  assert(store_stats.ring_request_count == 125000 && store_stats.ring_doorbell_count == expected_doorbells);
  assert(store_stats.read_bytes == UINT64_C(511999920));
  assert(!pending[0] && !pending[1]);
  check_utm();
  keystone_enclave_store_destroy();
  printf("online client: capacity=%llu bytes=511999920 requests=125000 doorbells=%llu utm_bytes=%llu zero future intent OCALLs PASS\n",
      (unsigned long long)GROUP_PMP_SQLITE_VFS_BATCH_MAX,
      (unsigned long long)doorbells, (unsigned long long)GROUP_PMP_SQLITE_VFS_UTM_BYTES);
  puts("online client: unchanged coverage/sequence/digest, five completion orders, obsolete lookahead rejected PASS");
}

static void test_wait_clock_failures(void) {
  for (int fault = 1; fault <= 2; ++fault) {
    uint64_t digest = 0;
    configure_case(GROUP_PMP_SQLITE_FILLSEQ, 16, 0, -1);
    wait_clock_fault = fault;
    assert(transfer_range(0, 16, 0, GROUP_PMP_SQLITE_STORE_PREFILL, &digest) == 0);
    assert(mock_waits == 1 && store_stats.pipeline.wait_clock_invalid == 1);
    assert(store_stats.pipeline.wait_oncpu_ticks == 0);
    assert(store_stats.pipeline.wait_offcpu_ticks == 0);
    wait_clock_fault = 0;
    test_clock.version = KEYSTONE_EXEC_CLOCK_VERSION;
    keystone_enclave_store_destroy();
  }
  puts("WAIT clock failures: invalid pre/post samples excluded, completion preserved PASS");
}

static void test_compact_security_pipeline(void) {
  const uint64_t sizes[]={999840,166800,166560,333360,333120};
  for (unsigned read=0;read<2;++read) {
    for (unsigned mode=0;mode<3;mode+=2) {
      for (unsigned i=0;i<sizeof(sizes)/sizeof(sizes[0]);++i) {
        uint64_t digest=0;
        configure_case(read ? GROUP_PMP_SQLITE_READRANDOM : GROUP_PMP_SQLITE_FILLRANDOM,
                       sizes[i],mode,-1);
        assert(keystone_enclave_store_set_security_sentinel(93)==0);
        const int result=transfer_range(0,sizes[i],read,GROUP_PMP_SQLITE_STORE_MEASURED,&digest);
        if(result)fprintf(stderr,"compact case: read=%u mode=%u bytes=%llu error=%llu\n",
            read,mode,(unsigned long long)sizes[i],(unsigned long long)last_error);
        assert(result==0);
        assert(largest_batch==GROUP_PMP_SECURITY_BATCH_REQUESTS);
        assert(slot_submissions[0]>=2 && slot_submissions[1]>=2);
        assert(store_stats.read_bytes+store_stats.write_bytes==sizes[i]);
        assert(!pending[0] && !pending[1]);
        assert(security_phase_state.seen & (UINT64_C(1)<<SECURITY_PHASE_REUSE));
        if(read)assert(security_phase_state.seen & (UINT64_C(1)<<SECURITY_PHASE_DECRYPTED));
        else assert(security_phase_state.seen & (UINT64_C(1)<<SECURITY_PHASE_ENCRYPTED));
        keystone_enclave_store_destroy();
      }
    }
  }
  puts("1MB security input: N=1/4 shards, eight-descriptor batches, both slots reused, real AES and completion PASS");
}

int main(void) {
  {
    assert(keystone_enclave_store_set_exec_clock(&test_clock)==0);
    uint64_t digest=0;
    configure_case(GROUP_PMP_SQLITE_READSEQ,4000080,0,1);
    assert(!keystone_enclave_store_set_system_trace(1));
    assert(!transfer_range(0,4000080,1,GROUP_PMP_SQLITE_STORE_MEASURED,&digest));
    assert(system_trace.count==3 && !system_trace.dropped);
    unsigned seen=0;
    for(unsigned i=0;i<3;++i) {
      const struct mot_system_event* e=&system_trace.events[i];
      assert(e->logical_offset%2000000==0 && e->logical_offset<=4000000);
      assert(e->bytes==(e->logical_offset==4000000?80:2000000));
      seen |= 1u<<(e->logical_offset/2000000);
    }
    assert(seen==7);
    assert(descriptors==3 && !pending[0] && !pending[1]);
    assert(!keystone_enclave_store_publish_system_trace());
    struct mot_system_trace exported;
    memcpy(&exported,test_utm+GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET,sizeof(exported));
    assert(exported.magic==MOT_SYSTEM_TRACE_MAGIC && exported.count==3);
    store_batches[0].pending=1;
    assert(keystone_enclave_store_publish_system_trace()!=0); store_batches[0].pending=0;
    system_trace.count=MOT_SYSTEM_TRACE_MAX;
    mot_system_append(&system_trace,1,2,0,16,1,0);
    assert(system_trace.count==MOT_SYSTEM_TRACE_MAX && system_trace.dropped==1);
    assert(keystone_enclave_store_publish_system_trace()!=0);
    keystone_enclave_store_destroy();
    configure_case(GROUP_PMP_SQLITE_READSEQ,16,0,1);
    assert(!system_trace_enabled); keystone_enclave_store_destroy();
    puts("Extent-I/O diagnostic: real read transforms, bounded metadata-only export after drain, counters unchanged and opt-in reset PASS");
  }
  {
    uint8_t marker[GROUP_PMP_SECURITY_SENTINEL_BYTES];
    assert(keystone_enclave_store_set_security_sentinel(91) != 0);
    configure_case(GROUP_PMP_SQLITE_FILLRANDOM, 4000000, 0, -1);
    assert(keystone_enclave_store_set_security_sentinel(0) != 0);
    assert(keystone_enclave_store_set_security_sentinel(91) == 0);
    group_pmp_security_sentinel(91, marker);
    for (size_t i = 0; i + sizeof(marker) <= STORE_TEMPLATE_BYTES; i += 4096)
      assert(!memcmp(plain_template + i, marker, sizeof(marker)));
    for (size_t i = 0; i + sizeof(marker) <= sizeof(test_utm); ++i)
      assert(memcmp(test_utm + i, marker, sizeof(marker)));
    keystone_enclave_store_destroy();
    puts("security-only sentinel installed in private template, never copied to UTM PASS");
  }
  test_locality_page_permutation();
  test_exec_clock();
  assert(keystone_enclave_store_set_exec_clock(&test_clock) == 0);
  test_compact_security_pipeline();
  test_wait_clock_failures();
  test_intent_lookahead();
  test_packed_file_layout();
  assert(keystone_enclave_store_set_paired_reads(1) != 0);
  test_read_digest_completion_order();
  test_read_digest_validation();
  for (unsigned mode = 0; mode < 3; ++mode) {
    run_case(GROUP_PMP_SQLITE_READRAND100K, 8100016, mode, 20, -1);
    run_case(GROUP_PMP_SQLITE_READSEQ, 8100016, mode, 1, -1);
    run_case(GROUP_PMP_SQLITE_READRANDOM, 2100016, mode, GROUP_PMP_SQLITE_VFS_BATCH_MAX, -1);
    run_case(GROUP_PMP_SQLITE_READSEQ, 8100016, mode, 1, 0);
    run_case(GROUP_PMP_SQLITE_READSEQ, 8100016, mode, 1, 1);
    run_case(GROUP_PMP_SQLITE_READRAND100K, 8100016, mode, 20, 1);
    run_case(GROUP_PMP_SQLITE_READRANDOM, 2100016, mode, GROUP_PMP_SQLITE_VFS_BATCH_MAX, 1);
  }
  run_case(GROUP_PMP_SQLITE_READSEQ, 8100016, 3, 1, 1);
  run_case(GROUP_PMP_SQLITE_READSEQ, 4000000, 0, 1, 1);
  run_case(GROUP_PMP_SQLITE_READSEQ, 2000016, 0, 1, 1);
  run_case(GROUP_PMP_SQLITE_READSEQ, 2000000, 0, 1, 1);
  run_case(GROUP_PMP_SQLITE_READSEQ, 16, 0, 1, 1);
  run_case(GROUP_PMP_SQLITE_FILLSEQ, 8100016, 0, 1, -1);
  run_case(GROUP_PMP_SQLITE_FILLRANDOM, 2100016, 0, GROUP_PMP_SQLITE_VFS_BATCH_MAX, -1);
  run_case(GROUP_PMP_SQLITE_FILLSEQ, 8100016, 0, 1, 1);
  /* Both busy at WAIT entry; the nonpreferred buffer completes first. */
  run_case(GROUP_PMP_SQLITE_READSEQ, 8100016, 4, 1, 0);
  run_case(GROUP_PMP_SQLITE_READRAND100K, 8100016, 4, 20, 0);
  run_case(GROUP_PMP_SQLITE_READRANDOM, 2100016, 4, GROUP_PMP_SQLITE_VFS_BATCH_MAX, 0);
  run_case(GROUP_PMP_SQLITE_FILLSEQ, 8100016, 4, 1, 0);
  test_pair_boundaries();
  test_consumption_clock();
  test_pair_prepare_failure();
  test_pair_ack_failures();
  /* Reconfigure, not just destroy, must reset the opt-in. */
  configure_case(GROUP_PMP_SQLITE_READSEQ, 16, 0, 1);
  /* AES has one static context; release it without resetting the store flag. */
  group_pmp_crypto_deinit(&crypto_context);
  configure_case(GROUP_PMP_SQLITE_READSEQ, 16, 0, -1);
  keystone_enclave_store_destroy();
  assert(keystone_enclave_store_set_paired_reads(1) != 0);
  test_overlap_clock();
  puts("ring generation and overlap accounting PASS");
  return 0;
}
