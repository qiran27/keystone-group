#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "app/syscall.h"
#include "group-pmp-crypto.h"
#include "benchmark-cipher.h"
#include "keystone_enclave_store.h"
#include "../motivation/system-trace.h"
static const volatile char system_trace_marker[] __attribute__((used)) = MOT_SYSTEM_MARKER;
static struct mot_system_trace system_trace;
static int system_trace_enabled;
_Static_assert(sizeof(struct mot_system_trace) <= GROUP_PMP_SQLITE_VFS_BUFFER_BYTES,
    "system trace must fit an already drained data buffer");
#include "../security/security-sentinel.h"
static int security_phase_enabled;
static struct group_pmp_security_phase_state security_phase_state;
static void security_phase(unsigned phase) {
  if (!security_phase_enabled || (security_phase_state.seen & (UINT64_C(1) << phase))) return;
  security_phase_state.magic = GROUP_PMP_SECURITY_PHASE_MAGIC;
  ++security_phase_state.sequence;
  (void)copy_to_shared_utm(GROUP_PMP_SECURITY_PROBE_OFFSET,
      &security_phase_state, sizeof(security_phase_state));
  __sync_synchronize();
  security_phase_state.phase = phase;
  security_phase_state.seen |= UINT64_C(1) << phase;
  (void)copy_to_shared_utm(GROUP_PMP_SECURITY_PROBE_OFFSET,
      &security_phase_state, offsetof(struct group_pmp_security_phase_state, sequence));
  __sync_synchronize();
  ++security_phase_state.sequence;
  (void)copy_to_shared_utm(GROUP_PMP_SECURITY_PROBE_OFFSET +
      offsetof(struct group_pmp_security_phase_state, sequence),
      &security_phase_state.sequence, sizeof(security_phase_state.sequence));
  __sync_synchronize();
}
#include "sqlite-locality-address.h"
static const volatile char security_capture_marker[] __attribute__((used)) =
    "keystone-security-capture-milestones-v2";

#define STORE_TEMPLATE_BYTES UINT64_C(65536)

struct store_buffer {
  uint64_t request_id;
  uint64_t length;
  uint64_t sequence;
  uint64_t logical_offset;
  uint64_t utm_offset;
  int pending;
  int read;
  int detached;
};

struct store_batch {
  uint64_t request_id;
  uint64_t count;
  uint64_t ring_slot;
  uint64_t generation;
  uint64_t submitted_ticks;
  uint64_t ack_ticks;
  int pending;
  int detached;
  struct store_buffer descriptors[GROUP_PMP_SQLITE_VFS_BATCH_MAX];
};

static const volatile char store_marker[] __attribute__((used)) =
    KEYSTONE_ENCLAVE_STORE_MARKER;
static const volatile char store_direct_utm_marker[] __attribute__((used)) =
    KEYSTONE_UTM_DIRECT_DATA_MARKER;
static const volatile char store_batched_random_read_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_BATCHED_RANDOM_READ_MARKER;
static const volatile char store_exact_io_granularity_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_EXACT_IO_GRANULARITY_MARKER;
static const volatile char store_descriptor_batch_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_DESCRIPTOR_BATCH_MARKER;
static const volatile char store_effective_batch_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_EFFECTIVE_BATCH_MARKER;
static const volatile char store_utm_buddy_layout_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_UTM_BUDDY_LAYOUT_MARKER;
static const volatile char store_status_commit_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_STATUS_COMMIT_MARKER;
static const volatile char store_crypto_timing_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_CRYPTO_TIMING_MARKER;
static const volatile char store_blocking_pipeline_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_BLOCKING_PIPELINE_MARKER;
static const volatile char store_batch_ocall_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_BATCH_OCALL_MARKER;
static const volatile char store_control_abi_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_CONTROL_ABI_MARKER;
static const volatile char store_central_io_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_CENTRAL_IO_MARKER;
static const volatile char store_vfs_abi_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_VFS_ABI_MARKER;
static const volatile char store_double_buffer_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_DOUBLE_BUFFER_MARKER;
static const volatile char store_completion_fastpath_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_COMPLETION_FASTPATH_MARKER;
static struct group_pmp_sqlite_vfs_config store_config;
static struct group_pmp_sqlite_vfs_stats store_stats;
static struct store_buffer store_buffers[GROUP_PMP_SQLITE_VFS_BUFFER_COUNT];
static struct store_batch store_batches[GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT];
static uint64_t buffer_consumed_ticks[GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT];
static struct group_pmp_sqlite_vfs_request
    store_request_workspace[GROUP_PMP_SQLITE_VFS_BATCH_MAX];
static int store_read_workspace[GROUP_PMP_SQLITE_VFS_BATCH_MAX];
static uint64_t store_logical_offset_workspace[
    GROUP_PMP_SQLITE_VFS_BATCH_MAX];
static uint64_t store_amount_workspace[GROUP_PMP_SQLITE_VFS_BATCH_MAX];
/* tiny-malloc starts at the end of the loaded EAPP image, which is not an
 * automatically mapped heap. Keep the streaming buffers in ELF BSS so the
 * loader includes them in the measured and mapped private EPM range. */
static uint8_t plain_template[STORE_TEMPLATE_BYTES]
    __attribute__((aligned(64)));
static uint8_t plain_scratch[GROUP_PMP_SQLITE_VFS_BUFFER_BYTES]
    __attribute__((aligned(64)));
/* AEAD authenticates the same immutable private bytes that it decrypts. */
static uint8_t cipher_snapshot[GROUP_PMP_SQLITE_VFS_BUFFER_BYTES]
    __attribute__((aligned(64)));
static struct keystone_utm_direct_info direct_utm;
static struct group_pmp_crypto_context crypto_context;
static uint64_t store_task_bytes;
static uint64_t next_request_id;
static uint64_t next_sequence;
static uint64_t next_ring_generation;
static uint64_t last_error;
#ifdef GROUP_PMP_KV_WORKER
static struct kv_bench_stats kv_stats;
/* Defined below with the shared, seeded online address mapping. */
static uint64_t extent_file_offset(uint64_t logical_offset);
static uint64_t kv_key_for_offset(uint64_t logical_offset) {
  return (extent_file_offset(logical_offset) - store_config.file_base) / UINT64_C(4096);
}
#endif
static int configured;
static int paired_reads;
static int intent_lookahead;
static uint32_t intent_order[GROUP_PMP_SQLITE_INTENT_MAX];
static uint8_t intent_seen[GROUP_PMP_SQLITE_INTENT_MAX / 8];
static const volatile struct keystone_member_exec_clock* exec_clock;

static int wait_all(uint64_t* digest);

static int wait_buffers(uint64_t count, uint64_t* digest);

static int wait_batch(uint64_t ring_slot, uint64_t* digest);

static int batch_completion_ready(uint64_t ring_slot);
static uint64_t extent_file_offset(uint64_t logical_offset);

static void wipe_private(void* memory, size_t bytes) {
  volatile uint8_t* p = (volatile uint8_t*)memory;
  while (bytes--) *p++ = 0;
}

static int initialize_aead(unsigned algorithm) {
  uint8_t key[32] __attribute__((aligned(8)));
  int rc = -1;
  /* Eyrie -> SM platform_random. VF2 currently supplies TEST-ONLY entropy;
   * this benchmark does not establish production key security. */
#if defined(BENCHMARK_TEST_RANDOM)
  rc = BENCHMARK_TEST_RANDOM(key, sizeof(key));
#elif defined(__riscv)
  rc = SYSCALL_3(278, key, sizeof(key), 0) == sizeof(key) ? 0 : -1;
#endif
  if (!rc) rc = benchmark_aead_init(algorithm, key);
  wipe_private(key, sizeof(key));
  return rc;
}

static uint64_t rdcycle(void) {
#if defined(__riscv)
  uint64_t value;
  __asm__ volatile("rdcycle %0" : "=r"(value));
  return value;
#else
  return 0;
#endif
}

static uint64_t rdtime(void) {
#if defined(__riscv)
  uint64_t value;
  __asm__ volatile("rdtime %0" : "=r"(value));
  return value;
#else
  return 0;
#endif
}

int keystone_enclave_store_set_exec_clock(
    const volatile struct keystone_member_exec_clock* clock) {
  struct keystone_exec_clock_sample sample;
  if (keystone_exec_clock_read(clock, rdtime, &sample) != 0)
    return -1;
  exec_clock = clock;
  return 0;
}

static int transform_measured(int operation, const uint8_t* input,
                               uint8_t* output, size_t length,
                               uint64_t logical_offset, uint64_t sequence,
                               uint8_t tag[16],
                               uint64_t* wall_start, uint64_t* wall_end) {
  struct keystone_exec_clock_sample before, after;
  uint64_t cycles, cpu, elapsed;
  int ret;
  if (keystone_exec_clock_read(exec_clock, rdtime, &before) != 0) {
    last_error = UINT64_C(2101);
    return -1;
  }
  cycles = rdcycle();
  if (store_config.cipher_algorithm == BENCHMARK_AES_ECB) {
    ret = group_pmp_crypto_transform(&crypto_context, operation, input, output, length);
  } else {
    const struct benchmark_aead_identity id = {
      store_config.run_id, store_config.worker_index, store_config.workload,
      extent_file_offset(logical_offset), store_task_bytes, logical_offset,
      length, sequence
    };
    if (!tag || length > sizeof(cipher_snapshot)) return -1;
    if (operation == GROUP_PMP_CRYPTO_ENCRYPT) {
      ret = benchmark_aead_seal(&id, input, output, tag);
    } else {
      memcpy(cipher_snapshot, input, length);
      ret = benchmark_aead_open(&id, cipher_snapshot, tag, output);
      wipe_private(cipher_snapshot, length);
    }
  }
  cycles = rdcycle() - cycles;
  if (keystone_exec_clock_read(exec_clock, rdtime, &after) != 0 ||
      before.generation != after.generation ||
      after.runtime_ticks < before.runtime_ticks ||
      after.wall_ticks < before.wall_ticks) {
    last_error = UINT64_C(2102);
    return -1;
  }
  cpu = after.runtime_ticks - before.runtime_ticks;
  elapsed = after.wall_ticks - before.wall_ticks;
  if (cpu > elapsed) {
    last_error = UINT64_C(2103);
    return -1;
  }
  if (operation == GROUP_PMP_CRYPTO_ENCRYPT) {
    store_stats.encrypt_cycles += cycles; // Raw cycle intervals, not on-CPU.
    store_stats.encrypt_time_ticks += cpu;
  } else {
    store_stats.decrypt_cycles += cycles;
    store_stats.decrypt_time_ticks += cpu;
  }
  store_stats.crypto_elapsed_ticks += elapsed;
  if (system_trace_enabled && !ret)
    mot_system_append(&system_trace,before.wall_ticks,after.wall_ticks,
        logical_offset,length,cpu,(uint64_t)operation);
  if (wall_start)
    *wall_start = before.wall_ticks;
  if (wall_end)
    *wall_end = after.wall_ticks;
  return ret;
}

static uintptr_t buffer_offset(uint64_t buffer_id) {
  return (uintptr_t)(buffer_id ? GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET :
                                GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET);
}

static uintptr_t status_offset(uint64_t ring_slot, uint64_t descriptor_id) {
  return (uintptr_t)(GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET_FOR_SLOT(
                         ring_slot) +
      descriptor_id * sizeof(struct group_pmp_sqlite_vfs_status));
}

static uintptr_t packed_buffer_offset(uint64_t physical_buffer,
                                      uint64_t request_index,
                                      uint64_t request_stride) {
  if (!request_stride || request_stride > GROUP_PMP_SQLITE_VFS_BUFFER_BYTES)
    return 0;
  if (physical_buffer >= GROUP_PMP_SQLITE_VFS_BUFFER_COUNT ||
      request_index >= GROUP_PMP_SQLITE_VFS_BATCH_MAX ||
      request_index >= GROUP_PMP_SQLITE_VFS_BUFFER_BYTES / request_stride)
    return 0;
  return buffer_offset(physical_buffer) + request_index * request_stride;
}

static int payload_range_matches(uint64_t buffer_id, uint64_t utm_offset,
                                 uint64_t length) {
  uint64_t begin;

  if (buffer_id >= GROUP_PMP_SQLITE_VFS_BUFFER_COUNT || !length ||
      length > GROUP_PMP_SQLITE_VFS_BUFFER_BYTES)
    return 0;
  begin = buffer_offset(buffer_id);
  return utm_offset >= begin &&
      utm_offset - begin <= GROUP_PMP_SQLITE_VFS_BUFFER_BYTES &&
      length <= GROUP_PMP_SQLITE_VFS_BUFFER_BYTES - (utm_offset - begin);
}

static uint8_t* direct_utm_pointer(uint64_t utm_offset, uint64_t length) {
  uint64_t relative;

  if (direct_utm.abi_version != KEYSTONE_UTM_DIRECT_ABI_VERSION ||
      direct_utm.struct_size != sizeof(direct_utm) ||
      !(direct_utm.flags & KEYSTONE_UTM_DIRECT_FLAG_READ) ||
      !(direct_utm.flags & KEYSTONE_UTM_DIRECT_FLAG_WRITE) ||
      !(direct_utm.flags & KEYSTONE_UTM_DIRECT_FLAG_NX) ||
      utm_offset < direct_utm.data_utm_offset)
    return NULL;
  relative = utm_offset - direct_utm.data_utm_offset;
  if (relative > direct_utm.data_size ||
      length > direct_utm.data_size - relative)
    return NULL;
  return (uint8_t*)(uintptr_t)(direct_utm.data_va + relative);
}

static int load_status(uint64_t ring_slot, uint64_t descriptor_id,
                       struct group_pmp_sqlite_vfs_status* status) {
  const void* source;
  if (!status || ring_slot >= GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT ||
      descriptor_id >= GROUP_PMP_SQLITE_VFS_BATCH_MAX)
    return -1;
  source = direct_utm_pointer(status_offset(ring_slot, descriptor_id),
                              sizeof(*status));
  if (!source)
    return -1;
  __sync_synchronize();
  memcpy(status, source, sizeof(*status));
  __sync_synchronize();
  return 0;
}

static int initialize_status(uint64_t ring_slot, uint64_t descriptor_id,
                             uint64_t request_id) {
  struct group_pmp_sqlite_vfs_status status;
  void* destination;
  if (ring_slot >= GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT ||
      descriptor_id >= GROUP_PMP_SQLITE_VFS_BATCH_MAX)
    return -1;
  destination = direct_utm_pointer(status_offset(ring_slot, descriptor_id),
                                   sizeof(status));
  if (!destination)
    return -1;
  memset(&status, 0, sizeof(status));
  status.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
  status.version = GROUP_PMP_SQLITE_VFS_VERSION;
  status.request_id = request_id;
  status.state = GROUP_PMP_SQLITE_VFS_STATE_PENDING;
  memcpy(destination, &status, sizeof(status));
  __sync_synchronize();
  return 0;
}

#ifndef GROUP_PMP_KV_WORKER
static void copy_template(uint8_t* output, uint64_t logical_offset,
                          uint64_t length) {
  uint64_t done = 0;
  while (done < length) {
    uint64_t source = (logical_offset + done) %
        STORE_TEMPLATE_BYTES;
    uint64_t amount = STORE_TEMPLATE_BYTES - source;
    if (amount > length - done)
      amount = length - done;
    memcpy(output + done, plain_template + source, (size_t)amount);
    done += amount;
  }
}
#endif

static int validate_plain_sample(const uint8_t* input,
                                 uint64_t logical_offset,
                                 uint64_t length, uint64_t* digest) {
#ifdef GROUP_PMP_KV_WORKER
  if (kv_record_check(input, (size_t)length, kv_key_for_offset(logical_offset),
                       (uint32_t)store_config.worker_index, 0, digest)) return -1;
  ++kv_stats.gets;
  ++kv_stats.validated_gets;
  kv_stats.bytes += length;
  return 0;
#else
  uint64_t sample_offsets[2];
  uint64_t value = UINT64_C(1469598103934665603);
  uint64_t sample;
  uint64_t byte;

  if (length < UINT64_C(16))
    return -1;
  value ^= logical_offset;
  value *= UINT64_C(1099511628211);
  value ^= length;
  value *= UINT64_C(1099511628211);
  sample_offsets[0] = 0;
  sample_offsets[1] = length - UINT64_C(16);
  for (sample = 0; sample < 2; ++sample) {
    for (byte = 0; byte < UINT64_C(16); ++byte) {
      uint64_t offset = sample_offsets[sample] + byte;
      uint8_t expected = plain_template[(logical_offset + offset) %
          STORE_TEMPLATE_BYTES];
      if (input[offset] != expected)
        return -1;
      value ^= input[offset];
      value *= UINT64_C(1099511628211);
    }
  }
  /* WAIT_ANY may consume either buffer first. Sum offset-bound per-request
   * fingerprints, not an arrival-ordered hash stream. This is a lightweight
   * benchmark checksum, not authentication; keep the byte checks above. */
  if (digest)
    *digest += value;
  return 0;
#endif
}

#ifdef GROUP_PMP_KV_WORKER
static int kv_prepare_put(uint64_t logical_offset, uint64_t length, uint64_t flags) {
  const int measured = (flags & GROUP_PMP_SQLITE_STORE_MEASURED) != 0;
  const uint32_t version = measured &&
      store_config.workload == GROUP_PMP_SQLITE_OVERWRITE ? 1 : 0;
  if (kv_record_make(plain_scratch, (size_t)length, kv_key_for_offset(logical_offset),
                     (uint32_t)store_config.worker_index, version)) return -1;
  if (measured) { ++kv_stats.puts; kv_stats.bytes += length; }
  return 0;
}
void keystone_enclave_store_get_kv_stats(struct kv_bench_stats* stats) {
  if (stats) *stats = kv_stats;
}
#endif

static int wait_buffer(uint64_t buffer_id, uint64_t* digest) {
  struct group_pmp_sqlite_vfs_wait wait_request;
  struct group_pmp_sqlite_vfs_ack ack;
  struct group_pmp_sqlite_vfs_status status;
  struct store_buffer* buffer;
  uint64_t started = rdtime();
  uint8_t* cipher;

  if (buffer_id >= GROUP_PMP_SQLITE_VFS_BUFFER_COUNT)
    return -1;
  buffer = &store_buffers[buffer_id];
  if (!buffer->pending)
    return 0;
  ++store_stats.wait_count;
  if (load_status(buffer_id, 0, &status) != 0) {
    last_error = UINT64_C(1001);
    return -1;
  }
  __sync_synchronize();
  /* A detached data submission owns its Host completion until this explicit
   * wait OCALL consumes it. The OCALL blocks this member in the SM and lets a
   * READY same-lane peer run; it also reaps an already-completed request
   * without polling or cooperative yield. */
  if (buffer->detached &&
      status.state == GROUP_PMP_SQLITE_VFS_STATE_PENDING) {
    memset(&wait_request, 0, sizeof(wait_request));
    memset(&ack, 0, sizeof(ack));
    wait_request.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    wait_request.version = GROUP_PMP_SQLITE_VFS_VERSION;
    wait_request.run_id = store_config.run_id;
    wait_request.worker_index = store_config.worker_index;
    wait_request.request_id = buffer->request_id;
    wait_request.buffer_id = buffer_id;
    ++store_stats.blocked_completion_count;
    if (ocall(GROUP_PMP_SQLITE_VFS_OCALL_ID, &wait_request,
              sizeof(wait_request), &ack, sizeof(ack)) != 0 ||
        ack.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
        ack.version != GROUP_PMP_SQLITE_VFS_VERSION ||
        ack.request_id != wait_request.request_id || ack.status != 0) {
      last_error = UINT64_C(1004);
      return -1;
    }
    if (load_status(buffer_id, 0, &status) != 0) {
      last_error = UINT64_C(1006);
      return -1;
    }
    __sync_synchronize();
  }
  if (status.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
      status.version != GROUP_PMP_SQLITE_VFS_VERSION ||
      status.request_id != buffer->request_id ||
      status.state == GROUP_PMP_SQLITE_VFS_STATE_PENDING) {
    last_error = UINT64_C(1005);
    return -1;
  }
  store_stats.wait_ticks += rdtime() - started;
  buffer->pending = 0;
  buffer->detached = 0;
  if (status.state != GROUP_PMP_SQLITE_VFS_STATE_DONE) {
    if (status.state == GROUP_PMP_SQLITE_VFS_STATE_ERROR && status.result)
      last_error = UINT64_C(1200000) +
          (uint64_t)(status.result < 0 ? -status.result : status.result);
    else
      last_error = UINT64_C(1100001);
    return -1;
  }
  if (status.result != 0) {
    last_error = UINT64_C(1200000) +
        (uint64_t)(status.result < 0 ? -status.result : status.result);
    return -1;
  }
  if (status.length != buffer->length) {
    last_error = UINT64_C(1100002);
    return -1;
  }
  if (!buffer->read && status.sequence != buffer->sequence) {
    last_error = UINT64_C(1100003);
    return -1;
  }
  if (!buffer->read)
    return 0;
  cipher = direct_utm_pointer(buffer->utm_offset, buffer->length);
  if (!cipher) {
    last_error = UINT64_C(1003);
    return -1;
  }
  __sync_synchronize();
  if (transform_measured(GROUP_PMP_CRYPTO_DECRYPT, cipher, plain_scratch,
                          (size_t)buffer->length, buffer->logical_offset,
                          status.sequence, status.tag, 0, 0) != 0) {
    last_error = UINT64_C(100401);
    return -1;
  }
  if (validate_plain_sample(plain_scratch, buffer->logical_offset,
                            buffer->length, digest) != 0) {
    last_error = UINT64_C(100402);
    return -1;
  }
  security_phase(SECURITY_PHASE_DECRYPTED);
  store_stats.read_bytes += buffer->length;
  return 0;
}

static int acquire_buffer(uint64_t* output, uint64_t* digest) {
  uint64_t index;
  for (index = 0; index < GROUP_PMP_SQLITE_VFS_BUFFER_COUNT; ++index) {
    if (!store_buffers[index].pending) {
      if (store_buffers[index].request_id) security_phase(SECURITY_PHASE_REUSE);
      *output = index;
      return 0;
    }
  }
  if (wait_buffer(0, digest) != 0)
    return -1;
  *output = 0;
  return 0;
}

static int submit_request(struct group_pmp_sqlite_vfs_request* request,
                          uint64_t buffer_id, int read,
                          uint64_t logical_offset, uint64_t* digest) {
  struct group_pmp_sqlite_vfs_ack ack;
  struct store_buffer* buffer;
  uint64_t pending_count = 0;
  uint64_t started;

  if (buffer_id >= GROUP_PMP_SQLITE_VFS_BUFFER_COUNT ||
      store_buffers[buffer_id].pending)
    return -1;
  request->magic = GROUP_PMP_SQLITE_VFS_MAGIC;
  request->version = GROUP_PMP_SQLITE_VFS_VERSION;
  request->request_id = ++next_request_id;
  request->run_id = store_config.run_id;
  request->worker_index = store_config.worker_index;
  request->worker_count = store_config.worker_count;
  request->workload = store_config.workload;
  request->buffer_id = buffer_id;
  request->buffer_offset = buffer_offset(buffer_id);
  request->descriptor_id = 0;
  request->ring_slot = buffer_id;
  request->reserved[0] |= GROUP_PMP_SQLITE_STORE_RING;
  if (request->operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
      request->operation == GROUP_PMP_SQLITE_VFS_OP_WRITE)
    request->reserved[0] |= GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY;
  else
    request->reserved[0] |= GROUP_PMP_SQLITE_STORE_BLOCK_ON_COMPLETE;
  if (request->length > GROUP_PMP_SQLITE_VFS_BUFFER_BYTES ||
      ((request->operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
        request->operation == GROUP_PMP_SQLITE_VFS_OP_WRITE) &&
       !request->length))
    return -1;
  if ((request->operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
       request->operation == GROUP_PMP_SQLITE_VFS_OP_WRITE) &&
      !direct_utm_pointer(request->buffer_offset, request->length))
    return -1;
  /* Completion slots live in this enclave's own UTM control page. The EAPP
   * direct mapping deliberately excludes that page, and copy_to_shared_utm()
   * targets YXSTM rather than own UTM. Host publishes the complete status
   * before waking this request, so no EAPP-side PENDING write is required. */
  buffer = &store_buffers[buffer_id];
  memset(buffer, 0, sizeof(*buffer));
  buffer->request_id = request->request_id;
  buffer->length = request->length;
  buffer->sequence = request->sequence;
  buffer->logical_offset = logical_offset;
  buffer->utm_offset = request->buffer_offset;
  buffer->pending = 1;
  buffer->read = read;
  buffer->detached =
      (request->reserved[0] & GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY) != 0;
  if (initialize_status(buffer_id, 0, request->request_id) != 0) {
    memset(buffer, 0, sizeof(*buffer));
    return -1;
  }
  memset(&ack, 0, sizeof(ack));
  started = rdtime();
  if (ocall(GROUP_PMP_SQLITE_VFS_OCALL_ID, request, sizeof(*request),
            &ack, sizeof(ack)) != 0 ||
      ack.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
      ack.version != GROUP_PMP_SQLITE_VFS_VERSION ||
      ack.request_id != request->request_id || ack.status != 0) {
    last_error = UINT64_C(2001);
    memset(buffer, 0, sizeof(*buffer));
    return -1;
  }
  store_stats.ocall_ticks += rdtime() - started;
  ++store_stats.submit_count;
  ++store_stats.batch_submit_count;
  for (uint64_t index = 0; index < GROUP_PMP_SQLITE_VFS_BUFFER_COUNT; ++index)
    if (store_buffers[index].pending)
      pending_count++;
  if (store_stats.queue_depth_peak < pending_count)
    store_stats.queue_depth_peak = pending_count;
  if (buffer->detached)
    return 0;
  ++store_stats.blocked_completion_count;
  return wait_buffer(buffer_id, digest);
}

static int wait_all(uint64_t* digest) {
  uint64_t slot;
  if (wait_buffers(GROUP_PMP_SQLITE_VFS_BUFFER_COUNT, digest) != 0)
    return -1;
  for (slot = 0; slot < GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT; ++slot)
    if (wait_batch(slot, digest) != 0)
      return -1;
  return 0;
}

static int wait_buffers(uint64_t count, uint64_t* digest) {
  uint64_t index;
  if (count > GROUP_PMP_SQLITE_VFS_BUFFER_COUNT)
    return -1;
  for (index = 0; index < count; ++index)
    if (wait_buffer(index, digest) != 0)
      return -1;
  return 0;
}

static uint64_t chunk_bytes(void) {
  return group_pmp_sqlite_io_chunk(store_config.workload, store_config.direct_layout);
}

static uint64_t greatest_common_divisor(uint64_t left, uint64_t right) {
  while (right) {
    uint64_t remainder = left % right;
    left = right;
    right = remainder;
  }
  return left;
}

static uint64_t extent_key(uint64_t logical_offset) {
  uint64_t chunk = chunk_bytes();
  uint64_t count = (store_task_bytes + chunk - UINT64_C(1)) / chunk;
  uint64_t index = logical_offset / chunk;
  if (group_pmp_sqlite_page_random(store_config.workload))
    return sqlite_locality_page(index, store_task_bytes, store_config.worker_index);
  if (group_pmp_sqlite_is_random(store_config.workload) && count > 1) {
    uint64_t multiplier = UINT64_C(65537);
    while (greatest_common_divisor(multiplier, count) != 1)
      multiplier += UINT64_C(2);
    index = (index * multiplier +
             store_config.worker_index * UINT64_C(104729)) % count;
  }
  return index;
}

static uint64_t packed_tail_index, packed_tail_gap;

static uint64_t extent_file_offset(uint64_t logical_offset) {
  const uint64_t chunk = chunk_bytes();
  uint64_t index = extent_key(logical_offset);
  if (!store_config.direct_layout &&
      group_pmp_sqlite_page_random(store_config.workload) && packed_tail_gap) {
    const uint64_t full_slots = store_task_bytes / chunk;
    /* Remove the tail's permutation slot as a whole page, never as bytes. */
    if (logical_offset / chunk == full_slots) index = full_slots;
    else if (index > packed_tail_index) --index;
    return store_config.file_base + index * chunk + logical_offset % chunk;
  }
  return store_config.file_base + index * chunk + logical_offset % chunk -
      (index > packed_tail_index ? packed_tail_gap : 0);
}

static int prepare_intent_window(uint64_t first, uint64_t length, uint64_t chunk,
                                 uint64_t slot, uint64_t count, int read) {
  struct group_pmp_sqlite_intent_plan plan = {0};
  struct group_pmp_sqlite_intent_ack ack = {0};
  struct group_pmp_sqlite_io_intent* intents;
  uint64_t started;
  if (!count || count > GROUP_PMP_SQLITE_INTENT_MAX || slot >= 2 ||
      store_batches[slot].pending || store_buffers[slot].pending)
    return -1;
  intents = (void*)direct_utm_pointer(buffer_offset(slot), count * sizeof(*intents));
  if (!intents) return -1;
  for (uint64_t i = 0; i < count; ++i) {
    const uint64_t remaining = length - i * chunk;
    intents[i].file_offset = extent_file_offset(first + i * chunk);
    intents[i].length = remaining < chunk ? remaining : chunk;
  }
  plan.magic = GROUP_PMP_SQLITE_INTENT_MAGIC;
  plan.version = GROUP_PMP_SQLITE_INTENT_VERSION;
  plan.request_id = ++next_request_id;
  plan.run_id = store_config.run_id;
  plan.worker_index = store_config.worker_index;
  plan.worker_count = store_config.worker_count;
  plan.workload = store_config.workload;
  plan.operation = read ? GROUP_PMP_SQLITE_VFS_OP_READ : GROUP_PMP_SQLITE_VFS_OP_WRITE;
  plan.buffer_id = slot;
  plan.buffer_offset = buffer_offset(slot);
  plan.count = count;
  plan.flags = GROUP_PMP_SQLITE_STORE_MEASURED;
  plan.file_base = store_config.file_base;
  plan.file_span = group_pmp_sqlite_file_span(store_config.workload,
      store_task_bytes, store_config.direct_layout);
  __sync_synchronize();
  started = rdtime();
  if (ocall(GROUP_PMP_SQLITE_VFS_OCALL_ID, &plan, sizeof(plan), &ack, sizeof(ack)) ||
      ack.magic != plan.magic || ack.version != plan.version ||
      ack.request_id != plan.request_id || ack.count != count || ack.status) {
    last_error = UINT64_C(2201);
    return -1;
  }
  store_stats.ocall_ticks += rdtime() - started;
  /* Snapshot untrusted order into EPM, then verify an exact permutation.
   * Offsets, lengths, task IDs and sequences are recomputed inside enclave. */
  memcpy(intent_order, intents, count * sizeof(intent_order[0]));
  memset(intent_seen, 0, sizeof(intent_seen));
  for (uint64_t i = 0; i < count; ++i) {
    uint32_t index = intent_order[i];
    if (index >= count || (intent_seen[index / 8] & (1u << (index % 8)))) {
      last_error = UINT64_C(2202);
      return -1;
    }
    intent_seen[index / 8] |= (uint8_t)(1u << (index % 8));
  }
  return 0;
}

static int batch_completion_ready(uint64_t ring_slot) {
  struct group_pmp_sqlite_vfs_ring_header* ring;
  const struct store_batch* batch;

  if (ring_slot >= GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT)
    return 0;
  batch = &store_batches[ring_slot];
  if (!batch->pending || !batch->generation || !batch->count)
    return 0;
  ring = (struct group_pmp_sqlite_vfs_ring_header*)direct_utm_pointer(
      GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(ring_slot),
      GROUP_PMP_SQLITE_VFS_RING_SLOT_BYTES);
  if (!ring || ring->magic != GROUP_PMP_SQLITE_VFS_RING_MAGIC ||
      ring->version != GROUP_PMP_SQLITE_VFS_VERSION ||
      ring->generation != batch->generation ||
      __atomic_load_n(&ring->producer, __ATOMIC_ACQUIRE) != batch->count)
    return 0;
  return __atomic_load_n(&ring->completion_count, __ATOMIC_ACQUIRE) >=
      batch->count;
}

/* Time in crypto while the other UTM buffer still has an outstanding batch.
 * Host's diagnostic timestamp is clamped to the crypto interval. This measures
 * pipeline overlap, not device-active time, and never controls permissions. */
static void account_crypto_overlap(uint64_t ring_slot, uint64_t start,
                                    uint64_t end) {
  uint64_t other = (ring_slot + UINT64_C(1)) %
      GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT;
  const struct store_batch* peer = &store_batches[other];
  uint64_t overlap_start;
  uint64_t overlap_end = end;
  if (store_config.workload != GROUP_PMP_SQLITE_READRAND100K &&
      store_config.workload != GROUP_PMP_SQLITE_READSEQ)
    return;
  if (end < start)
    return;
  store_stats.crypto_io_sample_ticks += end - start;
  if (!peer->pending || !peer->submitted_ticks)
    return;
  overlap_start = peer->submitted_ticks > start ? peer->submitted_ticks : start;
  if (batch_completion_ready(other)) {
    const struct group_pmp_sqlite_vfs_ring_header* ring =
        (const struct group_pmp_sqlite_vfs_ring_header*)direct_utm_pointer(
            GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(other),
            sizeof(struct group_pmp_sqlite_vfs_ring_header));
    uint64_t completed = __atomic_load_n(&ring->completed_time_ticks,
                                         __ATOMIC_RELAXED);
    if (!completed || completed < peer->submitted_ticks)
      return;
    if (completed < overlap_end)
      overlap_end = completed;
  }
  if (overlap_end > overlap_start)
    store_stats.crypto_io_overlap_ticks += overlap_end - overlap_start;
}

static void account_completion_consumption(uint64_t ring_slot,
                                            uint64_t consume_started) {
  const struct store_batch* batch = &store_batches[ring_slot];
  {
    const int ready = batch_completion_ready(ring_slot);
    const struct group_pmp_sqlite_vfs_ring_header* ring =
        (const struct group_pmp_sqlite_vfs_ring_header*)direct_utm_pointer(
            GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(ring_slot), sizeof(*ring));
    const uint64_t completed = ring ? __atomic_load_n(
        &ring->completed_time_ticks, __ATOMIC_RELAXED) : 0;
    if (ready && completed &&
        completed >= batch->submitted_ticks && completed <= consume_started) {
      const uint64_t elapsed = consume_started - completed;
      ++store_stats.pipeline.completion_to_consume_count;
      store_stats.pipeline.completion_to_consume_ticks += elapsed;
      if (elapsed > store_stats.pipeline.completion_to_consume_max_ticks)
        store_stats.pipeline.completion_to_consume_max_ticks = elapsed;
    } else {
      ++store_stats.pipeline.completion_timestamp_invalid;
    }
    if (batch->ack_ticks && consume_started >= batch->ack_ticks) {
      const uint64_t elapsed = consume_started - batch->ack_ticks;
      store_stats.pipeline.ack_to_consume_ticks += elapsed;
      if (elapsed > store_stats.pipeline.ack_to_consume_max_ticks)
        store_stats.pipeline.ack_to_consume_max_ticks = elapsed;
    }
  }
}

static int wait_batch_selected(uint64_t* selected, uint64_t* digest, int allow_any) {
  uint64_t ring_slot = *selected;
  struct group_pmp_sqlite_vfs_wait wait_request;
  struct group_pmp_sqlite_vfs_ack ack;
  struct store_batch* batch;
  uint64_t started;
  uint64_t index;
  uint64_t consume_started;

  if (ring_slot >= GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT)
    return -1;
  batch = &store_batches[ring_slot];
  if (!batch->pending)
    return 0;
  started = 0;
  if (batch->detached && !batch_completion_ready(ring_slot)) {
    struct group_pmp_sqlite_vfs_wait_any wait_any;
    const void* wait_packet = &wait_request;
    size_t wait_packet_size = sizeof(wait_request);
    struct keystone_exec_clock_sample cpu_before = {0}, cpu_after = {0};
    struct group_pmp_sqlite_vfs_ring_header* wait_ring =
        (struct group_pmp_sqlite_vfs_ring_header*)direct_utm_pointer(
            GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(ring_slot),
            sizeof(struct group_pmp_sqlite_vfs_ring_header));
    int clock_valid;
    const uint64_t other = (ring_slot + UINT64_C(1)) %
        GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT;
    const int both_waiting = store_batches[other].pending &&
        !batch_completion_ready(other);
    started = rdtime();
    ++store_stats.wait_count;
    memset(&wait_request, 0, sizeof(wait_request));
    memset(&ack, 0, sizeof(ack));
    wait_request.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    wait_request.version = GROUP_PMP_SQLITE_VFS_VERSION;
    wait_request.run_id = store_config.run_id;
    wait_request.worker_index = store_config.worker_index;
    wait_request.request_id = batch->request_id;
    wait_request.buffer_id = ring_slot;
    if (allow_any && both_waiting && store_batches[other].detached) {
      wait_any.buffers[0] = wait_request;
      wait_any.buffers[1] = wait_request;
      wait_any.buffers[1].buffer_id = other;
      wait_any.buffers[1].request_id = store_batches[other].request_id;
      wait_packet = &wait_any;
      wait_packet_size = sizeof(wait_any);
    }
    ++store_stats.blocked_completion_count;
    if (!wait_ring)
      return -1;
    wait_ring->wait_host_received_ticks = 0;
    wait_ring->wait_host_ack_ticks = 0;
    wait_ring->wait_host_resume_request_ticks = 0;
    clock_valid = keystone_exec_clock_read(exec_clock, rdtime, &cpu_before) == 0;
    if (ocall(GROUP_PMP_SQLITE_VFS_OCALL_ID, (void*)wait_packet,
              wait_packet_size, &ack, sizeof(ack)) != 0 ||
        ack.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
        ack.version != GROUP_PMP_SQLITE_VFS_VERSION ||
        ack.request_id != wait_request.request_id || ack.status != 0) {
      last_error = UINT64_C(2010);
      return -1;
    }
    {
      const uint64_t returned = rdtime();
      uint64_t elapsed = returned - started;
      group_pmp_sqlite_pipeline_wait(&store_stats.pipeline, started,
          __atomic_load_n(&wait_ring->wait_host_received_ticks, __ATOMIC_ACQUIRE),
          __atomic_load_n(&wait_ring->wait_host_ack_ticks, __ATOMIC_ACQUIRE),
          __atomic_load_n(&wait_ring->wait_host_resume_request_ticks, __ATOMIC_ACQUIRE),
          returned);
      if (clock_valid && keystone_exec_clock_read(exec_clock, rdtime, &cpu_after) == 0 &&
          cpu_before.generation == cpu_after.generation &&
          cpu_after.runtime_ticks >= cpu_before.runtime_ticks &&
          cpu_after.wall_ticks >= cpu_before.wall_ticks &&
          cpu_after.runtime_ticks - cpu_before.runtime_ticks <=
              cpu_after.wall_ticks - cpu_before.wall_ticks) {
        const uint64_t cpu = cpu_after.runtime_ticks - cpu_before.runtime_ticks;
        store_stats.pipeline.wait_oncpu_ticks += cpu;
        store_stats.pipeline.wait_offcpu_ticks +=
            cpu_after.wall_ticks - cpu_before.wall_ticks - cpu;
      } else {
        ++store_stats.pipeline.wait_clock_invalid;
      }
      store_stats.wait_ticks += elapsed;
      if (both_waiting)
        store_stats.both_buffers_wait_ticks += elapsed;
    }
    if (wait_packet == &wait_any && !batch_completion_ready(ring_slot) &&
        batch_completion_ready(other)) {
      ring_slot = other;
      batch = &store_batches[ring_slot];
      *selected = ring_slot;
    }
  } else {
    ++store_stats.completion_local_reaps;
  }
  __sync_synchronize();
  consume_started = rdtime();
  account_completion_consumption(ring_slot, consume_started);
  for (index = 0; index < batch->count; ++index) {
    struct group_pmp_sqlite_vfs_status status;
    struct store_buffer* buffer = &batch->descriptors[index];
    uint8_t* cipher;
    uint64_t aes_time_started;
    uint64_t aes_end;

    if (load_status(ring_slot, index, &status) != 0 ||
        status.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
        status.version != GROUP_PMP_SQLITE_VFS_VERSION ||
        status.request_id != buffer->request_id ||
        status.state == GROUP_PMP_SQLITE_VFS_STATE_PENDING) {
      last_error = UINT64_C(2011);
      return -1;
    }
    if (status.state != GROUP_PMP_SQLITE_VFS_STATE_DONE ||
        status.result != 0 || status.length != buffer->length ||
        (!buffer->read && status.sequence != buffer->sequence)) {
      last_error = status.result ? UINT64_C(1200000) +
          (uint64_t)(status.result < 0 ? -status.result : status.result) :
          UINT64_C(2012);
      return -1;
    }
    if (!buffer->read)
      continue;
    cipher = direct_utm_pointer(buffer->utm_offset, buffer->length);
    if (!cipher) {
      last_error = UINT64_C(2013);
      return -1;
    }
    if (transform_measured(GROUP_PMP_CRYPTO_DECRYPT, cipher, plain_scratch,
                            (size_t)buffer->length,
                            buffer->logical_offset, status.sequence, status.tag,
                            &aes_time_started, &aes_end) != 0) {
      last_error = UINT64_C(2014);
      return -1;
    }
    account_crypto_overlap(ring_slot, aes_time_started, aes_end);
    security_phase(SECURITY_PHASE_DECRYPTED);
    if (validate_plain_sample(plain_scratch, buffer->logical_offset,
                              buffer->length, digest) != 0) {
      last_error = UINT64_C(2015);
      return -1;
    }
    store_stats.read_bytes += buffer->length;
  }
  batch->pending = 0;
  batch->count = 0;
  batch->submitted_ticks = 0;
  ++store_stats.buffer_reuses;
  security_phase(SECURITY_PHASE_REUSE);
  ++store_stats.completion_batch_count;
  {
    const uint64_t end = rdtime();
    const uint64_t elapsed = end - consume_started;
    ++store_stats.pipeline.buffer_consume_count;
    store_stats.pipeline.buffer_consume_ticks += elapsed;
    if (elapsed > store_stats.pipeline.buffer_consume_max_ticks)
      store_stats.pipeline.buffer_consume_max_ticks = elapsed;
    buffer_consumed_ticks[ring_slot] = end;
  }
  return 0;
}

static int wait_batch(uint64_t ring_slot, uint64_t* digest) {
  return wait_batch_selected(&ring_slot, digest, 0);
}

static int prepare_request_batch(
    struct group_pmp_sqlite_vfs_request* requests,
    uint64_t count, const int* reads, const uint64_t* logical_offsets,
    uint64_t ring_slot, struct group_pmp_sqlite_vfs_ring_doorbell* doorbell) {
  struct group_pmp_sqlite_vfs_ring_header* ring;
  struct group_pmp_sqlite_vfs_request* descriptor_table;
  struct store_batch* batch;
  uint64_t batch_request_id;
  uint64_t generation;
  uint64_t index;

  if (!count || count > GROUP_PMP_SQLITE_VFS_BATCH_MAX ||
      ring_slot >= GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT)
    return -1;
  batch = &store_batches[ring_slot];
  if (batch->pending)
    return -1;
  ring = (struct group_pmp_sqlite_vfs_ring_header*)direct_utm_pointer(
      GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(ring_slot),
      GROUP_PMP_SQLITE_VFS_RING_SLOT_BYTES);
  descriptor_table = (struct group_pmp_sqlite_vfs_request*)direct_utm_pointer(
      GROUP_PMP_SQLITE_VFS_RING_REQUEST_OFFSET_FOR_SLOT(ring_slot),
      GROUP_PMP_SQLITE_VFS_DESCRIPTOR_BYTES);
  if (!ring || !descriptor_table)
    return -1;
  memset(doorbell, 0, sizeof(*doorbell));
  /* Only descriptors [0,count) are live; initializing all 256 entries penalizes
   * every small readrand100k batch without changing its ownership contract. */
  memset(batch, 0, offsetof(struct store_batch, descriptors));
  generation = ++next_ring_generation;
  if (!generation)
    generation = ++next_ring_generation;
  batch_request_id = ++next_request_id;
  if (!batch_request_id)
    batch_request_id = ++next_request_id;
  for (index = 0; index < count; ++index) {
    struct store_buffer* buffer = &batch->descriptors[index];
    struct group_pmp_sqlite_vfs_request* request = &requests[index];

    if (!payload_range_matches(request->buffer_id, request->buffer_offset,
                               request->length))
      goto prepare_failed;
    request->magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    request->version = GROUP_PMP_SQLITE_VFS_VERSION;
    request->request_id = ++next_request_id;
    request->run_id = store_config.run_id;
    request->worker_index = store_config.worker_index;
    request->worker_count = store_config.worker_count;
    request->workload = store_config.workload;
    request->descriptor_id = index;
    request->ring_slot = ring_slot;
    request->reserved[0] |= GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY |
                            GROUP_PMP_SQLITE_STORE_RING;
    if (!direct_utm_pointer(request->buffer_offset, request->length))
      goto prepare_failed;
    memset(buffer, 0, sizeof(*buffer));
    buffer->request_id = request->request_id;
    buffer->length = request->length;
    buffer->sequence = request->sequence;
    buffer->logical_offset = logical_offsets[index];
    buffer->utm_offset = request->buffer_offset;
    buffer->pending = 1;
    buffer->read = reads[index];
    buffer->detached = 1;
    if (initialize_status(ring_slot, index, request->request_id) != 0)
      goto prepare_failed;
  }
  memset(ring, 0, sizeof(*ring));
  ring->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
  ring->version = GROUP_PMP_SQLITE_VFS_VERSION;
  ring->generation = generation;
  memcpy(descriptor_table, requests, count * sizeof(requests[0]));
  doorbell->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
  doorbell->version = GROUP_PMP_SQLITE_VFS_VERSION;
  doorbell->generation = generation;
  doorbell->producer = count;
  doorbell->count = count;
  doorbell->flags = GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY;
  doorbell->ring_slot = ring_slot;
  doorbell->batch_request_id = batch_request_id;
  batch->request_id = batch_request_id;
  batch->count = count;
  batch->ring_slot = ring_slot;
  batch->generation = generation;
  batch->detached = 1;
  return 0;

prepare_failed:
  memset(batch, 0, sizeof(*batch));
  return -1;
}

static void publish_request_batch(
    const struct group_pmp_sqlite_vfs_ring_doorbell* doorbell,
    uint64_t started) {
  struct store_batch* batch = &store_batches[doorbell->ring_slot];
  struct group_pmp_sqlite_vfs_ring_header* ring =
      (struct group_pmp_sqlite_vfs_ring_header*)direct_utm_pointer(
          GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(doorbell->ring_slot),
          sizeof(*ring));
  /* Ownership must be recorded before Host can observe or complete the ring. */
  batch->submitted_ticks = started;
  batch->pending = 1;
  if (buffer_consumed_ticks[doorbell->ring_slot]) {
    const uint64_t elapsed = started - buffer_consumed_ticks[doorbell->ring_slot];
    ++store_stats.pipeline.buffer_refill_count;
    store_stats.pipeline.buffer_refill_ticks += elapsed;
    if (elapsed > store_stats.pipeline.buffer_refill_max_ticks)
      store_stats.pipeline.buffer_refill_max_ticks = elapsed;
    buffer_consumed_ticks[doorbell->ring_slot] = 0;
  }
  __atomic_store_n(&ring->producer, doorbell->producer, __ATOMIC_RELEASE);
}

static int ring_ack_valid(
    const struct group_pmp_sqlite_vfs_ring_doorbell* doorbell,
    const struct group_pmp_sqlite_vfs_ring_ack* ack) {
  return ack->magic == GROUP_PMP_SQLITE_VFS_RING_MAGIC &&
      ack->version == GROUP_PMP_SQLITE_VFS_VERSION &&
      ack->generation == doorbell->generation &&
      ack->accepted == doorbell->count && ack->consumer == doorbell->producer &&
      ack->status == 0 && ack->ring_slot == doorbell->ring_slot &&
      ack->batch_request_id == doorbell->batch_request_id;
}

static void account_submission_stages(uint64_t ring_slot,
                                       uint64_t started, uint64_t ended) {
  const struct group_pmp_sqlite_vfs_ring_header* ring =
      (const struct group_pmp_sqlite_vfs_ring_header*)direct_utm_pointer(
          GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(ring_slot), sizeof(*ring));
  if (!ring || ring->generation != store_batches[ring_slot].generation) {
    ++store_stats.pipeline.submission_timestamp_invalid;
    return;
  }
  uint64_t resume = __atomic_load_n(&ring->host_resume_request_ticks,
                                    __ATOMIC_ACQUIRE);
  group_pmp_sqlite_pipeline_submission(&store_stats.pipeline, started,
      __atomic_load_n(&ring->host_received_ticks, __ATOMIC_RELAXED),
      __atomic_load_n(&ring->host_ack_ticks, __ATOMIC_RELAXED), resume, ended);
}

static void account_ring_submission(uint64_t started, uint64_t ended,
                                    uint64_t count) {
  const uint64_t elapsed = ended - started;
  store_stats.ocall_ticks += elapsed;
  ++store_stats.pipeline.doorbell_count;
  store_stats.pipeline.doorbell_ack_ticks += elapsed;
  if (elapsed > store_stats.pipeline.doorbell_ack_max_ticks)
    store_stats.pipeline.doorbell_ack_max_ticks = elapsed;
  store_stats.submit_count += count;
  store_stats.batch_submit_count++;
  store_stats.ring_doorbell_count++;
  store_stats.ring_request_count += count;
  {
    uint64_t depth = 0;
    uint64_t slot;
    for (slot = 0; slot < GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT; ++slot)
      if (store_batches[slot].pending)
        depth += store_batches[slot].count;
    if (store_stats.queue_depth_peak < depth)
      store_stats.queue_depth_peak = depth;
  }
}

static int submit_request_batch(
    struct group_pmp_sqlite_vfs_request* requests,
    uint64_t count, const int* reads, const uint64_t* logical_offsets,
    uint64_t ring_slot) {
  struct group_pmp_sqlite_vfs_ring_doorbell doorbell;
  struct group_pmp_sqlite_vfs_ring_ack ack = {0};
  uint64_t started;
  uint64_t ended;
  int ret;
  started = rdtime();
  if (prepare_request_batch(requests, count, reads, logical_offsets,
                            ring_slot, &doorbell) != 0)
    return -1;
  store_stats.pipeline.request_prepare_ticks += rdtime() - started;
  started = rdtime();
  publish_request_batch(&doorbell, started);
  ret = ocall(GROUP_PMP_SQLITE_VFS_OCALL_ID, &doorbell, sizeof(doorbell),
                &ack, sizeof(ack));
  ended = rdtime();
  store_batches[ring_slot].ack_ticks = ended;
  account_ring_submission(started, ended, count);
  if (ret != 0 || !ring_ack_valid(&doorbell, &ack)) {
    /* A failed boundary/ACK does not prove Host released the payload. */
    last_error = UINT64_C(2002);
    return -1;
  }
  account_submission_stages(ring_slot, started, ended);
  return 0;
}

static int submit_read_pair(
    struct group_pmp_sqlite_vfs_request* requests,
    const int* reads, const uint64_t* logical_offsets, uint64_t ring_slot) {
  struct group_pmp_sqlite_vfs_ring_pair_doorbell doorbell;
  struct group_pmp_sqlite_vfs_ring_pair_ack ack = {0};
  const uint64_t other = (ring_slot + UINT64_C(1)) %
      GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT;
  uint64_t started;
  uint64_t ended;
  int ret;
  started = rdtime();
  if (prepare_request_batch(requests, 1, reads, logical_offsets,
                            ring_slot, &doorbell.rings[0]) != 0)
    return -1;
  if (prepare_request_batch(requests + 1, 1, reads + 1, logical_offsets + 1,
                            other, &doorbell.rings[1]) != 0) {
    /* Neither producer was published, so the first preparation can unwind. */
    memset(&store_batches[ring_slot], 0, sizeof(store_batches[ring_slot]));
    return -1;
  }
  ended = rdtime();
  store_stats.pipeline.request_prepare_ticks += ended - started;
  started = ended;
  publish_request_batch(&doorbell.rings[0], started);
  publish_request_batch(&doorbell.rings[1], started);
  ret = ocall(GROUP_PMP_SQLITE_VFS_OCALL_ID, &doorbell, sizeof(doorbell),
                &ack, sizeof(ack));
  ended = rdtime();
  store_batches[ring_slot].ack_ticks = ended;
  store_batches[other].ack_ticks = ended;
  account_ring_submission(started, ended, 2);
  if (ret != 0 || !ring_ack_valid(&doorbell.rings[0], &ack.rings[0]) ||
      !ring_ack_valid(&doorbell.rings[1], &ack.rings[1])) {
    last_error = UINT64_C(2002);
    return -1;
  }
  /* Both rings share one doorbell and one resume; do not double-count. */
  account_submission_stages(ring_slot, started, ended);
  return 0;
}

static int transfer_range_batched(uint64_t first, uint64_t length, int read,
                                  uint64_t flags, uint64_t chunk,
                                  uint64_t* digest) {
  uint64_t done = 0;
  uint64_t next_slot = 0;
  const int planned = intent_lookahead && flags == GROUP_PMP_SQLITE_STORE_MEASURED &&
      first % chunk == 0;
  uint64_t plan_count = 0, plan_cursor = 0, plan_first = 0, plan_length = 0;
  uint64_t plan_sequence = 0;
  /* 100 KB buffered requests are exact AES-block-aligned payloads: twenty
   * fit in 2 MB. Their lengths are already ineligible for 4 KiB O_DIRECT.
   * Random 4 KiB descriptors retain their page-aligned packing and batching. */
  const uint64_t request_stride =
      chunk >= GROUP_PMP_SQLITE_LARGE_VALUE_BYTES ? chunk :
      (chunk + UINT64_C(4095)) & ~UINT64_C(4095);
  uint64_t max_batch =
      (chunk == GROUP_PMP_SQLITE_VFS_BUFFER_BYTES ? UINT64_C(1) :
       request_stride ?
       GROUP_PMP_SQLITE_VFS_BUFFER_BYTES / request_stride : 0);

  if (max_batch > GROUP_PMP_SQLITE_VFS_BATCH_MAX)
    max_batch = GROUP_PMP_SQLITE_VFS_BATCH_MAX;
  // Small security inputs must exercise both slots and reuse, even at N=4.
  if (security_phase_enabled && max_batch > GROUP_PMP_SECURITY_BATCH_REQUESTS)
    max_batch = GROUP_PMP_SECURITY_BATCH_REQUESTS;
  if (!max_batch)
    return -1;

  while (done < length) {
    struct group_pmp_sqlite_vfs_request* requests =
        store_request_workspace;
    int* reads = store_read_workspace;
    uint64_t* logical_offsets = store_logical_offset_workspace;
    uint64_t* amounts = store_amount_workspace;
    uint64_t count = 0;
    uint64_t batch_bytes = 0;
    uint64_t index;
    uint64_t ring_slot;
    uint64_t prepare_count;
    uint64_t refill_diagnostic = 0;
    int pair;

    {
      uint64_t preferred = next_slot % GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT;
      uint64_t alternate =
          (preferred + UINT64_C(1)) % GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT;

      /* Reuse a locally visible completed slot before blocking on the
       * preferred slot. Host release-publishes all statuses before the ring
       * completion counter, so the acquire load also makes descriptors safe
       * to consume without a second OCALL. */
      if (store_batches[preferred].pending &&
          (!store_batches[alternate].pending ||
           (!batch_completion_ready(preferred) && batch_completion_ready(alternate))))
        preferred = alternate;
      ring_slot = preferred;
      if (wait_batch_selected(&ring_slot, digest, 1) != 0)
        return -1;
      next_slot = ring_slot + UINT64_C(1);
    }

    if (planned && plan_cursor == plan_count) {
      uint64_t limit = GROUP_PMP_SQLITE_INTENT_WINDOW_BYTES / chunk;
      if (limit > GROUP_PMP_SQLITE_INTENT_MAX) limit = GROUP_PMP_SQLITE_INTENT_MAX;
      plan_first = first + done;
      plan_length = length - done;
      plan_count = (plan_length + chunk - 1) / chunk;
      if (plan_count > limit) plan_count = limit;
      if (plan_length > plan_count * chunk) plan_length = plan_count * chunk;
      plan_cursor = 0;
      plan_sequence = next_sequence;
      if (prepare_intent_window(plan_first, plan_length, chunk, ring_slot,
                                 plan_count, read) != 0)
        return -1;
    }

    /* Pair only chunks already in this range and only free buffers. Never
     * reap or wait for the peer just to coalesce a refill. */
    pair = paired_reads && read &&
        store_config.workload == GROUP_PMP_SQLITE_READSEQ &&
        chunk == group_pmp_sqlite_io_chunk(GROUP_PMP_SQLITE_READSEQ,
                                            store_config.direct_layout) &&
        !store_batches[0].pending && !store_batches[1].pending &&
        !store_buffers[0].pending && !store_buffers[1].pending &&
        length - done > chunk - (first + done) % chunk;
    prepare_count = pair ? UINT64_C(2) : max_batch;
    if (read && store_config.workload == GROUP_PMP_SQLITE_READSEQ) {
      const uint64_t peer = (ring_slot + UINT64_C(1)) %
          GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT;
      /* A completed peer still owns ciphertext until wait_batch decrypts it.
       * Do not consume that peer or defer this free buffer to manufacture a
       * pair: that would serialize two AES chunks ahead of the next read. */
      refill_diagnostic = !done ? GROUP_PMP_SQLITE_READSEQ_INITIAL :
          !store_batches[peer].pending ? GROUP_PMP_SQLITE_READSEQ_PEER_IDLE :
          batch_completion_ready(peer) ? GROUP_PMP_SQLITE_READSEQ_PEER_READY :
          GROUP_PMP_SQLITE_READSEQ_PEER_IO;
    }
    memset(requests, 0, prepare_count * sizeof(requests[0]));
    while (done + batch_bytes < length && count < prepare_count &&
           (!planned || plan_cursor < plan_count)) {
      struct group_pmp_sqlite_vfs_request* request = &requests[count];
      uint64_t logical_offset = planned ?
          plan_first + (uint64_t)intent_order[plan_cursor] * chunk : first + done + batch_bytes;
      uint64_t within_chunk = logical_offset % chunk;
      uint64_t amount = planned ? first + length - logical_offset : length - done - batch_bytes;
      uint64_t available = chunk - within_chunk;
      uint64_t buffer_id = pair ? (ring_slot + count) % GROUP_PMP_SQLITE_VFS_BUFFER_COUNT :
          ring_slot;
      uintptr_t packed_offset;
      uint8_t* cipher;

      if (amount > available)
        amount = available;
      /* Ciphertext stays in its owning UTM buffer; decrypt writes directly
       * into private EPM, without a Host or EAPP staging copy. */
      packed_offset = pair ?
          buffer_offset(buffer_id) :
          packed_buffer_offset(ring_slot, count, request_stride);
      if (!amount || amount > chunk || (amount & UINT64_C(15)) != 0 ||
          !packed_offset)
        return -1;
      cipher = direct_utm_pointer(packed_offset, amount);
      if (!cipher)
        return -1;
      request->operation = read ? GROUP_PMP_SQLITE_VFS_OP_READ :
                                  GROUP_PMP_SQLITE_VFS_OP_WRITE;
      request->file_id = store_config.workload;
      request->buffer_id = buffer_id;
      request->buffer_offset = packed_offset;
      request->length = amount;
      request->file_offset =
          extent_file_offset(logical_offset);
      request->logical_size = store_task_bytes;
      request->sequence = read ? logical_offset / chunk + UINT64_C(1) :
          planned ? plan_sequence + intent_order[plan_cursor] + 1 : next_sequence + 1;
      if (!read) ++next_sequence;
      request->task_id = logical_offset / chunk + UINT64_C(1);
      request->reserved[0] = flags | refill_diagnostic;
      request->reserved[1] = logical_offset;
      if (done == 0 && count == 0)
        request->reserved[0] |= GROUP_PMP_SQLITE_STORE_TXN_BEGIN;
      if (done + batch_bytes + amount == length)
        request->reserved[0] |= GROUP_PMP_SQLITE_STORE_TXN_END;
      if (!read) {
#ifdef GROUP_PMP_KV_WORKER
        if (kv_prepare_put(logical_offset, amount, flags)) return -1;
#else
        copy_template(plain_scratch, logical_offset, amount);
#endif
        if (transform_measured(GROUP_PMP_CRYPTO_ENCRYPT, plain_scratch,
                                cipher, (size_t)amount, logical_offset,
                                request->sequence, request->tag, 0, 0) != 0)
          return -1;
        security_phase(SECURITY_PHASE_ENCRYPTED);
      }
      reads[count] = read;
      logical_offsets[count] = logical_offset;
      amounts[count] = amount;
      batch_bytes += amount;
      ++count;
      if (planned) ++plan_cursor;
    }
    __sync_synchronize();
    if (pair) {
      if (submit_read_pair(requests, reads, logical_offsets, ring_slot) != 0)
        return -1;
      next_slot = ring_slot;
    } else if (submit_request_batch(requests, count, reads, logical_offsets,
                                    ring_slot) != 0) {
      return -1;
    }
    security_phase(SECURITY_PHASE_INFLIGHT);
    if (!read) {
      for (index = 0; index < count; ++index) {
        store_stats.write_bytes += amounts[index];
        if (digest && !planned) {
          *digest ^= requests[index].task_id + requests[index].sequence +
              amounts[index];
          *digest *= UINT64_C(1099511628211);
        }
      }
    }
    done += batch_bytes;
    if (planned && !read && digest && plan_cursor == plan_count) {
      // Preserve the baseline logical-order digest despite independent execution order.
      for (uint64_t i = 0; i < plan_count; ++i) {
        const uint64_t remaining = plan_length - i * chunk;
        *digest ^= (plan_first / chunk + i + 1) + (plan_sequence + i + 1) +
            (remaining < chunk ? remaining : chunk);
        *digest *= UINT64_C(1099511628211);
      }
    }
  }
  // At the tail, consume an already completed peer before blocking on slot 0.
  // Do not let a fixed drain order leave useful decrypt work idle behind I/O.
  for (uint64_t drained = 0; drained < GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT;
       ++drained) {
    next_slot = !store_batches[0].pending ||
        (!batch_completion_ready(0) && store_batches[1].pending &&
         batch_completion_ready(1)) ? 1 : 0;
    if (wait_batch_selected(&next_slot, digest, 1) != 0)
      return -1;
  }
  return 0;
}

static int transfer_range(uint64_t first, uint64_t length, int read,
                          uint64_t flags, uint64_t* digest) {
  uint64_t done = 0;
  uint64_t chunk = chunk_bytes();

  if (chunk)
    return transfer_range_batched(first, length, read, flags, chunk, digest);

  while (done < length) {
    struct group_pmp_sqlite_vfs_request request;
    uint64_t amount = length - done;
    uint64_t logical_offset = first + done;
    uint64_t within_chunk;
    uint64_t chunk_remaining;
    uint64_t buffer_id;
    uint8_t* cipher;

    if (!chunk || acquire_buffer(&buffer_id, digest) != 0)
      return -1;
    within_chunk = logical_offset % chunk;
    chunk_remaining = chunk - within_chunk;
    if (amount > chunk_remaining)
      amount = chunk_remaining;
    if (!amount || amount > GROUP_PMP_SQLITE_VFS_BUFFER_BYTES ||
        (amount & UINT64_C(15)) != 0)
      return -1;
    memset(&request, 0, sizeof(request));
    request.operation = read ? GROUP_PMP_SQLITE_VFS_OP_READ :
                               GROUP_PMP_SQLITE_VFS_OP_WRITE;
    request.file_id = store_config.workload;
    request.file_offset =
        extent_file_offset(logical_offset);
    request.logical_size = store_task_bytes;
    request.length = amount;
    request.sequence = read ? logical_offset / chunk + UINT64_C(1) :
                              ++next_sequence;
    request.task_id = logical_offset / chunk + UINT64_C(1);
    request.reserved[0] = flags;
    request.reserved[1] = logical_offset;
    if (done == 0)
      request.reserved[0] |= GROUP_PMP_SQLITE_STORE_TXN_BEGIN;
    if (done + amount == length)
      request.reserved[0] |= GROUP_PMP_SQLITE_STORE_TXN_END;
    cipher = direct_utm_pointer(buffer_offset(buffer_id), amount);
    if (!cipher)
      return -1;
    if (!read) {
#ifdef GROUP_PMP_KV_WORKER
      if (kv_prepare_put(logical_offset, amount, flags)) return -1;
#else
      copy_template(plain_scratch, logical_offset, amount);
#endif
      if (transform_measured(GROUP_PMP_CRYPTO_ENCRYPT, plain_scratch,
                              cipher, (size_t)amount, logical_offset,
                              request.sequence, request.tag, 0, 0) != 0)
        return -1;
      security_phase(SECURITY_PHASE_ENCRYPTED);
    }
    __sync_synchronize();
    if (submit_request(&request, buffer_id, read, logical_offset, digest) != 0)
      return -1;
    if (!read) {
      store_stats.write_bytes += amount;
      if (digest) {
        *digest ^= request.task_id + request.sequence + amount;
        *digest *= UINT64_C(1099511628211);
      }
    }
    done += amount;
  }
  return wait_all(digest);
}

static int submit_control(uint64_t operation) {
  struct group_pmp_sqlite_vfs_request request;
  uint64_t digest = 0;
  uint64_t buffer_id;
  memset(&request, 0, sizeof(request));
  request.operation = operation;
  request.length = 0;
  request.sequence = ++next_sequence;
  memset(request.tag, 0, sizeof(request.tag));
  if (acquire_buffer(&buffer_id, &digest) != 0 ||
      submit_request(&request, buffer_id, 0, 0, &digest) != 0)
    return -1;
  return wait_all(&digest);
}

int keystone_enclave_store_configure(
    const struct group_pmp_sqlite_vfs_config* config, uint64_t task_bytes) {
  uint64_t index;
  uint64_t file_alignment;
  uint64_t padded_task_bytes;
  security_phase_enabled = 0;
  system_trace_enabled = 0;
  memset(&security_phase_state, 0, sizeof(security_phase_state));
  if (store_marker[0] != 'k' || store_direct_utm_marker[0] != 'k' ||
      store_batched_random_read_marker[0] != 'k' ||
      store_exact_io_granularity_marker[0] != 'k' ||
      store_descriptor_batch_marker[0] != 'k' ||
      store_effective_batch_marker[0] != 'k' ||
      store_status_commit_marker[0] != 'k' ||
      store_crypto_timing_marker[0] != 'k' ||
      store_blocking_pipeline_marker[0] != 'k' ||
      store_batch_ocall_marker[0] != 'k' ||
      store_central_io_marker[0] != 'k' ||
      store_vfs_abi_marker[0] != 'k' ||
      store_double_buffer_marker[0] != 'k' ||
      !config || !config->run_id || config->cipher_algorithm > BENCHMARK_CHACHA_POLY ||
      !config->worker_count || config->worker_index >= config->worker_count ||
      !task_bytes ||
      task_bytes > GROUP_PMP_SQLITE_VFS_WORKER_FILE_STRIDE -
                       GROUP_PMP_SQLITE_VFS_BUFFER_BYTES ||
      (task_bytes & UINT64_C(15)) != 0)
    return -1;
  file_alignment = config->direct_layout || group_pmp_sqlite_page_random(config->workload) ?
      UINT64_C(4096) : UINT64_C(16);
  padded_task_bytes = group_pmp_sqlite_file_span(config->workload,
      task_bytes, config->direct_layout);
  if (!padded_task_bytes || padded_task_bytes > INT64_MAX ||
      config->file_base % file_alignment != 0 ||
      config->file_base > INT64_MAX - padded_task_bytes)
    return -1;
  memset(&direct_utm, 0, sizeof(direct_utm));
  if (utm_query_direct(&direct_utm, sizeof(direct_utm)) != 0 ||
      direct_utm.abi_version != KEYSTONE_UTM_DIRECT_ABI_VERSION ||
      direct_utm.struct_size != sizeof(direct_utm) ||
      direct_utm.data_utm_offset != GROUP_PMP_SQLITE_VFS_CONTROL_BYTES ||
      (direct_utm.data_va & UINT64_C(63)) != 0 ||
      direct_utm.data_size < GROUP_PMP_SQLITE_VFS_UTM_BYTES -
                                 GROUP_PMP_SQLITE_VFS_CONTROL_BYTES ||
      !direct_utm_pointer(GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET,
                          GROUP_PMP_SQLITE_VFS_BUFFER_BYTES) ||
      !direct_utm_pointer(GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET,
                          GROUP_PMP_SQLITE_VFS_BUFFER_BYTES) ||
      !direct_utm_pointer(GROUP_PMP_SQLITE_VFS_RING_OFFSET,
                          GROUP_PMP_SQLITE_VFS_RING_BYTES))
    return -1;
  store_config = *config;
  store_task_bytes = task_bytes;
  packed_tail_index = packed_tail_gap = 0;
  if (!config->direct_layout && task_bytes % chunk_bytes()) {
    packed_tail_index = extent_key(task_bytes - task_bytes % chunk_bytes());
    packed_tail_gap = chunk_bytes() - task_bytes % chunk_bytes();
  }
  for (index = 0; index < STORE_TEMPLATE_BYTES; ++index)
    plain_template[index] = group_pmp_sqlite_value_byte(
        config->worker_index + UINT64_C(1), index);
  if (config->cipher_algorithm == BENCHMARK_AES_ECB) {
    if (group_pmp_crypto_init(&crypto_context,
                            GROUP_PMP_CRYPTO_AES_128_ECB,
                            config->aes128_key, 16) != 0 ||
      group_pmp_crypto_self_test(&crypto_context) != 0)
      return -1;
  } else if (initialize_aead((unsigned)config->cipher_algorithm) != 0) {
    return -1;
  }
  memset(&store_stats, 0, sizeof(store_stats));
  memset(store_buffers, 0, sizeof(store_buffers));
  memset(store_batches, 0, sizeof(store_batches));
  memset(buffer_consumed_ticks, 0, sizeof(buffer_consumed_ticks));
  next_request_id = 0;
  next_sequence = 0;
  next_ring_generation = 0;
  last_error = 0;
  paired_reads = 0;
  intent_lookahead = 0;
  configured = 1;
  /* Host owns release-publication in the direct-mapped UTM completion ring. */
  return 0;
}

int keystone_enclave_store_set_security_sentinel(uint64_t nonce) {
  uint8_t marker[GROUP_PMP_SECURITY_SENTINEL_BYTES];
  uint64_t offset;
  if (!configured || !nonce) return -1;
  security_phase_enabled = 1;
  group_pmp_security_sentinel(nonce, marker);
  for (offset = 0; offset + sizeof(marker) <= STORE_TEMPLATE_BYTES; offset += 4096)
    memcpy(plain_template + offset, marker, sizeof(marker));
  memset(marker, 0, sizeof(marker));
  return 0;
}

int keystone_enclave_store_set_paired_reads(int enabled) {
  if (!configured)
    return -1;
  paired_reads = enabled && store_config.workload == GROUP_PMP_SQLITE_READSEQ;
  return 0;
}

int keystone_enclave_store_set_intent_lookahead(int enabled) {
  if (!configured) return -1;
  intent_lookahead = 0;
  return enabled ? -1 : 0;
}

int keystone_enclave_store_prepare(void) {
  uint64_t digest = UINT64_C(1469598103934665603);
  if (!configured || submit_control(GROUP_PMP_SQLITE_VFS_OP_RESET) != 0)
    return -1;
  if ((group_pmp_sqlite_is_read(store_config.workload) ||
       store_config.workload == GROUP_PMP_SQLITE_OVERWRITE) &&
      transfer_range(0, store_task_bytes, 0,
                     GROUP_PMP_SQLITE_STORE_PREFILL, &digest) != 0)
    return -1;
  return submit_control(GROUP_PMP_SQLITE_VFS_OP_SYNC);
}

int keystone_enclave_store_begin_measurement(void) {
  if (!configured || wait_all(NULL) != 0)
    return -1;
#ifdef GROUP_PMP_KV_WORKER
  memset(&kv_stats, 0, sizeof(kv_stats));
  kv_stats.magic = KV_RESULT_MAGIC;
  kv_stats.version = 1;
  kv_stats.workload = store_config.workload;
#endif
  memset(&store_stats, 0, sizeof(store_stats));
  memset(buffer_consumed_ticks, 0, sizeof(buffer_consumed_ticks));
  last_error = 0;
  return 0;
}

int keystone_enclave_store_execute(
    const struct group_pmp_sqlite_packet_header* header, uint64_t* digest) {
  uint64_t first;
  if (!configured || !header || header->workload != store_config.workload ||
      header->logical_bytes != header->record_count * header->value_size)
    return -1;
  first = header->first_record * header->value_size;
  if (first > store_task_bytes ||
      header->logical_bytes > store_task_bytes - first)
    return -1;
  return transfer_range(first, header->logical_bytes,
                        group_pmp_sqlite_is_read(store_config.workload),
                        GROUP_PMP_SQLITE_STORE_MEASURED, digest);
}

int keystone_enclave_store_set_system_trace(int enabled) {
  if (!configured || (enabled && store_config.workload != GROUP_PMP_SQLITE_READSEQ)) return -1;
  memset(&system_trace,0,sizeof(system_trace));
  system_trace.magic=MOT_SYSTEM_TRACE_MAGIC; system_trace.version=1;
  system_trace_enabled=enabled;
  return system_trace_marker[0]=='k' ? 0 : -1;
}

int keystone_enclave_store_publish_system_trace(void) {
  if (!system_trace_enabled) return 0;
  if (system_trace.dropped || !system_trace.count ||
      store_batches[0].pending || store_batches[1].pending) return -1;
  /* All ciphertext has been consumed and drained. Reuse the now-free data
   * buffer only after the real workload; never change its request protocol. */
  return copy_to_shared_utm(GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET,&system_trace,
      sizeof(system_trace));
}

int keystone_enclave_store_sync(void) {
  return configured && wait_all(NULL) == 0 ?
      submit_control(GROUP_PMP_SQLITE_VFS_OP_SYNC) : -1;
}

void keystone_enclave_store_get_stats(
    struct group_pmp_sqlite_vfs_stats* stats) {
  if (stats)
    *stats = store_stats;
}

uint64_t keystone_enclave_store_last_error(void) {
  return last_error;
}

void keystone_enclave_store_destroy(void) {
  system_trace_enabled = 0;
  security_phase(SECURITY_PHASE_EXIT);
  security_phase_enabled = 0;
  group_pmp_crypto_deinit(&crypto_context);
  benchmark_aead_free();
  wipe_private(plain_scratch, sizeof(plain_scratch));
  wipe_private(cipher_snapshot, sizeof(cipher_snapshot));
  memset(&direct_utm, 0, sizeof(direct_utm));
  configured = 0;
  paired_reads = 0;
  intent_lookahead = 0;
}
