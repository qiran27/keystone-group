#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes_core.h"
#include "app/syscall.h"
#include "group-pmp-sqlite-shared.h"
#include "keystone_enclave_vfs.h"

#define KEYSTONE_VFS_MAX_FILES 4
#define KEYSTONE_VFS_MAX_PATH 96
#define KEYSTONE_VFS_RANDOM_CACHE_BYTES UINT64_C(65536)
#define KEYSTONE_VFS_MAX_DATABASE_BYTES UINT64_C(1000000000)
#define KEYSTONE_VFS_MAX_AUTH_BLOCKS \
  ((KEYSTONE_VFS_MAX_DATABASE_BYTES + KEYSTONE_VFS_RANDOM_CACHE_BYTES - 1) / \
   KEYSTONE_VFS_RANDOM_CACHE_BYTES)

struct keystone_async_storage {
  int used;
  int refs;
  char name[KEYSTONE_VFS_MAX_PATH];
  uint64_t file_id;
  sqlite3_int64 size;
  sqlite3_int64 cache_base;
  uint64_t cache_length;
  uint32_t authenticated_length[KEYSTONE_VFS_MAX_AUTH_BLOCKS];
  uint32_t valid_length[KEYSTONE_VFS_MAX_AUTH_BLOCKS];
  uint64_t authenticated_sequence[KEYSTONE_VFS_MAX_AUTH_BLOCKS];
  int cache_valid;
  int cache_dirty;
};

struct keystone_async_file {
  sqlite3_file base;
  struct keystone_async_storage* storage;
  int delete_on_close;
};

struct keystone_async_buffer {
  uint64_t request_id;
  int pending;
  int detached;
};

static const char async_vfs_artifact_marker[] __attribute__((used)) =
    GROUP_PMP_SQLITE_ASYNC_VFS_MARKER;
static const char vfs_perf_window_artifact_marker[] __attribute__((used)) =
    KEYSTONE_SQLITE_VFS_PERF_WINDOW_MARKER;
static const char vfs_growing_block_artifact_marker[] __attribute__((used)) =
    "keystone-sqlite-vfs-growing-block-v3";
static const char vfs_solo_wait_artifact_marker[] __attribute__((used)) =
    "keystone-sqlite-vfs-event-wait-v2";
static const char vfs_adaptive_cache_artifact_marker[] __attribute__((used)) =
    "keystone-sqlite-vfs-adaptive-cache-v1";
static const char vfs_sparse_auth_map_artifact_marker[]
    __attribute__((used)) = "keystone-sqlite-vfs-sparse-auth-map-v1";
static const char vfs_rmw_drain_artifact_marker[]
    __attribute__((used)) = "keystone-sqlite-vfs-rmw-drain-v1";
static const char vfs_double_buffer_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_DOUBLE_BUFFER_MARKER;
static struct keystone_async_storage files[KEYSTONE_VFS_MAX_FILES];
static struct keystone_async_buffer buffers[GROUP_PMP_SQLITE_VFS_BUFFER_COUNT];
static struct group_pmp_sqlite_vfs_config vfs_config;
static struct group_pmp_sqlite_vfs_stats vfs_stats;
static sqlite3_vfs enclave_vfs;
static uint8_t* cache_data;
static uint8_t* cipher_data;
static struct keystone_async_storage* cache_owner;
static void* encrypt_context;
static void* decrypt_context;
static uint64_t next_request_id;
static uint64_t next_sequence;
static uint64_t last_error;
static uint64_t random_state = UINT64_C(0x9e3779b97f4a7c15);
static int configured;

static uint64_t cache_span_bytes(void) {
  return group_pmp_sqlite_is_random(vfs_config.workload) ?
      KEYSTONE_VFS_RANDOM_CACHE_BYTES :
      GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
}

static int cache_block_index(sqlite3_int64 base, uint64_t cache_span,
                             uint64_t* output) {
  uint64_t index;
  if (!output || base < 0 || !cache_span ||
      ((uint64_t)base % cache_span) != 0 ||
      (uint64_t)base >= KEYSTONE_VFS_MAX_DATABASE_BYTES)
    return -1;
  index = (uint64_t)base / cache_span;
  if (index >= KEYSTONE_VFS_MAX_AUTH_BLOCKS)
    return -1;
  *output = index;
  return 0;
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

static uint64_t buffer_offset(uint64_t buffer_id) {
  return buffer_id ? GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET :
                     GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
}

static uintptr_t status_offset(uint64_t buffer_id) {
  return (uintptr_t)(GROUP_PMP_SQLITE_VFS_STATUS_OFFSET +
      buffer_id * sizeof(struct group_pmp_sqlite_vfs_status));
}

static int name_equal(const char* left, const char* right) {
  while (*left && *left == *right) {
    ++left;
    ++right;
  }
  return *left == *right;
}

static size_t name_length(const char* name) {
  size_t length = 0;
  while (name[length])
    ++length;
  return length;
}

static void name_copy(char* output, size_t capacity, const char* input) {
  size_t index = 0;
  if (!capacity)
    return;
  while (index + 1 < capacity && input[index]) {
    output[index] = input[index];
    ++index;
  }
  output[index] = 0;
}

static uint64_t name_hash(const char* name) {
  uint64_t value = UINT64_C(1469598103934665603);
  while (*name) {
    value ^= (uint8_t)*name++;
    value *= UINT64_C(1099511628211);
  }
  return value ? value : UINT64_C(1);
}

static void encode_u64(uint8_t output[8], uint64_t value) {
  unsigned int index;
  for (index = 0; index < 8; ++index)
    output[index] = (uint8_t)(value >> (index * 8));
}

/* The benchmark deliberately uses the project's existing AES-128-ECB core.
 * SQLite is fixed to 4 KiB pages, so every encrypted disk range is a whole
 * number of AES blocks. */
static int crypt_range(uint64_t file_offset, const uint8_t* input,
                       uint8_t* output, size_t length, int decrypt) {
  size_t done = 0;

  if ((file_offset & UINT64_C(15)) || (length & 15))
    return -1;
  while (done < length) {
    if (decrypt)
      aes_decrypt(decrypt_context, input + done, output + done);
    else
      aes_encrypt(encrypt_context, input + done, output + done);
    done += 16;
  }
  return 0;
}

static void tag_block(uint8_t state[16], const uint8_t input[16]) {
  uint8_t block[16];
  unsigned int index;
  for (index = 0; index < sizeof(block); ++index)
    block[index] = state[index] ^ input[index];
  aes_encrypt(encrypt_context, block, state);
  memset(block, 0, sizeof(block));
}

static void compute_tag(uint64_t file_id, uint64_t file_offset,
                        uint64_t length, uint64_t sequence,
                        const uint8_t* ciphertext, uint8_t output[16]) {
  uint8_t state[16] = {0};
  uint8_t block[16] = {0};
  size_t done = 0;

  encode_u64(block, file_id);
  encode_u64(block + 8, file_offset);
  tag_block(state, block);
  encode_u64(block, length);
  encode_u64(block + 8, sequence);
  tag_block(state, block);
  while (done + sizeof(block) <= length) {
    tag_block(state, ciphertext + done);
    done += sizeof(block);
  }
  memset(block, 0, sizeof(block));
  if (done < length)
    memcpy(block, ciphertext + done, length - done);
  block[length - done] = 0x80;
  tag_block(state, block);
  memcpy(output, state, sizeof(state));
  memset(state, 0, sizeof(state));
  memset(block, 0, sizeof(block));
}

static int tag_equal(const uint8_t left[16], const uint8_t right[16]) {
  uint8_t difference = 0;
  unsigned int index;
  for (index = 0; index < 16; ++index)
    difference |= left[index] ^ right[index];
  return difference == 0;
}

static int wait_buffer(uint64_t buffer_id,
                       struct group_pmp_sqlite_vfs_status* output) {
  struct group_pmp_sqlite_vfs_wait wait_request;
  struct group_pmp_sqlite_vfs_ack ack;
  struct group_pmp_sqlite_vfs_status status;
  uint64_t started = rdtime();
  if (buffer_id >= GROUP_PMP_SQLITE_VFS_BUFFER_COUNT) {
    last_error = UINT64_C(1001);
    return -1;
  }
  if (!buffers[buffer_id].pending) {
    if (output)
      memset(output, 0, sizeof(*output));
    return 0;
  }
  ++vfs_stats.wait_count;
  if (copy_from_shared(&status, status_offset(buffer_id),
                       sizeof(status)) != 0) {
    last_error = UINT64_C(1002);
    return -1;
  }
  __sync_synchronize();
  /* Submit-only requests deliberately return while storage is pending. Bind
   * this explicit wait OCALL to the saved Host completion object so the SM
   * transitions this member to BLOCKED and immediately schedules a lane peer.
   * No status polling or cooperative yield is used. */
  if (buffers[buffer_id].detached) {
    memset(&wait_request, 0, sizeof(wait_request));
    memset(&ack, 0, sizeof(ack));
    wait_request.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    wait_request.version = GROUP_PMP_SQLITE_VFS_VERSION;
    wait_request.run_id = vfs_config.run_id;
    wait_request.worker_index = vfs_config.worker_index;
    wait_request.request_id = buffers[buffer_id].request_id;
    wait_request.buffer_id = buffer_id;
    ++vfs_stats.blocked_completion_count;
    if (ocall(GROUP_PMP_SQLITE_VFS_OCALL_ID, &wait_request,
              sizeof(wait_request), &ack, sizeof(ack)) != 0 ||
        ack.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
        ack.version != GROUP_PMP_SQLITE_VFS_VERSION ||
        ack.request_id != wait_request.request_id || ack.status != 0) {
      last_error = UINT64_C(1004);
      return -1;
    }
    vfs_stats.ocall_ticks += rdtime() - started;
    if (copy_from_shared(&status, status_offset(buffer_id),
                         sizeof(status)) != 0) {
      last_error = UINT64_C(1005);
      return -1;
    }
    __sync_synchronize();
  }
  if (status.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
      status.version != GROUP_PMP_SQLITE_VFS_VERSION ||
      status.request_id != buffers[buffer_id].request_id ||
      status.state == GROUP_PMP_SQLITE_VFS_STATE_PENDING) {
    last_error = UINT64_C(1003);
    return -1;
  }
  vfs_stats.wait_ticks += rdtime() - started;
  buffers[buffer_id].pending = 0;
  buffers[buffer_id].detached = 0;
  if (output)
    *output = status;
  if (status.state != GROUP_PMP_SQLITE_VFS_STATE_DONE || status.result != 0) {
    last_error = UINT64_C(1100000) +
        (uint64_t)(status.result < 0 ? -status.result : status.result);
    return -1;
  }
  return 0;
}

static int acquire_buffer(uint64_t* output) {
  uint64_t index;
  for (index = 0; index < GROUP_PMP_SQLITE_VFS_BUFFER_COUNT; ++index)
    if (!buffers[index].pending) {
      *output = index;
      return 0;
    }
  if (wait_buffer(0, NULL) != 0)
    return -1;
  *output = 0;
  return 0;
}

static int submit_request(struct group_pmp_sqlite_vfs_request* request,
                          const uint8_t* write_data, int wait,
                          struct group_pmp_sqlite_vfs_status* completion) {
  struct group_pmp_sqlite_vfs_status status;
  struct group_pmp_sqlite_vfs_ack ack;
  uint64_t buffer_id;
  uint64_t started;

  if (!configured || !request) {
    last_error = UINT64_C(2001);
    return -1;
  }
  if (acquire_buffer(&buffer_id) != 0) {
    if (!last_error)
      last_error = UINT64_C(2002);
    return -1;
  }
  memset(&status, 0, sizeof(status));
  memset(&ack, 0, sizeof(ack));
  request->magic = GROUP_PMP_SQLITE_VFS_MAGIC;
  request->version = GROUP_PMP_SQLITE_VFS_VERSION;
  request->request_id = ++next_request_id;
  request->run_id = vfs_config.run_id;
  request->worker_index = vfs_config.worker_index;
  request->worker_count = vfs_config.worker_count;
  request->workload = vfs_config.workload;
  request->buffer_id = buffer_id;
  request->buffer_offset = buffer_offset(buffer_id);
  request->reserved[0] |= wait ?
      GROUP_PMP_SQLITE_STORE_BLOCK_ON_COMPLETE :
      GROUP_PMP_SQLITE_STORE_SUBMIT_ONLY;
  if (request->length > GROUP_PMP_SQLITE_VFS_BUFFER_BYTES) {
    last_error = UINT64_C(2003);
    return -1;
  }
  if (write_data && request->length &&
      copy_to_shared_utm((uintptr_t)request->buffer_offset, write_data,
                         (size_t)request->length) != 0) {
    last_error = UINT64_C(2004);
    return -1;
  }
  status.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
  status.version = GROUP_PMP_SQLITE_VFS_VERSION;
  status.request_id = request->request_id;
  status.state = GROUP_PMP_SQLITE_VFS_STATE_PENDING;
  if (copy_to_shared_utm(status_offset(buffer_id), &status,
                         sizeof(status)) != 0) {
    last_error = UINT64_C(2005);
    return -1;
  }
  __sync_synchronize();
  started = rdtime();
  if (ocall(GROUP_PMP_SQLITE_VFS_OCALL_ID, request, sizeof(*request),
            &ack, sizeof(ack)) != 0 ||
      ack.magic != GROUP_PMP_SQLITE_VFS_MAGIC ||
      ack.version != GROUP_PMP_SQLITE_VFS_VERSION ||
      ack.request_id != request->request_id || ack.status != 0) {
    last_error = UINT64_C(2006);
    return -1;
  }
  vfs_stats.ocall_ticks += rdtime() - started;
  ++vfs_stats.submit_count;
  ++vfs_stats.batch_submit_count;
  buffers[buffer_id].request_id = request->request_id;
  buffers[buffer_id].pending = 1;
  buffers[buffer_id].detached = wait ? 0 : 1;
  {
    uint64_t index;
    uint64_t pending = 0;
    for (index = 0; index < GROUP_PMP_SQLITE_VFS_BUFFER_COUNT; ++index)
      if (buffers[index].pending)
        pending++;
    if (vfs_stats.queue_depth_peak < pending)
      vfs_stats.queue_depth_peak = pending;
  }
  if (!wait)
    return 0;
  ++vfs_stats.blocked_completion_count;
  return wait_buffer(buffer_id, completion);
}

static int wait_all(void) {
  uint64_t index;
  for (index = 0; index < GROUP_PMP_SQLITE_VFS_BUFFER_COUNT; ++index)
    if (wait_buffer(index, NULL) != 0)
      return -1;
  return 0;
}

static int submit_control(uint64_t operation, uint64_t file_id,
                          uint64_t offset, uint64_t size) {
  struct group_pmp_sqlite_vfs_request request;
  memset(&request, 0, sizeof(request));
  request.operation = operation;
  request.file_id = file_id;
  request.file_offset = offset;
  request.logical_size = size;
  return submit_request(&request, NULL, 1, NULL);
}

static struct keystone_async_storage* find_file(const char* name) {
  int index;
  for (index = 0; index < KEYSTONE_VFS_MAX_FILES; ++index)
    if (files[index].used && name_equal(files[index].name, name))
      return &files[index];
  return NULL;
}

static struct keystone_async_storage* create_file(const char* name) {
  int index;
  for (index = 0; index < KEYSTONE_VFS_MAX_FILES; ++index) {
    if (!files[index].used) {
      memset(&files[index], 0, sizeof(files[index]));
      files[index].used = 1;
      files[index].cache_base = -1;
      files[index].file_id = name_hash(name);
      name_copy(files[index].name, sizeof(files[index].name), name);
      return &files[index];
    }
  }
  return NULL;
}

static int flush_cache(struct keystone_async_storage* storage) {
  struct group_pmp_sqlite_vfs_request request;
  uint64_t started;
  uint64_t length;
  uint64_t cache_span = cache_span_bytes();
  uint64_t block_index;

  if (!storage || cache_owner != storage || !storage->cache_valid ||
      !storage->cache_dirty)
    return SQLITE_OK;
  if (storage->cache_base < 0 || storage->cache_base >= storage->size) {
    storage->cache_dirty = 0;
    return SQLITE_OK;
  }
  if (cache_block_index(storage->cache_base, cache_span, &block_index) != 0) {
    last_error = UINT64_C(3001);
    return SQLITE_FULL;
  }
  length = (uint64_t)(storage->size - storage->cache_base);
  if (length > cache_span)
    length = cache_span;
  started = rdcycle();
  if (crypt_range((uint64_t)storage->cache_base, cache_data, cipher_data,
                  (size_t)length, 0) != 0) {
    last_error = UINT64_C(3002);
    return SQLITE_IOERR_WRITE;
  }
  vfs_stats.encrypt_cycles += rdcycle() - started;
  memset(&request, 0, sizeof(request));
  request.operation = GROUP_PMP_SQLITE_VFS_OP_WRITE;
  request.file_id = storage->file_id;
  request.file_offset = (uint64_t)storage->cache_base;
  request.logical_size = (uint64_t)storage->size;
  request.length = length;
  request.sequence = ++next_sequence;
  compute_tag(request.file_id, request.file_offset, request.length,
              request.sequence, cipher_data, request.tag);
  if (submit_request(&request, cipher_data, 0, NULL) != 0) {
    if (!last_error)
      last_error = UINT64_C(3003);
    return SQLITE_IOERR_WRITE;
  }
  storage->authenticated_length[block_index] = (uint32_t)length;
  storage->valid_length[block_index] = (uint32_t)length;
  storage->authenticated_sequence[block_index] = request.sequence;
  storage->cache_dirty = 0;
  vfs_stats.write_bytes += length;
  return SQLITE_OK;
}

static int load_cache(struct keystone_async_storage* storage,
                      sqlite3_int64 base) {
  struct group_pmp_sqlite_vfs_request request;
  struct group_pmp_sqlite_vfs_status completion;
  uint8_t expected_tag[16];
  uint64_t started;
  uint64_t logical_length;
  uint64_t persisted_length;
  uint64_t cache_span = cache_span_bytes();
  uint64_t block_index;
  uint64_t valid_length;

  if (!storage || base < 0 ||
      cache_block_index(base, cache_span, &block_index) != 0) {
    last_error = UINT64_C(4001);
    return SQLITE_IOERR_READ;
  }
  if (cache_owner == storage && storage->cache_valid &&
      storage->cache_base == base)
    return SQLITE_OK;
  if (cache_owner) {
    if (flush_cache(cache_owner) != SQLITE_OK) {
      if (!last_error)
        last_error = UINT64_C(4002);
      return SQLITE_IOERR_WRITE;
    }
    cache_owner->cache_valid = 0;
    cache_owner->cache_dirty = 0;
  }
  cache_owner = storage;
  storage->cache_base = base;
  storage->cache_length = 0;
  storage->cache_valid = 1;
  storage->cache_dirty = 0;
  memset(cache_data, 0, (size_t)cache_span);
  if (base >= storage->size)
    return SQLITE_OK;
  logical_length = (uint64_t)(storage->size - base);
  if (logical_length > cache_span)
    logical_length = cache_span;
  storage->cache_length = logical_length;
  persisted_length = storage->authenticated_length[block_index];
  valid_length = storage->valid_length[block_index];
  if (!persisted_length)
    return SQLITE_OK;
  if (persisted_length > cache_span || valid_length > persisted_length ||
      !storage->authenticated_sequence[block_index]) {
    last_error = UINT64_C(4003);
    return SQLITE_IOERR_READ;
  }
  /*
   * Random SQLite writes are read-modify-write operations over one enclave
   * cache.  A block's trusted sequence is advanced when its encrypted WRITE
   * is submitted, while the host publishes that sequence only after pwrite
   * completes.  Drain both UTM buffers before issuing a dependent READ so the
   * disk/tag state and enclave metadata describe the same committed block.
   * Sequential writes that never reload a persisted block remain pipelined.
   */
  if (wait_all() != 0) {
    if (!last_error)
      last_error = UINT64_C(4008);
    return SQLITE_IOERR_READ;
  }
  memset(&request, 0, sizeof(request));
  request.operation = GROUP_PMP_SQLITE_VFS_OP_READ;
  request.file_id = storage->file_id;
  request.file_offset = (uint64_t)base;
  request.logical_size = (uint64_t)storage->size;
  request.length = persisted_length;
  if (submit_request(&request, NULL, 1, &completion) != 0) {
    if (!last_error)
      last_error = UINT64_C(4004);
    return SQLITE_IOERR_READ;
  }
  if (completion.length != persisted_length) {
    last_error = UINT64_C(4009);
    return SQLITE_IOERR_READ;
  }
  if (completion.length & UINT64_C(15)) {
    last_error = UINT64_C(4010);
    return SQLITE_IOERR_READ;
  }
  if (completion.sequence !=
      storage->authenticated_sequence[block_index]) {
    last_error = UINT64_C(4011);
    return SQLITE_IOERR_READ;
  }
  if (copy_from_shared(cipher_data, (uintptr_t)request.buffer_offset,
                       (size_t)completion.length) != 0) {
    last_error = UINT64_C(4005);
    return SQLITE_IOERR_READ;
  }
  compute_tag(request.file_id, request.file_offset, completion.length,
              completion.sequence, cipher_data, expected_tag);
  if (!tag_equal(expected_tag, completion.tag)) {
    last_error = UINT64_C(4006);
    memset(expected_tag, 0, sizeof(expected_tag));
    return SQLITE_IOERR_READ;
  }
  memset(expected_tag, 0, sizeof(expected_tag));
  started = rdcycle();
  if (crypt_range((uint64_t)base, cipher_data, cache_data,
                  (size_t)completion.length, 1) != 0) {
    last_error = UINT64_C(4007);
    return SQLITE_IOERR_READ;
  }
  /* A physical authenticated block may be longer than SQLite's current
   * logical EOF after xTruncate. Never expose the authenticated stale tail
   * if SQLite later grows the file sparsely. */
  if (valid_length > logical_length)
    valid_length = logical_length;
  if (completion.length > valid_length)
    memset(cache_data + valid_length, 0,
           (size_t)(completion.length - valid_length));
  vfs_stats.decrypt_cycles += rdcycle() - started;
  vfs_stats.read_bytes += completion.length;
  return SQLITE_OK;
}

static int async_close(sqlite3_file* file) {
  struct keystone_async_file* async = (struct keystone_async_file*)file;
  int result = SQLITE_OK;
  if (async->storage && flush_cache(async->storage) != SQLITE_OK)
    result = SQLITE_IOERR_WRITE;
  if (wait_all() != 0)
    result = SQLITE_IOERR_FSYNC;
  if (async->storage && async->storage->refs > 0)
    --async->storage->refs;
  if (async->storage && async->delete_on_close &&
      async->storage->refs == 0) {
    if (submit_control(GROUP_PMP_SQLITE_VFS_OP_DELETE,
                       async->storage->file_id, 0, 0) != 0)
      result = SQLITE_IOERR_DELETE;
    if (cache_owner == async->storage)
      cache_owner = NULL;
    memset(async->storage, 0, sizeof(*async->storage));
  }
  async->storage = NULL;
  return result;
}

static int async_read(sqlite3_file* file, void* output, int amount,
                      sqlite3_int64 offset) {
  struct keystone_async_file* async = (struct keystone_async_file*)file;
  uint8_t* destination = (uint8_t*)output;
  int remaining = amount;
  int short_read = 0;

  if (!async->storage || offset < 0 || amount < 0)
    return SQLITE_IOERR_READ;
  while (remaining > 0) {
    uint64_t cache_span = cache_span_bytes();
    sqlite3_int64 base = (offset / (sqlite3_int64)cache_span) *
        (sqlite3_int64)cache_span;
    uint64_t within = (uint64_t)(offset - base);
    uint64_t copy = cache_span - within;
    if (copy > (uint64_t)remaining)
      copy = (uint64_t)remaining;
    if (offset >= async->storage->size) {
      memset(destination, 0, (size_t)copy);
      short_read = 1;
    } else {
      uint64_t available = (uint64_t)(async->storage->size - offset);
      if (copy > available) {
        copy = available;
        short_read = 1;
      }
      if (load_cache(async->storage, base) != SQLITE_OK)
        return SQLITE_IOERR_READ;
      memcpy(destination, cache_data + within, (size_t)copy);
    }
    destination += copy;
    offset += (sqlite3_int64)copy;
    remaining -= (int)copy;
    if (!copy) {
      memset(destination, 0, (size_t)remaining);
      short_read = 1;
      break;
    }
  }
  return short_read ? SQLITE_IOERR_SHORT_READ : SQLITE_OK;
}

static int async_write(sqlite3_file* file, const void* input, int amount,
                       sqlite3_int64 offset) {
  struct keystone_async_file* async = (struct keystone_async_file*)file;
  const uint8_t* source = (const uint8_t*)input;
  int remaining = amount;
  if (!async->storage || offset < 0 || amount < 0 ||
      offset > INT64_MAX - amount ||
      (uint64_t)offset + (uint64_t)amount >
          KEYSTONE_VFS_MAX_DATABASE_BYTES)
    return SQLITE_IOERR_WRITE;
  while (remaining > 0) {
    uint64_t cache_span = cache_span_bytes();
    sqlite3_int64 base = (offset / (sqlite3_int64)cache_span) *
        (sqlite3_int64)cache_span;
    uint64_t within = (uint64_t)(offset - base);
    uint64_t copy = cache_span - within;
    if (copy > (uint64_t)remaining)
      copy = (uint64_t)remaining;
    if (load_cache(async->storage, base) != SQLITE_OK)
      return SQLITE_IOERR_WRITE;
    memcpy(cache_data + within, source, (size_t)copy);
    async->storage->cache_dirty = 1;
    if (within + copy > async->storage->cache_length)
      async->storage->cache_length = within + copy;
    offset += (sqlite3_int64)copy;
    source += copy;
    remaining -= (int)copy;
    if (offset > async->storage->size)
      async->storage->size = offset;
  }
  return SQLITE_OK;
}

static int async_truncate(sqlite3_file* file, sqlite3_int64 size) {
  struct keystone_async_file* async = (struct keystone_async_file*)file;
  uint64_t cache_span = cache_span_bytes();
  uint64_t index;
  if (!async->storage || size < 0 ||
      (uint64_t)size > KEYSTONE_VFS_MAX_DATABASE_BYTES ||
      flush_cache(async->storage) != SQLITE_OK || wait_all() != 0 ||
      submit_control(GROUP_PMP_SQLITE_VFS_OP_TRUNCATE,
                     async->storage->file_id, 0, (uint64_t)size) != 0)
    return SQLITE_IOERR_TRUNCATE;
  async->storage->size = size;
  for (index = 0; index < KEYSTONE_VFS_MAX_AUTH_BLOCKS; ++index) {
    uint64_t base = index * cache_span;
    if (base >= (uint64_t)size) {
      async->storage->authenticated_length[index] = 0;
      async->storage->valid_length[index] = 0;
      async->storage->authenticated_sequence[index] = 0;
    } else if (base + async->storage->valid_length[index] >
               (uint64_t)size) {
      async->storage->valid_length[index] = (uint32_t)((uint64_t)size - base);
    }
  }
  async->storage->cache_valid = 0;
  if (cache_owner == async->storage)
    cache_owner = NULL;
  return SQLITE_OK;
}

static int async_sync(sqlite3_file* file, int flags) {
  struct keystone_async_file* async = (struct keystone_async_file*)file;
  (void)flags;
  if (!async->storage || flush_cache(async->storage) != SQLITE_OK ||
      wait_all() != 0 ||
      submit_control(GROUP_PMP_SQLITE_VFS_OP_SYNC,
                     async->storage->file_id, 0,
                     (uint64_t)async->storage->size) != 0)
    return SQLITE_IOERR_FSYNC;
  return SQLITE_OK;
}

static int async_size(sqlite3_file* file, sqlite3_int64* size) {
  struct keystone_async_file* async = (struct keystone_async_file*)file;
  *size = async->storage ? async->storage->size : 0;
  return SQLITE_OK;
}
static int async_lock(sqlite3_file* file, int lock) {
  (void)file; (void)lock; return SQLITE_OK;
}
static int async_unlock(sqlite3_file* file, int lock) {
  (void)file; (void)lock; return SQLITE_OK;
}
static int async_reserved(sqlite3_file* file, int* output) {
  (void)file; *output = 0; return SQLITE_OK;
}
static int async_control(sqlite3_file* file, int operation, void* argument) {
  (void)file; (void)operation; (void)argument; return SQLITE_NOTFOUND;
}
static int async_sector(sqlite3_file* file) {
  (void)file; return 4096;
}
static int async_characteristics(sqlite3_file* file) {
  (void)file; return 0;
}

static const sqlite3_io_methods async_methods = {
  .iVersion = 1,
  .xClose = async_close,
  .xRead = async_read,
  .xWrite = async_write,
  .xTruncate = async_truncate,
  .xSync = async_sync,
  .xFileSize = async_size,
  .xLock = async_lock,
  .xUnlock = async_unlock,
  .xCheckReservedLock = async_reserved,
  .xFileControl = async_control,
  .xSectorSize = async_sector,
  .xDeviceCharacteristics = async_characteristics,
};

static int vfs_open(sqlite3_vfs* vfs, const char* name, sqlite3_file* file,
                    int flags, int* output_flags) {
  struct keystone_async_file* async = (struct keystone_async_file*)file;
  struct keystone_async_storage* storage;
  const char* actual = name && name[0] ? name : "keystone-temp";
  (void)vfs;
  if (!configured)
    return SQLITE_CANTOPEN;
  memset(async, 0, sizeof(*async));
  storage = find_file(actual);
  if (!storage && (flags & SQLITE_OPEN_CREATE))
    storage = create_file(actual);
  if (!storage)
    return SQLITE_CANTOPEN;
  ++storage->refs;
  async->base.pMethods = &async_methods;
  async->storage = storage;
  async->delete_on_close = (flags & SQLITE_OPEN_DELETEONCLOSE) != 0;
  if (output_flags)
    *output_flags = flags;
  return SQLITE_OK;
}

static int vfs_delete(sqlite3_vfs* vfs, const char* name, int sync_dir) {
  struct keystone_async_storage* storage = find_file(name);
  (void)vfs; (void)sync_dir;
  if (storage && storage->refs == 0) {
    if (submit_control(GROUP_PMP_SQLITE_VFS_OP_DELETE,
                       storage->file_id, 0, 0) != 0)
      return SQLITE_IOERR_DELETE;
    if (cache_owner == storage)
      cache_owner = NULL;
    memset(storage, 0, sizeof(*storage));
  }
  return SQLITE_OK;
}
static int vfs_access(sqlite3_vfs* vfs, const char* name, int flags,
                      int* output) {
  (void)vfs; (void)flags; *output = find_file(name) != NULL; return SQLITE_OK;
}
static int vfs_path(sqlite3_vfs* vfs, const char* name, int length,
                    char* output) {
  size_t source_length;
  (void)vfs;
  if (!output || length <= 0)
    return SQLITE_CANTOPEN;
  if (!name)
    name = "";
  source_length = name_length(name);
  if (source_length >= (size_t)length)
    source_length = (size_t)length - 1;
  memcpy(output, name, source_length);
  output[source_length] = 0;
  return SQLITE_OK;
}
static void* vfs_dlopen(sqlite3_vfs* vfs, const char* name) {
  (void)vfs; (void)name; return NULL;
}
static void vfs_dlerror(sqlite3_vfs* vfs, int length, char* output) {
  (void)vfs; if (length > 0) output[0] = 0;
}
static void (*vfs_dlsym(sqlite3_vfs* vfs, void* handle,
                        const char* symbol))(void) {
  (void)vfs; (void)handle; (void)symbol; return NULL;
}
static void vfs_dlclose(sqlite3_vfs* vfs, void* handle) {
  (void)vfs; (void)handle;
}
static int vfs_random(sqlite3_vfs* vfs, int length, char* output) {
  int index;
  (void)vfs;
  for (index = 0; index < length; ++index) {
    random_state ^= random_state >> 12;
    random_state ^= random_state << 25;
    random_state ^= random_state >> 27;
    output[index] = (char)(random_state >> 56);
  }
  return length;
}
static int vfs_sleep(sqlite3_vfs* vfs, int microseconds) {
  (void)vfs; return microseconds;
}
static int vfs_time(sqlite3_vfs* vfs, double* output) {
  (void)vfs; *output = 2440587.5; return SQLITE_OK;
}
static int vfs_error(sqlite3_vfs* vfs, int length, char* output) {
  (void)vfs; if (length > 0) output[0] = 0; return 0;
}

int sqlite3_os_init(void) {
  memset(&enclave_vfs, 0, sizeof(enclave_vfs));
  enclave_vfs.iVersion = 1;
  enclave_vfs.szOsFile = sizeof(struct keystone_async_file);
  enclave_vfs.mxPathname = KEYSTONE_VFS_MAX_PATH;
  enclave_vfs.zName = KEYSTONE_ENCLAVE_VFS_NAME;
  enclave_vfs.xOpen = vfs_open;
  enclave_vfs.xDelete = vfs_delete;
  enclave_vfs.xAccess = vfs_access;
  enclave_vfs.xFullPathname = vfs_path;
  enclave_vfs.xDlOpen = vfs_dlopen;
  enclave_vfs.xDlError = vfs_dlerror;
  enclave_vfs.xDlSym = vfs_dlsym;
  enclave_vfs.xDlClose = vfs_dlclose;
  enclave_vfs.xRandomness = vfs_random;
  enclave_vfs.xSleep = vfs_sleep;
  enclave_vfs.xCurrentTime = vfs_time;
  enclave_vfs.xGetLastError = vfs_error;
  return sqlite3_vfs_register(&enclave_vfs, 1);
}

int sqlite3_os_end(void) {
  return keystone_enclave_vfs_reset();
}

int keystone_enclave_vfs_configure(
    const struct group_pmp_sqlite_vfs_config* config) {
  struct group_pmp_sqlite_vfs_status status;
  uint64_t index;
  if (async_vfs_artifact_marker[0] != 'k' || !config ||
      vfs_double_buffer_artifact_marker[0] != 'k' ||
      !config->run_id || !config->worker_count ||
      config->worker_index >= config->worker_count)
    return SQLITE_MISUSE;
  if (!cache_data)
    cache_data = (uint8_t*)malloc((size_t)GROUP_PMP_SQLITE_VFS_BUFFER_BYTES);
  if (!cipher_data)
    cipher_data = (uint8_t*)malloc((size_t)GROUP_PMP_SQLITE_VFS_BUFFER_BYTES);
  if (!cache_data || !cipher_data)
    return SQLITE_NOMEM;
  if (encrypt_context)
    aes_encrypt_deinit(encrypt_context);
  if (decrypt_context)
    aes_decrypt_deinit(decrypt_context);
  encrypt_context = aes_encrypt_init(config->aes128_key, 16);
  decrypt_context = aes_decrypt_init(config->aes128_key, 16);
  if (!encrypt_context || !decrypt_context)
    return SQLITE_ERROR;
  vfs_config = *config;
  memset(&vfs_stats, 0, sizeof(vfs_stats));
  memset(buffers, 0, sizeof(buffers));
  cache_owner = NULL;
  next_request_id = 0;
  next_sequence = 0;
  last_error = 0;
  configured = 1;
  memset(&status, 0, sizeof(status));
  status.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
  status.version = GROUP_PMP_SQLITE_VFS_VERSION;
  status.state = GROUP_PMP_SQLITE_VFS_STATE_IDLE;
  for (index = 0; index < GROUP_PMP_SQLITE_VFS_BUFFER_COUNT; ++index)
    if (copy_to_shared_utm(status_offset(index), &status,
                           sizeof(status)) != 0)
      return SQLITE_IOERR;
  return SQLITE_OK;
}

int keystone_enclave_vfs_reset(void) {
  int index;
  int result = SQLITE_OK;
  if (configured) {
    for (index = 0; index < KEYSTONE_VFS_MAX_FILES; ++index)
      if (files[index].used && flush_cache(&files[index]) != SQLITE_OK)
        result = SQLITE_IOERR_WRITE;
    if (wait_all() != 0 ||
        submit_control(GROUP_PMP_SQLITE_VFS_OP_RESET, 0, 0, 0) != 0)
      result = SQLITE_IOERR;
  }
  memset(files, 0, sizeof(files));
  cache_owner = NULL;
  if (cache_data)
    memset(cache_data, 0, (size_t)GROUP_PMP_SQLITE_VFS_BUFFER_BYTES);
  if (cipher_data)
    memset(cipher_data, 0, (size_t)GROUP_PMP_SQLITE_VFS_BUFFER_BYTES);
  return result;
}

int keystone_enclave_vfs_reset_stats(void) {
  uint64_t index;

  if (!configured || vfs_perf_window_artifact_marker[0] != 'k' ||
      vfs_solo_wait_artifact_marker[0] != 'k' ||
      vfs_adaptive_cache_artifact_marker[0] != 'k')
    return SQLITE_MISUSE;
  /*
   * This is a measurement boundary, not a storage reset. All setup/prefill
   * requests must be complete so no pre-window request can later contribute
   * completion time to the measured interval.
   */
  for (index = 0; index < GROUP_PMP_SQLITE_VFS_BUFFER_COUNT; ++index)
    if (buffers[index].pending)
      return SQLITE_BUSY;
  memset(&vfs_stats, 0, sizeof(vfs_stats));
  return SQLITE_OK;
}

int keystone_enclave_vfs_sync(void) {
  int index;
  for (index = 0; index < KEYSTONE_VFS_MAX_FILES; ++index)
    if (files[index].used &&
        (flush_cache(&files[index]) != SQLITE_OK || wait_all() != 0 ||
         submit_control(GROUP_PMP_SQLITE_VFS_OP_SYNC, files[index].file_id,
                        0, (uint64_t)files[index].size) != 0))
      return SQLITE_IOERR_FSYNC;
  return SQLITE_OK;
}

sqlite3_int64 keystone_enclave_vfs_bytes(void) {
  sqlite3_int64 total = 0;
  int index;
  for (index = 0; index < KEYSTONE_VFS_MAX_FILES; ++index)
    if (files[index].used)
      total += files[index].size;
  return total;
}

void keystone_enclave_vfs_get_stats(
    struct group_pmp_sqlite_vfs_stats* stats) {
  if (stats)
    *stats = vfs_stats;
}

uint64_t keystone_enclave_vfs_last_error(void) {
  return last_error;
}
