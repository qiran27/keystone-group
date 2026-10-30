// Copyright (c 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "bench.h"

#include <errno.h>
#include <sys/stat.h>

#ifndef SQLITE_BENCH_HAVE_SEC
#define SQLITE_BENCH_HAVE_SEC 0
#endif

#if SQLITE_BENCH_HAVE_SEC
#include "../sec-aesgcm-bench/jh7110_aes_gcm_user.h"
#endif

#define KEYSTONE_SQLITE_HEAP_SIZE       (2U * 1024U * 1024U)
#define KEYSTONE_BATCH_MAX_BYTES        (8U * 1024U * 1024U)
#define KEYSTONE_AES_GCM_OVERHEAD       28U
#define KEYSTONE_SQLITE_BLOB_CHUNK_SIZE (32U * 1024U)
#define KEYSTONE_DB_MAX_CHUNKS          ((KEYSTONE_BATCH_MAX_BYTES + KEYSTONE_AES_GCM_OVERHEAD + KEYSTONE_SQLITE_BLOB_CHUNK_SIZE - 1U) / KEYSTONE_SQLITE_BLOB_CHUNK_SIZE)
#define KEYSTONE_RAM_VFS_NAME           "keystone_ram_vfs"
#define KEYSTONE_RAM_VFS_MAX_FILES      16
#define KEYSTONE_RAM_VFS_MAX_PATH       256

enum Order {
  SEQUENTIAL,
  RANDOM
};

enum DBState {
  FRESH,
  EXISTING
};

sqlite3* db_;
int db_num_;
int num_;
int reads_;
double start_;
double last_op_finish_;
int64_t bytes_;
char* message_;
Histogram hist_;
Raw raw_;
RandomGenerator gen_;
Random rand_;
static unsigned char keystone_sqlite_heap_[KEYSTONE_SQLITE_HEAP_SIZE];
#if SQLITE_BENCH_HAVE_SEC
static jh7110_sec_user_ctx_t keystone_sec_ctx_;
static bool keystone_sec_ready_;
#endif

typedef struct KeystoneRamStorage {
  bool used;
  char name[KEYSTONE_RAM_VFS_MAX_PATH];
  uint8_t* data;
  sqlite3_int64 size;
  sqlite3_int64 capacity;
  int refs;
} KeystoneRamStorage;

typedef struct KeystoneRamFile {
  sqlite3_file base;
  KeystoneRamStorage* storage;
  int delete_on_close;
} KeystoneRamFile;

static KeystoneRamStorage keystone_ram_files_[KEYSTONE_RAM_VFS_MAX_FILES];
static sqlite3_vfs keystone_ram_vfs_;
static sqlite3_vfs* keystone_default_vfs_;
static bool keystone_ram_vfs_registered_;

/* State kept for progress messages */
int done_;
int next_report_;

static void print_header(void);
static void print_warnings(void);
static void print_environment(void);
static void start(void);
static void stop(const char *name);
static void benchmark_keystone_run_one(const char* name);
static DIR* open_or_create_db_dir(const char* path);
static void keystone_ram_vfs_register(void);
static void keystone_ram_vfs_reset(void);

inline
static void exec_error_check(int status, char *err_msg) {
  if (status != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err_msg);
    sqlite3_free(err_msg);
    exit(1);
  }
}

inline
static void step_error_check(int status) {
  if (status != SQLITE_DONE) {
    fprintf(stderr, "SQL step error: status = %d\n", status);
    exit(1);
  }
}

inline
static void error_check(int status) {
  if (status != SQLITE_OK) {
    fprintf(stderr, "sqlite3 error: status = %d\n", status);
    exit(1);
  }
}

inline
static void wal_checkpoint(sqlite3* db_) {
  /* Flush all writes to disk */
  if (FLAGS_WAL_enabled) {
    sqlite3_wal_checkpoint_v2(db_, NULL, SQLITE_CHECKPOINT_FULL, NULL,
                              NULL);
  }
}

static void print_header() {
  const int kKeySize = 16;
  print_environment();
  if (FLAGS_keystone_mode) {
    fprintf(stderr, "Mode:       Keystone-compatible native SQLite\n");
    fprintf(stderr, "Batch:      %d MB\n", FLAGS_batch_mb);
    fprintf(stderr, "Total:      %d MB\n", FLAGS_total_mb);
    fprintf(stderr, "Resident:   %d MB\n", FLAGS_resident_mb);
    fprintf(stderr, "SQLiteHeap: %u MB\n", KEYSTONE_SQLITE_HEAP_SIZE / 1048576U);
    fprintf(stderr, "BlobChunk:  %u KB\n", KEYSTONE_SQLITE_BLOB_CHUNK_SIZE / 1024U);
    fprintf(stderr, "Storage:    SQLite RAM VFS (database pages outside SQLite heap)\n");
#if SQLITE_BENCH_HAVE_SEC
    fprintf(stderr, "Crypto:     JH7110 SEC PIO AES-GCM-128 (base=0x%llx size=0x%x)\n",
            (unsigned long long)FLAGS_sec_base, FLAGS_sec_size);
#else
    fprintf(stderr, "Crypto:     fallback XOR stub (non-RISC-V build only)\n");
#endif
    fprintf(stderr, "------------------------------------------------\n");
    return;
  }
  fprintf(stderr, "Keys:       %d bytes each\n", kKeySize);
  fprintf(stderr, "Values:     %d bytes each\n", FLAGS_value_size);  
  fprintf(stderr, "Entries:    %d\n", num_);
  fprintf(stderr, "RawSize:    %.1f MB (estimated)\n",
            (((int64_t)(kKeySize + FLAGS_value_size) * num_)
            / 1048576.0));
  print_warnings();
  fprintf(stderr, "------------------------------------------------\n");
}

static void print_warnings() {
#if defined(__GNUC__) && !defined(__OPTIMIZE__)
  fprintf(stderr,
      "WARNING: Optimization is disabled: benchmarks unnecessarily slow\n"
      );
#endif
#ifndef NDEBUG
  fprintf(stderr,
      "WARNING: Assertions are enabled: benchmarks unnecessarily slow\n"
      );
#endif
}

static DIR* open_or_create_db_dir(const char* path) {
  DIR* dir;
  char mkdir_path[1000];
  size_t len;

  if (path == NULL || path[0] == '\0') {
    fprintf(stderr, "Invalid --db path\n");
    exit(1);
  }

  dir = opendir(path);
  if (dir != NULL) {
    return dir;
  }

  if (errno != ENOENT) {
    fprintf(stderr, "Failed to open --db directory '%s': %s\n",
            path, strerror(errno));
    exit(1);
  }

  len = strlen(path);
  if (len >= sizeof(mkdir_path)) {
    fprintf(stderr, "--db path too long: %s\n", path);
    exit(1);
  }
  strcpy(mkdir_path, path);
  while (len > 1 && mkdir_path[len - 1] == '/') {
    mkdir_path[--len] = '\0';
  }

  if (mkdir(mkdir_path, 0755) != 0 && errno != EEXIST) {
    fprintf(stderr, "Failed to create --db directory '%s': %s\n",
            mkdir_path, strerror(errno));
    exit(1);
  }

  dir = opendir(path);
  if (dir == NULL) {
    fprintf(stderr, "Failed to open --db directory after create '%s': %s\n",
            path, strerror(errno));
    exit(1);
  }
  return dir;
}

static KeystoneRamStorage* keystone_ram_find(const char* name) {
  for (int i = 0; i < KEYSTONE_RAM_VFS_MAX_FILES; i++) {
    if (keystone_ram_files_[i].used &&
        strcmp(keystone_ram_files_[i].name, name) == 0) {
      return &keystone_ram_files_[i];
    }
  }
  return NULL;
}

static KeystoneRamStorage* keystone_ram_create(const char* name) {
  for (int i = 0; i < KEYSTONE_RAM_VFS_MAX_FILES; i++) {
    if (!keystone_ram_files_[i].used) {
      KeystoneRamStorage* s = &keystone_ram_files_[i];
      memset(s, 0, sizeof(*s));
      s->used = true;
      snprintf(s->name, sizeof(s->name), "%s", name);
      return s;
    }
  }
  return NULL;
}

static void keystone_ram_free_storage(KeystoneRamStorage* s) {
  if (!s) {
    return;
  }
  free(s->data);
  memset(s, 0, sizeof(*s));
}

static int keystone_ram_reserve(KeystoneRamStorage* s, sqlite3_int64 want) {
  sqlite3_int64 new_cap;
  uint8_t* new_data;

  if (want < 0) {
    return SQLITE_IOERR_NOMEM;
  }
  if (want <= s->capacity) {
    return SQLITE_OK;
  }

  new_cap = s->capacity > 0 ? s->capacity : 65536;
  while (new_cap < want) {
    if (new_cap > (((sqlite3_int64)1 << 62) / 2)) {
      return SQLITE_IOERR_NOMEM;
    }
    new_cap *= 2;
  }

  new_data = (uint8_t*)realloc(s->data, (size_t)new_cap);
  if (new_data == NULL) {
    return SQLITE_IOERR_NOMEM;
  }
  if (new_cap > s->capacity) {
    memset(new_data + s->capacity, 0, (size_t)(new_cap - s->capacity));
  }
  s->data = new_data;
  s->capacity = new_cap;
  return SQLITE_OK;
}

static int keystone_ram_close(sqlite3_file* file) {
  KeystoneRamFile* f = (KeystoneRamFile*)file;
  if (f->storage) {
    if (f->storage->refs > 0) {
      f->storage->refs--;
    }
    if (f->delete_on_close && f->storage->refs == 0) {
      keystone_ram_free_storage(f->storage);
    }
  }
  f->storage = NULL;
  return SQLITE_OK;
}

static int keystone_ram_read(sqlite3_file* file, void* buf, int amt,
                             sqlite3_int64 offset) {
  KeystoneRamFile* f = (KeystoneRamFile*)file;
  sqlite3_int64 available;

  if (!f->storage || offset < 0 || amt < 0) {
    return SQLITE_IOERR_READ;
  }
  if (offset >= f->storage->size) {
    memset(buf, 0, (size_t)amt);
    return SQLITE_IOERR_SHORT_READ;
  }

  available = f->storage->size - offset;
  if (available >= amt) {
    memcpy(buf, f->storage->data + offset, (size_t)amt);
    return SQLITE_OK;
  }

  memcpy(buf, f->storage->data + offset, (size_t)available);
  memset((uint8_t*)buf + available, 0, (size_t)(amt - available));
  return SQLITE_IOERR_SHORT_READ;
}

static int keystone_ram_write(sqlite3_file* file, const void* buf, int amt,
                              sqlite3_int64 offset) {
  KeystoneRamFile* f = (KeystoneRamFile*)file;
  sqlite3_int64 end;
  int rc;

  if (!f->storage || offset < 0 || amt < 0) {
    return SQLITE_IOERR_WRITE;
  }
  end = offset + amt;
  if (end < offset) {
    return SQLITE_IOERR_WRITE;
  }

  rc = keystone_ram_reserve(f->storage, end);
  if (rc != SQLITE_OK) {
    return rc;
  }
  if (offset > f->storage->size) {
    memset(f->storage->data + f->storage->size, 0,
           (size_t)(offset - f->storage->size));
  }
  memcpy(f->storage->data + offset, buf, (size_t)amt);
  if (end > f->storage->size) {
    f->storage->size = end;
  }
  return SQLITE_OK;
}

static int keystone_ram_truncate(sqlite3_file* file, sqlite3_int64 size) {
  KeystoneRamFile* f = (KeystoneRamFile*)file;
  int rc;

  if (!f->storage || size < 0) {
    return SQLITE_IOERR_TRUNCATE;
  }
  rc = keystone_ram_reserve(f->storage, size);
  if (rc != SQLITE_OK) {
    return rc;
  }
  if (size > f->storage->size) {
    memset(f->storage->data + f->storage->size, 0,
           (size_t)(size - f->storage->size));
  }
  f->storage->size = size;
  return SQLITE_OK;
}

static int keystone_ram_sync(sqlite3_file* file, int flags) {
  (void)file;
  (void)flags;
  return SQLITE_OK;
}

static int keystone_ram_file_size(sqlite3_file* file, sqlite3_int64* size) {
  KeystoneRamFile* f = (KeystoneRamFile*)file;
  *size = f->storage ? f->storage->size : 0;
  return SQLITE_OK;
}

static int keystone_ram_lock(sqlite3_file* file, int lock_type) {
  (void)file;
  (void)lock_type;
  return SQLITE_OK;
}

static int keystone_ram_unlock(sqlite3_file* file, int lock_type) {
  (void)file;
  (void)lock_type;
  return SQLITE_OK;
}

static int keystone_ram_check_reserved_lock(sqlite3_file* file, int* out) {
  (void)file;
  *out = 0;
  return SQLITE_OK;
}

static int keystone_ram_file_control(sqlite3_file* file, int op, void* arg) {
  (void)file;
  (void)op;
  (void)arg;
  return SQLITE_NOTFOUND;
}

static int keystone_ram_sector_size(sqlite3_file* file) {
  (void)file;
  return 4096;
}

static int keystone_ram_device_characteristics(sqlite3_file* file) {
  (void)file;
  return SQLITE_IOCAP_ATOMIC | SQLITE_IOCAP_SAFE_APPEND |
         SQLITE_IOCAP_SEQUENTIAL;
}

static const sqlite3_io_methods keystone_ram_io_methods_ = {
  1,
  keystone_ram_close,
  keystone_ram_read,
  keystone_ram_write,
  keystone_ram_truncate,
  keystone_ram_sync,
  keystone_ram_file_size,
  keystone_ram_lock,
  keystone_ram_unlock,
  keystone_ram_check_reserved_lock,
  keystone_ram_file_control,
  keystone_ram_sector_size,
  keystone_ram_device_characteristics
};

static int keystone_ram_x_open(sqlite3_vfs* vfs, const char* name,
                               sqlite3_file* file, int flags, int* out_flags) {
  KeystoneRamFile* f = (KeystoneRamFile*)file;
  KeystoneRamStorage* storage;
  char temp_name[KEYSTONE_RAM_VFS_MAX_PATH];
  const char* effective_name = name;

  (void)vfs;
  memset(f, 0, sizeof(*f));
  if (effective_name == NULL || effective_name[0] == '\0') {
    snprintf(temp_name, sizeof(temp_name), "temp-%p", (void*)file);
    effective_name = temp_name;
  }

  storage = keystone_ram_find(effective_name);
  if (storage == NULL) {
    if ((flags & SQLITE_OPEN_CREATE) == 0) {
      return SQLITE_CANTOPEN;
    }
    storage = keystone_ram_create(effective_name);
    if (storage == NULL) {
      return SQLITE_FULL;
    }
  }

  storage->refs++;
  f->base.pMethods = &keystone_ram_io_methods_;
  f->storage = storage;
  f->delete_on_close = (flags & SQLITE_OPEN_DELETEONCLOSE) != 0;
  if (out_flags) {
    *out_flags = flags;
  }
  return SQLITE_OK;
}

static int keystone_ram_x_delete(sqlite3_vfs* vfs, const char* name,
                                 int sync_dir) {
  KeystoneRamStorage* storage;
  (void)vfs;
  (void)sync_dir;
  storage = keystone_ram_find(name);
  if (storage != NULL && storage->refs == 0) {
    keystone_ram_free_storage(storage);
  }
  return SQLITE_OK;
}

static int keystone_ram_x_access(sqlite3_vfs* vfs, const char* name,
                                 int flags, int* out) {
  (void)vfs;
  (void)flags;
  *out = keystone_ram_find(name) != NULL;
  return SQLITE_OK;
}

static int keystone_ram_x_full_pathname(sqlite3_vfs* vfs, const char* name,
                                        int out_size, char* out) {
  (void)vfs;
  snprintf(out, (size_t)out_size, "%s", name ? name : "");
  return SQLITE_OK;
}

static void* keystone_ram_x_dl_open(sqlite3_vfs* vfs, const char* name) {
  return keystone_default_vfs_ && keystone_default_vfs_->xDlOpen
    ? keystone_default_vfs_->xDlOpen(keystone_default_vfs_, name)
    : NULL;
}

static void keystone_ram_x_dl_error(sqlite3_vfs* vfs, int n, char* msg) {
  if (keystone_default_vfs_ && keystone_default_vfs_->xDlError) {
    keystone_default_vfs_->xDlError(keystone_default_vfs_, n, msg);
  } else if (n > 0) {
    msg[0] = '\0';
  }
  (void)vfs;
}

static void (*keystone_ram_x_dl_sym(sqlite3_vfs* vfs, void* handle,
                                    const char* symbol))(void) {
  return keystone_default_vfs_ && keystone_default_vfs_->xDlSym
    ? keystone_default_vfs_->xDlSym(keystone_default_vfs_, handle, symbol)
    : NULL;
}

static void keystone_ram_x_dl_close(sqlite3_vfs* vfs, void* handle) {
  if (keystone_default_vfs_ && keystone_default_vfs_->xDlClose) {
    keystone_default_vfs_->xDlClose(keystone_default_vfs_, handle);
  }
  (void)vfs;
}

static int keystone_ram_x_randomness(sqlite3_vfs* vfs, int n, char* out) {
  if (keystone_default_vfs_ && keystone_default_vfs_->xRandomness) {
    return keystone_default_vfs_->xRandomness(keystone_default_vfs_, n, out);
  }
  for (int i = 0; i < n; i++) {
    out[i] = (char)(rand() & 0xff);
  }
  (void)vfs;
  return n;
}

static int keystone_ram_x_sleep(sqlite3_vfs* vfs, int microseconds) {
  if (keystone_default_vfs_ && keystone_default_vfs_->xSleep) {
    return keystone_default_vfs_->xSleep(keystone_default_vfs_, microseconds);
  }
  (void)vfs;
  return microseconds;
}

static int keystone_ram_x_current_time(sqlite3_vfs* vfs, double* out) {
  if (keystone_default_vfs_ && keystone_default_vfs_->xCurrentTime) {
    return keystone_default_vfs_->xCurrentTime(keystone_default_vfs_, out);
  }
  *out = time(NULL) / 86400.0 + 2440587.5;
  (void)vfs;
  return SQLITE_OK;
}

static int keystone_ram_x_get_last_error(sqlite3_vfs* vfs, int n, char* out) {
  (void)vfs;
  if (n > 0) {
    out[0] = '\0';
  }
  return SQLITE_OK;
}

static void keystone_ram_vfs_register(void) {
  if (keystone_ram_vfs_registered_) {
    return;
  }

  keystone_default_vfs_ = sqlite3_vfs_find(NULL);
  memset(&keystone_ram_vfs_, 0, sizeof(keystone_ram_vfs_));
  keystone_ram_vfs_.iVersion = 1;
  keystone_ram_vfs_.szOsFile = sizeof(KeystoneRamFile);
  keystone_ram_vfs_.mxPathname = KEYSTONE_RAM_VFS_MAX_PATH;
  keystone_ram_vfs_.zName = KEYSTONE_RAM_VFS_NAME;
  keystone_ram_vfs_.xOpen = keystone_ram_x_open;
  keystone_ram_vfs_.xDelete = keystone_ram_x_delete;
  keystone_ram_vfs_.xAccess = keystone_ram_x_access;
  keystone_ram_vfs_.xFullPathname = keystone_ram_x_full_pathname;
  keystone_ram_vfs_.xDlOpen = keystone_ram_x_dl_open;
  keystone_ram_vfs_.xDlError = keystone_ram_x_dl_error;
  keystone_ram_vfs_.xDlSym = keystone_ram_x_dl_sym;
  keystone_ram_vfs_.xDlClose = keystone_ram_x_dl_close;
  keystone_ram_vfs_.xRandomness = keystone_ram_x_randomness;
  keystone_ram_vfs_.xSleep = keystone_ram_x_sleep;
  keystone_ram_vfs_.xCurrentTime = keystone_ram_x_current_time;
  keystone_ram_vfs_.xGetLastError = keystone_ram_x_get_last_error;

  int rc = sqlite3_vfs_register(&keystone_ram_vfs_, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to register Keystone RAM VFS: status=%d\n", rc);
    exit(1);
  }
  keystone_ram_vfs_registered_ = true;
}

static void keystone_ram_vfs_reset(void) {
  for (int i = 0; i < KEYSTONE_RAM_VFS_MAX_FILES; i++) {
    keystone_ram_free_storage(&keystone_ram_files_[i]);
  }
}

static void print_environment() {
  fprintf(stderr, "SQLite:     version %s\n", SQLITE_VERSION);
#if defined(__linux)
  time_t now = time(NULL);
  fprintf(stderr, "Date:       %s", ctime(&now));

  FILE* cpuinfo = fopen("/proc/cpuinfo", "r");
  if (cpuinfo != NULL) {
    char line[1000];
    int num_cpus = 0;
    char* cpu_type = malloc(sizeof(char) * 1000);
    char* cache_size = malloc(sizeof(char) * 1000);
    while (fgets(line, sizeof(line), cpuinfo) != NULL) {
      char* sep = strchr(line, ':');
      if (sep == NULL) {
        continue;
      }
      char* key = calloc(sizeof(char), 1000);
      char* val = calloc(sizeof(char), 1000);
      strncpy(key, line, sep - 1 - line);
      strcpy(val, sep + 1);
      char* trimed_key = trim_space(key);
      char* trimed_val = trim_space(val);
      free(key);
      free(val);
      if (!strcmp(trimed_key, "model name")) {
        ++num_cpus;
        strcpy(cpu_type, trimed_val);
      } else if (!strcmp(trimed_key, "cache size")) {
        strcpy(cache_size, trimed_val);
      }
      free(trimed_key);
      free(trimed_val);
    }
    fclose(cpuinfo);
    fprintf(stderr, "CPU:        %d * %s\n", num_cpus, cpu_type);
    fprintf(stderr, "CPUCache:   %s\n", cache_size);
    free(cpu_type);
    free(cache_size);
  }
#endif
}

static void start() {
  start_ =  now_micros() * 1e-6;
  bytes_ = 0;
  message_ = malloc(sizeof(char) * 10000);
  strcpy(message_, "");
  last_op_finish_ = start_;
  histogram_clear(&hist_);
  raw_clear(&raw_);
  done_ = 0;
  next_report_ = 100;
}

void finished_single_op() {
  if (FLAGS_histogram || FLAGS_raw) {
    double now = now_micros() * 1e-6;
    double micros = (now - last_op_finish_) * 1e6;
    if (FLAGS_histogram) {
      histogram_add(&hist_, micros);
      if (micros > 20000) {
        fprintf(stderr, "long op: %.1f micros%30s\r", micros, "");
        fflush(stderr);
      }
    }
    if (FLAGS_raw) {
      raw_add(&raw_, micros);
    }
    last_op_finish_ = now;
  }

  done_++;
  if (done_ >= next_report_) {
    if      (next_report_ < 1000)   next_report_ += 100;
    else if (next_report_ < 5000)   next_report_ += 500;
    else if (next_report_ < 10000)  next_report_ += 1000;
    else if (next_report_ < 50000)  next_report_ += 5000;
    else if (next_report_ < 100000) next_report_ += 10000;
    else if (next_report_ < 500000) next_report_ += 50000;
    else                            next_report_ += 100000;
    fprintf(stderr, "... finished %d ops%30s\r", done_, "");
    fflush(stderr);
  }
}

static void stop(const char* name) {
  double finish = now_micros() * 1e-6;

  if (done_ < 1) done_ = 1;

  if (bytes_ > 0) {
    char rate[100];
    snprintf(rate, sizeof(rate), "%6.2f MB/s",
             (bytes_ / 1048576.0) / (finish - start_));
    if (message_ && message_[0] != '\0') {
      char old_message[256];
      snprintf(old_message, sizeof(old_message), "%.200s", message_);
      snprintf(message_, 10000, "%s %s", rate, old_message);
    } else if (message_) {
      snprintf(message_, 10000, "%s", rate);
    }
  }

  fprintf(stderr, "%-12s : %11.2f micros/op;%s%s\n",
          name,
          (finish - start_) * 1e6 / done_,
          (!message_ || !strcmp(message_, "") ? "" : " "),
          (!message_) ? "" : message_);
  if (FLAGS_raw) {
    raw_print(stdout, &raw_);
  }
  if (FLAGS_histogram) {
    fprintf(stderr, "Microseconds per op:\n%s\n",
            histogram_to_string(&hist_));
  }
  fflush(stdout);
  fflush(stderr);
}

void benchmark_init() {
  db_ = NULL;
  db_num_ = 0;
  num_ = FLAGS_num;
  reads_ = FLAGS_reads < 0 ? FLAGS_num : FLAGS_reads;
  bytes_ = 0;
  rand_gen_init(&gen_, FLAGS_compression_ratio);
  rand_init(&rand_, 301);;

  if (FLAGS_keystone_mode) {
    int status;
    sqlite3_shutdown();
    status = sqlite3_config(SQLITE_CONFIG_HEAP,
                            keystone_sqlite_heap_,
                            (int)sizeof(keystone_sqlite_heap_),
                            64);
    error_check(status);
    status = sqlite3_initialize();
    error_check(status);
    keystone_ram_vfs_register();
#if SQLITE_BENCH_HAVE_SEC
    memset(&keystone_sec_ctx_, 0, sizeof(keystone_sec_ctx_));
    int sec_status = jh7110_sec_user_init(&keystone_sec_ctx_,
                                          (uintptr_t)FLAGS_sec_base,
                                          (size_t)FLAGS_sec_size);
    if (sec_status != JH7110_AES_GCM_USER_SUCCESS) {
      fprintf(stderr,
              "JH7110 SEC init failed: status=%d base=0x%llx size=0x%x "
              "(native SEC mode requires /dev/mem access)\n",
              sec_status,
              (unsigned long long)FLAGS_sec_base,
              FLAGS_sec_size);
      exit(1);
    }
    keystone_sec_ready_ = true;
#endif
    return;
  }

  struct dirent* ep;
  DIR* test_dir = open_or_create_db_dir(FLAGS_db);
  if (!FLAGS_use_existing_db) {
    while ((ep = readdir(test_dir)) != NULL) {
      if (starts_with(ep->d_name, "dbbench_sqlite3")) {
        char file_name[1000];
        strcpy(file_name, FLAGS_db);
        strcat(file_name, ep->d_name);
        remove(file_name);
      }
    }
  }
  closedir(test_dir);
}

void benchmark_fini() {
  int status = sqlite3_close(db_);
  error_check(status);
  if (FLAGS_keystone_mode) {
    keystone_ram_vfs_reset();
  }
#if SQLITE_BENCH_HAVE_SEC
  if (keystone_sec_ready_) {
    jh7110_sec_user_close(&keystone_sec_ctx_);
    keystone_sec_ready_ = false;
  }
#endif
}

void benchmark_run() {
  print_header();
  benchmark_open();

  char* benchmarks = FLAGS_benchmarks;
  while (benchmarks != NULL) {
    char* sep = strchr(benchmarks, ',');
    char* name;
    if (sep == NULL) {
      name = benchmarks;
      benchmarks = NULL;
    } else {
      name = calloc(sizeof(char), (sep - benchmarks + 1));
      strncpy(name, benchmarks, sep - benchmarks);
      benchmarks = sep + 1;
    }
    bytes_ = 0;
    start();
    bool known = true;
    bool write_sync = false;
    if (!strcmp(name, "fillseq")) {
      if (FLAGS_keystone_mode) benchmark_keystone_run_one(name);
      else {
        benchmark_write(write_sync, SEQUENTIAL, FRESH, num_, FLAGS_value_size, 1);
        wal_checkpoint(db_);
      }
    } else if (!strcmp(name, "fillseqbatch")) {
      if (FLAGS_keystone_mode) benchmark_keystone_run_one(name);
      else {
        benchmark_write(write_sync, SEQUENTIAL, FRESH, num_, FLAGS_value_size, 1000);
        wal_checkpoint(db_);
      }
    } else if (!strcmp(name, "fillrandom")) {
      if (FLAGS_keystone_mode) benchmark_keystone_run_one(name);
      else {
        benchmark_write(write_sync, RANDOM, FRESH, num_, FLAGS_value_size, 1);
        wal_checkpoint(db_);
      }
    } else if (!strcmp(name, "fillrandbatch")) {
      if (FLAGS_keystone_mode) benchmark_keystone_run_one(name);
      else {
        benchmark_write(write_sync, RANDOM, FRESH, num_, FLAGS_value_size, 1000);
        wal_checkpoint(db_);
      }
    } else if (!strcmp(name, "overwrite")) {
      if (FLAGS_keystone_mode) benchmark_keystone_run_one(name);
      else {
        benchmark_write(write_sync, RANDOM, EXISTING, num_, FLAGS_value_size, 1);
        wal_checkpoint(db_);
      }
    } else if (!strcmp(name, "overwritebatch")) {
      benchmark_write(write_sync, RANDOM, EXISTING, num_, FLAGS_value_size, 1000);
      wal_checkpoint(db_);
    } else if (!strcmp(name, "fillrandsync")) {
      write_sync = true;
      benchmark_write(write_sync, RANDOM, FRESH, num_ / 100, FLAGS_value_size, 1);
      wal_checkpoint(db_);
    } else if (!strcmp(name, "fillseqsync")) {
      write_sync = true;
      benchmark_write(write_sync, SEQUENTIAL, FRESH, num_ / 100, FLAGS_value_size, 1);
      wal_checkpoint(db_);
    } else if (!strcmp(name, "fillrand100K")) {
      benchmark_write(write_sync, RANDOM, FRESH, num_ / 1000, 100 * 1000, 1);
      wal_checkpoint(db_);
    } else if (!strcmp(name, "fillseq100K")) {
      benchmark_write(write_sync, SEQUENTIAL, FRESH, num_ / 1000, 100 * 1000, 1);
      wal_checkpoint(db_);
    } else if (!strcmp(name, "readseq")) {
      if (FLAGS_keystone_mode) benchmark_keystone_run_one(name);
      else benchmark_read(SEQUENTIAL, 1);
    } else if (!strcmp(name, "readrandom")) {
      if (FLAGS_keystone_mode) benchmark_keystone_run_one(name);
      else benchmark_read(RANDOM, 1);
    } else if (!strcmp(name, "readrand100K")) {
      if (FLAGS_keystone_mode) benchmark_keystone_run_one(name);
      else {
        int n = reads_;
        reads_ /= 1000;
        benchmark_read(RANDOM, 1);
        reads_ = n;
      }
    } else {
      known = false;
      if (strcmp(name, "")) {
        fprintf(stderr, "unknown benchmark '%s'\n", name);
      }
    }
    if (known) {
      stop(name);
    }
  }
}

void benchmark_open() {
  assert(db_ == NULL);

  int status;
  char file_name[100];
  char* err_msg = NULL;
  db_num_++;

  /* Open database */
  if (FLAGS_keystone_mode) {
    status = sqlite3_open_v2("keystone-native.db",
                             &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                             KEYSTONE_RAM_VFS_NAME);
    if (status) {
      fprintf(stderr, "open RAM VFS error: %s\n",
              db_ ? sqlite3_errmsg(db_) : "no db handle");
      exit(1);
    }
  } else {
  char *tmp_dir = FLAGS_db;
  snprintf(file_name, sizeof(file_name),
            "%sdbbench_sqlite3-%d.db",
            tmp_dir,
            db_num_);
  status = sqlite3_open(file_name, &db_);
  if (status) {
    fprintf(stderr, "open error: %s\n", sqlite3_errmsg(db_));
    exit(1);
  }
  }

  if (FLAGS_keystone_mode) {
    char* stmt_array[] = {
      "PRAGMA journal_mode = OFF",
      "PRAGMA synchronous = OFF",
      "PRAGMA temp_store = MEMORY",
      "PRAGMA locking_mode = EXCLUSIVE",
      "PRAGMA cache_size = -512",
      "PRAGMA mmap_size = 0",
      "CREATE TABLE IF NOT EXISTS kv (k INTEGER PRIMARY KEY, v BLOB)",
      NULL
    };
    for (int i = 0; stmt_array[i] != NULL; i++) {
      status = sqlite3_exec(db_, stmt_array[i], NULL, NULL, &err_msg);
      exec_error_check(status, err_msg);
    }
    return;
  }

  /* Change SQLite cache size */
  char cache_size[100];
  snprintf(cache_size, sizeof(cache_size), "PRAGMA cache_size = %d",
            FLAGS_num_pages);
  status = sqlite3_exec(db_, cache_size, NULL, NULL, &err_msg);
  exec_error_check(status, err_msg);

  /* FLAGS_page_size is defaulted to 1024 */
  if (FLAGS_page_size != 1024) {
    char page_size[100];
    snprintf(page_size, sizeof(page_size), "PRAGMA page_size = %d",
              FLAGS_page_size);
    status = sqlite3_exec(db_, page_size, NULL, NULL, &err_msg);
    exec_error_check(status, err_msg);
  }

  /* Change journal mode to WAL if WAL enabled flag is on */
  if (FLAGS_WAL_enabled) {
    char* WAL_stmt = "PRAGMA journal_mode = WAL";

    /* Default cache size is a combined 4 MB */
    char* WAL_checkpoint = "PRAGMA wal_autocheckpoint = 4096";
    status = sqlite3_exec(db_, WAL_stmt, NULL, NULL, &err_msg);
    exec_error_check(status, err_msg);
    status = sqlite3_exec(db_, WAL_checkpoint, NULL, NULL, &err_msg);
    exec_error_check(status, err_msg);
  }

  /* Change locking mode to exclusive and create tables/index for database */
  char* locking_stmt = "PRAGMA locking_mode = EXCLUSIVE";
  char* create_stmt =
          "CREATE TABLE test (key blob, value blob, PRIMARY KEY (key))";
  char* stmt_array[] = { locking_stmt, create_stmt, NULL };
  int stmt_array_length = sizeof(stmt_array) / sizeof(char*);
  for (int i = 0; i < stmt_array_length; i++) {
    status = sqlite3_exec(db_, stmt_array[i], NULL, NULL, &err_msg);
    exec_error_check(status, err_msg);
  }
}

void benchmark_write(bool write_sync, int order, int state,
                  int num_entries, int value_size, int entries_per_batch) {
  /* Create new database if state == FRESH */
  if (state == FRESH) {
    if (FLAGS_use_existing_db) {
      snprintf(message_, 10000, "skipping (--use_existing_db is true)");
      return;
    }
    sqlite3_close(db_);
    db_ = NULL;
    benchmark_open();
    start();
  }

  if (num_entries != num_) {
    snprintf(message_, 10000, "(%d ops)", num_entries);
  }

  char* err_msg = NULL;
  int status;

  sqlite3_stmt *replace_stmt, *begin_trans_stmt, *end_trans_stmt;
  char* replace_str = "REPLACE INTO test (key, value) VALUES (?, ?)";
  char* begin_trans_str = "BEGIN TRANSACTION";
  char* end_trans_str = "END TRANSACTION";

  /* Check for synchronous flag in options */
  char* sync_stmt = (write_sync) ? "PRAGMA synchronous = FULL" :
                                    "PRAGMA synchronous = OFF";
  status = sqlite3_exec(db_, sync_stmt, NULL, NULL, &err_msg);
  exec_error_check(status, err_msg);

  /* Preparing sqlite3 statements */
  status = sqlite3_prepare_v2(db_, replace_str, -1,
                              &replace_stmt, NULL);
  error_check(status);
  status = sqlite3_prepare_v2(db_, begin_trans_str, -1,
                              &begin_trans_stmt, NULL);
  error_check(status);
  status = sqlite3_prepare_v2(db_, end_trans_str, -1,
                              &end_trans_stmt, NULL);
  error_check(status);

  bool transaction = (entries_per_batch > 1);
  for (int i = 0; i < num_entries; i += entries_per_batch) {
    /* Begin write transaction */
    if (FLAGS_transaction && transaction) {
      status = sqlite3_step(begin_trans_stmt);
      step_error_check(status);
      status = sqlite3_reset(begin_trans_stmt);
      error_check(status);
    }

    /* Create and execute SQL statements */
    for (int j = 0; j < entries_per_batch; j++) {
      const char* value = rand_gen_generate(&gen_, value_size);

      /* Create values for key-value pair */
      const int k = (order == SEQUENTIAL) ? i + j :
                    (rand_next(&rand_) % num_entries);
      char key[100];
      snprintf(key, sizeof(key), "%016d", k);

      /* Bind KV values into replace_stmt */
      status = sqlite3_bind_blob(replace_stmt, 1, key, 16, SQLITE_STATIC);
      error_check(status);
      status = sqlite3_bind_blob(replace_stmt, 2, value,
                                  value_size, SQLITE_STATIC);
      error_check(status);

      /* Execute replace_stmt */
      bytes_ += value_size + strlen(key);
      status = sqlite3_step(replace_stmt);
      step_error_check(status);

      /* Reset SQLite statement for another use */
      status = sqlite3_clear_bindings(replace_stmt);
      error_check(status);
      status = sqlite3_reset(replace_stmt);
      error_check(status);

      finished_single_op();
    }

    /* End write transaction */
    if (FLAGS_transaction && transaction) {
      status = sqlite3_step(end_trans_stmt);
      step_error_check(status);
      status = sqlite3_reset(end_trans_stmt);
      error_check(status);
    }
  }

  status = sqlite3_finalize(replace_stmt);
  error_check(status);
  status = sqlite3_finalize(begin_trans_stmt);
  error_check(status);
  status = sqlite3_finalize(end_trans_stmt);
  error_check(status);
}

void benchmark_read(int order, int entries_per_batch) {
  int status;
  sqlite3_stmt *read_stmt, *begin_trans_stmt, *end_trans_stmt;

  char *read_str = "SELECT * FROM test WHERE key = ?";
  char *begin_trans_str = "BEGIN TRANSACTION";
  char *end_trans_str = "END TRANSACTION";

  /* Preparing sqlite3 statements */
  status = sqlite3_prepare_v2(db_, begin_trans_str, -1,
                              &begin_trans_stmt, NULL);
  error_check(status);
  status = sqlite3_prepare_v2(db_, end_trans_str, -1,
                              &end_trans_stmt, NULL);
  error_check(status);
  status = sqlite3_prepare_v2(db_, read_str, -1,
                              &read_stmt, NULL);
  error_check(status);

  bool transaction = (entries_per_batch > 1);
  for (int i = 0; i < reads_; i += entries_per_batch) {
    /* Begin read transaction */
    if (FLAGS_transaction && transaction) {
      status = sqlite3_step(begin_trans_stmt);
      step_error_check(status);
      status = sqlite3_reset(begin_trans_stmt);
      error_check(status);
    }

    /* Create and execute SQL statements */
    for (int j = 0; j < entries_per_batch; j++) {
      /* Create key value */
      char key[100];
      int k = (order == SEQUENTIAL) ? i + j : (rand_next(&rand_) % reads_);
      snprintf(key, sizeof(key), "%016d", k);

      /* Bind key value into read_stmt */
      status = sqlite3_bind_blob(read_stmt, 1, key, 16, SQLITE_STATIC);
      error_check(status);
      
      /* Execute read statement */
      while ((status = sqlite3_step(read_stmt)) == SQLITE_ROW) {}
      step_error_check(status);

      /* Reset SQLite statement for another use */
      status = sqlite3_clear_bindings(read_stmt);
      error_check(status);
      status = sqlite3_reset(read_stmt);
      error_check(status);
      finished_single_op();
    }

    /* End read transaction */
    if (FLAGS_transaction && transaction) {
      status = sqlite3_step(end_trans_stmt);
      step_error_check(status);
      status = sqlite3_reset(end_trans_stmt);
      error_check(status);
    }
  }

  status = sqlite3_finalize(read_stmt);
  error_check(status);
  status = sqlite3_finalize(begin_trans_stmt);
  error_check(status);
  status = sqlite3_finalize(end_trans_stmt);
  error_check(status);
}

static uint32_t keystone_db_chunk_key(uint32_t batch_key, uint32_t chunk_idx) {
  return batch_key * KEYSTONE_DB_MAX_CHUNKS + chunk_idx;
}

static void keystone_fill_plain(uint8_t* plain, uint32_t len, uint32_t batch_id) {
  uint32_t x = 0x9e3779b9U ^ batch_id;
  for (uint32_t i = 0; i < len; i++) {
    x = x * 1664525U + 1013904223U;
    plain[i] = (uint8_t)(x >> 24);
  }
}

static uint64_t keystone_checksum(const uint8_t* data, uint32_t len) {
  uint64_t h = 1469598103934665603ULL;
  for (uint32_t i = 0; i < len; i++) {
    h ^= data[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static int keystone_encrypt_batch(const uint8_t* plain, uint32_t plain_len,
                                  uint8_t* cipher, size_t* cipher_len,
                                  uint32_t batch_id) {
  static const uint8_t key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
#if SQLITE_BENCH_HAVE_SEC
  if (!keystone_sec_ready_) {
    return JH7110_AES_GCM_USER_ERR_INVALID_PARAM;
  }
  return jh7110_aesgcm128_encrypt_with_counter_user(&keystone_sec_ctx_,
                                                    key,
                                                    (uint64_t)batch_id,
                                                    plain,
                                                    plain_len,
                                                    NULL,
                                                    0,
                                                    cipher,
                                                    cipher_len);
#else
  for (uint32_t i = 0; i < 12U; i++) {
    cipher[i] = (uint8_t)((batch_id >> ((i & 3U) * 8U)) & 0xffU);
  }
  for (uint32_t i = 0; i < plain_len; i++) {
    cipher[12U + i] = (uint8_t)(plain[i] ^ key[i & 15U] ^ (uint8_t)batch_id);
  }
  for (uint32_t i = 0; i < 16U; i++) {
    cipher[12U + plain_len + i] = (uint8_t)(0xa5U ^ i ^ batch_id);
  }
  *cipher_len = plain_len + KEYSTONE_AES_GCM_OVERHEAD;
  return 0;
#endif
}

static int keystone_decrypt_batch(const uint8_t* cipher, uint32_t cipher_len,
                                  uint8_t* plain, size_t* plain_len,
                                  uint32_t batch_id) {
  static const uint8_t key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
#if SQLITE_BENCH_HAVE_SEC
  (void)batch_id;
  if (!keystone_sec_ready_) {
    return JH7110_AES_GCM_USER_ERR_INVALID_PARAM;
  }
  return jh7110_aesgcm128_decrypt_user(&keystone_sec_ctx_,
                                       key,
                                       cipher,
                                       cipher_len,
                                       NULL,
                                       0,
                                       plain,
                                       plain_len);
#else
  if (cipher_len <= KEYSTONE_AES_GCM_OVERHEAD) {
    return -1;
  }
  *plain_len = cipher_len - KEYSTONE_AES_GCM_OVERHEAD;
  for (uint32_t i = 0; i < *plain_len; i++) {
    plain[i] = (uint8_t)(cipher[12U + i] ^ key[i & 15U] ^ (uint8_t)batch_id);
  }
  return 0;
#endif
}

static void keystone_reset_table(void) {
  char* err_msg = NULL;
  int status = sqlite3_exec(db_, "DELETE FROM kv", NULL, NULL, &err_msg);
  exec_error_check(status, err_msg);
}

static void keystone_put_batch(sqlite3_stmt* stmt, uint32_t key,
                               const uint8_t* plain, uint32_t plain_len,
                               uint8_t* cipher, uint32_t* cipher_len) {
  size_t out_len = 0;
  int status = keystone_encrypt_batch(plain, plain_len, cipher, &out_len, key);
  if (status != 0) {
    fprintf(stderr, "keystone encrypt error: status = %d\n", status);
    exit(1);
  }
  *cipher_len = (uint32_t)out_len;
  uint32_t chunks = (uint32_t)((out_len + KEYSTONE_SQLITE_BLOB_CHUNK_SIZE - 1U) /
                              KEYSTONE_SQLITE_BLOB_CHUNK_SIZE);
  for (uint32_t chunk = 0; chunk < chunks; chunk++) {
    uint32_t off = chunk * KEYSTONE_SQLITE_BLOB_CHUNK_SIZE;
    uint32_t remaining = (uint32_t)out_len - off;
    uint32_t len = remaining > KEYSTONE_SQLITE_BLOB_CHUNK_SIZE ?
                   KEYSTONE_SQLITE_BLOB_CHUNK_SIZE : remaining;
    status = sqlite3_reset(stmt);
    error_check(status);
    status = sqlite3_clear_bindings(stmt);
    error_check(status);
    status = sqlite3_bind_int(stmt, 1, (int)keystone_db_chunk_key(key, chunk));
    error_check(status);
    status = sqlite3_bind_blob(stmt, 2, cipher + off, (int)len, SQLITE_STATIC);
    error_check(status);
    status = sqlite3_step(stmt);
    step_error_check(status);
  }
}

static void keystone_get_batch(sqlite3_stmt* stmt, uint32_t key,
                               uint8_t* cipher, uint8_t* plain,
                               uint32_t plain_len, uint64_t* checksum) {
  uint32_t expected_cipher_len = plain_len + KEYSTONE_AES_GCM_OVERHEAD;
  uint32_t chunks = (expected_cipher_len + KEYSTONE_SQLITE_BLOB_CHUNK_SIZE - 1U) /
                    KEYSTONE_SQLITE_BLOB_CHUNK_SIZE;
  uint32_t copied = 0;
  for (uint32_t chunk = 0; chunk < chunks; chunk++) {
    int status = sqlite3_reset(stmt);
    error_check(status);
    status = sqlite3_clear_bindings(stmt);
    error_check(status);
    status = sqlite3_bind_int(stmt, 1, (int)keystone_db_chunk_key(key, chunk));
    error_check(status);
    status = sqlite3_step(stmt);
    if (status != SQLITE_ROW) {
      fprintf(stderr, "keystone read missing chunk: batch=%u chunk=%u status=%d\n",
              key, chunk, status);
      exit(1);
    }
    const uint8_t* ptr = (const uint8_t*)sqlite3_column_blob(stmt, 0);
    int len = sqlite3_column_bytes(stmt, 0);
    if (!ptr || len <= 0 || copied + (uint32_t)len > expected_cipher_len) {
      fprintf(stderr, "keystone read invalid chunk: batch=%u chunk=%u len=%d\n",
              key, chunk, len);
      exit(1);
    }
    memcpy(cipher + copied, ptr, (size_t)len);
    copied += (uint32_t)len;
  }
  if (copied != expected_cipher_len) {
    fprintf(stderr, "keystone read short cipher: batch=%u copied=%u expected=%u\n",
            key, copied, expected_cipher_len);
    exit(1);
  }
  size_t got_plain = 0;
  int rc = keystone_decrypt_batch(cipher, expected_cipher_len, plain, &got_plain, key);
  if (rc != 0 || got_plain != plain_len) {
    fprintf(stderr, "keystone decrypt error: batch=%u status=%d plain=%zu\n",
            key, rc, got_plain);
    exit(1);
  }
  *checksum ^= keystone_checksum(plain, plain_len);
}

static void keystone_prefill(uint32_t resident_batches, uint32_t batch_size,
                             uint8_t* plain, uint8_t* cipher) {
  sqlite3_stmt* stmt = NULL;
  uint32_t cipher_len = 0;
  int status = sqlite3_prepare_v2(db_, "INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)",
                                  -1, &stmt, NULL);
  error_check(status);
  keystone_reset_table();
  status = sqlite3_exec(db_, "BEGIN IMMEDIATE", NULL, NULL, NULL);
  error_check(status);
  for (uint32_t i = 0; i < resident_batches; i++) {
    keystone_fill_plain(plain, batch_size, i);
    keystone_put_batch(stmt, i, plain, batch_size, cipher, &cipher_len);
  }
  status = sqlite3_exec(db_, "COMMIT", NULL, NULL, NULL);
  error_check(status);
  status = sqlite3_finalize(stmt);
  error_check(status);
}

static void benchmark_keystone_run_one(const char* name) {
  uint32_t total_bytes = (uint32_t)FLAGS_total_mb * 1024U * 1024U;
  uint32_t batch_size = (uint32_t)FLAGS_batch_mb * 1024U * 1024U;
  uint32_t batches;
  uint32_t resident_batches;
  bool random_order = (!strcmp(name, "fillrandom") || !strcmp(name, "fillrandbatch") ||
                       !strcmp(name, "overwrite") || !strcmp(name, "readrandom") ||
                       !strcmp(name, "readrand100K"));
  bool batch_tx = (!strcmp(name, "fillseqbatch") || !strcmp(name, "fillrandbatch") ||
                   !strcmp(name, "overwrite"));
  bool is_read = (!strcmp(name, "readseq") || !strcmp(name, "readrandom") ||
                  !strcmp(name, "readrand100K"));
  bool is_overwrite = (!strcmp(name, "overwrite"));
  uint8_t* plain = NULL;
  uint8_t* cipher = NULL;
  sqlite3_stmt* stmt = NULL;
  uint32_t cipher_len = 0;
  uint64_t checksum = 0;
  Random local_rand;

  if (batch_size == 0 || batch_size > KEYSTONE_BATCH_MAX_BYTES ||
      total_bytes == 0 || (total_bytes % batch_size) != 0) {
    fprintf(stderr, "invalid Keystone-compatible sizes: total_mb=%d batch_mb=%d\n",
            FLAGS_total_mb, FLAGS_batch_mb);
    exit(1);
  }
  batches = total_bytes / batch_size;
  resident_batches = ((uint32_t)FLAGS_resident_mb * 1024U * 1024U) / batch_size;
  if (resident_batches == 0) {
    resident_batches = 1;
  }
  if (resident_batches > batches) {
    resident_batches = batches;
  }

  plain = (uint8_t*)malloc(batch_size);
  cipher = (uint8_t*)malloc(batch_size + KEYSTONE_AES_GCM_OVERHEAD);
  if (!plain || !cipher) {
    fprintf(stderr, "failed to allocate Keystone-compatible buffers\n");
    exit(1);
  }

  rand_init(&local_rand, 301);

  if (is_read || is_overwrite) {
    keystone_prefill(resident_batches, batch_size, plain, cipher);
    start();
  } else {
    keystone_reset_table();
  }

  if (is_read) {
    int status = sqlite3_prepare_v2(db_, "SELECT v FROM kv WHERE k=?",
                                    -1, &stmt, NULL);
    error_check(status);
    uint32_t ops = (!strcmp(name, "readrand100K") && batches > 100000U) ?
                   100000U : batches;
    for (uint32_t i = 0; i < ops; i++) {
      uint32_t logical = random_order ? (rand_next(&local_rand) % batches) : (i % batches);
      uint32_t key = logical % resident_batches;
      keystone_get_batch(stmt, key, cipher, plain, batch_size, &checksum);
      bytes_ += batch_size;
      finished_single_op();
    }
  } else {
    int status = sqlite3_prepare_v2(db_, "INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)",
                                    -1, &stmt, NULL);
    error_check(status);
    if (batch_tx) {
      status = sqlite3_exec(db_, "BEGIN IMMEDIATE", NULL, NULL, NULL);
      error_check(status);
    }
    for (uint32_t i = 0; i < batches; i++) {
      uint32_t logical = random_order ? (rand_next(&local_rand) % batches) : i;
      uint32_t key = logical % resident_batches;
      uint32_t data_id = is_overwrite ? (logical ^ 0x5555U) : logical;
      keystone_fill_plain(plain, batch_size, data_id);
      keystone_put_batch(stmt, key, plain, batch_size, cipher, &cipher_len);
      checksum ^= keystone_checksum(cipher, cipher_len);
      bytes_ += batch_size;
      finished_single_op();
    }
    if (batch_tx) {
      status = sqlite3_exec(db_, "COMMIT", NULL, NULL, NULL);
      error_check(status);
    }
  }

  if (stmt) {
    int status = sqlite3_finalize(stmt);
    error_check(status);
  }
  snprintf(message_, 10000, "checksum=%llu batch=%u resident=%u blob_chunk=%u",
           (unsigned long long)checksum, batch_size, resident_batches,
           KEYSTONE_SQLITE_BLOB_CHUNK_SIZE);
  free(plain);
  free(cipher);
}
