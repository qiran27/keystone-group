#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#ifndef O_DIRECT
#define O_DIRECT 040000
#endif
#define TMPFS_MAGIC 0x01021994
#define ALIGNMENT 4096U
#define MIB UINT64_C(1048576)

enum cache_mode { CACHE_HOT, CACHE_COLD, CACHE_DIRECT };
enum operation { SEQ_WRITE, SEQ_READ, RAND_WRITE, RAND_READ };

struct options {
  const char *sd_dir;
  const char *usb_dir;
  const char *output;
  uint64_t size;
  uint64_t seq_block;
  uint64_t rand_block;
  unsigned repeats;
  enum cache_mode cache;
  int run_sd;
  int run_usb;
  int allow_same_fs;
  int allow_tmpfs;
};

struct target {
  const char *name;
  const char *directory;
  dev_t device;
  char path[PATH_MAX];
  int fd;
};

static volatile sig_atomic_t interrupted;

static void on_signal(int signal_number) {
  (void)signal_number;
  interrupted = 1;
}

static void usage(const char *program) {
  fprintf(stderr,
      "usage: %s [--device sd|usb|both] [--sd-dir DIR] [--usb-dir DIR] "
      "[--size SIZE] [--seq-block SIZE] [--rand-block SIZE] "
      "[--cache hot|cold|direct] [--repeat N] [--output CSV] "
      "[--allow-same-fs] [--allow-tmpfs]\n"
      "defaults: both, /var/tmp, /myusb, 128MiB, 1MiB, 4KiB, cold, 3 repeats\n"
      "SIZE accepts bytes or KB/MB/GB (decimal) or KiB/MiB/GiB (binary).\n",
      program);
}

static int parse_bytes(const char *text, uint64_t *value) {
  char *end;
  unsigned long long number;
  uint64_t factor;
  errno = 0;
  number = strtoull(text, &end, 10);
  if (errno || end == text || number == 0)
    return -1;
  if (*end == '\0' || strcasecmp(end, "B") == 0) factor = 1;
  else if (strcasecmp(end, "KB") == 0) factor = 1000;
  else if (strcasecmp(end, "MB") == 0) factor = 1000000;
  else if (strcasecmp(end, "GB") == 0) factor = UINT64_C(1000000000);
  else if (strcasecmp(end, "KiB") == 0) factor = 1024;
  else if (strcasecmp(end, "MiB") == 0) factor = MIB;
  else if (strcasecmp(end, "GiB") == 0) factor = UINT64_C(1073741824);
  else return -1;
  if ((uint64_t)number > UINT64_MAX / factor)
    return -1;
  *value = (uint64_t)number * factor;
  return 0;
}

static int parse_options(int argc, char **argv, struct options *options) {
  int i;
  *options = (struct options){
      .sd_dir = "/var/tmp", .usb_dir = "/myusb", .size = 128 * MIB,
      .seq_block = MIB, .rand_block = 4096, .repeats = 3,
      .cache = CACHE_COLD, .run_sd = 1, .run_usb = 1};
  for (i = 1; i < argc; ++i) {
    const char *arg = argv[i];
    const char *value = NULL;
    if (strcmp(arg, "--allow-same-fs") == 0) {
      options->allow_same_fs = 1;
      continue;
    }
    if (strcmp(arg, "--allow-tmpfs") == 0) {
      options->allow_tmpfs = 1;
      continue;
    }
    if (i + 1 >= argc)
      return -1;
    value = argv[++i];
    if (strcmp(arg, "--sd-dir") == 0) options->sd_dir = value;
    else if (strcmp(arg, "--usb-dir") == 0) options->usb_dir = value;
    else if (strcmp(arg, "--output") == 0) options->output = value;
    else if (strcmp(arg, "--size") == 0) {
      if (parse_bytes(value, &options->size)) return -1;
    } else if (strcmp(arg, "--seq-block") == 0) {
      if (parse_bytes(value, &options->seq_block)) return -1;
    } else if (strcmp(arg, "--rand-block") == 0) {
      if (parse_bytes(value, &options->rand_block)) return -1;
    } else if (strcmp(arg, "--repeat") == 0) {
      char *end;
      unsigned long parsed;
      errno = 0;
      parsed = strtoul(value, &end, 10);
      if (errno || end == value || *end || parsed < 1 || parsed > 50)
        return -1;
      options->repeats = (unsigned)parsed;
    } else if (strcmp(arg, "--device") == 0) {
      options->run_sd = strcmp(value, "sd") == 0 || strcmp(value, "both") == 0;
      options->run_usb = strcmp(value, "usb") == 0 || strcmp(value, "both") == 0;
      if (!options->run_sd && !options->run_usb) return -1;
    } else if (strcmp(arg, "--cache") == 0) {
      if (strcmp(value, "hot") == 0) options->cache = CACHE_HOT;
      else if (strcmp(value, "cold") == 0) options->cache = CACHE_COLD;
      else if (strcmp(value, "direct") == 0) options->cache = CACHE_DIRECT;
      else return -1;
    } else return -1;
  }
  if (options->size > UINT64_C(16) * 1024 * MIB ||
      options->seq_block > 16 * MIB || options->rand_block > 16 * MIB ||
      options->size % options->seq_block ||
      options->size % options->rand_block ||
      options->seq_block % ALIGNMENT ||
      options->rand_block % ALIGNMENT ||
      options->seq_block > SIZE_MAX || options->rand_block > SIZE_MAX ||
      options->size > INT64_MAX)
    return -1;
  if (strpbrk(options->sd_dir, ",\r\n") ||
      strpbrk(options->usb_dir, ",\r\n")) {
    fprintf(stderr, "directory paths cannot contain commas or newlines in CSV output\n");
    return -1;
  }
  return 0;
}

static uint64_t now_ns(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0) {
    perror("clock_gettime");
    exit(1);
  }
  return (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
}

static uint64_t random_u64(uint64_t *state) {
  uint64_t x = *state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *state = x;
  return x * UINT64_C(2685821657736338717);
}

static uint64_t *make_permutation(uint64_t count) {
  uint64_t *permutation;
  uint64_t state = UINT64_C(0x8b6d91a772ee1401);
  uint64_t i;
  if (count > SIZE_MAX / sizeof(*permutation)) return NULL;
  permutation = malloc((size_t)count * sizeof(*permutation));
  if (!permutation) return NULL;
  for (i = 0; i < count; ++i) permutation[i] = i;
  for (i = count; i > 1; --i) {
    uint64_t j = random_u64(&state) % i;
    uint64_t temp = permutation[i - 1];
    permutation[i - 1] = permutation[j];
    permutation[j] = temp;
  }
  return permutation;
}

static int check_directory(const char *path, uint64_t required_bytes,
                           int allow_tmpfs, dev_t *device) {
  struct stat status;
  struct statfs filesystem;
  struct statvfs space;
  uint64_t available;
  if (stat(path, &status) || statfs(path, &filesystem) ||
      statvfs(path, &space)) {
    fprintf(stderr, "invalid test directory %s: %s\n", path, strerror(errno));
    return -1;
  }
  if (!S_ISDIR(status.st_mode)) {
    fprintf(stderr, "not a directory: %s\n", path);
    return -1;
  }
  if (!allow_tmpfs && filesystem.f_type == TMPFS_MAGIC) {
    fprintf(stderr, "refusing tmpfs directory %s (not storage media)\n", path);
    return -1;
  }
  available = (uint64_t)space.f_bavail * space.f_frsize;
  if (available < required_bytes + 32 * MIB) {
    fprintf(stderr, "insufficient free space in %s: available=%" PRIu64
                    " required=%" PRIu64 "\n", path, available,
                    required_bytes + 32 * MIB);
    return -1;
  }
  *device = status.st_dev;
  return 0;
}

static int create_target(struct target *target, enum cache_mode cache) {
  int length = snprintf(target->path, sizeof(target->path),
                        "%s/.keystone-usb-sd-test-XXXXXX", target->directory);
  if (length < 0 || (size_t)length >= sizeof(target->path)) return -1;
  target->fd = mkstemp(target->path);
  if (target->fd < 0) {
    perror("mkstemp");
    return -1;
  }
  if (cache == CACHE_DIRECT) {
    close(target->fd);
    target->fd = open(target->path, O_RDWR | O_DIRECT | O_CLOEXEC);
    if (target->fd < 0) {
      fprintf(stderr, "O_DIRECT unavailable for %s: %s\n",
              target->path, strerror(errno));
      unlink(target->path);
      target->path[0] = '\0';
      return -1;
    }
  }
  return 0;
}

static void close_target(struct target *target) {
  if (target->fd >= 0) {
    close(target->fd);
    target->fd = -1;
  }
  if (target->path[0]) {
    if (unlink(target->path))
      fprintf(stderr, "warning: could not remove %s: %s\n",
              target->path, strerror(errno));
    target->path[0] = '\0';
  }
}

static int exact_io(int fd, void *buffer, size_t length, off_t offset,
                    int write_operation) {
  ssize_t done = write_operation ? pwrite(fd, buffer, length, offset) :
                                   pread(fd, buffer, length, offset);
  if (done != (ssize_t)length) {
    if (done >= 0) errno = EIO;
    return -1;
  }
  return 0;
}

static int prefill(struct target *target, const struct options *options,
                   void *buffer) {
  uint64_t offset;
  if (ftruncate(target->fd, (off_t)options->size)) return -1;
  for (offset = 0; offset < options->size; offset += options->seq_block) {
    if (interrupted || exact_io(target->fd, buffer,
        (size_t)options->seq_block, (off_t)offset, 1)) return -1;
  }
  return fdatasync(target->fd);
}

static int prepare_read(int fd, const struct options *options, void *buffer) {
  uint64_t offset;
  if (options->cache == CACHE_DIRECT) return 0;
  if (options->cache == CACHE_COLD) {
    if (fdatasync(fd)) return -1;
    int advice_error = posix_fadvise(fd, 0, (off_t)options->size,
                                      POSIX_FADV_DONTNEED);
    if (advice_error) {
      errno = advice_error;
      return -1;
    }
    return 0;
  }
  for (offset = 0; offset < options->size; offset += options->seq_block)
    if (interrupted || exact_io(fd, buffer, (size_t)options->seq_block,
                                (off_t)offset, 0)) return -1;
  return 0;
}

static int compare_u64(const void *left, const void *right) {
  uint64_t a = *(const uint64_t *)left, b = *(const uint64_t *)right;
  return (a > b) - (a < b);
}

static uint64_t percentile(const uint64_t *sorted, uint64_t count,
                           unsigned percent) {
  uint64_t rank = (count * percent + 99) / 100;
  if (!rank) rank = 1;
  return sorted[rank - 1];
}

static const char *operation_name(enum operation operation) {
  switch (operation) {
    case SEQ_WRITE: return "seq-write";
    case SEQ_READ: return "seq-read";
    case RAND_WRITE: return "rand-write";
    case RAND_READ: return "rand-read";
  }
  return "unknown";
}

static const char *cache_name(enum cache_mode cache) {
  switch (cache) {
    case CACHE_HOT: return "buffered-hot";
    case CACHE_COLD: return "buffered-cold-requested";
    case CACHE_DIRECT: return "direct";
  }
  return "unknown";
}

static int run_case(FILE *output, struct target *target,
                    const struct options *options, void *buffer,
                    const uint64_t *permutation, enum operation operation,
                    unsigned repetition) {
  const int write_operation = operation == SEQ_WRITE || operation == RAND_WRITE;
  const int random_operation = operation == RAND_WRITE || operation == RAND_READ;
  const uint64_t block = random_operation ? options->rand_block : options->seq_block;
  const uint64_t count = options->size / block;
  uint64_t *latencies;
  uint64_t i, io_started, io_elapsed, sync_elapsed = 0;
  double io_seconds, total_seconds;
  if (count > SIZE_MAX / sizeof(*latencies)) return -1;
  latencies = malloc((size_t)count * sizeof(*latencies));
  if (!latencies) return -1;
  if (!write_operation && prepare_read(target->fd, options, buffer)) {
    fprintf(stderr, "%s %s cache preparation failed: %s\n", target->name,
            operation_name(operation), interrupted ? "interrupted" : strerror(errno));
    free(latencies);
    return -1;
  }
  io_started = now_ns();
  for (i = 0; i < count; ++i) {
    uint64_t offset = (random_operation ? permutation[i] : i) * block;
    uint64_t started = now_ns();
    if (interrupted || exact_io(target->fd, buffer, (size_t)block,
                                (off_t)offset, write_operation)) {
      fprintf(stderr, "%s %s offset=%" PRIu64 ": %s\n", target->name,
              operation_name(operation), offset,
              interrupted ? "interrupted" : strerror(errno));
      free(latencies);
      return -1;
    }
    latencies[i] = now_ns() - started;
    if (!write_operation &&
        (((const unsigned char *)buffer)[0] != 0xa5 ||
         ((const unsigned char *)buffer)[block - 1] != 0xa5)) {
      fprintf(stderr, "%s %s data mismatch at offset=%" PRIu64 "\n",
              target->name, operation_name(operation), offset);
      free(latencies);
      return -1;
    }
  }
  io_elapsed = now_ns() - io_started;
  if (write_operation) {
    uint64_t started = now_ns();
    if (fdatasync(target->fd)) {
      fprintf(stderr, "%s %s fdatasync failed: %s\n", target->name,
              operation_name(operation), strerror(errno));
      free(latencies);
      return -1;
    }
    sync_elapsed = now_ns() - started;
  }
  qsort(latencies, (size_t)count, sizeof(*latencies), compare_u64);
  io_seconds = (double)io_elapsed / 1000000000.0;
  total_seconds = (double)(io_elapsed + sync_elapsed) / 1000000000.0;
  fprintf(output,
      "usb-sd-file-io-v1,%s,%s,%s,%s,%" PRIu64 ",%" PRIu64
      ",%u,%" PRIu64 ",%.9f,%.9f,%.9f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%" PRIu64 "\n",
      target->name, target->directory, cache_name(options->cache),
      operation_name(operation), block, options->size, repetition, count,
      io_seconds, (double)sync_elapsed / 1000000000.0, total_seconds,
      (double)options->size / MIB / io_seconds,
      (double)options->size / MIB / total_seconds,
      (double)count / io_seconds,
      (double)percentile(latencies, count, 50) / 1000.0,
      (double)percentile(latencies, count, 95) / 1000.0,
      (double)percentile(latencies, count, 99) / 1000.0,
      (uint64_t)target->device);
  fflush(output);
  free(latencies);
  return ferror(output) ? -1 : 0;
}

int main(int argc, char **argv) {
  struct options options;
  struct target targets[2] = {
      {.name = "sd", .fd = -1}, {.name = "usb", .fd = -1}};
  FILE *output = stdout;
  uint64_t *permutation = NULL;
  void *buffer = NULL;
  int count = 0, index, result = 1;
  unsigned repeat;
  enum operation operation;
  if (parse_options(argc, argv, &options)) {
    usage(argv[0]);
    return 2;
  }
  if (options.run_sd) {
    targets[count].name = "sd";
    targets[count++].directory = options.sd_dir;
  }
  if (options.run_usb) {
    targets[count].name = "usb";
    targets[count++].directory = options.usb_dir;
  }
  for (index = 0; index < count; ++index)
    if (check_directory(targets[index].directory, options.size,
                        options.allow_tmpfs, &targets[index].device))
      goto out;
  if (count == 2 && targets[0].device == targets[1].device &&
      !options.allow_same_fs) {
    fprintf(stderr, "SD and USB paths resolve to the same filesystem; "
                    "check the USB mount (or use --allow-same-fs for tests)\n");
    goto out;
  }
  if (options.output) {
    int fd = open(options.output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    FILE *stream = fd >= 0 ? fdopen(fd, "w") : NULL;
    if (!stream) {
      if (fd >= 0) close(fd);
      perror("output CSV");
      goto out;
    }
    output = stream;
  }
  if (posix_memalign(&buffer, ALIGNMENT,
                     (size_t)(options.seq_block > options.rand_block ?
                              options.seq_block : options.rand_block))) {
    fprintf(stderr, "aligned buffer allocation failed\n");
    goto out;
  }
  memset(buffer, 0xa5, (size_t)(options.seq_block > options.rand_block ?
                               options.seq_block : options.rand_block));
  permutation = make_permutation(options.size / options.rand_block);
  if (!permutation) {
    fprintf(stderr, "random permutation allocation failed\n");
    goto out;
  }
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  fprintf(output,
      "benchmark,device,directory,cache_mode,operation,block_bytes,file_bytes,"
      "repeat,requests,io_seconds,fdatasync_seconds,total_seconds,"
      "mib_per_second_io,mib_per_second_with_sync,iops,p50_us,p95_us,p99_us,fs_device_id\n");
  for (index = 0; index < count; ++index) {
    struct target *target = &targets[index];
    if (create_target(target, options.cache)) goto out;
    fprintf(stderr, "[%s] prefill %" PRIu64 " bytes: %s\n",
            target->name, options.size, target->path);
    if (prefill(target, &options, buffer)) {
      perror("prefill");
      goto out;
    }
    for (repeat = 1; repeat <= options.repeats; ++repeat) {
      for (operation = SEQ_WRITE; operation <= RAND_READ; ++operation) {
        fprintf(stderr, "[%s] repeat=%u/%u operation=%s\n", target->name,
                repeat, options.repeats, operation_name(operation));
        if (run_case(output, target, &options, buffer, permutation,
                     operation, repeat)) goto out;
      }
    }
    close_target(target);
  }
  result = 0;
out:
  for (index = 0; index < 2; ++index) close_target(&targets[index]);
  free(permutation);
  free(buffer);
  if (output != stdout && fclose(output)) result = 1;
  return interrupted ? 130 : result;
}
