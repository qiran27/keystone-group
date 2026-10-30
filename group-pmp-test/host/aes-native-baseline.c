#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/if_alg.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "aes_core.h"
#include "native_counter.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef GROUP_PMP_AES_MARCH_STRING
#define GROUP_PMP_AES_MARCH_STRING "unknown"
#endif
#ifndef GROUP_PMP_AES_MABI_STRING
#define GROUP_PMP_AES_MABI_STRING "unknown"
#endif

#define AES_BLOCK_SIZE 16U
#define DEFAULT_BYTES (8U * 1000000U)
#define DEFAULT_SAMPLES 15U
#define DEFAULT_WARMUP 2U
#define AFALG_CHUNK_SIZE (64U * 1024U)

enum aes_operation {
  AES_OPERATION_ENCRYPT = 1,
  AES_OPERATION_DECRYPT = 2,
};

enum backend_result {
  BACKEND_FAILED = -1,
  BACKEND_OK = 0,
  BACKEND_SKIPPED = 1,
};

struct options {
  int cpu;
  size_t bytes;
  unsigned int samples;
  unsigned int warmup;
  const char* backend;
  const char* operation;
};

struct sample {
  double seconds;
  double cycles_per_byte;
  double mb_per_second;
};

struct software_state {
  enum aes_operation operation;
  void* context;
};

struct afalg_state {
  enum aes_operation operation;
  int transform_fd;
  int operation_fd;
};

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;

struct openssl_state {
  enum aes_operation operation;
  void* library;
  EVP_CIPHER_CTX* context;
  EVP_CIPHER_CTX* (*context_new)(void);
  void (*context_free)(EVP_CIPHER_CTX*);
  const EVP_CIPHER* (*aes_128_ecb)(void);
  int (*encrypt_init)(EVP_CIPHER_CTX*, const EVP_CIPHER*, void*,
                      const unsigned char*, const unsigned char*);
  int (*decrypt_init)(EVP_CIPHER_CTX*, const EVP_CIPHER*, void*,
                      const unsigned char*, const unsigned char*);
  int (*encrypt_update)(EVP_CIPHER_CTX*, unsigned char*, int*,
                        const unsigned char*, int);
  int (*decrypt_update)(EVP_CIPHER_CTX*, unsigned char*, int*,
                        const unsigned char*, int);
  int (*set_padding)(EVP_CIPHER_CTX*, int);
};

typedef int (*backend_process_fn)(void*, const uint8_t*, uint8_t*, size_t,
                                  char*, size_t);

static const uint8_t benchmark_key[AES_BLOCK_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static void usage(const char* program)
{
  fprintf(stderr,
          "usage: %s [--cpu N] [--bytes N] [--samples N] [--warmup N] "
          "[--backend all|software|afalg|openssl] "
          "[--operation both|encrypt|decrypt]\n",
          program);
}

static int parse_unsigned(const char* text, uint64_t minimum,
                          uint64_t maximum, uint64_t* value)
{
  char* end = NULL;
  unsigned long long parsed;

  errno = 0;
  parsed = strtoull(text, &end, 0);
  if (errno != 0 || end == text || *end != '\0' ||
      parsed < minimum || parsed > maximum) {
    return -1;
  }
  *value = (uint64_t)parsed;
  return 0;
}

static int parse_options(int argc, char** argv, struct options* options)
{
  int index;

  options->cpu = 1;
  options->bytes = DEFAULT_BYTES;
  options->samples = DEFAULT_SAMPLES;
  options->warmup = DEFAULT_WARMUP;
  options->backend = "all";
  options->operation = "both";

  for (index = 1; index < argc; ++index) {
    uint64_t value;

    if (strcmp(argv[index], "--help") == 0) {
      usage(argv[0]);
      return 1;
    }
    if (index + 1 >= argc) {
      return -1;
    }
    if (strcmp(argv[index], "--cpu") == 0) {
      if (parse_unsigned(argv[++index], 0, CPU_SETSIZE - 1, &value) != 0) {
        return -1;
      }
      options->cpu = (int)value;
    } else if (strcmp(argv[index], "--bytes") == 0) {
      if (parse_unsigned(argv[++index], AES_BLOCK_SIZE, SIZE_MAX, &value) != 0 ||
          (value % AES_BLOCK_SIZE) != 0) {
        return -1;
      }
      options->bytes = (size_t)value;
    } else if (strcmp(argv[index], "--samples") == 0) {
      if (parse_unsigned(argv[++index], 3, 101, &value) != 0) {
        return -1;
      }
      options->samples = (unsigned int)value;
    } else if (strcmp(argv[index], "--warmup") == 0) {
      if (parse_unsigned(argv[++index], 0, 100, &value) != 0) {
        return -1;
      }
      options->warmup = (unsigned int)value;
    } else if (strcmp(argv[index], "--backend") == 0) {
      options->backend = argv[++index];
      if (strcmp(options->backend, "all") != 0 &&
          strcmp(options->backend, "software") != 0 &&
          strcmp(options->backend, "afalg") != 0 &&
          strcmp(options->backend, "openssl") != 0) {
        return -1;
      }
    } else if (strcmp(argv[index], "--operation") == 0) {
      options->operation = argv[++index];
      if (strcmp(options->operation, "both") != 0 &&
          strcmp(options->operation, "encrypt") != 0 &&
          strcmp(options->operation, "decrypt") != 0) {
        return -1;
      }
    } else {
      return -1;
    }
  }
  return 0;
}

static int pin_to_cpu(int cpu)
{
  cpu_set_t set;

  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  if (sched_setaffinity(0, sizeof(set), &set) != 0) {
    return -1;
  }
  return sched_getcpu() == cpu ? 0 : -1;
}

static uint64_t read_cycles(void)
{
  return native_counter_read();
}

static double timespec_delta(const struct timespec* start,
                             const struct timespec* end)
{
  return (double)(end->tv_sec - start->tv_sec) +
         (double)(end->tv_nsec - start->tv_nsec) / 1000000000.0;
}

static int compare_double(const void* left, const void* right)
{
  const double a = *(const double*)left;
  const double b = *(const double*)right;
  return (a > b) - (a < b);
}

static double percentile(const double* values, size_t count,
                         unsigned int percent)
{
  double* sorted;
  size_t rank;
  double result;

  sorted = (double*)malloc(count * sizeof(*sorted));
  if (sorted == NULL) {
    return -1.0;
  }
  memcpy(sorted, values, count * sizeof(*sorted));
  qsort(sorted, count, sizeof(*sorted), compare_double);
  rank = ((size_t)percent * count + 99U) / 100U;
  if (rank == 0) {
    rank = 1;
  }
  if (rank > count) {
    rank = count;
  }
  result = sorted[rank - 1U];
  free(sorted);
  return result;
}

static uint64_t checksum64(const uint8_t* data, size_t length)
{
  uint64_t value = 1469598103934665603ULL;
  size_t index;

  for (index = 0; index < length; ++index) {
    value ^= data[index];
    value *= 1099511628211ULL;
  }
  return value;
}

static void fill_plaintext(uint8_t* data, size_t length)
{
  uint64_t state = 0x9e3779b97f4a7c15ULL;
  size_t index;

  for (index = 0; index < length; ++index) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    data[index] = (uint8_t)(state ^ (state >> 23));
  }
}

static int software_known_answer_test(void)
{
  static const uint8_t plain[AES_BLOCK_SIZE] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  };
  static const uint8_t expected[AES_BLOCK_SIZE] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  };
  uint8_t output[AES_BLOCK_SIZE];
  void* context = aes_encrypt_init(benchmark_key, sizeof(benchmark_key));

  if (context == NULL) {
    return -1;
  }
  aes_encrypt(context, plain, output);
  aes_encrypt_deinit(context);
  return memcmp(output, expected, sizeof(output)) == 0 ? 0 : -1;
}

static int generate_ciphertext(const uint8_t* plain, uint8_t* cipher,
                               size_t length)
{
  void* context = aes_encrypt_init(benchmark_key, sizeof(benchmark_key));
  size_t offset;

  if (context == NULL) {
    return -1;
  }
  for (offset = 0; offset < length; offset += AES_BLOCK_SIZE) {
    aes_encrypt(context, plain + offset, cipher + offset);
  }
  aes_encrypt_deinit(context);
  return 0;
}

static int software_init(struct software_state* state,
                         enum aes_operation operation)
{
  state->operation = operation;
  state->context = operation == AES_OPERATION_ENCRYPT ?
      aes_encrypt_init(benchmark_key, sizeof(benchmark_key)) :
      aes_decrypt_init(benchmark_key, sizeof(benchmark_key));
  return state->context == NULL ? -1 : 0;
}

static int software_process(void* opaque, const uint8_t* input,
                            uint8_t* output, size_t length,
                            char* error, size_t error_size)
{
  struct software_state* state = (struct software_state*)opaque;
  size_t offset;

  (void)error;
  (void)error_size;
  for (offset = 0; offset < length; offset += AES_BLOCK_SIZE) {
    if (state->operation == AES_OPERATION_ENCRYPT) {
      aes_encrypt(state->context, input + offset, output + offset);
    } else {
      aes_decrypt(state->context, input + offset, output + offset);
    }
  }
  return 0;
}

static void software_destroy(struct software_state* state)
{
  if (state->context == NULL) {
    return;
  }
  if (state->operation == AES_OPERATION_ENCRYPT) {
    aes_encrypt_deinit(state->context);
  } else {
    aes_decrypt_deinit(state->context);
  }
  state->context = NULL;
}

static int afalg_init(struct afalg_state* state, enum aes_operation operation,
                      char* error, size_t error_size)
{
  struct sockaddr_alg address;

  memset(state, 0, sizeof(*state));
  state->operation = operation;
  state->transform_fd = -1;
  state->operation_fd = -1;
  state->transform_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
  if (state->transform_fd < 0) {
    snprintf(error, error_size, "socket(AF_ALG): %s", strerror(errno));
    return BACKEND_SKIPPED;
  }

  memset(&address, 0, sizeof(address));
  address.salg_family = AF_ALG;
  memcpy(address.salg_type, "skcipher", sizeof("skcipher"));
  memcpy(address.salg_name, "ecb(aes)", sizeof("ecb(aes)"));
  if (bind(state->transform_fd, (struct sockaddr*)&address,
           sizeof(address)) != 0) {
    snprintf(error, error_size, "bind(ecb(aes)): %s", strerror(errno));
    return BACKEND_SKIPPED;
  }
  if (setsockopt(state->transform_fd, SOL_ALG, ALG_SET_KEY,
                 benchmark_key, sizeof(benchmark_key)) != 0) {
    snprintf(error, error_size, "ALG_SET_KEY: %s", strerror(errno));
    return BACKEND_SKIPPED;
  }
  state->operation_fd = accept(state->transform_fd, NULL, NULL);
  if (state->operation_fd < 0) {
    snprintf(error, error_size, "accept(AF_ALG): %s", strerror(errno));
    return BACKEND_SKIPPED;
  }
  return BACKEND_OK;
}

static int read_exact(int fd, uint8_t* output, size_t length,
                      char* error, size_t error_size)
{
  size_t offset = 0;

  while (offset < length) {
    ssize_t received = read(fd, output + offset, length - offset);
    if (received < 0 && errno == EINTR) {
      continue;
    }
    if (received <= 0) {
      snprintf(error, error_size, "AF_ALG read: %s",
               received == 0 ? "unexpected EOF" : strerror(errno));
      return -1;
    }
    offset += (size_t)received;
  }
  return 0;
}

static int afalg_process(void* opaque, const uint8_t* input,
                         uint8_t* output, size_t length,
                         char* error, size_t error_size)
{
  struct afalg_state* state = (struct afalg_state*)opaque;
  size_t offset = 0;

  while (offset < length) {
    uint8_t control[CMSG_SPACE(sizeof(uint32_t))];
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr* header;
    size_t chunk = length - offset;
    ssize_t sent;
    uint32_t operation = state->operation == AES_OPERATION_ENCRYPT ?
        ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

    if (chunk > AFALG_CHUNK_SIZE) {
      chunk = AFALG_CHUNK_SIZE;
    }
    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    iov.iov_base = (void*)(input + offset);
    iov.iov_len = chunk;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_ALG;
    header->cmsg_type = ALG_SET_OP;
    header->cmsg_len = CMSG_LEN(sizeof(operation));
    memcpy(CMSG_DATA(header), &operation, sizeof(operation));

    do {
      sent = sendmsg(state->operation_fd, &message, 0);
    } while (sent < 0 && errno == EINTR);
    if (sent <= 0 || ((size_t)sent % AES_BLOCK_SIZE) != 0) {
      snprintf(error, error_size, "AF_ALG sendmsg: %s",
               sent <= 0 ? strerror(errno) : "partial AES block");
      return -1;
    }
    if (read_exact(state->operation_fd, output + offset, (size_t)sent,
                   error, error_size) != 0) {
      return -1;
    }
    offset += (size_t)sent;
  }
  return 0;
}

static void afalg_destroy(struct afalg_state* state)
{
  if (state->operation_fd >= 0) {
    close(state->operation_fd);
  }
  if (state->transform_fd >= 0) {
    close(state->transform_fd);
  }
  state->operation_fd = -1;
  state->transform_fd = -1;
}

static int load_symbol(void* library, const char* name, void* destination,
                       char* error, size_t error_size)
{
  void* symbol;

  dlerror();
  symbol = dlsym(library, name);
  if (symbol == NULL) {
    const char* detail = dlerror();
    snprintf(error, error_size, "%s: %s", name,
             detail == NULL ? "not found" : detail);
    return -1;
  }
  memcpy(destination, &symbol, sizeof(symbol));
  return 0;
}

static int openssl_init(struct openssl_state* state,
                        enum aes_operation operation,
                        char* error, size_t error_size)
{
  static const char* libraries[] = {
    "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so", NULL,
  };
  const EVP_CIPHER* cipher;
  size_t index;
  int initialized;

  memset(state, 0, sizeof(*state));
  state->operation = operation;
  for (index = 0; libraries[index] != NULL; ++index) {
    state->library = dlopen(libraries[index], RTLD_NOW | RTLD_LOCAL);
    if (state->library != NULL) {
      break;
    }
  }
  if (state->library == NULL) {
    snprintf(error, error_size, "libcrypto is not installed");
    return BACKEND_SKIPPED;
  }

#define LOAD_OPENSSL_SYMBOL(member, symbol_name) \
  do { \
    if (load_symbol(state->library, symbol_name, &state->member, \
                    error, error_size) != 0) { \
      return BACKEND_SKIPPED; \
    } \
  } while (0)
  LOAD_OPENSSL_SYMBOL(context_new, "EVP_CIPHER_CTX_new");
  LOAD_OPENSSL_SYMBOL(context_free, "EVP_CIPHER_CTX_free");
  LOAD_OPENSSL_SYMBOL(aes_128_ecb, "EVP_aes_128_ecb");
  LOAD_OPENSSL_SYMBOL(encrypt_init, "EVP_EncryptInit_ex");
  LOAD_OPENSSL_SYMBOL(decrypt_init, "EVP_DecryptInit_ex");
  LOAD_OPENSSL_SYMBOL(encrypt_update, "EVP_EncryptUpdate");
  LOAD_OPENSSL_SYMBOL(decrypt_update, "EVP_DecryptUpdate");
  LOAD_OPENSSL_SYMBOL(set_padding, "EVP_CIPHER_CTX_set_padding");
#undef LOAD_OPENSSL_SYMBOL

  state->context = state->context_new();
  cipher = state->aes_128_ecb();
  if (state->context == NULL || cipher == NULL) {
    snprintf(error, error_size, "OpenSSL EVP AES-128-ECB is unavailable");
    return BACKEND_SKIPPED;
  }
  if (operation == AES_OPERATION_ENCRYPT) {
    initialized = state->encrypt_init(
        state->context, cipher, NULL, benchmark_key, NULL);
  } else {
    initialized = state->decrypt_init(
        state->context, cipher, NULL, benchmark_key, NULL);
  }
  if (initialized != 1 || state->set_padding(state->context, 0) != 1) {
    snprintf(error, error_size, "OpenSSL EVP context initialization failed");
    return BACKEND_SKIPPED;
  }
  return BACKEND_OK;
}

static int openssl_process(void* opaque, const uint8_t* input,
                           uint8_t* output, size_t length,
                           char* error, size_t error_size)
{
  struct openssl_state* state = (struct openssl_state*)opaque;
  int output_length = 0;
  int result;

  if (length > INT_MAX) {
    snprintf(error, error_size, "OpenSSL input exceeds INT_MAX");
    return -1;
  }
  if (state->operation == AES_OPERATION_ENCRYPT) {
    result = state->encrypt_update(state->context, output, &output_length,
                                   input, (int)length);
  } else {
    result = state->decrypt_update(state->context, output, &output_length,
                                   input, (int)length);
  }
  if (result != 1 || output_length != (int)length) {
    snprintf(error, error_size,
             "OpenSSL EVP update failed: result=%d output=%d expected=%zu",
             result, output_length, length);
    return -1;
  }
  return 0;
}

static void openssl_destroy(struct openssl_state* state)
{
  if (state->context != NULL && state->context_free != NULL) {
    state->context_free(state->context);
  }
  if (state->library != NULL) {
    dlclose(state->library);
  }
  memset(state, 0, sizeof(*state));
}

static void read_cpu_setting(int cpu, const char* setting,
                             char* output, size_t output_size)
{
  char path[PATH_MAX];
  FILE* file;

  snprintf(path, sizeof(path),
           "/sys/devices/system/cpu/cpu%d/cpufreq/%s", cpu, setting);
  file = fopen(path, "r");
  if (file == NULL || fgets(output, (int)output_size, file) == NULL) {
    snprintf(output, output_size, "unavailable");
  }
  if (file != NULL) {
    fclose(file);
  }
  output[strcspn(output, "\r\n")] = '\0';
}

static int benchmark_backend(const char* backend_name,
                             enum aes_operation operation,
                             void* backend_state,
                             backend_process_fn process,
                             const uint8_t* input,
                             const uint8_t* expected,
                             uint8_t* output,
                             const struct options* options)
{
  struct sample* samples;
  double* seconds;
  double* cycles_per_byte;
  double* mb_per_second;
  char error[192] = {0};
  char governor[64];
  char frequency[64];
  unsigned int index;
  int result = BACKEND_OK;
  uint64_t checksum;
  const char* operation_name = operation == AES_OPERATION_ENCRYPT ?
      "encrypt" : "decrypt";

  samples = (struct sample*)calloc(options->samples, sizeof(*samples));
  seconds = (double*)calloc(options->samples, sizeof(*seconds));
  cycles_per_byte = (double*)calloc(options->samples,
                                     sizeof(*cycles_per_byte));
  mb_per_second = (double*)calloc(options->samples,
                                  sizeof(*mb_per_second));
  if (samples == NULL || seconds == NULL || cycles_per_byte == NULL ||
      mb_per_second == NULL) {
    fprintf(stderr, "[AES-NATIVE] allocation failed for samples\n");
    result = BACKEND_FAILED;
    goto out;
  }

  for (index = 0; index < options->warmup; ++index) {
    if (process(backend_state, input, output, options->bytes,
                error, sizeof(error)) != 0) {
      result = BACKEND_FAILED;
      goto out;
    }
  }

  for (index = 0; index < options->samples; ++index) {
    struct timespec start;
    struct timespec end;
    uint64_t start_cycles;
    uint64_t end_cycles;
    double elapsed;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &start) != 0) {
      snprintf(error, sizeof(error), "clock_gettime: %s", strerror(errno));
      result = BACKEND_FAILED;
      goto out;
    }
    start_cycles = read_cycles();
    if (process(backend_state, input, output, options->bytes,
                error, sizeof(error)) != 0) {
      result = BACKEND_FAILED;
      goto out;
    }
    end_cycles = read_cycles();
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &end) != 0) {
      snprintf(error, sizeof(error), "clock_gettime: %s", strerror(errno));
      result = BACKEND_FAILED;
      goto out;
    }
    elapsed = timespec_delta(&start, &end);
    if (elapsed <= 0.0 || end_cycles < start_cycles) {
      snprintf(error, sizeof(error), "invalid timer sample");
      result = BACKEND_FAILED;
      goto out;
    }
    samples[index].seconds = elapsed;
    samples[index].cycles_per_byte =
        (double)(end_cycles - start_cycles) / (double)options->bytes;
    samples[index].mb_per_second =
        ((double)options->bytes / 1000000.0) / elapsed;
    seconds[index] = samples[index].seconds;
    cycles_per_byte[index] = samples[index].cycles_per_byte;
    mb_per_second[index] = samples[index].mb_per_second;
  }

  if (memcmp(output, expected, options->bytes) != 0) {
    snprintf(error, sizeof(error), "output verification failed");
    result = BACKEND_FAILED;
    goto out;
  }

  checksum = checksum64(output, options->bytes);
  read_cpu_setting(options->cpu, "scaling_governor",
                   governor, sizeof(governor));
  read_cpu_setting(options->cpu, "scaling_cur_freq",
                   frequency, sizeof(frequency));
  printf("[AES-NATIVE] backend=%s operation=%s cpu=%d data_mb=%.6f "
         "samples=%u warmup=%u optimization=O3 march=%s mabi=%s "
         "full_unroll=1 cycle_source=%s governor=%s freq_khz=%s "
         "seconds_median=%.9f seconds_p95=%.9f "
         "cycles_per_byte_median=%.4f cycles_per_byte_p95=%.4f "
         "mb_per_sec_median=%.3f mb_per_sec_p05=%.3f "
         "mb_per_sec_p95=%.3f checksum=%" PRIu64 " verify=PASS\n",
         backend_name, operation_name, options->cpu,
         (double)options->bytes / 1000000.0,
         options->samples, options->warmup, GROUP_PMP_AES_MARCH_STRING,
         GROUP_PMP_AES_MABI_STRING,
         native_counter_source(),
         governor, frequency,
         percentile(seconds, options->samples, 50),
         percentile(seconds, options->samples, 95),
         percentile(cycles_per_byte, options->samples, 50),
         percentile(cycles_per_byte, options->samples, 95),
         percentile(mb_per_second, options->samples, 50),
         percentile(mb_per_second, options->samples, 5),
         percentile(mb_per_second, options->samples, 95), checksum);

out:
  if (result == BACKEND_FAILED) {
    fprintf(stderr,
            "[AES-NATIVE] backend=%s operation=%s cpu=%d status=FAIL "
            "reason=\"%s\"\n",
            backend_name, operation_name, options->cpu,
            error[0] == '\0' ? "unknown" : error);
  }
  free(samples);
  free(seconds);
  free(cycles_per_byte);
  free(mb_per_second);
  return result;
}

static int run_backend(const char* backend,
                       enum aes_operation operation,
                       const uint8_t* plain,
                       const uint8_t* cipher,
                       uint8_t* output,
                       const struct options* options)
{
  const uint8_t* input = operation == AES_OPERATION_ENCRYPT ? plain : cipher;
  const uint8_t* expected = operation == AES_OPERATION_ENCRYPT ? cipher : plain;
  const char* operation_name = operation == AES_OPERATION_ENCRYPT ?
      "encrypt" : "decrypt";
  char error[192] = {0};
  int initialized;
  int result;

  if (strcmp(backend, "software") == 0) {
    struct software_state state;
    memset(&state, 0, sizeof(state));
    if (software_init(&state, operation) != 0) {
      fprintf(stderr, "[AES-NATIVE] backend=software operation=%s "
                      "cpu=%d status=FAIL reason=\"context init\"\n",
              operation_name, options->cpu);
      return BACKEND_FAILED;
    }
    result = benchmark_backend("software", operation, &state,
                               software_process, input, expected, output,
                               options);
    software_destroy(&state);
    return result;
  }

  if (strcmp(backend, "afalg") == 0) {
    struct afalg_state state;
    initialized = afalg_init(&state, operation, error, sizeof(error));
    if (initialized != BACKEND_OK) {
      printf("[AES-NATIVE] backend=afalg operation=%s cpu=%d status=SKIP "
             "reason=\"%s\"\n", operation_name, options->cpu, error);
      afalg_destroy(&state);
      return initialized;
    }
    result = benchmark_backend("afalg", operation, &state, afalg_process,
                               input, expected, output, options);
    afalg_destroy(&state);
    return result;
  }

  if (strcmp(backend, "openssl") == 0) {
    struct openssl_state state;
    initialized = openssl_init(&state, operation, error, sizeof(error));
    if (initialized != BACKEND_OK) {
      printf("[AES-NATIVE] backend=openssl operation=%s cpu=%d status=SKIP "
             "reason=\"%s\"\n", operation_name, options->cpu, error);
      openssl_destroy(&state);
      return initialized;
    }
    result = benchmark_backend("openssl", operation, &state, openssl_process,
                               input, expected, output, options);
    openssl_destroy(&state);
    return result;
  }

  return BACKEND_FAILED;
}

static int backend_selected(const char* requested, const char* backend)
{
  return strcmp(requested, "all") == 0 || strcmp(requested, backend) == 0;
}

static int operation_selected(const char* requested,
                              enum aes_operation operation)
{
  if (strcmp(requested, "both") == 0) {
    return 1;
  }
  return operation == AES_OPERATION_ENCRYPT ?
      strcmp(requested, "encrypt") == 0 : strcmp(requested, "decrypt") == 0;
}

int main(int argc, char** argv)
{
  static const char* backends[] = {"software", "afalg", "openssl"};
  static const enum aes_operation operations[] = {
    AES_OPERATION_ENCRYPT, AES_OPERATION_DECRYPT,
  };
  struct options options;
  uint8_t* plain = NULL;
  uint8_t* cipher = NULL;
  uint8_t* output = NULL;
  size_t backend_index;
  size_t operation_index;
  int parse_result;
  int failed = 0;

  parse_result = parse_options(argc, argv, &options);
  if (parse_result != 0) {
    if (parse_result < 0) {
      usage(argv[0]);
      return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
  }
  if (pin_to_cpu(options.cpu) != 0) {
    fprintf(stderr, "[AES-NATIVE] cannot pin to CPU%d: %s\n",
            options.cpu, strerror(errno));
    return EXIT_FAILURE;
  }
  native_counter_initialize();
  if (software_known_answer_test() != 0) {
    fprintf(stderr, "[AES-NATIVE] software AES known-answer test failed\n");
    return EXIT_FAILURE;
  }
  if (posix_memalign((void**)&plain, 64, options.bytes) != 0 ||
      posix_memalign((void**)&cipher, 64, options.bytes) != 0 ||
      posix_memalign((void**)&output, 64, options.bytes) != 0) {
    fprintf(stderr, "[AES-NATIVE] failed to allocate three %zu-byte buffers\n",
            options.bytes);
    failed = 1;
    goto out;
  }
  fill_plaintext(plain, options.bytes);
  memset(cipher, 0, options.bytes);
  memset(output, 0, options.bytes);
  if (generate_ciphertext(plain, cipher, options.bytes) != 0) {
    fprintf(stderr, "[AES-NATIVE] failed to generate reference ciphertext\n");
    failed = 1;
    goto out;
  }

  printf("[AES-NATIVE] start cpu=%d data_mb=%.6f samples=%u warmup=%u "
         "backend=%s operation=%s\n",
         options.cpu, (double)options.bytes / 1000000.0,
         options.samples, options.warmup,
         options.backend, options.operation);
  for (backend_index = 0;
       backend_index < sizeof(backends) / sizeof(backends[0]);
       ++backend_index) {
    if (!backend_selected(options.backend, backends[backend_index])) {
      continue;
    }
    for (operation_index = 0;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
      int result;
      if (!operation_selected(options.operation, operations[operation_index])) {
        continue;
      }
      result = run_backend(backends[backend_index], operations[operation_index],
                           plain, cipher, output, &options);
      if (result == BACKEND_FAILED) {
        failed = 1;
      }
    }
  }

out:
  free(plain);
  free(cipher);
  free(output);
  native_counter_destroy();
  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
