#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aes_core.h"
#include "ecdsa_p256_bench.h"
#include "rsa2048_bench.h"
#include "sha256.h"
#include "sm2_bench.h"
#include "sm3.h"
#include "sm4.h"
#include "native_counter.h"

#ifndef GROUP_PMP_AES_MARCH_STRING
#define GROUP_PMP_AES_MARCH_STRING "unknown"
#endif
#ifndef GROUP_PMP_AES_MABI_STRING
#define GROUP_PMP_AES_MABI_STRING "unknown"
#endif

#define AES_BLOCK_SIZE 16U
#define DECIMAL_MB_BYTES 1000000U
#define BENCH_CHUNK_SIZE DECIMAL_MB_BYTES
#define DEFAULT_BYTES (10U * DECIMAL_MB_BYTES)
#define DEFAULT_SAMPLES 5U
#define DEFAULT_WARMUP 1U
#define MAX_SIGNATURE_SIZE 512U
#define NATIVE_CRYPTO_MATRIX_MARKER "keystone-native-crypto-ecc-sha256-v1"
#define NATIVE_CRYPTO_PORTABLE_OPENSSL_MARKER \
  "keystone-native-crypto-portable-openssl-v1"
#define NATIVE_CRYPTO_LOCAL_ECC_SM2_MARKER \
  "keystone-native-crypto-supplied-sm2-micro-ecc-v2"

static const volatile char native_crypto_matrix_marker[]
    __attribute__((used)) = NATIVE_CRYPTO_MATRIX_MARKER;
static const volatile char native_crypto_portable_openssl_marker[]
    __attribute__((used)) = NATIVE_CRYPTO_PORTABLE_OPENSSL_MARKER;
static const volatile char native_crypto_counter_marker[]
    __attribute__((used)) = KEYSTONE_NATIVE_COUNTER_MARKER;
static const volatile char native_crypto_local_ecc_sm2_marker[]
    __attribute__((used)) = NATIVE_CRYPTO_LOCAL_ECC_SM2_MARKER;

enum algorithm_id {
  ALGORITHM_AES128,
  ALGORITHM_RSA2048,
  ALGORITHM_ECDSA_P256,
  ALGORITHM_SM2,
  ALGORITHM_SHA256,
  ALGORITHM_SM3,
  ALGORITHM_SM4,
};

enum operation_id {
  OPERATION_ENCRYPT,
  OPERATION_DECRYPT,
  OPERATION_HASH,
  OPERATION_HASH_SIGN,
  OPERATION_HASH_VERIFY,
};

struct options {
  enum algorithm_id algorithm;
  enum operation_id operation;
  int cpu;
  uint64_t bytes;
  unsigned int samples;
  unsigned int warmup;
  int csv;
};

struct benchmark_state {
  struct options options;
  uint8_t* input;
  uint8_t* prepared_input;
  uint8_t* output;
  size_t chunk_size;
  void* aes_context;
  sm4_context sm4;
  struct rsa2048_bench_key* rsa;
  struct ecdsa_p256_bench_key* ecdsa;
  struct sm2_bench_key* sm2;
  uint8_t expected_digest[32];
  uint8_t prepared_signature[MAX_SIGNATURE_SIZE];
  size_t prepared_signature_size;
  uint8_t sample_signature[MAX_SIGNATURE_SIZE];
  size_t sample_signature_size;
  uint64_t primitive_cycles;
};

static const uint8_t benchmark_key[AES_BLOCK_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static void usage(const char* program)
{
  fprintf(stderr,
          "usage: %s --algorithm aes128|rsa2048|ecdsa|sm2|sha256|sm3|sm4 "
          "--operation encrypt|decrypt|hash|hash-sign|hash-verify "
          "[--cpu N] [--bytes N] [--samples N] [--warmup N] [--csv]\n",
          program);
}

static int parse_u64(const char* text, uint64_t minimum, uint64_t maximum,
                     uint64_t* value)
{
  char* end = NULL;
  unsigned long long parsed;

  errno = 0;
  parsed = strtoull(text, &end, 0);
  if (errno != 0 || end == text || *end != '\0' || parsed < minimum ||
      parsed > maximum) {
    return -1;
  }
  *value = (uint64_t)parsed;
  return 0;
}

static int parse_algorithm(const char* text, enum algorithm_id* algorithm)
{
  if (strcmp(text, "aes128") == 0) {
    *algorithm = ALGORITHM_AES128;
  } else if (strcmp(text, "rsa2048") == 0) {
    *algorithm = ALGORITHM_RSA2048;
  } else if (strcmp(text, "ecdsa") == 0) {
    *algorithm = ALGORITHM_ECDSA_P256;
  } else if (strcmp(text, "sm2") == 0) {
    *algorithm = ALGORITHM_SM2;
  } else if (strcmp(text, "sha256") == 0) {
    *algorithm = ALGORITHM_SHA256;
  } else if (strcmp(text, "sm3") == 0) {
    *algorithm = ALGORITHM_SM3;
  } else if (strcmp(text, "sm4") == 0) {
    *algorithm = ALGORITHM_SM4;
  } else {
    return -1;
  }
  return 0;
}

static int parse_operation(const char* text, enum operation_id* operation)
{
  if (strcmp(text, "encrypt") == 0) {
    *operation = OPERATION_ENCRYPT;
  } else if (strcmp(text, "decrypt") == 0) {
    *operation = OPERATION_DECRYPT;
  } else if (strcmp(text, "hash") == 0) {
    *operation = OPERATION_HASH;
  } else if (strcmp(text, "hash-sign") == 0) {
    *operation = OPERATION_HASH_SIGN;
  } else if (strcmp(text, "hash-verify") == 0) {
    *operation = OPERATION_HASH_VERIFY;
  } else {
    return -1;
  }
  return 0;
}

static int operation_matches_algorithm(enum algorithm_id algorithm,
                                       enum operation_id operation)
{
  if (algorithm == ALGORITHM_AES128 || algorithm == ALGORITHM_SM4) {
    return operation == OPERATION_ENCRYPT || operation == OPERATION_DECRYPT;
  }
  if (algorithm == ALGORITHM_SHA256 || algorithm == ALGORITHM_SM3) {
    return operation == OPERATION_HASH;
  }
  return operation == OPERATION_HASH_SIGN ||
         operation == OPERATION_HASH_VERIFY;
}

static int parse_options(int argc, char** argv, struct options* options)
{
  int have_algorithm = 0;
  int have_operation = 0;
  int index;

  memset(options, 0, sizeof(*options));
  options->cpu = 1;
  options->bytes = DEFAULT_BYTES;
  options->samples = DEFAULT_SAMPLES;
  options->warmup = DEFAULT_WARMUP;

  for (index = 1; index < argc; ++index) {
    uint64_t parsed;

    if (strcmp(argv[index], "--help") == 0) {
      usage(argv[0]);
      return 1;
    }
    if (strcmp(argv[index], "--csv") == 0) {
      options->csv = 1;
      continue;
    }
    if (index + 1 >= argc) {
      return -1;
    }
    if (strcmp(argv[index], "--algorithm") == 0) {
      if (parse_algorithm(argv[++index], &options->algorithm) != 0) {
        return -1;
      }
      have_algorithm = 1;
    } else if (strcmp(argv[index], "--operation") == 0) {
      if (parse_operation(argv[++index], &options->operation) != 0) {
        return -1;
      }
      have_operation = 1;
    } else if (strcmp(argv[index], "--cpu") == 0) {
      if (parse_u64(argv[++index], 0, CPU_SETSIZE - 1, &parsed) != 0) {
        return -1;
      }
      options->cpu = (int)parsed;
    } else if (strcmp(argv[index], "--bytes") == 0) {
      if (parse_u64(argv[++index], AES_BLOCK_SIZE, UINT64_MAX, &parsed) != 0 ||
          (parsed % AES_BLOCK_SIZE) != 0) {
        return -1;
      }
      options->bytes = parsed;
    } else if (strcmp(argv[index], "--samples") == 0) {
      if (parse_u64(argv[++index], 1, 100, &parsed) != 0) {
        return -1;
      }
      options->samples = (unsigned int)parsed;
    } else if (strcmp(argv[index], "--warmup") == 0) {
      if (parse_u64(argv[++index], 0, 20, &parsed) != 0) {
        return -1;
      }
      options->warmup = (unsigned int)parsed;
    } else {
      return -1;
    }
  }
  if (!have_algorithm || !have_operation ||
      !operation_matches_algorithm(options->algorithm, options->operation)) {
    return -1;
  }
  return 0;
}

static const char* algorithm_name(enum algorithm_id algorithm)
{
  static const char* names[] = {"aes-128-ecb", "rsa-2048-pss",
                                "ecdsa-p256", "sm2", "sha-256",
                                "sm3", "sm4-ecb"};
  return names[algorithm];
}

static const char* operation_name(enum operation_id operation)
{
  static const char* names[] = {"encrypt", "decrypt", "hash", "hash-sign",
                                "hash-verify"};
  return names[operation];
}

static const char* implementation_name(enum algorithm_id algorithm)
{
  static const char* names[] = {"project-aes_core", "openssl-rsa-pss",
                                "micro-ecc-secp256r1",
                                "supplied-sm2-formula-openssl-ec",
                                "project-sha256", "project-sm3",
                                "project-sm4"};
  return names[algorithm];
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

static double elapsed_seconds(const struct timespec* start,
                              const struct timespec* end)
{
  return (double)(end->tv_sec - start->tv_sec) +
         (double)(end->tv_nsec - start->tv_nsec) / 1000000000.0;
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

static void fill_input(uint8_t* data, size_t length)
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

static int sm3_stream(const uint8_t* data, size_t chunk_size, uint64_t bytes,
                      uint8_t digest[32])
{
  sm3_context context;
  uint64_t remaining = bytes;

  sm3_starts(&context);
  while (remaining != 0) {
    size_t current = remaining < chunk_size ? (size_t)remaining : chunk_size;
    sm3_update(&context, (unsigned char*)data, (int)current);
    remaining -= current;
  }
  sm3_finish(&context, digest);
  memset(&context, 0, sizeof(context));
  return 0;
}

static int project_sha256_stream(const uint8_t* data, size_t chunk_size,
                                 uint64_t bytes, uint8_t digest[32])
{
  SHA256_CTX context;
  uint64_t remaining = bytes;

  sha256_init(&context);
  while (remaining != 0) {
    size_t current = remaining < chunk_size ? (size_t)remaining : chunk_size;
    sha256_update(&context, data, current);
    remaining -= current;
  }
  sha256_final(&context, digest);
  memset(&context, 0, sizeof(context));
  return 0;
}

static const char* known_answer_test_failure(void)
{
  static const uint8_t aes_plain[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  };
  static const uint8_t aes_expected[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  };
  static const uint8_t sm3_expected[32] = {
    0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
    0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
    0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
    0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
  };
  static const uint8_t sha256_expected[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
  };
  static uint8_t sm4_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
  };
  static const uint8_t sm4_expected[16] = {
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
  };
  uint8_t output[32];
  void* aes = aes_encrypt_init(benchmark_key, sizeof(benchmark_key));
  sm4_context sm4;

  if (aes == NULL) {
    return "aes128-init";
  }
  aes_encrypt(aes, aes_plain, output);
  aes_encrypt_deinit(aes);
  if (memcmp(output, aes_expected, 16) != 0) {
    return "aes128";
  }
  {
    SHA256_CTX sha256;
    sha256_init(&sha256);
    sha256_update(&sha256, (const BYTE*)"abc", 3);
    sha256_final(&sha256, output);
  }
  if (memcmp(output, sha256_expected, sizeof(sha256_expected)) != 0) {
    return "sha256";
  }
  sm3((unsigned char*)"abc", 3, output);
  if (memcmp(output, sm3_expected, sizeof(sm3_expected)) != 0) {
    return "sm3";
  }
  sm4_setkey_enc(&sm4, sm4_key);
  sm4_crypt_ecb(&sm4, SM4_ENCRYPT, 16, sm4_key, output);
  return memcmp(output, sm4_expected, 16) == 0 ? NULL : "sm4";
}

static int setup_state(struct benchmark_state* state,
                       const struct options* options)
{
  uint8_t digest[32];

  memset(state, 0, sizeof(*state));
  state->options = *options;
  state->chunk_size = options->bytes < BENCH_CHUNK_SIZE ?
      (size_t)options->bytes : BENCH_CHUNK_SIZE;
  state->chunk_size &= ~(size_t)(AES_BLOCK_SIZE - 1U);
  if (posix_memalign((void**)&state->input, 64, state->chunk_size) != 0 ||
      posix_memalign((void**)&state->prepared_input, 64,
                     state->chunk_size) != 0 ||
      posix_memalign((void**)&state->output, 64, state->chunk_size) != 0) {
    return -1;
  }
  fill_input(state->input, state->chunk_size);
  memset(state->prepared_input, 0, state->chunk_size);
  memset(state->output, 0, state->chunk_size);

  if (options->algorithm == ALGORITHM_AES128) {
    void* encrypt_context;
    if (options->operation == OPERATION_ENCRYPT) {
      state->aes_context = aes_encrypt_init(benchmark_key,
                                            sizeof(benchmark_key));
      if (state->aes_context == NULL) {
        return -1;
      }
      aes_encrypt_blocks(state->aes_context, state->input,
                         state->prepared_input,
                         state->chunk_size / AES_BLOCK_SIZE);
    } else {
      state->aes_context = aes_decrypt_init(benchmark_key,
                                            sizeof(benchmark_key));
      encrypt_context = aes_encrypt_init(benchmark_key, sizeof(benchmark_key));
      if (encrypt_context == NULL) {
        return -1;
      }
      aes_encrypt_blocks(encrypt_context, state->input, state->prepared_input,
                         state->chunk_size / AES_BLOCK_SIZE);
      aes_encrypt_deinit(encrypt_context);
    }
    return state->aes_context == NULL ? -1 : 0;
  }

  if (options->algorithm == ALGORITHM_SM4) {
    uint8_t key[16];
    memcpy(key, benchmark_key, sizeof(key));
    if (options->operation == OPERATION_ENCRYPT) {
      sm4_setkey_enc(&state->sm4, key);
      sm4_crypt_ecb(&state->sm4, SM4_ENCRYPT, (int)state->chunk_size,
                    state->input, state->prepared_input);
    } else {
      sm4_context encrypt_context;
      sm4_setkey_enc(&encrypt_context, key);
      sm4_crypt_ecb(&encrypt_context, SM4_ENCRYPT, (int)state->chunk_size,
                    state->input, state->prepared_input);
      sm4_setkey_dec(&state->sm4, key);
    }
    return 0;
  }

  if (options->algorithm == ALGORITHM_SHA256) {
    return project_sha256_stream(state->input, state->chunk_size,
                                 options->bytes, state->expected_digest);
  }

  if (options->algorithm == ALGORITHM_SM3) {
    return sm3_stream(state->input, state->chunk_size, options->bytes,
                      state->expected_digest);
  }

  if (options->algorithm == ALGORITHM_RSA2048) {
    state->rsa = rsa2048_bench_key_create();
    if (state->rsa == NULL ||
        project_sha256_stream(state->input, state->chunk_size, options->bytes,
                              digest) != 0) {
      return -1;
    }
    state->prepared_signature_size = sizeof(state->prepared_signature);
    return rsa2048_bench_sign(state->rsa, digest,
                              state->prepared_signature,
                              &state->prepared_signature_size);
  }

  if (options->algorithm == ALGORITHM_ECDSA_P256) {
    state->ecdsa = ecdsa_p256_bench_key_create();
    if (state->ecdsa == NULL ||
        project_sha256_stream(state->input, state->chunk_size, options->bytes,
                              digest) != 0) {
      return -1;
    }
    state->prepared_signature_size = sizeof(state->prepared_signature);
    return ecdsa_p256_bench_sign(state->ecdsa, digest,
                                 state->prepared_signature,
                                 &state->prepared_signature_size);
  }

  state->sm2 = sm2_bench_key_create();
  if (state->sm2 == NULL ||
      sm3_stream(state->input, state->chunk_size, options->bytes, digest) != 0) {
    return -1;
  }
  state->prepared_signature_size = sizeof(state->prepared_signature);
  return sm2_bench_sign(state->sm2, digest, state->prepared_signature,
                        &state->prepared_signature_size);
}

static void destroy_state(struct benchmark_state* state)
{
  if (state->aes_context != NULL) {
    if (state->options.operation == OPERATION_ENCRYPT) {
      aes_encrypt_deinit(state->aes_context);
    } else {
      aes_decrypt_deinit(state->aes_context);
    }
  }
  rsa2048_bench_key_destroy(state->rsa);
  ecdsa_p256_bench_key_destroy(state->ecdsa);
  sm2_bench_key_destroy(state->sm2);
  free(state->input);
  free(state->prepared_input);
  free(state->output);
  memset(state, 0, sizeof(*state));
}

static int execute_symmetric(struct benchmark_state* state)
{
  const uint8_t* input = state->options.operation == OPERATION_ENCRYPT ?
      state->input : state->prepared_input;
  uint64_t remaining = state->options.bytes;
  uint64_t start = read_cycles();

  while (remaining != 0) {
    size_t current = remaining < state->chunk_size ?
        (size_t)remaining : state->chunk_size;
    if (state->options.algorithm == ALGORITHM_AES128) {
      if (state->options.operation == OPERATION_ENCRYPT) {
        aes_encrypt_blocks(state->aes_context, input, state->output,
                           current / AES_BLOCK_SIZE);
      } else {
        aes_decrypt_blocks(state->aes_context, input, state->output,
                           current / AES_BLOCK_SIZE);
      }
    } else {
      sm4_crypt_ecb(&state->sm4,
                    state->options.operation == OPERATION_ENCRYPT ?
                        SM4_ENCRYPT : SM4_DECRYPT,
                    (int)current, (unsigned char*)input, state->output);
    }
    remaining -= current;
  }
  state->primitive_cycles = read_cycles() - start;
  return 0;
}

static int execute_public_key(struct benchmark_state* state)
{
  uint8_t digest[32];
  uint64_t start;

  if (state->options.algorithm == ALGORITHM_RSA2048) {
    if (project_sha256_stream(state->input, state->chunk_size,
                              state->options.bytes, digest) != 0) {
      return -1;
    }
    start = read_cycles();
    if (state->options.operation == OPERATION_HASH_SIGN) {
      state->sample_signature_size = sizeof(state->sample_signature);
      if (rsa2048_bench_sign(state->rsa, digest, state->sample_signature,
                             &state->sample_signature_size) != 0) {
        return -1;
      }
    } else if (rsa2048_bench_verify(state->rsa, digest,
                                    state->prepared_signature,
                                    state->prepared_signature_size) != 0) {
      return -1;
    }
  } else if (state->options.algorithm == ALGORITHM_ECDSA_P256) {
    if (project_sha256_stream(state->input, state->chunk_size,
                              state->options.bytes, digest) != 0) {
      return -1;
    }
    start = read_cycles();
    if (state->options.operation == OPERATION_HASH_SIGN) {
      state->sample_signature_size = sizeof(state->sample_signature);
      if (ecdsa_p256_bench_sign(state->ecdsa, digest,
                                state->sample_signature,
                                &state->sample_signature_size) != 0) {
        return -1;
      }
    } else if (ecdsa_p256_bench_verify(
                   state->ecdsa, digest, state->prepared_signature,
                   state->prepared_signature_size) != 0) {
      return -1;
    }
  } else {
    sm3_stream(state->input, state->chunk_size, state->options.bytes, digest);
    start = read_cycles();
    if (state->options.operation == OPERATION_HASH_SIGN) {
      state->sample_signature_size = sizeof(state->sample_signature);
      if (sm2_bench_sign(state->sm2, digest, state->sample_signature,
                         &state->sample_signature_size) != 0) {
        return -1;
      }
    } else if (sm2_bench_verify(state->sm2, digest,
                                state->prepared_signature,
                                state->prepared_signature_size) != 0) {
      return -1;
    }
  }
  state->primitive_cycles = read_cycles() - start;
  memcpy(state->output, digest, sizeof(digest));
  return 0;
}

static int execute_once(struct benchmark_state* state)
{
  uint64_t start;

  state->primitive_cycles = 0;
  if (state->options.algorithm == ALGORITHM_AES128 ||
      state->options.algorithm == ALGORITHM_SM4) {
    return execute_symmetric(state);
  }
  if (state->options.algorithm == ALGORITHM_SHA256) {
    start = read_cycles();
    project_sha256_stream(state->input, state->chunk_size,
                          state->options.bytes, state->output);
    state->primitive_cycles = read_cycles() - start;
    return 0;
  }
  if (state->options.algorithm == ALGORITHM_SM3) {
    start = read_cycles();
    sm3_stream(state->input, state->chunk_size, state->options.bytes,
               state->output);
    state->primitive_cycles = read_cycles() - start;
    return 0;
  }
  return execute_public_key(state);
}

static int verify_sample(struct benchmark_state* state)
{
  if (state->options.algorithm == ALGORITHM_AES128 ||
      state->options.algorithm == ALGORITHM_SM4) {
    const uint8_t* expected = state->options.operation == OPERATION_ENCRYPT ?
        state->prepared_input : state->input;
    return memcmp(state->output, expected, state->chunk_size) == 0 ? 0 : -1;
  }
  if (state->options.algorithm == ALGORITHM_SHA256 ||
      state->options.algorithm == ALGORITHM_SM3) {
    return memcmp(state->output, state->expected_digest, 32) == 0 ? 0 : -1;
  }
  if (state->options.operation == OPERATION_HASH_VERIFY) {
    return 0;
  }
  if (state->options.algorithm == ALGORITHM_RSA2048) {
    return rsa2048_bench_verify(state->rsa, state->output,
                                state->sample_signature,
                                state->sample_signature_size);
  }
  if (state->options.algorithm == ALGORITHM_ECDSA_P256) {
    return ecdsa_p256_bench_verify(state->ecdsa, state->output,
                                   state->sample_signature,
                                   state->sample_signature_size);
  }
  return sm2_bench_verify(state->sm2, state->output, state->sample_signature,
                          state->sample_signature_size);
}

static uint64_t sample_checksum(const struct benchmark_state* state)
{
  uint64_t value;

  if ((state->options.algorithm == ALGORITHM_RSA2048 ||
       state->options.algorithm == ALGORITHM_ECDSA_P256 ||
       state->options.algorithm == ALGORITHM_SM2) &&
      state->options.operation == OPERATION_HASH_SIGN) {
    value = checksum64(state->sample_signature, state->sample_signature_size);
  } else if (state->options.algorithm == ALGORITHM_AES128 ||
             state->options.algorithm == ALGORITHM_SM4) {
    value = checksum64(state->output, state->chunk_size);
  } else {
    value = checksum64(state->output, 32);
  }
  return value ^ state->options.bytes;
}

static void print_sample(const struct benchmark_state* state,
                         unsigned int round, double seconds, uint64_t cycles)
{
  double mb = (double)state->options.bytes / 1000000.0;
  double mb_per_second = mb / seconds;
  double cycles_per_byte = (double)cycles / (double)state->options.bytes;

  if (state->options.csv) {
    printf("%s,%s,%s,%d,%.0f,%" PRIu64 ",%zu,%u,%.9f,%" PRIu64
           ",%" PRIu64 ",%.6f,%.6f,%" PRIu64 ",PASS,%s,%s,%s\n",
           algorithm_name(state->options.algorithm),
           operation_name(state->options.operation),
           implementation_name(state->options.algorithm), state->options.cpu,
           mb, state->options.bytes, state->chunk_size, round, seconds, cycles,
           state->primitive_cycles, cycles_per_byte, mb_per_second,
           sample_checksum(state), GROUP_PMP_AES_MARCH_STRING,
           GROUP_PMP_AES_MABI_STRING, native_counter_source());
  } else {
    printf("[CRYPTO-NATIVE] algorithm=%s operation=%s implementation=%s "
           "cpu=%d data_mb=%.6f stream_chunk_mb=%.6f round=%u "
           "seconds=%.9f cycles=%" PRIu64
           " primitive_cycles=%" PRIu64 " cycles_per_byte=%.6f "
           "mb_per_sec=%.6f checksum=%" PRIu64
           " verify=PASS march=%s mabi=%s counter_source=%s\n",
           algorithm_name(state->options.algorithm),
           operation_name(state->options.operation),
           implementation_name(state->options.algorithm), state->options.cpu,
           mb, (double)state->chunk_size / 1000000.0,
           round, seconds, cycles,
           state->primitive_cycles, cycles_per_byte, mb_per_second,
           sample_checksum(state), GROUP_PMP_AES_MARCH_STRING,
           GROUP_PMP_AES_MABI_STRING, native_counter_source());
  }
}

int main(int argc, char** argv)
{
  struct benchmark_state state;
  struct options options;
  unsigned int index;
  const char* kat_failure;
  int parsed = parse_options(argc, argv, &options);

  if (parsed != 0) {
    if (parsed < 0) {
      usage(argv[0]);
      return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
  }
  if (pin_to_cpu(options.cpu) != 0) {
    fprintf(stderr, "[CRYPTO-NATIVE] cannot pin to CPU%d: %s\n",
            options.cpu, strerror(errno));
    return EXIT_FAILURE;
  }
  native_counter_initialize();
  kat_failure = known_answer_test_failure();
  if (kat_failure != NULL) {
    fprintf(stderr,
            "[CRYPTO-NATIVE] known-answer test failed: algorithm=%s\n",
            kat_failure);
    return EXIT_FAILURE;
  }
  if (setup_state(&state, &options) != 0) {
    fprintf(stderr, "[CRYPTO-NATIVE] setup failed for %s/%s\n",
            algorithm_name(options.algorithm),
            operation_name(options.operation));
    destroy_state(&state);
    return EXIT_FAILURE;
  }

  for (index = 0; index < options.warmup; ++index) {
    if (execute_once(&state) != 0) {
      fprintf(stderr, "[CRYPTO-NATIVE] warmup execution failed for %s/%s\n",
              algorithm_name(options.algorithm),
              operation_name(options.operation));
      destroy_state(&state);
      return EXIT_FAILURE;
    }
    if (verify_sample(&state) != 0) {
      fprintf(stderr,
              "[CRYPTO-NATIVE] warmup verification failed for %s/%s\n",
              algorithm_name(options.algorithm),
              operation_name(options.operation));
      destroy_state(&state);
      return EXIT_FAILURE;
    }
  }

  for (index = 0; index < options.samples; ++index) {
    struct timespec start_time;
    struct timespec end_time;
    uint64_t start_cycles;
    uint64_t end_cycles;
    double seconds;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &start_time) != 0) {
      destroy_state(&state);
      return EXIT_FAILURE;
    }
    start_cycles = read_cycles();
    if (execute_once(&state) != 0) {
      fprintf(stderr, "[CRYPTO-NATIVE] measured operation failed\n");
      destroy_state(&state);
      return EXIT_FAILURE;
    }
    end_cycles = read_cycles();
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &end_time) != 0 ||
        verify_sample(&state) != 0) {
      fprintf(stderr, "[CRYPTO-NATIVE] sample verification failed\n");
      destroy_state(&state);
      return EXIT_FAILURE;
    }
    seconds = elapsed_seconds(&start_time, &end_time);
    if (seconds <= 0.0 || end_cycles < start_cycles) {
      fprintf(stderr, "[CRYPTO-NATIVE] invalid timing sample\n");
      destroy_state(&state);
      return EXIT_FAILURE;
    }
    print_sample(&state, index + 1, seconds, end_cycles - start_cycles);
  }

  destroy_state(&state);
  native_counter_destroy();
  return EXIT_SUCCESS;
}
