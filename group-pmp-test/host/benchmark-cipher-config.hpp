#ifndef GROUP_PMP_BENCHMARK_CIPHER_CONFIG_HPP
#define GROUP_PMP_BENCHMARK_CIPHER_CONFIG_HPP
#include <cstdlib>
#include <cstring>
#include "../eapp/benchmark-cipher.h"

inline unsigned selected_benchmark_cipher() {
  const char* value = std::getenv("GROUP_PMP_BENCH_CIPHER");
  if (!value || !*value || !std::strcmp(value, "aes-ecb-128")) return BENCHMARK_AES_ECB;
  if (!std::strcmp(value, "aes-gcm-128")) return BENCHMARK_AES_GCM;
  if (!std::strcmp(value, "chacha20-poly1305")) return BENCHMARK_CHACHA_POLY;
  return 3;
}
inline const char* selected_benchmark_cipher_name() {
  return benchmark_cipher_name(selected_benchmark_cipher());
}
#endif
