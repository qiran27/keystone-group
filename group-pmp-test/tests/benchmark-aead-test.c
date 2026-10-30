#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../eapp/benchmark-cipher.h"
#include "../security/security-aead.h"

int main(void) {
  uint8_t key[32] = {0}, plain[4096], cipher[4096], snapshot[4096], out[4096], tag[16];
  memset(plain, 77, sizeof(plain));
  assert(security_aead_self_test() == 0);
  for (unsigned alg = 1; alg <= 2; ++alg) {
    struct benchmark_aead_identity id = {17, 3, 7, 4096, 8000000, 8192, 4096, 19};
    assert(benchmark_aead_init(alg, key) == 0);
    assert(benchmark_aead_seal(&id, plain, cipher, tag) == 0);
    assert(benchmark_aead_seal(&id, plain, cipher, tag) != 0);
    assert(benchmark_aead_open(&id, cipher, tag, out) == 0);
    assert(!memcmp(plain, out, sizeof(out)));
    struct benchmark_aead_identity wrong = id;
    ++wrong.file_offset;
    assert(benchmark_aead_open(&wrong, cipher, tag, out) != 0);
    wrong = id; ++wrong.worker;
    assert(benchmark_aead_open(&wrong, cipher, tag, out) != 0);
    wrong = id; ++wrong.logical_offset;
    assert(benchmark_aead_open(&wrong, cipher, tag, out) != 0);
    wrong = id; ++wrong.workload;
    assert(benchmark_aead_open(&wrong, cipher, tag, out) != 0);
    tag[0] ^= 1;
    assert(benchmark_aead_open(&id, cipher, tag, out) != 0);
    for (size_t i = 0; i < sizeof(out); ++i) assert(!out[i]);
    tag[0] ^= 1;
    memcpy(snapshot, cipher, sizeof(cipher));
    cipher[0] ^= 1;
    assert(benchmark_aead_open(&id, cipher, tag, out) != 0);
    assert(benchmark_aead_open(&id, snapshot, tag, out) == 0);
    assert(!memcmp(plain, out, sizeof(out)));
    benchmark_aead_free();
  }
  puts("AEAD KAT, identity/tag/cipher tamper, nonce reuse rejection and private snapshot PASS");
}
