#include "../security/security-aead.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
  assert(security_aead_self_test() == 0);
  assert(security_aead_self_test_algorithm(SECURITY_AEAD_GCM) == 0);
  assert(security_aead_self_test_algorithm(SECURITY_AEAD_CHACHA) == 0);
  assert(security_aead_self_test_algorithm(0) != 0);
  assert(security_aead_self_test_algorithm(3) != 0);
  for (unsigned algorithm = 1; algorithm <= 2; ++algorithm) {
    uint8_t key[32] = {0}, plain[SECURITY_AEAD_BYTES], output[SECURITY_AEAD_BYTES];
    uint8_t expected[40];
    memset(plain, 0x42, sizeof(plain));
    for (unsigned iteration = 0; iteration < 32; ++iteration) {
      struct security_aead_packet packet = {0};
      packet.nonce[0] = (uint8_t)iteration;
      packet.aad[0] = 7;
      memcpy(expected, packet.aad, sizeof(expected));
      assert(!security_aead_encrypt(algorithm, key, plain, &packet));
      for (unsigned attack = 0; attack < 7; ++attack) {
        struct security_aead_packet changed = packet;
        memset(output, 0xa5, sizeof(output));
        if (attack == 1) changed.ciphertext[0] ^= 1;
        if (attack == 2) changed.tag[0] ^= 1;
        if (attack == 3) changed.nonce[0] ^= 1;
        if (attack == 4) changed.aad[0] ^= 1;
        if (attack == 5) {
          changed.aad[8] = 1;
          changed.nonce[11] ^= 1;
          assert(!security_aead_encrypt(algorithm, key, plain, &changed));
        }
        if (attack == 6) {
          changed.aad[0] = 2;
          changed.nonce[11] ^= 2;
          assert(!security_aead_encrypt(algorithm, key, plain, &changed));
        }
        const int rc = security_aead_open(algorithm, key, &changed, expected, output);
        if (!attack) assert(!rc && !memcmp(output, plain, sizeof(plain)));
        else {
          assert(rc != 0);
          for (size_t i = 0; i < sizeof(output); ++i) assert(output[i] == 0xa5);
        }
      }
      struct security_aead_packet snapshot = packet;
      struct security_aead_packet forged_aad = packet;
      forged_aad.aad[0] ^= 1;
      memset(output, 0xa5, sizeof(output));
      /* Even if identity checking accepts the new AAD, authentication must fail. */
      assert(security_aead_open(algorithm, key, &forged_aad, forged_aad.aad, output) != 0);
      for (size_t i = 0; i < sizeof(output); ++i) assert(output[i] == 0xa5);
      packet.ciphertext[17] ^= 1; /* UTM changed after snapshot. */
      assert(!security_aead_open(algorithm, key, &snapshot, expected, output));
      assert(!memcmp(output, plain, sizeof(plain)));
    }
  }
  puts("AEAD KATs, tamper, object/range identity, failure output and snapshot tests PASS");
  return 0;
}
