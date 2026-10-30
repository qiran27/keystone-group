# Test-Only Cryptographic Dependency

- Upstream: https://github.com/Mbed-TLS/mbedtls
- Release: Mbed TLS 3.6.7.
- Archive: https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
- Verified upstream archive SHA-256:
  `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`.
- License: upstream Apache-2.0 OR GPL-2.0-or-later; LICENSE retained.
- Imported unchanged: public headers, library headers and C translation units
  aes, gcm, block_cipher, cipher, cipher_wrap, chacha20, poly1305, chachapoly,
  platform_util and constant_time. No complete upstream build tree is required.
- Local configuration: `../aead-config.h`. Hardware-specific AES, TLS, PSA,
  networking and production key management are not enabled.
- Consumers: only `group-pmp-security-aead-lib`, the standalone security eapp
  and native security regression. SQLite/fio/MediaBench performance workers
  do not link this library. Their existing AES-128-ECB remains unchanged.

Fixture v7 imports `library/block_cipher.c` unchanged from the same verified
release. The GCM build uses its inline AES context instead of the generic
heap-backed cipher adapter; the previously imported cipher sources are retained
but no longer compiled into the standalone security library. Upstream algorithms
and all GCM known-answer vectors remain unchanged.

Upstream known-answer self-tests and local negative tests are executed before
reporting AEAD security-fixture results. Public test keys and run-local nonces
are NOT a production key-establishment, anti-replay or anti-rollback design.
