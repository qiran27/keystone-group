#ifndef GROUP_PMP_SECURITY_AEAD_CONFIG_H
#define GROUP_PMP_SECURITY_AEAD_CONFIG_H
#define MBEDTLS_AES_C
/* Keep the GCM AES context in private memory, without cipher heap callbacks. */
#define MBEDTLS_BLOCK_CIPHER_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_SELF_TEST
#endif
