#ifndef GROUP_PMP_AES_CORE_H
#define GROUP_PMP_AES_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void* aes_encrypt_init(const uint8_t* key, size_t len);
void aes_encrypt(void* ctx, const uint8_t* plain, uint8_t* crypt);
void aes_encrypt_blocks(void* ctx, const uint8_t* plain, uint8_t* crypt,
                        size_t block_count);
void aes_encrypt_deinit(void* ctx);
void* aes_decrypt_init(const uint8_t* key, size_t len);
void aes_decrypt(void* ctx, const uint8_t* crypt, uint8_t* plain);
void aes_decrypt_blocks(void* ctx, const uint8_t* crypt, uint8_t* plain,
                        size_t block_count);
void aes_decrypt_deinit(void* ctx);

#ifdef __cplusplus
}
#endif

#endif
