#ifndef GM_H
#define GM_H

#include <stdint.h>
#include <stddef.h>

#define GM_KEY_BYTES 32
#define GM_BLOCK_SIZE 1

#ifdef __cplusplus
extern "C" {
#endif

void gm_generate_keys(uint8_t* key);
void gm_encrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* key);
void gm_decrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* key);
void gm_generate_iv(uint8_t* iv);

#ifdef __cplusplus
}
#endif

#endif