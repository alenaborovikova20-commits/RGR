#ifndef MO_H
#define MO_H

#include <stdint.h>
#include <stddef.h>

#define MO_KEY_BYTES 24
#define MO_BLOCK_SIZE 1

#ifdef __cplusplus
extern "C" {
#endif

void mo_generate_keys(uint8_t* key);
void mo_encrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* key);
void mo_decrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* key);
void mo_generate_iv(uint8_t* iv);

#ifdef __cplusplus
}
#endif

#endif