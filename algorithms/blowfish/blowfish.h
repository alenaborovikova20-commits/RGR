#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <cstdint>
#include <cstddef>
#include <iostream>

#define BLOWFISH_BLOCK_SIZE 8
#define BLOWFISH_KEY_BYTES 16

#ifdef __cplusplus
extern "C" {
#endif

void blowfish_expand_key(const uint8_t* key, uint32_t* P, uint32_t (*S)[256]);
void blowfish_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* P, const uint32_t (*S)[256]);
void blowfish_decrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* P, const uint32_t (*S)[256]);

#ifdef __cplusplus
}
#endif

#endif