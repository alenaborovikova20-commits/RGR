#ifndef RC5_H
#define RC5_H

#include <cstdint>
#include <cstddef>
#include <iostream>

#define RC5_BLOCK_SIZE 8
#define RC5_ROUNDS 12
#define RC5_KEY_BYTES 16

void rc5_expand_key(const uint8_t* key, uint32_t* S);

void rc5_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* S);

void rc5_decrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* S);

#endif