#ifndef GM_H
#define GM_H

#include <stdint.h>
#include <stddef.h>
#include <iostream>

#define GM_KEY_BYTES 32       
#define GM_PUBLIC_KEY_BYTES 16  
#define GM_PRIVATE_KEY_BYTES 16 
#ifdef __cplusplus
extern "C" {
#endif

void gm_generate_keys(uint8_t* public_key, uint8_t* private_key);

void gm_encrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* public_key);

void gm_decrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* private_key);

#ifdef __cplusplus
}
#endif

#endif