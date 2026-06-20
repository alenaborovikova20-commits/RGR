#ifndef THREEFISH_H
#define THREEFISH_H

#include <cstdint>
#include <cstddef>
#include <iostream>

#define TF_BLOCK_SIZE 64      
#define TF_WORDS 8            
#define TF_ROUNDS 72          
#define TF_KEY_BYTES 64       
#define TF_TWEAK_BYTES 16     

void threefish_key_schedule(const uint64_t* key, const uint64_t* tweak, uint64_t* round_keys);

void threefish_encrypt_block(const uint8_t* in, uint8_t* out, const uint64_t* round_keys);

void threefish_decrypt_block(const uint8_t* in, uint8_t* out, const uint64_t* round_keys);

void threefish_generate_iv(uint8_t* iv);

#endif