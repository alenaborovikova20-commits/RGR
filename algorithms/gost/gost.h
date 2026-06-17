#ifndef GOST_H
#define GOST_H
 
#include <cstdint>
#include <cstddef>
 
#define GOST_BLOCK 8     
#define GOST_KEY 32       
#define GOST_ROUNDS 32    
 
void gost_prepare_keys(const uint8_t* user_key, uint32_t* round_keys);
void gost_encrypt_block(const uint8_t* input, uint8_t* output, const uint32_t* round_keys);
void gost_decrypt_block(const uint8_t* input, uint8_t* output, const uint32_t* round_keys);
 
#endif
