#ifndef XTEA_H
#define XTEA_H
 
#include <cstdint>
#include <iostream>

#define XTEA_BLOCK 8      
#define XTEA_KEY 16        
#define XTEA_ROUNDS 32    
 
void xtea_prepare_keys(const uint8_t* user_key, uint32_t* round_keys);
 
void xtea_encrypt(const uint8_t* input, uint8_t* output, const uint32_t* round_keys);
 
void xtea_decrypt(const uint8_t* input, uint8_t* output, const uint32_t* round_keys);
 
#endif