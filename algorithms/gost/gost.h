#ifndef GOST_H
#define GOST_H
 
#include <cstdint>
 
#define GOST_BLOCK 8      // размер блока 
#define GOST_KEY 32       // размер ключа 
 
// Подготовка ключей для шифрования
void gost_prepare_keys(const uint8_t* user_key, uint32_t* round_keys);
 
// Шифрование одного блока (8 байт -> 8 байт)
void gost_encrypt(const uint8_t* input, uint8_t* output, const uint32_t* round_keys);
 
// Расшифрование одного блока (8 байт -> 8 байт)
void gost_decrypt(const uint8_t* input, uint8_t* output, const uint32_t* round_keys);
 
#endif
