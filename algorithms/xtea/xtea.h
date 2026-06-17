#ifndef XTEA_H
#define XTEA_H
 
#include <cstdint>
 
#define XTEA_BLOCK 8      // размер блока
#define XTEA_KEY 16       // размер ключа 
#define XTEA_ROUNDS 32    // количество раундов
 
// Подготовка ключей для шифрования
void xtea_prepare_keys(const uint8_t* user_key, uint32_t* round_keys);
 
// Шифрование одного блока (8 байт -> 8 байт)
void xtea_encrypt(const uint8_t* input, uint8_t* output, const uint32_t* round_keys);
 
// Расшифрование одного блока (8 байт -> 8 байт)
void xtea_decrypt(const uint8_t* input, uint8_t* output, const uint32_t* round_keys);
 
#endif