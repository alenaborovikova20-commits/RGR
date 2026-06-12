#include "gost.h"
#include <cstring>
 
// S-блоки
static const uint8_t SBOX[8][16] = {
    {0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC},
    {0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC},
    {0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE},
    {0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2},
    {0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC},
    {0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC},
    {0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE},
    {0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2}
};
 
// Циклический сдвиг влево
static uint32_t rotate_left(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}
 
// Замена через S-блоки
static uint32_t substitution(uint32_t value) {
    uint32_t result = 0;
    
    for (int i = 0; i < 8; i++) {
        uint8_t nibble = (value >> (i * 4)) & 0x0F;
        result |= (uint32_t)SBOX[i][nibble] << (i * 4);
    }
    
    return result;
}
 
// Функция Фейстеля
static uint32_t feistel(uint32_t part, uint32_t key) {
    return rotate_left(substitution(part + key), 11);
}
 
// Подготовка ключей
void gost_prepare_keys(const uint8_t* user_key, uint32_t* round_keys) {
    for (int i = 0; i < 8; i++) {
        round_keys[i] = 0;
        round_keys[i] |= (uint32_t)user_key[i * 4 + 0];
        round_keys[i] |= (uint32_t)user_key[i * 4 + 1] << 8;
        round_keys[i] |= (uint32_t)user_key[i * 4 + 2] << 16;
        round_keys[i] |= (uint32_t)user_key[i * 4 + 3] << 24;
    }
}
 
// Шифрование блока
void gost_encrypt(const uint8_t* input, uint8_t* output, const uint32_t* round_keys) {
    uint32_t left, right;
    
    left = 0;
    left |= (uint32_t)input[0];
    left |= (uint32_t)input[1] << 8;
    left |= (uint32_t)input[2] << 16;
    left |= (uint32_t)input[3] << 24;
    
    right = 0;
    right |= (uint32_t)input[4];
    right |= (uint32_t)input[5] << 8;
    right |= (uint32_t)input[6] << 16;
    right |= (uint32_t)input[7] << 24;
    
    // 24 раунда с прямым порядком ключей
    for (int i = 0; i < 24; i++) {
        uint32_t temp = left;
        left = right ^ feistel(left, round_keys[i % 8]);
        right = temp;
    }
    
    // 8 раундов с обратным порядком ключей
    for (int i = 0; i < 8; i++) {
        uint32_t temp = left;
        left = right ^ feistel(left, round_keys[7 - i]);
        right = temp;
    }
    
    output[0] = left & 0xFF;
    output[1] = (left >> 8) & 0xFF;
    output[2] = (left >> 16) & 0xFF;
    output[3] = (left >> 24) & 0xFF;
    output[4] = right & 0xFF;
    output[5] = (right >> 8) & 0xFF;
    output[6] = (right >> 16) & 0xFF;
    output[7] = (right >> 24) & 0xFF;
}
 
// Расшифрование блока
void gost_decrypt(const uint8_t* input, uint8_t* output, const uint32_t* round_keys) {
    uint32_t left, right;
    
    left = 0;
    left |= (uint32_t)input[0];
    left |= (uint32_t)input[1] << 8;
    left |= (uint32_t)input[2] << 16;
    left |= (uint32_t)input[3] << 24;
    
    right = 0;
    right |= (uint32_t)input[4];
    right |= (uint32_t)input[5] << 8;
    right |= (uint32_t)input[6] << 16;
    right |= (uint32_t)input[7] << 24;
    
    // 8 раундов с прямым порядком ключей
    for (int i = 0; i < 8; i++) {
        uint32_t temp = left;
        left = right ^ feistel(left, round_keys[i]);
        right = temp;
    }
    
    // 24 раунда с обратным порядком ключей
    for (int i = 0; i < 24; i++) {
        uint32_t temp = left;
        left = right ^ feistel(left, round_keys[7 - (i % 8)]);
        right = temp;
    }
    
    output[0] = left & 0xFF;
    output[1] = (left >> 8) & 0xFF;
    output[2] = (left >> 16) & 0xFF;
    output[3] = (left >> 24) & 0xFF;
    output[4] = right & 0xFF;
    output[5] = (right >> 8) & 0xFF;
    output[6] = (right >> 16) & 0xFF;
    output[7] = (right >> 24) & 0xFF;
}
