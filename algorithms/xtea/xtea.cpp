#include "xtea.h"
 
static const uint32_t DELTA = 0x9E3779B9;
 
// Из 16 байт ключа делаем 4 ключа по 32 бита
void xtea_prepare_keys(const uint8_t* user_key, uint32_t* round_keys) {
    for (int i = 0; i < 4; i++) {
        round_keys[i] = 0;
        round_keys[i] |= (uint32_t)user_key[i * 4 + 0];
        round_keys[i] |= (uint32_t)user_key[i * 4 + 1] << 8;
        round_keys[i] |= (uint32_t)user_key[i * 4 + 2] << 16;
        round_keys[i] |= (uint32_t)user_key[i * 4 + 3] << 24;
    }
}
 
// Шифрование
void xtea_encrypt(const uint8_t* input, uint8_t* output, const uint32_t* round_keys) {
    uint32_t left, right;
    
    // Собираем 8 байт в два 32-битных числа
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
    
    uint32_t sum = 0;
    
    for (int i = 0; i < XTEA_ROUNDS; i++) {
        left += (((right << 4) ^ (right >> 5)) + right) ^ (sum + round_keys[sum & 3]);
        sum += DELTA;
        right += (((left << 4) ^ (left >> 5)) + left) ^ (sum + round_keys[(sum >> 11) & 3]);
    }
    
    // Разбираем обратно в 8 байт
    output[0] = left & 0xFF;
    output[1] = (left >> 8) & 0xFF;
    output[2] = (left >> 16) & 0xFF;
    output[3] = (left >> 24) & 0xFF;
    output[4] = right & 0xFF;
    output[5] = (right >> 8) & 0xFF;
    output[6] = (right >> 16) & 0xFF;
    output[7] = (right >> 24) & 0xFF;
}
 
// Расшифрование
void xtea_decrypt(const uint8_t* input, uint8_t* output, const uint32_t* round_keys) {
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
    
    uint32_t sum = DELTA * XTEA_ROUNDS;
    
    for (int i = 0; i < XTEA_ROUNDS; i++) {
        right -= (((left << 4) ^ (left >> 5)) + left) ^ (sum + round_keys[(sum >> 11) & 3]);
        sum -= DELTA;
        left -= (((right << 4) ^ (right >> 5)) + right) ^ (sum + round_keys[sum & 3]);
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
