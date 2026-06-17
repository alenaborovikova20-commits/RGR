#include "gost.h"
#include <cstring>
 
static const uint8_t S_BOX[8][16] = {
    {0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5},
    {0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1},
    {0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9},
    {0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6},
    {0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6},
    {0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6},
    {0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE},
    {0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4}
};
 
static inline uint32_t rot_left_11(uint32_t x) {
    return (x << 11) | (x >> (32 - 11));
}
 
static uint32_t substitute(uint32_t x) {
    uint32_t result = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t nibble = (x >> (4 * i)) & 0x0F;
        result |= (uint32_t)S_BOX[i][nibble] << (4 * i);
    }
    return result;
}
 
static void gost_round(uint32_t& left, uint32_t& right, uint32_t key) {
    uint32_t sum = right + key;
    uint32_t substituted = substitute(sum);
    uint32_t shifted = rot_left_11(substituted);
    left ^= shifted;
}
 
void gost_prepare_keys(const uint8_t* user_key, uint32_t* round_keys) {
    for (int i = 0; i < 8; i++) {
        round_keys[i] = 0;
        round_keys[i] |= (uint32_t)user_key[i * 4 + 0];
        round_keys[i] |= (uint32_t)user_key[i * 4 + 1] << 8;
        round_keys[i] |= (uint32_t)user_key[i * 4 + 2] << 16;
        round_keys[i] |= (uint32_t)user_key[i * 4 + 3] << 24;
    }
}
 
void gost_encrypt_block(const uint8_t* input, uint8_t* output, const uint32_t* round_keys) {
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
    
    const int key_order[GOST_ROUNDS] = {
        0,1,2,3,4,5,6,7, 0,1,2,3,4,5,6,7,
        0,1,2,3,4,5,6,7, 7,6,5,4,3,2,1,0
    };
    
    for (int i = 0; i < GOST_ROUNDS; i++) {
        gost_round(left, right, round_keys[key_order[i]]);
         if (i != GOST_ROUNDS - 1) {
            uint32_t temp = left;
            left = right;
            right = temp;
        }
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
 
void gost_decrypt_block(const uint8_t* input, uint8_t* output, const uint32_t* round_keys) {
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
    
    const int key_order[GOST_ROUNDS] = {
        0,1,2,3,4,5,6,7, 0,1,2,3,4,5,6,7,
        0,1,2,3,4,5,6,7, 7,6,5,4,3,2,1,0
    };
    
    for (int i = GOST_ROUNDS - 1; i >= 0; i--) {
        gost_round(left, right, round_keys[key_order[i]]);
        if (i != 0) {
            uint32_t temp = left;
            left = right;
            right = temp;
        }
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
