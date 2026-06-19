#include "rc5.h"

static uint32_t rotl(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

static uint32_t rotr(uint32_t x, int r) {
    return (x >> r) | (x << (32 - r));
}

void rc5_expand_key(const uint8_t* key, uint32_t* S) {
    const uint32_t P32 = 0xB7E15163;
    const uint32_t Q32 = 0x9E3779B9;
    
    uint32_t L[4];
    for (int i = 0; i < 4; i++) {
        L[i] = ((uint32_t)key[4*i + 0]) |
               ((uint32_t)key[4*i + 1] << 8) |
               ((uint32_t)key[4*i + 2] << 16) |
               ((uint32_t)key[4*i + 3] << 24);
    }
    
    S[0] = P32;
    for (int i = 1; i < 2 * RC5_ROUNDS + 2; i++) {
        S[i] = S[i-1] + Q32;
    }
    
    int i = 0, j = 0;
    uint32_t A = 0, B = 0;
    for (int k = 0; k < 78; k++) {
        A = S[i] = rotl(S[i] + A + B, 3);
        B = L[j] = rotl(L[j] + A + B, A + B);
        i = (i + 1) % (2 * RC5_ROUNDS + 2);
        j = (j + 1) % 4;
    }
}

void rc5_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* S) {
    uint32_t A = ((uint32_t)in[0]) | ((uint32_t)in[1] << 8) |
                 ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    uint32_t B = ((uint32_t)in[4]) | ((uint32_t)in[5] << 8) |
                 ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    A += S[0];
    B += S[1];
    
    for (int r = 1; r <= RC5_ROUNDS; r++) {
        A = rotl(A ^ B, B) + S[2 * r];
        B = rotl(B ^ A, A) + S[2 * r + 1];
    }
    
    out[0] = (A >> 0) & 0xFF;
    out[1] = (A >> 8) & 0xFF;
    out[2] = (A >> 16) & 0xFF;
    out[3] = (A >> 24) & 0xFF;
    out[4] = (B >> 0) & 0xFF;
    out[5] = (B >> 8) & 0xFF;
    out[6] = (B >> 16) & 0xFF;
    out[7] = (B >> 24) & 0xFF;
}

void rc5_decrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* S) {
    uint32_t A = ((uint32_t)in[0]) | ((uint32_t)in[1] << 8) |
                 ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    uint32_t B = ((uint32_t)in[4]) | ((uint32_t)in[5] << 8) |
                 ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    for (int r = RC5_ROUNDS; r >= 1; r--) {
        B = rotr(B - S[2 * r + 1], A) ^ A;
        A = rotr(A - S[2 * r], B) ^ B;
    }
    
    B -= S[1];
    A -= S[0];
    
    // 2 слова → 8 байт
    out[0] = (A >> 0) & 0xFF;
    out[1] = (A >> 8) & 0xFF;
    out[2] = (A >> 16) & 0xFF;
    out[3] = (A >> 24) & 0xFF;
    out[4] = (B >> 0) & 0xFF;
    out[5] = (B >> 8) & 0xFF;
    out[6] = (B >> 16) & 0xFF;
    out[7] = (B >> 24) & 0xFF;
}