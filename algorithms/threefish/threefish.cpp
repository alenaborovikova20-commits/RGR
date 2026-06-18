#include "threefish.h"
#include <cstring>
#include <random>

const int ROT[8][4] = {
    {46, 36, 19, 37},
    {33, 27, 14, 42},
    {17, 49, 36, 39},
    {44,  9, 54, 56},
    {39, 30, 34, 24},
    {13, 50, 10, 17},
    {25, 29, 39, 43},
    { 8, 35, 56, 22}
};

const uint64_t TF_CONST = 0x1BD11BDAA9FC1A22;

static uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static uint64_t rotr64(uint64_t x, int r) {
    return (x >> r) | (x << (64 - r));
}

static void mix(uint64_t& x, uint64_t& y, int rot) {
    x = x + y;
    y = rotl64(y, rot) ^ x;
}

static void unmix(uint64_t& x, uint64_t& y, int rot) {
    y = rotr64(y ^ x, rot);
    x = x - y;
}

static void permute(uint64_t* v) {
    uint64_t tmp;
    tmp = v[1]; v[1] = v[3]; v[3] = tmp;
    tmp = v[5]; v[5] = v[7]; v[7] = tmp;
}

static void unpermute(uint64_t* v) {
    uint64_t tmp;
    tmp = v[1]; v[1] = v[3]; v[3] = tmp;
    tmp = v[5]; v[5] = v[7]; v[7] = tmp;
}

void threefish_key_schedule(const uint64_t* key, const uint64_t* tweak, uint64_t* round_keys) {
    uint64_t K[9];
    for (int i = 0; i < 8; i++) K[i] = key[i];
    K[8] = TF_CONST;
    for (int i = 0; i < 8; i++) K[8] ^= K[i];

    uint64_t T[3];
    T[0] = tweak[0];
    T[1] = tweak[1];
    T[2] = T[0] ^ T[1];

    for (int r = 0; r < TF_ROUNDS; r++) {
        int s = r / 4;
        int sub = r % 4;
        switch (sub) {
            case 0:
                round_keys[r * 8 + 0] = K[(s + 0) % 9];
                round_keys[r * 8 + 1] = K[(s + 1) % 9];
                round_keys[r * 8 + 2] = T[(s + 0) % 3];
                round_keys[r * 8 + 3] = T[(s + 1) % 3];
                for (int i = 4; i < 8; i++) round_keys[r * 8 + i] = 0;
                break;
            case 1:
                round_keys[r * 8 + 0] = K[(s + 2) % 9];
                round_keys[r * 8 + 1] = K[(s + 3) % 9];
                round_keys[r * 8 + 2] = T[(s + 2) % 3];
                for (int i = 3; i < 8; i++) round_keys[r * 8 + i] = 0;
                break;
            case 2:
                round_keys[r * 8 + 0] = K[(s + 4) % 9];
                round_keys[r * 8 + 1] = K[(s + 5) % 9];
                round_keys[r * 8 + 2] = T[(s + 0) % 3];
                round_keys[r * 8 + 3] = T[(s + 1) % 3];
                for (int i = 4; i < 8; i++) round_keys[r * 8 + i] = 0;
                break;
            case 3:
                round_keys[r * 8 + 0] = K[(s + 6) % 9];
                round_keys[r * 8 + 1] = K[(s + 7) % 9];
                round_keys[r * 8 + 2] = T[(s + 2) % 3];
                for (int i = 3; i < 8; i++) round_keys[r * 8 + i] = 0;
                break;
        }
    }
}

void threefish_encrypt_block(const uint8_t* in, uint8_t* out, const uint64_t* round_keys) {
    uint64_t v[TF_WORDS];
    for (int i = 0; i < TF_WORDS; i++) {
        v[i] = 0;
        for (int b = 0; b < 8; b++)
            v[i] |= (uint64_t)in[i * 8 + b] << (b * 8);
    }
    for (int i = 0; i < TF_WORDS; i++)
        v[i] += round_keys[i];

    for (int r = 0; r < TF_ROUNDS; r++) {
        mix(v[0], v[1], ROT[r % 8][0]);
        mix(v[2], v[3], ROT[r % 8][1]);
        mix(v[4], v[5], ROT[r % 8][2]);
        mix(v[6], v[7], ROT[r % 8][3]);
        permute(v);
        for (int i = 0; i < TF_WORDS; i++)
            v[i] += round_keys[(r + 1) * 8 + i];
    }

    for (int i = 0; i < TF_WORDS; i++) {
        for (int b = 0; b < 8; b++)
            out[i * 8 + b] = (v[i] >> (b * 8)) & 0xFF;
    }
}

void threefish_decrypt_block(const uint8_t* in, uint8_t* out, const uint64_t* round_keys) {
    uint64_t v[TF_WORDS];
    for (int i = 0; i < TF_WORDS; i++) {
        v[i] = 0;
        for (int b = 0; b < 8; b++)
            v[i] |= (uint64_t)in[i * 8 + b] << (b * 8);
    }

    for (int r = TF_ROUNDS - 1; r >= 0; r--) {
        for (int i = 0; i < TF_WORDS; i++)
            v[i] -= round_keys[(r + 1) * 8 + i];
        unpermute(v);
        unmix(v[0], v[1], ROT[r % 8][0]);
        unmix(v[2], v[3], ROT[r % 8][1]);
        unmix(v[4], v[5], ROT[r % 8][2]);
        unmix(v[6], v[7], ROT[r % 8][3]);
    }

    for (int i = 0; i < TF_WORDS; i++)
        v[i] -= round_keys[i];

    for (int i = 0; i < TF_WORDS; i++) {
        for (int b = 0; b < 8; b++)
            out[i * 8 + b] = (v[i] >> (b * 8)) & 0xFF;
    }
}

void threefish_generate_iv(uint8_t* iv) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (int i = 0; i < TF_WORDS; i++) {
        uint64_t val = gen();
        for (int b = 0; b < 8; b++)
            iv[i * 8 + b] = (val >> (b * 8)) & 0xFF;
    }
}