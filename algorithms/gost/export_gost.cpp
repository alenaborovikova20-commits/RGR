#include "crypto_abi.h"
#include "gost.h"
#include <cstring>
#include <random>
 
static std::mt19937_64 rng(std::random_device{}());
 
static AlgorithmInfo info = {
    "gost28147",
    GOST_KEY
};
 
static size_t padded_len(size_t n) {
    size_t b = GOST_BLOCK;
    size_t p = b - (n % b);
    if (p == 0) p = b;
    return n + p;
}
 
static void add_padding(uint8_t* d, size_t old, size_t newlen) {
    uint8_t v = newlen - old;
    for (size_t i = old; i < newlen; i++) {
        d[i] = v;
    }
}
 
static int remove_padding(uint8_t* d, size_t* len) {
    if (*len == 0) return -1;
    uint8_t v = d[*len - 1];
    if (v == 0 || v > GOST_BLOCK || v > *len) return -1;
    for (size_t i = *len - v; i < *len; i++) {
        if (d[i] != v) return -1;
    }
    *len -= v;
    return 0;
}
 
static uint64_t generate_iv() {
    std::uniform_int_distribution<uint64_t> dist;
    return dist(rng);
}
 
static void secure_zero(void* ptr, size_t size) {
    if (ptr == NULL || size == 0) return;
    volatile uint8_t* v = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < size; i++) {
        v[i] = 0;
    }
}
 
extern "C" {
 
const AlgorithmInfo* get_algorithm_info() {
    return &info;
}
 
size_t get_output_size(size_t input_size, int mode) {
    (void)mode;
    return padded_len(input_size) + GOST_BLOCK;
}
 
int encrypt(InputData key, InputData input, OutputData* out) {
    if (key.length != GOST_KEY) return -1;
 
    size_t data_pad = padded_len(input.length);
    size_t total = data_pad + GOST_BLOCK;
 
    if (out->length < total) return -2;
 
    uint64_t iv = generate_iv();
    memcpy(out->bytes, &iv, GOST_BLOCK);
 
    memcpy(out->bytes + GOST_BLOCK, input.bytes, input.length);
    add_padding(out->bytes + GOST_BLOCK, input.length, data_pad);
 
    uint32_t round_keys[8];
    gost_prepare_keys(key.bytes, round_keys);
 
    for (size_t i = 0; i < data_pad; i += GOST_BLOCK) {
        gost_encrypt_block(out->bytes + GOST_BLOCK + i,
                           out->bytes + GOST_BLOCK + i,
                           round_keys);
    }
 
    out->length = total;
    secure_zero((void*)key.bytes, key.length);
    return 0;
}
 
int decrypt(InputData key, InputData input, OutputData* out) {
    if (key.length != GOST_KEY) return -1;
    if (input.length < GOST_BLOCK) return -2;
    if ((input.length - GOST_BLOCK) % GOST_BLOCK != 0) return -3;
    if (out->length < input.length) return -4;
 
    size_t cipher_len = input.length - GOST_BLOCK;
    memcpy(out->bytes, input.bytes + GOST_BLOCK, cipher_len);
 
    uint32_t round_keys[8];
    gost_prepare_keys(key.bytes, round_keys);
 
    for (size_t i = 0; i < cipher_len; i += GOST_BLOCK) {
        gost_decrypt_block(out->bytes + i, out->bytes + i, round_keys);
    }
 
    size_t real_len = cipher_len;
    if (remove_padding(out->bytes, &real_len) != 0) return -5;
 
    out->length = real_len;
    secure_zero((void*)key.bytes, key.length);
    return 0;
}
 
int encrypt_fixed_iv(InputData key, InputData iv, InputData input, OutputData* out) {
    if (key.length != GOST_KEY) return -1;
    if (iv.length != GOST_BLOCK) return -2;
 
    size_t data_pad = padded_len(input.length);
    size_t total = data_pad + GOST_BLOCK;
 
    if (out->length < total) return -3;
 
    memcpy(out->bytes, iv.bytes, GOST_BLOCK);
    memcpy(out->bytes + GOST_BLOCK, input.bytes, input.length);
    add_padding(out->bytes + GOST_BLOCK, input.length, data_pad);
 
    uint32_t round_keys[8];
    gost_prepare_keys(key.bytes, round_keys);
 
    for (size_t i = 0; i < data_pad; i += GOST_BLOCK) {
        gost_encrypt_block(out->bytes + GOST_BLOCK + i,
                           out->bytes + GOST_BLOCK + i,
                           round_keys);
    }
 
    out->length = total;
    return 0;
}
 
}
