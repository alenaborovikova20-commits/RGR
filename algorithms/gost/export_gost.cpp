#include "crypto_abi.h"
#include "gost.h"
#include <cstring>
#include <cstdio>
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
 
extern "C" {
 
const AlgorithmInfo* get_algorithm_info() {
    return &info;
}
 
size_t get_output_size(size_t input_size, int mode) {
    (void)mode;
    return padded_len(input_size) + GOST_BLOCK;
}
 
int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* out) {
    if (key.size != GOST_KEY) return -1;
 
    size_t data_pad = padded_len(input.size);
    size_t total = data_pad + GOST_BLOCK;
 
    if (out->size < total) return -2;
 
    uint64_t iv = generate_iv();
    memcpy(out->data, &iv, GOST_BLOCK);
 
    printf("\nШифрование ГОСТ 28147-89 в режиме CBC\n");
    printf("Исходные данные: ");
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");
 
    memcpy(out->data + GOST_BLOCK, input.data, input.size);
    add_padding(out->data + GOST_BLOCK, input.size, data_pad);
 
    printf("Данные после паддинга: ");
    for (size_t i = 0; i < data_pad; i++) printf("%02x ", out->data[GOST_BLOCK + i]);
    printf("\n");
 
    uint32_t round_keys[8];
    gost_prepare_keys(key.data, round_keys);
 
    printf("Вектор инициализации: ");
    for (int i = 0; i < GOST_BLOCK; i++) printf("%02x ", out->data[i]);
    printf("\n");
    printf("Количество раундов: 32\n\n");
 
    uint8_t prev[GOST_BLOCK];
    memcpy(prev, out->data, GOST_BLOCK);
 
    for (size_t i = 0; i < data_pad; i += GOST_BLOCK) {
        size_t block_num = i / GOST_BLOCK;
        
        printf("Блок %zu до XOR: ", block_num);
        for (int j = 0; j < GOST_BLOCK; j++) printf("%02x ", out->data[GOST_BLOCK + i + j]);
        printf("\n");
        
        for (int j = 0; j < GOST_BLOCK; j++) {
            out->data[GOST_BLOCK + i + j] ^= prev[j];
        }
        
        printf("Блок %zu после XOR: ", block_num);
        for (int j = 0; j < GOST_BLOCK; j++) printf("%02x ", out->data[GOST_BLOCK + i + j]);
        printf("\n");
        
        gost_encrypt_block(out->data + GOST_BLOCK + i, out->data + GOST_BLOCK + i, round_keys);
        
        printf("Блок %zu зашифрован: ", block_num);
        for (int j = 0; j < GOST_BLOCK; j++) printf("%02x ", out->data[GOST_BLOCK + i + j]);
        printf("\n\n");
        
        memcpy(prev, out->data + GOST_BLOCK + i, GOST_BLOCK);
    }
 
    out->size = total;
 
    printf("Полный шифротекст: ");
    for (size_t i = 0; i < out->size; i++) printf("%02x ", out->data[i]);
    printf("\n\n");
 
    return 0;
}
 
int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* out) {
    if (key.size != GOST_KEY) return -1;
    if (input.size < GOST_BLOCK) return -2;
    if ((input.size - GOST_BLOCK) % GOST_BLOCK != 0) return -3;
    if (out->size < input.size) return -4;
 
    size_t cipher_len = input.size - GOST_BLOCK;
    const uint8_t* iv = input.data;
    const uint8_t* ciphertext = input.data + GOST_BLOCK;
 
    printf("\nРасшифрование ГОСТ 28147-89 в режиме CBC\n");
    printf("Полученный шифротекст: ");
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");
 
    printf("Вектор инициализации: ");
    for (int i = 0; i < GOST_BLOCK; i++) printf("%02x ", iv[i]);
    printf("\n\n");
 
    uint32_t round_keys[8];
    gost_prepare_keys(key.data, round_keys);
 
    uint8_t prev[GOST_BLOCK];
    memcpy(prev, iv, GOST_BLOCK);
 
    for (size_t i = 0; i < cipher_len; i += GOST_BLOCK) {
        size_t block_num = i / GOST_BLOCK;
        
        gost_decrypt_block(ciphertext + i, out->data + i, round_keys);
        
        printf("Блок %zu расшифрован: ", block_num);
        for (int j = 0; j < GOST_BLOCK; j++) printf("%02x ", out->data[i + j]);
        printf("\n");
        
        for (int j = 0; j < GOST_BLOCK; j++) {
            out->data[i + j] ^= prev[j];
        }
        
        printf("Блок %zu после XOR: ", block_num);
        for (int j = 0; j < GOST_BLOCK; j++) printf("%02x ", out->data[i + j]);
        printf("\n\n");
        
        memcpy(prev, ciphertext + i, GOST_BLOCK);
    }
 
    size_t real_len = cipher_len;
    if (remove_padding(out->data, &real_len) != 0) return -5;
    out->size = real_len;
 
    printf("Расшифрованные данные: ");
    for (size_t i = 0; i < out->size; i++) printf("%02x ", out->data[i]);
    printf("\n");
    printf("Текст: ");
    for (size_t i = 0; i < out->size; i++) printf("%c", out->data[i]);
    printf("\n\n");
 
    return 0;
}
 
int encrypt_fixed_iv(ConstBuffer key, ConstBuffer iv, ConstBuffer input, MutBuffer* out) {
    if (key.size != GOST_KEY) return -1;
    if (iv.size != GOST_BLOCK) return -2;
 
    size_t data_pad = padded_len(input.size);
    size_t total = data_pad + GOST_BLOCK;
 
    if (out->size < total) return -3;
 
    memcpy(out->data, iv.data, GOST_BLOCK);
    memcpy(out->data + GOST_BLOCK, input.data, input.size);
    add_padding(out->data + GOST_BLOCK, input.size, data_pad);
 
    uint32_t round_keys[8];
    gost_prepare_keys(key.data, round_keys);
 
    uint8_t prev[GOST_BLOCK];
    memcpy(prev, out->data, GOST_BLOCK);
 
    for (size_t i = 0; i < data_pad; i += GOST_BLOCK) {
        for (int j = 0; j < GOST_BLOCK; j++) {
            out->data[GOST_BLOCK + i + j] ^= prev[j];
        }
        
        gost_encrypt_block(out->data + GOST_BLOCK + i, out->data + GOST_BLOCK + i, round_keys);
        
        memcpy(prev, out->data + GOST_BLOCK + i, GOST_BLOCK);
    }
 
    out->size = total;
    return 0;
}
 
}