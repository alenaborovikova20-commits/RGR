#include "crypto_abi.h"
#include "gm.h"
#include <cstring>
#include <cstdio>

static AlgorithmInfo info = {"Goldwasser-Micali", GM_KEY_BYTES};

// Новый формат ключа: [публичный 16 байт][приватный 16 байт]
// Всего 32 байта

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

size_t get_output_size(size_t input_size, int encrypt_mode) {
    (void)encrypt_mode;
    return input_size * 8 * sizeof(int64_t);
}

int generate_key(uint8_t* buffer, size_t* size, int mode) {
    if (*size < 32) return -1;
    
    uint8_t pub[16];
    uint8_t priv[16];
    
    gm_generate_keys(pub, priv);
    
    // Формат: [публичный 16 байт][приватный 16 байт]
    memcpy(buffer, pub, 16);
    memcpy(buffer + 16, priv, 16);
    
    *size = 32;
    return 0;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != 32) return -1;  // Полный ключ (публичный + приватный)
    
    // БЕРЁМ ПЕРВЫЕ 16 БАЙТ — ПУБЛИЧНЫЙ КЛЮЧ
    ConstBuffer pub_key = {key.data, 16};
    
    size_t needed = input.size * 8 * sizeof(int64_t);
    if (output->size < needed) return -2;
    
    for (size_t i = 0; i < input.size; i++) {
        gm_encrypt_block(input.data + i, 
                        output->data + i * 8 * sizeof(int64_t), 
                        pub_key.data);
    }
    
    output->size = needed;
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != 32) return -1;
    
    // БЕРЁМ ПОСЛЕДНИЕ 16 БАЙТ — ПРИВАТНЫЙ КЛЮЧ
    ConstBuffer priv_key = {key.data + 16, 16};
    
    size_t block_size = 8 * sizeof(int64_t);
    if (input.size % block_size != 0) return -3;
    
    size_t num_blocks = input.size / block_size;
    if (output->size < num_blocks) return -4;
    
    for (size_t i = 0; i < num_blocks; i++) {
        gm_decrypt_block(input.data + i * block_size, 
                        output->data + i, 
                        priv_key.data);
    }
    
    output->size = num_blocks;
    return 0;
}

}