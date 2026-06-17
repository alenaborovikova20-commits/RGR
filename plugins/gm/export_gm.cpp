#include "include/crypto_abi.h"
#include "gm.h"
#include <cstring>

static AlgorithmInfo info = {"Goldwasser-Micali", GM_KEY_BYTES};

static int gm_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    size_t num_blocks = input.size;
    size_t out_size = num_blocks * 8 * sizeof(int64_t);
    
    if (output->size < out_size) {
        return -2;
    }
    
    for (size_t i = 0; i < num_blocks; i++) {
        gm_encrypt_block(input.data + i, output->data + i * 8 * sizeof(int64_t), key.data);
    }
    
    output->size = out_size;
    return 0;
}

static int gm_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (input.size % (8 * sizeof(int64_t)) != 0) {
        return -2;
    }
    
    size_t num_blocks = input.size / (8 * sizeof(int64_t));
    
    if (output->size < num_blocks) {
        return -3;
    }
    
    for (size_t i = 0; i < num_blocks; i++) {
        gm_decrypt_block(input.data + i * 8 * sizeof(int64_t), output->data + i, key.data);
    }
    
    output->size = num_blocks;
    return 0;
}

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

size_t get_output_size(size_t input_size, int encrypt_mode) {
    (void)encrypt_mode;
    return input_size * 8 * sizeof(int64_t);
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != GM_KEY_BYTES) return -1;
    size_t needed = get_output_size(input.size, 1);
    if (output->size < needed) return -2;
    return gm_encrypt(key, input, output);
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != GM_KEY_BYTES) return -1;
    return gm_decrypt(key, input, output);
}

}