#include "crypto_abi.h"
#include "mo.h"
#include <cstring>

static AlgorithmInfo info = {"Massey-Omura", MO_KEY_BYTES};

static int mo_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!key.data || !input.data || !output || !output->data) {
        return -1;
    }
    
    if (key.size != MO_KEY_BYTES) {
        return -2;
    }
    
    size_t num_blocks = input.size;
    size_t out_size = num_blocks * sizeof(int64_t);
    
    if (output->size < out_size) {
        return -3;
    }
    
    for (size_t i = 0; i < num_blocks; i++) {
        mo_encrypt_block(input.data + i, output->data + i * sizeof(int64_t), key.data);
    }
    
    output->size = out_size;
    return 0;
}

static int mo_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!key.data || !input.data || !output || !output->data) {
        return -1;
    }
    
    if (key.size != MO_KEY_BYTES) {
        return -2;
    }
    
    if (input.size % sizeof(int64_t) != 0) {
        return -3;
    }
    
    size_t num_blocks = input.size / sizeof(int64_t);
    
    if (output->size < num_blocks) {
        return -4;
    }
    
    for (size_t i = 0; i < num_blocks; i++) {
        mo_decrypt_block(input.data + i * sizeof(int64_t), output->data + i, key.data);
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
    return input_size * sizeof(int64_t);
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return mo_encrypt(key, input, output);
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return mo_decrypt(key, input, output);
}

}