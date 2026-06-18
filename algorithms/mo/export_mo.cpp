#include "crypto_abi.h"
#include "mo.h"
#include <cstring>

static AlgorithmInfo info = {"Massey-Omura", MO_KEY_BYTES};

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

size_t get_output_size(size_t input_size, int encrypt_mode) {
    (void)encrypt_mode;
    // Как у GM: 1 байт → 8 * sizeof(int64_t)
    return input_size * 8 * sizeof(int64_t);
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != MO_KEY_BYTES) return -1;
    
    size_t needed = input.size * 8 * sizeof(int64_t);
    if (output->size < needed) return -2;
    
    for (size_t i = 0; i < input.size; i++) {
        mo_encrypt_block(input.data + i, 
                        output->data + i * 8 * sizeof(int64_t), 
                        key.data);
    }
    
    output->size = needed;
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != MO_KEY_BYTES) return -1;
    
    size_t block_size = 8 * sizeof(int64_t);
    if (input.size % block_size != 0) return -3;
    
    size_t num_blocks = input.size / block_size;
    if (output->size < num_blocks) return -4;
    
    for (size_t i = 0; i < num_blocks; i++) {
        mo_decrypt_block(input.data + i * block_size, 
                        output->data + i, 
                        key.data);
    }
    
    output->size = num_blocks;
    return 0;
}

}