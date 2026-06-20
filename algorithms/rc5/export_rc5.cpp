#include "crypto_abi.h"
#include "rc5.h"
#include <cstring>
#include <random>

static AlgorithmInfo info = {"RC5", RC5_KEY_BYTES};

static uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

static uint32_t rotr32(uint32_t x, int r) {
    return (x >> r) | (x << (32 - r));
}

static size_t pkcs7_padded_size(size_t input_len) {
    size_t block = RC5_BLOCK_SIZE;
    return ((input_len + block - 1) / block) * block;
}

static void pkcs7_apply_padding(uint8_t* data, size_t orig_len, size_t padded_len) {
    uint8_t pad_byte = padded_len - orig_len;
    for (size_t i = orig_len; i < padded_len; i++) {
        data[i] = pad_byte;
    }
}

static int pkcs7_remove_padding(uint8_t* data, size_t* len) {
    if (*len == 0) return -1;
    uint8_t pad_byte = data[*len - 1];
    if (pad_byte > RC5_BLOCK_SIZE || pad_byte > *len) return -1;
    for (size_t i = *len - pad_byte; i < *len; i++) {
        if (data[i] != pad_byte) return -1;
    }
    *len -= pad_byte;
    return 0;
}

static void generate_iv(uint8_t* iv) {
    std::random_device rd;
    for (size_t i = 0; i < RC5_BLOCK_SIZE; i++) {
        iv[i] = rd() & 0xFF;
    }
}

static void rc5_encrypt_block_debug(const uint8_t* in, uint8_t* out, const uint32_t* S, int block_num) {
    uint32_t A = ((uint32_t)in[0]) | ((uint32_t)in[1] << 8) |
                 ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    uint32_t B = ((uint32_t)in[4]) | ((uint32_t)in[5] << 8) |
                 ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    printf("Блок #%d начальное состояние: A=%08x B=%08x\n", block_num, A, B);
    
    A += S[0];
    B += S[1];
    printf("Раунд 0 (сложение): A=%08x B=%08x\n", A, B);
    
    for (int r = 1; r <= RC5_ROUNDS; r++) {
        A = rotl32(A ^ B, B) + S[2 * r];
        B = rotl32(B ^ A, A) + S[2 * r + 1];
        printf("Раунд %d: A=%08x B=%08x\n", r, A, B);
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

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

size_t get_output_size(size_t input_size, int encrypt_mode) {
    (void)encrypt_mode;
    size_t padded = pkcs7_padded_size(input_size);
    return RC5_BLOCK_SIZE + padded;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != RC5_KEY_BYTES) return -1;
    
    size_t padded_len = pkcs7_padded_size(input.size);
    size_t total_len = RC5_BLOCK_SIZE + padded_len;
    
    if (output->size < total_len) return -2;
    
    uint8_t iv[RC5_BLOCK_SIZE];
    generate_iv(iv);
    memcpy(output->data, iv, RC5_BLOCK_SIZE);
    
    printf("\nRC5 ШИФРОВАНИЕ\n");
    printf("Исходные данные (%zu): ", input.size);
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");
    
    uint8_t* padded = new uint8_t[padded_len];
    memcpy(padded, input.data, input.size);
    pkcs7_apply_padding(padded, input.size, padded_len);
    
    printf("Паддинг (%zu): ", padded_len);
    for (size_t i = 0; i < padded_len; i++) printf("%02x ", padded[i]);
    printf("\n");
    
    uint32_t S[2 * RC5_ROUNDS + 2];
    rc5_expand_key(key.data, S);
    
    printf("IV: ");
    for (int i = 0; i < RC5_BLOCK_SIZE; i++) printf("%02x ", iv[i]);
    printf("\n");
    printf("Раундов: %d\n\n", RC5_ROUNDS);
    
    uint8_t prev[RC5_BLOCK_SIZE];
    memcpy(prev, iv, RC5_BLOCK_SIZE);
    
    for (size_t i = 0; i < padded_len; i += RC5_BLOCK_SIZE) {
        size_t block_num = i / RC5_BLOCK_SIZE;
        
        printf("Блок #%zu до XOR: ", block_num);
        for (int j = 0; j < RC5_BLOCK_SIZE; j++) printf("%02x ", padded[i + j]);
        printf("\n");
        
        for (int j = 0; j < RC5_BLOCK_SIZE; j++) {
            padded[i + j] ^= prev[j];
        }
        
        printf("Блок #%zu после XOR: ", block_num);
        for (int j = 0; j < RC5_BLOCK_SIZE; j++) printf("%02x ", padded[i + j]);
        printf("\n");
        
        if (block_num == 0) {
            rc5_encrypt_block_debug(padded + i, output->data + RC5_BLOCK_SIZE + i, S, 0);
        } else {
            rc5_encrypt_block(padded + i, output->data + RC5_BLOCK_SIZE + i, S);
        }
        
        printf("Блок #%zu зашифрован: ", block_num);
        for (int j = 0; j < RC5_BLOCK_SIZE; j++) printf("%02x ", output->data[RC5_BLOCK_SIZE + i + j]);
        printf("\n");
        
        memcpy(prev, output->data + RC5_BLOCK_SIZE + i, RC5_BLOCK_SIZE);
    }
    
    output->size = total_len;
    
    printf("\nШифротекст (%zu): ", output->size);
    for (size_t i = 0; i < output->size; i++) printf("%02x ", output->data[i]);
    printf("\n\n");
    
    delete[] padded;
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != RC5_KEY_BYTES) return -1;
    if (input.size < RC5_BLOCK_SIZE) return -2;
    if ((input.size - RC5_BLOCK_SIZE) % RC5_BLOCK_SIZE != 0) return -3;
    if (output->size < input.size) return -4;
    
    const uint8_t* iv = input.data;
    const uint8_t* ciphertext = input.data + RC5_BLOCK_SIZE;
    size_t cipher_len = input.size - RC5_BLOCK_SIZE;
    
    uint32_t S[2 * RC5_ROUNDS + 2];
    rc5_expand_key(key.data, S);
    
    printf("\nRC5 РАСШИФРОВАНИЕ\n");
    printf("Шифротекст (%zu): ", input.size);
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");
    
    printf("IV: ");
    for (int i = 0; i < RC5_BLOCK_SIZE; i++) printf("%02x ", iv[i]);
    printf("\n");
    
    uint8_t prev[RC5_BLOCK_SIZE];
    memcpy(prev, iv, RC5_BLOCK_SIZE);
    
    uint8_t* decrypted = new uint8_t[cipher_len];
    
    for (size_t i = 0; i < cipher_len; i += RC5_BLOCK_SIZE) {
        size_t block_num = i / RC5_BLOCK_SIZE;
        
        rc5_decrypt_block(ciphertext + i, decrypted + i, S);
        
        printf("Блок #%zu расшифрован: ", block_num);
        for (int j = 0; j < RC5_BLOCK_SIZE; j++) printf("%02x ", decrypted[i + j]);
        printf("\n");
        
        for (int j = 0; j < RC5_BLOCK_SIZE; j++) {
            decrypted[i + j] ^= prev[j];
        }
        
        printf("Блок #%zu после XOR: ", block_num);
        for (int j = 0; j < RC5_BLOCK_SIZE; j++) printf("%02x ", decrypted[i + j]);
        printf("\n");
        
        memcpy(prev, ciphertext + i, RC5_BLOCK_SIZE);
    }
    
    size_t decrypted_len = cipher_len;
    if (pkcs7_remove_padding(decrypted, &decrypted_len) != 0) {
        delete[] decrypted;
        return -5;
    }
    
    if (output->size < decrypted_len) {
        delete[] decrypted;
        return -6;
    }
    
    memcpy(output->data, decrypted, decrypted_len);
    output->size = decrypted_len;
    
    printf("\nРезультат (%zu): ", output->size);
    for (size_t i = 0; i < output->size; i++) printf("%02x ", output->data[i]);
    printf("\n");
    printf("Текст: ");
    for (size_t i = 0; i < output->size; i++) printf("%c", output->data[i]);
    printf("\n\n");
    
    delete[] decrypted;
    return 0;
}

}