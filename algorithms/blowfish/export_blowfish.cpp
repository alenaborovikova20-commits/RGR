#include "crypto_abi.h"
#include "blowfish.h"
#include <cstring>
#include <cstdio>
#include <random>

static AlgorithmInfo info = {"Blowfish", BLOWFISH_KEY_BYTES};

static size_t pkcs7_padded_size(size_t input_len) {
    size_t block = BLOWFISH_BLOCK_SIZE;
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
    if (pad_byte > BLOWFISH_BLOCK_SIZE || pad_byte > *len) return -1;
    for (size_t i = *len - pad_byte; i < *len; i++) {
        if (data[i] != pad_byte) return -1;
    }
    *len -= pad_byte;
    return 0;
}

static void generate_iv(uint8_t* iv) {
    std::random_device rd;
    for (size_t i = 0; i < BLOWFISH_BLOCK_SIZE; i++) {
        iv[i] = rd() & 0xFF;
    }
}

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

size_t get_output_size(size_t input_size, int encrypt_mode) {
    (void)encrypt_mode;
    size_t padded = pkcs7_padded_size(input_size);
    return BLOWFISH_BLOCK_SIZE + padded;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != BLOWFISH_KEY_BYTES) return -1;
    
    size_t padded_len = pkcs7_padded_size(input.size);
    size_t total_len = BLOWFISH_BLOCK_SIZE + padded_len;
    
    if (output->size < total_len) return -2;
    
    uint8_t iv[BLOWFISH_BLOCK_SIZE];
    generate_iv(iv);
    memcpy(output->data, iv, BLOWFISH_BLOCK_SIZE);
    
    printf("\nШифрование Blowfish в режиме CBC\n");
    printf("Исходные данные: ");
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");
    
    uint8_t* padded = new uint8_t[padded_len];
    memcpy(padded, input.data, input.size);
    pkcs7_apply_padding(padded, input.size, padded_len);
    
    printf("Данные после добавления паддинга: ");
    for (size_t i = 0; i < padded_len; i++) printf("%02x ", padded[i]);
    printf("\n");
    
    uint32_t P[18];
    uint32_t S[4][256];
    blowfish_expand_key(key.data, P, S);
    
    printf("Вектор инициализации: ");
    for (int i = 0; i < BLOWFISH_BLOCK_SIZE; i++) printf("%02x ", iv[i]);
    printf("\n\n");
    
    uint8_t prev[BLOWFISH_BLOCK_SIZE];
    memcpy(prev, iv, BLOWFISH_BLOCK_SIZE);
    
    for (size_t i = 0; i < padded_len; i += BLOWFISH_BLOCK_SIZE) {
        size_t block_num = i / BLOWFISH_BLOCK_SIZE;
        
        printf("Блок %zu до XOR: ", block_num);
        for (int j = 0; j < BLOWFISH_BLOCK_SIZE; j++) printf("%02x ", padded[i + j]);
        printf("\n");
        
        for (int j = 0; j < BLOWFISH_BLOCK_SIZE; j++) {
            padded[i + j] ^= prev[j];
        }
        
        printf("Блок %zu после XOR: ", block_num);
        for (int j = 0; j < BLOWFISH_BLOCK_SIZE; j++) printf("%02x ", padded[i + j]);
        printf("\n");
        
        blowfish_encrypt_block(padded + i, output->data + BLOWFISH_BLOCK_SIZE + i, P, S);
        
        printf("Блок %zu зашифрован: ", block_num);
        for (int j = 0; j < BLOWFISH_BLOCK_SIZE; j++) printf("%02x ", output->data[BLOWFISH_BLOCK_SIZE + i + j]);
        printf("\n\n");
        
        memcpy(prev, output->data + BLOWFISH_BLOCK_SIZE + i, BLOWFISH_BLOCK_SIZE);
    }
    
    output->size = total_len;
    
    printf("Полный шифротекст: ");
    for (size_t i = 0; i < output->size; i++) printf("%02x ", output->data[i]);
    printf("\n\n");
    
    delete[] padded;
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != BLOWFISH_KEY_BYTES) return -1;
    if (input.size < BLOWFISH_BLOCK_SIZE) return -2;
    if ((input.size - BLOWFISH_BLOCK_SIZE) % BLOWFISH_BLOCK_SIZE != 0) return -3;
    if (output->size < input.size) return -4;
    
    const uint8_t* iv = input.data;
    const uint8_t* ciphertext = input.data + BLOWFISH_BLOCK_SIZE;
    size_t cipher_len = input.size - BLOWFISH_BLOCK_SIZE;
    
    uint32_t P[18];
    uint32_t S[4][256];
    blowfish_expand_key(key.data, P, S);
    
    printf("\nРасшифрование Blowfish в режиме CBC\n");
    printf("Полученный шифротекст: ");
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");
    
    printf("Вектор инициализации: ");
    for (int i = 0; i < BLOWFISH_BLOCK_SIZE; i++) printf("%02x ", iv[i]);
    printf("\n\n");
    
    uint8_t prev[BLOWFISH_BLOCK_SIZE];
    memcpy(prev, iv, BLOWFISH_BLOCK_SIZE);
    
    uint8_t* decrypted = new uint8_t[cipher_len];
    
    for (size_t i = 0; i < cipher_len; i += BLOWFISH_BLOCK_SIZE) {
        size_t block_num = i / BLOWFISH_BLOCK_SIZE;
        
        blowfish_decrypt_block(ciphertext + i, decrypted + i, P, S);
        
        printf("Блок %zu расшифрован: ", block_num);
        for (int j = 0; j < BLOWFISH_BLOCK_SIZE; j++) printf("%02x ", decrypted[i + j]);
        printf("\n");
        
        for (int j = 0; j < BLOWFISH_BLOCK_SIZE; j++) {
            decrypted[i + j] ^= prev[j];
        }
        
        printf("Блок %zu после XOR: ", block_num);
        for (int j = 0; j < BLOWFISH_BLOCK_SIZE; j++) printf("%02x ", decrypted[i + j]);
        printf("\n\n");
        
        memcpy(prev, ciphertext + i, BLOWFISH_BLOCK_SIZE);
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
    
    printf("Расшифрованные данные: ");
    for (size_t i = 0; i < output->size; i++) printf("%02x ", output->data[i]);
    printf("\n");
    printf("Текст: ");
    for (size_t i = 0; i < output->size; i++) printf("%c", output->data[i]);
    printf("\n\n");
    
    delete[] decrypted;
    return 0;
}

}