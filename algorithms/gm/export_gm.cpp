#include "crypto_abi.h"
#include "gm.h"
#include <cstring>
#include <cstdio>
#include <random>

static AlgorithmInfo info = {"Goldwasser-Micali", GM_KEY_BYTES};

static void generate_iv(uint8_t* iv, size_t size) {
    std::random_device rd;
    for (size_t i = 0; i < size; i++) {
        iv[i] = rd() & 0xFF;
    }
}

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
    
    memcpy(buffer, pub, 16);
    memcpy(buffer + 16, priv, 16);
    
    *size = 32;
    return 0;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != 32) return -1;
    
    ConstBuffer pub_key = {key.data, 16};
    
    size_t needed = input.size * 8 * sizeof(int64_t);
    if (output->size < needed) return -2;
    
    printf("\nШифрование Goldwasser-Micali\n");
    printf("Исходные данные: ");
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");
    
    printf("Открытый ключ: ");
    for (int i = 0; i < 16; i++) printf("%02x ", pub_key.data[i]);
    printf("\n");
    
    for (size_t i = 0; i < input.size; i++) {
        printf("\nБайт %zu: 0x%02x (", i, input.data[i]);
        for (int bit = 7; bit >= 0; bit--) {
            printf("%d", (input.data[i] >> bit) & 1);
        }
        printf(")\n");
        
        gm_encrypt_block(input.data + i, 
                        output->data + i * 8 * sizeof(int64_t), 
                        pub_key.data);
        
        printf("Зашифрованные биты: ");
        for (int bit = 0; bit < 8; bit++) {
            int64_t* cipher = (int64_t*)(output->data + i * 8 * sizeof(int64_t) + bit * sizeof(int64_t));
            printf("%016llx ", (unsigned long long)*cipher);
        }
        printf("\n");
    }
    
    output->size = needed;
    
    printf("\nПолный шифротекст: ");
    for (size_t i = 0; i < output->size; i++) printf("%02x ", output->data[i]);
    printf("\n\n");
    
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != 32) return -1;
    
    ConstBuffer priv_key = {key.data + 16, 16};
    
    size_t block_size = 8 * sizeof(int64_t);
    if (input.size % block_size != 0) return -3;
    
    size_t num_blocks = input.size / block_size;
    if (output->size < num_blocks) return -4;
    
    printf("\nРасшифрование Goldwasser-Micali\n");
    printf("Полученный шифротекст: ");
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");
    
    printf("Закрытый ключ: ");
    for (int i = 0; i < 16; i++) printf("%02x ", priv_key.data[i]);
    printf("\n");
    
    for (size_t i = 0; i < num_blocks; i++) {
        printf("\nБлок %zu зашифрованные биты: ", i);
        for (int bit = 0; bit < 8; bit++) {
            int64_t* cipher = (int64_t*)(input.data + i * block_size + bit * sizeof(int64_t));
            printf("%016llx ", (unsigned long long)*cipher);
        }
        printf("\n");
        
        gm_decrypt_block(input.data + i * block_size, 
                        output->data + i, 
                        priv_key.data);
        
        printf("Расшифрованный байт %zu: 0x%02x (", i, output->data[i]);
        for (int bit = 7; bit >= 0; bit--) {
            printf("%d", (output->data[i] >> bit) & 1);
        }
        printf(")\n");
    }
    
    output->size = num_blocks;
    
    printf("\nРасшифрованные данные: ");
    for (size_t i = 0; i < output->size; i++) printf("%02x ", output->data[i]);
    printf("\n");
    printf("Текст: ");
    for (size_t i = 0; i < output->size; i++) printf("%c", output->data[i]);
    printf("\n\n");
    
    return 0;
}

}