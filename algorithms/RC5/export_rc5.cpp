#include "include/crypto_abi.h"  // структуры ConstBuffer, MutBuffer, AlgorithmInfo
#include "rc5.h"         // функции RC5
#include <cstring>

// Метаинформация об алгоритме
static AlgorithmInfo info = {
    "RC5",
    RC5_KEY_BYTES   // 16 байт
};

// Вспомогательные функции для PKCS#7
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

// Экспортируемые функции (видны через dlsym)
extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

size_t get_output_size(size_t input_size, int encrypt_mode) {
    (void)encrypt_mode;  // не используется для RC5
    return pkcs7_padded_size(input_size);
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверки
    if (key.size != RC5_KEY_BYTES) return -1;
    
    size_t out_size = get_output_size(input.size, 1);
    if (output->size < out_size) return -2;
    
    // Разворачиваем ключ
    uint32_t S[2 * RC5_ROUNDS + 2];
    rc5_expand_key(key.data, S);
    
    // Копируем входные данные + паддинг
    memcpy(output->data, input.data, input.size);
    pkcs7_apply_padding(output->data, input.size, out_size);
    
    // Шифруем поблочно
    for (size_t i = 0; i < out_size; i += RC5_BLOCK_SIZE) {
        rc5_encrypt_block(output->data + i, output->data + i, S);
    }
    
    output->size = out_size;
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверки
    if (key.size != RC5_KEY_BYTES) return -1;
    if (input.size % RC5_BLOCK_SIZE != 0) return -2;
    if (output->size < input.size) return -3;
    
    // Разворачиваем ключ
    uint32_t S[2 * RC5_ROUNDS + 2];
    rc5_expand_key(key.data, S);
    
    // Копируем и расшифровываем
    memcpy(output->data, input.data, input.size);
    for (size_t i = 0; i < input.size; i += RC5_BLOCK_SIZE) {
        rc5_decrypt_block(output->data + i, output->data + i, S);
    }
    
    // Удаляем паддинг
    size_t len = input.size;
    if (pkcs7_remove_padding(output->data, &len) != 0) {
        return -4;
    }
    
    output->size = len;
    return 0;
}

} // extern "C"