#include "crypto_abi.h"
#include "threefish.h"
#include <cstring>

static AlgorithmInfo info = {"Threefish", TF_KEY_BYTES};

// PKCS#7
static size_t pkcs7_padded_size(size_t input_len) {
    size_t block = TF_BLOCK_SIZE;
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
    if (pad_byte > TF_BLOCK_SIZE || pad_byte > *len) return -1;
    for (size_t i = *len - pad_byte; i < *len; i++) {
        if (data[i] != pad_byte) return -1;
    }
    *len -= pad_byte;
    return 0;
}

// CBC режим с IV
static int cbc_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Разворачиваем ключ
    uint64_t round_keys[TF_ROUNDS * 8];
    uint64_t key_words[TF_WORDS];
    uint64_t tweak[2] = {0, 0};  // tweak пока нулевой
    
    for (int i = 0; i < TF_WORDS; i++) {
        key_words[i] = 0;
        for (int b = 0; b < 8; b++) {
            key_words[i] |= (uint64_t)key.data[i * 8 + b] << (b * 8);
        }
    }
    
    threefish_key_schedule(key_words, tweak, round_keys);
    
    // Генерируем IV
    uint8_t iv[TF_BLOCK_SIZE];
    threefish_generate_iv(iv);
    
    // Копируем IV в начало выхода
    memcpy(output->data, iv, TF_BLOCK_SIZE);
    
    // Подготовка буфера с паддингом
    size_t padded_len = pkcs7_padded_size(input.size);
    uint8_t* padded_data = new uint8_t[padded_len];
    memcpy(padded_data, input.data, input.size);
    pkcs7_apply_padding(padded_data, input.size, padded_len);
    
    // CBC шифрование
    uint8_t prev[TF_BLOCK_SIZE];
    memcpy(prev, iv, TF_BLOCK_SIZE);
    
    for (size_t block = 0; block < padded_len / TF_BLOCK_SIZE; block++) {
        // XOR с предыдущим шифротекстом (или IV)
        uint8_t block_data[TF_BLOCK_SIZE];
        memcpy(block_data, padded_data + block * TF_BLOCK_SIZE, TF_BLOCK_SIZE);
        
        for (int i = 0; i < TF_BLOCK_SIZE; i++) {
            block_data[i] ^= prev[i];
        }
        
        // Шифрование блока
        threefish_encrypt_block(block_data, output->data + TF_BLOCK_SIZE + block * TF_BLOCK_SIZE, round_keys);
        
        // Сохраняем для следующего блока
        memcpy(prev, output->data + TF_BLOCK_SIZE + block * TF_BLOCK_SIZE, TF_BLOCK_SIZE);
    }
    
    output->size = TF_BLOCK_SIZE + padded_len;
    delete[] padded_data;
    return 0;
}

static int cbc_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверки
    if (input.size < TF_BLOCK_SIZE) return -1;
    if ((input.size - TF_BLOCK_SIZE) % TF_BLOCK_SIZE != 0) return -2;
    
    // Извлекаем IV из начала
    const uint8_t* iv = input.data;
    const uint8_t* ciphertext = input.data + TF_BLOCK_SIZE;
    size_t cipher_len = input.size - TF_BLOCK_SIZE;
    
    // Разворачиваем ключ
    uint64_t round_keys[TF_ROUNDS * 8];
    uint64_t key_words[TF_WORDS];
    uint64_t tweak[2] = {0, 0};
    
    for (int i = 0; i < TF_WORDS; i++) {
        key_words[i] = 0;
        for (int b = 0; b < 8; b++) {
            key_words[i] |= (uint64_t)key.data[i * 8 + b] << (b * 8);
        }
    }
    
    threefish_key_schedule(key_words, tweak, round_keys);
    
    // Расшифровываем CBC
    uint8_t prev[TF_BLOCK_SIZE];
    memcpy(prev, iv, TF_BLOCK_SIZE);
    
    uint8_t* decrypted = new uint8_t[cipher_len];
    
    for (size_t block = 0; block < cipher_len / TF_BLOCK_SIZE; block++) {
        // Расшифровываем блок
        threefish_decrypt_block(ciphertext + block * TF_BLOCK_SIZE, decrypted + block * TF_BLOCK_SIZE, round_keys);
        
        // XOR с предыдущим
        for (int i = 0; i < TF_BLOCK_SIZE; i++) {
            decrypted[block * TF_BLOCK_SIZE + i] ^= prev[i];
        }
        
        // Сохраняем текущий шифротекст для следующего блока
        memcpy(prev, ciphertext + block * TF_BLOCK_SIZE, TF_BLOCK_SIZE);
    }
    
    // Удаляем паддинг
    size_t decrypted_len = cipher_len;
    if (pkcs7_remove_padding(decrypted, &decrypted_len) != 0) {
        delete[] decrypted;
        return -3;
    }
    
    // Копируем результат
    if (output->size < decrypted_len) {
        delete[] decrypted;
        return -4;
    }
    memcpy(output->data, decrypted, decrypted_len);
    output->size = decrypted_len;
    
    delete[] decrypted;
    return 0;
}

// Экспортируемые функции
extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

size_t get_output_size(size_t input_size, int encrypt_mode) {
    (void)encrypt_mode;
    // Для Threefish: IV (64 байта) + паддинг
    size_t padded = pkcs7_padded_size(input_size);
    return TF_BLOCK_SIZE + padded;  // IV + зашифрованные данные
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != TF_KEY_BYTES) return -1;
    
    size_t needed = get_output_size(input.size, 1);
    if (output->size < needed) return -2;
    
    return cbc_encrypt(key, input, output);
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != TF_KEY_BYTES) return -1;
    if (output->size < input.size) return -2;
    
    return cbc_decrypt(key, input, output);
}

} // extern "C"