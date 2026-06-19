#include "crypto_abi.h"
#include "rc5.h"
#include <cstring>
#include <random>

static AlgorithmInfo info = {
    "RC5",
    RC5_KEY_BYTES
};

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

    uint32_t S[2 * RC5_ROUNDS + 2];
    rc5_expand_key(key.data, S);

    uint8_t* padded = new uint8_t[padded_len];
    memcpy(padded, input.data, input.size);
    pkcs7_apply_padding(padded, input.size, padded_len);

    uint8_t prev[RC5_BLOCK_SIZE];
    memcpy(prev, iv, RC5_BLOCK_SIZE);

    for (size_t i = 0; i < padded_len; i += RC5_BLOCK_SIZE) {
        for (size_t j = 0; j < RC5_BLOCK_SIZE; j++) {
            padded[i + j] ^= prev[j];
        }

        rc5_encrypt_block(padded + i, output->data + RC5_BLOCK_SIZE + i, S);

        memcpy(prev, output->data + RC5_BLOCK_SIZE + i, RC5_BLOCK_SIZE);
    }
    output->size = total_len;
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

    uint8_t prev[RC5_BLOCK_SIZE];
    memcpy(prev, iv, RC5_BLOCK_SIZE);

    uint8_t* decrypted = new uint8_t[cipher_len];

    for (size_t i = 0; i < cipher_len; i += RC5_BLOCK_SIZE) {
        rc5_decrypt_block(ciphertext + i, decrypted + i, S);

        for (size_t j = 0; j < RC5_BLOCK_SIZE; j++) {
            decrypted[i + j] ^= prev[j];
        }

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

    delete[] decrypted;
    return 0;
}

}