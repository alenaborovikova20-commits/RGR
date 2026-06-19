#include "crypto_abi.h"
#include "xtea.h"
#include <cstring>
#include <random>

static std::mt19937_64 rng(std::random_device{}());

static AlgorithmInfo algo_info = {
    "xtea",
    XTEA_KEY
};

static size_t padded_length(size_t original) {
    size_t block = XTEA_BLOCK;
    size_t pad = block - (original % block);

    if (pad == 0) {
        pad = block;
    }

    return original + pad;
}

static void add_padding(uint8_t* data, size_t old_len, size_t new_len) {
    uint8_t pad_byte = new_len - old_len;

    for (size_t i = old_len; i < new_len; i++) {
        data[i] = pad_byte;
    }
}

static int remove_padding(uint8_t* data, size_t* length) {
    if (*length == 0) {
        return -1;
    }

    uint8_t pad_byte = data[*length - 1];

    if (pad_byte == 0 || pad_byte > XTEA_BLOCK || pad_byte > *length) {
        return -1;
    }

    for (size_t i = *length - pad_byte; i < *length; i++) {
        if (data[i] != pad_byte) {
            return -1;
        }
    }

    *length -= pad_byte;
    return 0;
}

static uint64_t random_iv() {
    std::uniform_int_distribution<uint64_t> dist;
    return dist(rng);
}

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &algo_info;
}

size_t get_output_size(size_t input_size, int mode) {
    (void)mode;
    return padded_length(input_size) + XTEA_BLOCK;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != XTEA_KEY) {
        return -1;
    }

    size_t data_with_padding = padded_length(input.size);
    size_t total = data_with_padding + XTEA_BLOCK;

    if (output->size < total) {
        return -2;
    }

    uint64_t iv = random_iv();
    memcpy(output->data, &iv, XTEA_BLOCK);

    memcpy(output->data + XTEA_BLOCK, input.data, input.size);
    add_padding(output->data + XTEA_BLOCK, input.size, data_with_padding);

    uint32_t round_keys[4];
    xtea_prepare_keys(key.data, round_keys);

    for (size_t i = 0; i < data_with_padding; i += XTEA_BLOCK) {
        xtea_encrypt(
            output->data + XTEA_BLOCK + i,
            output->data + XTEA_BLOCK + i,
            round_keys
        );
    }

    output->size = total;

    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != XTEA_KEY) {
        return -1;
    }

    if (input.size < XTEA_BLOCK) {
        return -2;
    }

    if ((input.size - XTEA_BLOCK) % XTEA_BLOCK != 0) {
        return -3;
    }

    if (output->size < input.size) {
        return -4;
    }

    size_t cipher_length = input.size - XTEA_BLOCK;
    memcpy(output->data, input.data + XTEA_BLOCK, cipher_length);

    uint32_t round_keys[4];
    xtea_prepare_keys(key.data, round_keys);

    for (size_t i = 0; i < cipher_length; i += XTEA_BLOCK) {
        xtea_decrypt(
            output->data + i,
            output->data + i,
            round_keys
        );
    }

    size_t real_length = cipher_length;
    if (remove_padding(output->data, &real_length) != 0) {
        return -5;
    }

    output->size = real_length;

    return 0;
}

int encrypt_fixed_iv(ConstBuffer key, ConstBuffer iv, ConstBuffer input, MutBuffer* output) {
    if (key.size != XTEA_KEY) {
        return -1;
    }

    if (iv.size != XTEA_BLOCK) {
        return -2;
    }

    size_t data_with_padding = padded_length(input.size);
    size_t total = data_with_padding + XTEA_BLOCK;

    if (output->size < total) {
        return -3;
    }

    memcpy(output->data, iv.data, XTEA_BLOCK);
    memcpy(output->data + XTEA_BLOCK, input.data, input.size);
    add_padding(output->data + XTEA_BLOCK, input.size, data_with_padding);

    uint32_t round_keys[4];
    xtea_prepare_keys(key.data, round_keys);

    for (size_t i = 0; i < data_with_padding; i += XTEA_BLOCK) {
        xtea_encrypt(
            output->data + XTEA_BLOCK + i,
            output->data + XTEA_BLOCK + i,
            round_keys
        );
    }

    output->size = total;
    return 0;
}

}