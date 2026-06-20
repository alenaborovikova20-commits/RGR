#include "crypto_abi.h"
#include "xtea.h"
#include <cstring>
#include <cstdio>
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

static void xtea_encrypt_block_debug(const uint8_t* in, uint8_t* out, const uint32_t* round_keys, int block_num) {
    uint32_t v0, v1;
    
    memcpy(&v0, in, 4);
    memcpy(&v1, in + 4, 4);
    
    printf("Блок %d начальное состояние: v0=%08x v1=%08x\n", block_num, v0, v1);
    
    uint32_t sum = 0;
    uint32_t delta = 0x9E3779B9;
    
    for (int r = 0; r < 32; r++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + round_keys[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + round_keys[(sum >> 11) & 3]);
        
        if (r < 4 || r % 8 == 0) {
            printf("Раунд %d: v0=%08x v1=%08x sum=%08x\n", r + 1, v0, v1, sum);
        }
    }
    
    memcpy(out, &v0, 4);
    memcpy(out + 4, &v1, 4);
    
    printf("Блок %d зашифрован: ", block_num);
    for (int i = 0; i < XTEA_BLOCK; i++) printf("%02x ", out[i]);
    printf("\n");
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

    printf("\nШифрование XTEA в режиме CBC\n");
    printf("Исходные данные: ");
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");

    memcpy(output->data + XTEA_BLOCK, input.data, input.size);
    add_padding(output->data + XTEA_BLOCK, input.size, data_with_padding);

    printf("Данные после паддинга: ");
    for (size_t i = 0; i < data_with_padding; i++) printf("%02x ", output->data[XTEA_BLOCK + i]);
    printf("\n");

    uint32_t round_keys[4];
    xtea_prepare_keys(key.data, round_keys);

    printf("Вектор инициализации: ");
    for (int i = 0; i < XTEA_BLOCK; i++) printf("%02x ", output->data[i]);
    printf("\n");
    printf("Количество раундов: 32\n\n");

    uint8_t prev[XTEA_BLOCK];
    memcpy(prev, output->data, XTEA_BLOCK);

    for (size_t i = 0; i < data_with_padding; i += XTEA_BLOCK) {
        size_t block_num = i / XTEA_BLOCK;
        
        printf("Блок %zu до XOR: ", block_num);
        for (int j = 0; j < XTEA_BLOCK; j++) printf("%02x ", output->data[XTEA_BLOCK + i + j]);
        printf("\n");
        
        for (int j = 0; j < XTEA_BLOCK; j++) {
            output->data[XTEA_BLOCK + i + j] ^= prev[j];
        }
        
        printf("Блок %zu после XOR: ", block_num);
        for (int j = 0; j < XTEA_BLOCK; j++) printf("%02x ", output->data[XTEA_BLOCK + i + j]);
        printf("\n");
        
        if (block_num == 0) {
            xtea_encrypt_block_debug(output->data + XTEA_BLOCK + i, output->data + XTEA_BLOCK + i, round_keys, 0);
        } else {
            xtea_encrypt(output->data + XTEA_BLOCK + i, output->data + XTEA_BLOCK + i, round_keys);
        }
        
        printf("Блок %zu зашифрован: ", block_num);
        for (int j = 0; j < XTEA_BLOCK; j++) printf("%02x ", output->data[XTEA_BLOCK + i + j]);
        printf("\n\n");
        
        memcpy(prev, output->data + XTEA_BLOCK + i, XTEA_BLOCK);
    }

    output->size = total;

    printf("Полный шифротекст: ");
    for (size_t i = 0; i < output->size; i++) printf("%02x ", output->data[i]);
    printf("\n\n");

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
    const uint8_t* iv = input.data;
    const uint8_t* ciphertext = input.data + XTEA_BLOCK;

    printf("\nРасшифрование XTEA в режиме CBC\n");
    printf("Полученный шифротекст: ");
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");

    printf("Вектор инициализации: ");
    for (int i = 0; i < XTEA_BLOCK; i++) printf("%02x ", iv[i]);
    printf("\n\n");

    uint32_t round_keys[4];
    xtea_prepare_keys(key.data, round_keys);

    uint8_t prev[XTEA_BLOCK];
    memcpy(prev, iv, XTEA_BLOCK);

    for (size_t i = 0; i < cipher_length; i += XTEA_BLOCK) {
        size_t block_num = i / XTEA_BLOCK;
        
        xtea_decrypt(output->data + i, output->data + i, round_keys);
        
        printf("Блок %zu расшифрован: ", block_num);
        for (int j = 0; j < XTEA_BLOCK; j++) printf("%02x ", output->data[i + j]);
        printf("\n");
        
        for (int j = 0; j < XTEA_BLOCK; j++) {
            output->data[i + j] ^= prev[j];
        }
        
        printf("Блок %zu после XOR: ", block_num);
        for (int j = 0; j < XTEA_BLOCK; j++) printf("%02x ", output->data[i + j]);
        printf("\n\n");
        
        memcpy(prev, ciphertext + i, XTEA_BLOCK);
    }

    size_t real_length = cipher_length;
    if (remove_padding(output->data, &real_length) != 0) {
        return -5;
    }

    output->size = real_length;

    printf("Расшифрованные данные: ");
    for (size_t i = 0; i < output->size; i++) printf("%02x ", output->data[i]);
    printf("\n");
    printf("Текст: ");
    for (size_t i = 0; i < output->size; i++) printf("%c", output->data[i]);
    printf("\n\n");

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

    uint8_t prev[XTEA_BLOCK];
    memcpy(prev, output->data, XTEA_BLOCK);

    for (size_t i = 0; i < data_with_padding; i += XTEA_BLOCK) {
        for (int j = 0; j < XTEA_BLOCK; j++) {
            output->data[XTEA_BLOCK + i + j] ^= prev[j];
        }
        
        xtea_encrypt(output->data + XTEA_BLOCK + i, output->data + XTEA_BLOCK + i, round_keys);
        
        memcpy(prev, output->data + XTEA_BLOCK + i, XTEA_BLOCK);
    }

    output->size = total;
    return 0;
}

}