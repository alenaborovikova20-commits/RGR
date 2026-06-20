#include "crypto_abi.h"
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <vector>
#include <random>
#include <stdexcept>
#define TF_KEY_BYTES 64          

static AlgorithmInfo info = {"Threefish", TF_KEY_BYTES};

#define TF_BLOCK_SIZE 64
#define TF_WORDS 8
#define TF_ROUNDS 72
#define TF_KEY_BYTES 64

const int ROT[8][4] = {
    {46, 36, 19, 37},
    {33, 27, 14, 42},
    {17, 49, 36, 39},
    {44,  9, 54, 56},
    {39, 30, 34, 24},
    {13, 50, 10, 17},
    {25, 29, 39, 43},
    { 8, 35, 56, 22}
};

static uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static uint64_t rotr64(uint64_t x, int r) {
    return (x >> r) | (x << (64 - r));
}

static void mix(uint64_t& x, uint64_t& y, int rot) {
    x = x + y;
    y = rotl64(y, rot) ^ x;
}

static void unmix(uint64_t& x, uint64_t& y, int rot) {
    y = rotr64(y ^ x, rot);
    x = x - y;
}

static void permute(uint64_t* v) {
    uint64_t tmp;
    tmp = v[1]; v[1] = v[3]; v[3] = tmp;
    tmp = v[5]; v[5] = v[7]; v[7] = tmp;
}

static void unpermute(uint64_t* v) {
    permute(v);
}

static void generate_iv(uint8_t* iv) {
    std::random_device rd;
    for (size_t i = 0; i < TF_BLOCK_SIZE; i++) {
        iv[i] = rd() & 0xFF;
    }
}

static void threefish_encrypt_block_debug(const uint8_t* in, uint8_t* out, const uint64_t* key, int block_num) {
    uint64_t v[TF_WORDS];
    
    printf("Блок %d начальные данные: ", block_num);
    for (int i = 0; i < TF_BLOCK_SIZE; i++) printf("%02x ", in[i]);
    printf("\n");
    
    for (int i = 0; i < TF_WORDS; i++) {
        v[i] = 0;
        for (int b = 0; b < 8; b++) {
            v[i] |= (uint64_t)in[i * 8 + b] << (b * 8);
        }
    }
    
    printf("Начальные слова: ");
    for (int i = 0; i < TF_WORDS; i++) printf("%016llx ", (unsigned long long)v[i]);
    printf("\n");
    
    for (int i = 0; i < TF_WORDS; i++) {
        v[i] += key[i];
    }
    
    printf("После добавления ключа: ");
    for (int i = 0; i < TF_WORDS; i++) printf("%016llx ", (unsigned long long)v[i]);
    printf("\n");
    
    for (int r = 0; r < TF_ROUNDS; r++) {
        mix(v[0], v[1], ROT[r % 8][0]);
        mix(v[2], v[3], ROT[r % 8][1]);
        mix(v[4], v[5], ROT[r % 8][2]);
        mix(v[6], v[7], ROT[r % 8][3]);
        
        permute(v);
        
        if (r % 4 == 0) {
            for (int i = 0; i < TF_WORDS; i++) {
                v[i] += key[i];
            }
        }
        
        if (r < 4 || r % 8 == 0) {
            printf("Раунд %d: ", r);
            for (int i = 0; i < TF_WORDS; i++) printf("%016llx ", (unsigned long long)v[i]);
            printf("\n");
        }
    }
    
    for (int i = 0; i < TF_WORDS; i++) {
        for (int b = 0; b < 8; b++) {
            out[i * 8 + b] = (v[i] >> (b * 8)) & 0xFF;
        }
    }
    
    printf("Блок %d зашифрован: ", block_num);
    for (int i = 0; i < TF_BLOCK_SIZE; i++) printf("%02x ", out[i]);
    printf("\n");
}

static void threefish_encrypt_block(const uint8_t* in, uint8_t* out, const uint64_t* key) {
    uint64_t v[TF_WORDS];
    
    for (int i = 0; i < TF_WORDS; i++) {
        v[i] = 0;
        for (int b = 0; b < 8; b++) {
            v[i] |= (uint64_t)in[i * 8 + b] << (b * 8);
        }
    }
    
    for (int i = 0; i < TF_WORDS; i++) {
        v[i] += key[i];
    }
    
    for (int r = 0; r < TF_ROUNDS; r++) {
        mix(v[0], v[1], ROT[r % 8][0]);
        mix(v[2], v[3], ROT[r % 8][1]);
        mix(v[4], v[5], ROT[r % 8][2]);
        mix(v[6], v[7], ROT[r % 8][3]);
        
        permute(v);
        
        if (r % 4 == 0) {
            for (int i = 0; i < TF_WORDS; i++) {
                v[i] += key[i];
            }
        }
    }
    
    for (int i = 0; i < TF_WORDS; i++) {
        for (int b = 0; b < 8; b++) {
            out[i * 8 + b] = (v[i] >> (b * 8)) & 0xFF;
        }
    }
}

static void threefish_decrypt_block(const uint8_t* in, uint8_t* out, const uint64_t* key) {
    uint64_t v[TF_WORDS];
    
    for (int i = 0; i < TF_WORDS; i++) {
        v[i] = 0;
        for (int b = 0; b < 8; b++) {
            v[i] |= (uint64_t)in[i * 8 + b] << (b * 8);
        }
    }
    
    for (int r = TF_ROUNDS - 1; r >= 0; r--) {
        if (r % 4 == 0) {
            for (int i = 0; i < TF_WORDS; i++) {
                v[i] -= key[i];
            }
        }
        
        unpermute(v);
        
        unmix(v[0], v[1], ROT[r % 8][0]);
        unmix(v[2], v[3], ROT[r % 8][1]);
        unmix(v[4], v[5], ROT[r % 8][2]);
        unmix(v[6], v[7], ROT[r % 8][3]);
    }
    
    for (int i = 0; i < TF_WORDS; i++) {
        v[i] -= key[i];
    }
    
    for (int i = 0; i < TF_WORDS; i++) {
        for (int b = 0; b < 8; b++) {
            out[i * 8 + b] = (v[i] >> (b * 8)) & 0xFF;
        }
    }
}

static std::vector<uint8_t> add_padding(const std::vector<uint8_t>& data) {
    size_t block_size = TF_BLOCK_SIZE;
    size_t padded_len = ((data.size() + block_size - 1) / block_size) * block_size;
    uint8_t pad_byte = padded_len - data.size();
    
    std::vector<uint8_t> result = data;
    result.resize(padded_len, pad_byte);
    return result;
}

static std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& data) {
    if (data.empty()) return data;
    
    uint8_t pad_byte = data.back();
    if (pad_byte > TF_BLOCK_SIZE || pad_byte > data.size()) {
        throw std::runtime_error("Invalid padding");
    }
    
    for (size_t i = data.size() - pad_byte; i < data.size(); i++) {
        if (data[i] != pad_byte) {
            throw std::runtime_error("Invalid padding");
        }
    }
    
    return std::vector<uint8_t>(data.begin(), data.end() - pad_byte);
}

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

size_t get_output_size(size_t input_size, int encrypt_mode) {
    (void)encrypt_mode;
    size_t block_size = TF_BLOCK_SIZE;
    size_t padded_len = ((input_size + block_size - 1) / block_size) * block_size;
    return TF_BLOCK_SIZE + padded_len;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != TF_KEY_BYTES) return -1;
    
    size_t padded_len = ((input.size + TF_BLOCK_SIZE - 1) / TF_BLOCK_SIZE) * TF_BLOCK_SIZE;
    size_t total_len = TF_BLOCK_SIZE + padded_len;
    
    if (output->size < total_len) return -2;
    
    uint8_t iv[TF_BLOCK_SIZE];
    generate_iv(iv);
    memcpy(output->data, iv, TF_BLOCK_SIZE);
    
    printf("\nШифрование Threefish в режиме CBC\n");
    printf("Исходные данные: ");
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");
    
    uint64_t key_words[TF_WORDS];
    for (int i = 0; i < TF_WORDS; i++) {
        key_words[i] = 0;
        for (int b = 0; b < 8; b++) {
            key_words[i] |= (uint64_t)key.data[i * 8 + b] << (b * 8);
        }
    }
    
    std::vector<uint8_t> plain(input.data, input.data + input.size);
    std::vector<uint8_t> padded = add_padding(plain);
    
    printf("Данные после паддинга: ");
    for (size_t i = 0; i < padded.size(); i++) printf("%02x ", padded[i]);
    printf("\n");
    
    printf("Вектор инициализации: ");
    for (int i = 0; i < TF_BLOCK_SIZE; i++) printf("%02x ", iv[i]);
    printf("\n");
    printf("Количество раундов: %d\n\n", TF_ROUNDS);
    
    uint8_t prev[TF_BLOCK_SIZE];
    memcpy(prev, iv, TF_BLOCK_SIZE);
    
    std::vector<uint8_t> cipher(padded.size());
    
    for (size_t i = 0; i < padded.size(); i += TF_BLOCK_SIZE) {
        size_t block_num = i / TF_BLOCK_SIZE;
        
        printf("Блок %zu до XOR: ", block_num);
        for (int j = 0; j < TF_BLOCK_SIZE; j++) printf("%02x ", padded[i + j]);
        printf("\n");
        
        for (int j = 0; j < TF_BLOCK_SIZE; j++) {
            padded[i + j] ^= prev[j];
        }
        
        printf("Блок %zu после XOR: ", block_num);
        for (int j = 0; j < TF_BLOCK_SIZE; j++) printf("%02x ", padded[i + j]);
        printf("\n");
        
        if (block_num == 0) {
            threefish_encrypt_block_debug(padded.data() + i, cipher.data() + i, key_words, 0);
        } else {
            threefish_encrypt_block(padded.data() + i, cipher.data() + i, key_words);
        }
        
        printf("Блок %zu зашифрован: ", block_num);
        for (int j = 0; j < TF_BLOCK_SIZE; j++) printf("%02x ", cipher[i + j]);
        printf("\n\n");
        
        memcpy(prev, cipher.data() + i, TF_BLOCK_SIZE);
    }
    
    memcpy(output->data + TF_BLOCK_SIZE, cipher.data(), cipher.size());
    output->size = total_len;
    
    printf("Полный шифротекст: ");
    for (size_t i = 0; i < output->size; i++) printf("%02x ", output->data[i]);
    printf("\n\n");
    
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != TF_KEY_BYTES) return -1;
    if (input.size < TF_BLOCK_SIZE) return -2;
    if ((input.size - TF_BLOCK_SIZE) % TF_BLOCK_SIZE != 0) return -3;
    if (output->size < input.size) return -4;
    
    const uint8_t* iv = input.data;
    const uint8_t* ciphertext = input.data + TF_BLOCK_SIZE;
    size_t cipher_len = input.size - TF_BLOCK_SIZE;
    
    printf("\nРасшифрование Threefish в режиме CBC\n");
    printf("Полученный шифротекст: ");
    for (size_t i = 0; i < input.size; i++) printf("%02x ", input.data[i]);
    printf("\n");
    
    printf("Вектор инициализации: ");
    for (int i = 0; i < TF_BLOCK_SIZE; i++) printf("%02x ", iv[i]);
    printf("\n\n");
    
    uint64_t key_words[TF_WORDS];
    for (int i = 0; i < TF_WORDS; i++) {
        key_words[i] = 0;
        for (int b = 0; b < 8; b++) {
            key_words[i] |= (uint64_t)key.data[i * 8 + b] << (b * 8);
        }
    }
    
    uint8_t prev[TF_BLOCK_SIZE];
    memcpy(prev, iv, TF_BLOCK_SIZE);
    
    std::vector<uint8_t> decrypted(cipher_len);
    
    for (size_t i = 0; i < cipher_len; i += TF_BLOCK_SIZE) {
        size_t block_num = i / TF_BLOCK_SIZE;
        
        threefish_decrypt_block(ciphertext + i, decrypted.data() + i, key_words);
        
        printf("Блок %zu расшифрован: ", block_num);
        for (int j = 0; j < TF_BLOCK_SIZE; j++) printf("%02x ", decrypted[i + j]);
        printf("\n");
        
        for (int j = 0; j < TF_BLOCK_SIZE; j++) {
            decrypted[i + j] ^= prev[j];
        }
        
        printf("Блок %zu после XOR: ", block_num);
        for (int j = 0; j < TF_BLOCK_SIZE; j++) printf("%02x ", decrypted[i + j]);
        printf("\n\n");
        
        memcpy(prev, ciphertext + i, TF_BLOCK_SIZE);
    }
    
    std::vector<uint8_t> plain;
    try {
        plain = remove_padding(decrypted);
    } catch (...) {
        return -5;
    }
    
    if (output->size < plain.size()) {
        return -6;
    }
    
    memcpy(output->data, plain.data(), plain.size());
    output->size = plain.size();
    
    printf("Расшифрованные данные: ");
    for (size_t i = 0; i < output->size; i++) printf("%02x ", output->data[i]);
    printf("\n");
    printf("Текст: ");
    for (size_t i = 0; i < output->size; i++) printf("%c", output->data[i]);
    printf("\n\n");
    
    return 0;
}

}