#include "crypto_abi.h"
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <vector>
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

static int simple_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    uint64_t key_words[TF_WORDS];
    for (int i = 0; i < TF_WORDS; i++) {
        key_words[i] = 0;
        for (int b = 0; b < 8; b++) {
            key_words[i] |= (uint64_t)key.data[i * 8 + b] << (b * 8);
        }
    }
    
    std::vector<uint8_t> plain(input.data, input.data + input.size);
    std::vector<uint8_t> padded = add_padding(plain);
    
    std::vector<uint8_t> cipher(padded.size());
    for (size_t i = 0; i < padded.size(); i += TF_BLOCK_SIZE) {
        threefish_encrypt_block(padded.data() + i, cipher.data() + i, key_words);
    }
    
    if (output->size < cipher.size()) {
        return -2;
    }
    memcpy(output->data, cipher.data(), cipher.size());
    output->size = cipher.size();
    return 0;
}

static int simple_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (input.size % TF_BLOCK_SIZE != 0) return -1;
    
    uint64_t key_words[TF_WORDS];
    for (int i = 0; i < TF_WORDS; i++) {
        key_words[i] = 0;
        for (int b = 0; b < 8; b++) {
            key_words[i] |= (uint64_t)key.data[i * 8 + b] << (b * 8);
        }
    }
    
    std::vector<uint8_t> cipher(input.data, input.data + input.size);
    std::vector<uint8_t> padded(cipher.size());
    
    for (size_t i = 0; i < cipher.size(); i += TF_BLOCK_SIZE) {
        threefish_decrypt_block(cipher.data() + i, padded.data() + i, key_words);
    }
    
    std::vector<uint8_t> plain = remove_padding(padded);
    
    if (output->size < plain.size()) {
        return -2;
    }
    memcpy(output->data, plain.data(), plain.size());
    output->size = plain.size();
    return 0;
}

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

size_t get_output_size(size_t input_size, int encrypt_mode) {
    (void)encrypt_mode;
    size_t block_size = TF_BLOCK_SIZE;
    size_t padded_len = ((input_size + block_size - 1) / block_size) * block_size;
    return padded_len;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != TF_KEY_BYTES) return -1;
    size_t needed = get_output_size(input.size, 1);
    if (output->size < needed) return -2;
    return simple_encrypt(key, input, output);
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != TF_KEY_BYTES) return -1;
    if (output->size < input.size) return -2;
    return simple_decrypt(key, input, output);
}

}