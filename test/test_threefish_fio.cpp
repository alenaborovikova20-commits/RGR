#include <iostream>
#include <vector>
#include <cstring>
#include <cstdio>
#include <random>

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

uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

uint64_t rotr64(uint64_t x, int r) {
    return (x >> r) | (x << (64 - r));
}

void mix(uint64_t& x, uint64_t& y, int rot) {
    x = x + y;
    y = rotl64(y, rot) ^ x;
}

void unmix(uint64_t& x, uint64_t& y, int rot) {
    y = rotr64(y ^ x, rot);
    x = x - y;
}

void permute(uint64_t* v) {
    uint64_t tmp;
    tmp = v[1]; v[1] = v[3]; v[3] = tmp;
    tmp = v[5]; v[5] = v[7]; v[7] = tmp;
}

void unpermute(uint64_t* v) {
    permute(v);
}

void threefish_encrypt_block(const uint8_t* in, uint8_t* out, const uint64_t* key) {
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

void threefish_decrypt_block(const uint8_t* in, uint8_t* out, const uint64_t* key) {
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

void print_hex(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

std::vector<uint8_t> string_to_bytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string bytes_to_string(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

int main() {
    std::string fio = "Ushaneva Yulia Maksimovna";
    auto plain = string_to_bytes(fio);
    
    // Ключ для Threefish (64 байта)
    uint8_t key_bytes[TF_KEY_BYTES];
    for (int i = 0; i < TF_KEY_BYTES; i++) {
        key_bytes[i] = i & 0xFF;
    }
    
    uint64_t key_words[TF_WORDS];
    for (int i = 0; i < TF_WORDS; i++) {
        key_words[i] = 0;
        for (int b = 0; b < 8; b++) {
            key_words[i] |= (uint64_t)key_bytes[i * 8 + b] << (b * 8);
        }
    }
    
    size_t padded_len = ((plain.size() + TF_BLOCK_SIZE - 1) / TF_BLOCK_SIZE) * TF_BLOCK_SIZE;
    uint8_t pad_byte = padded_len - plain.size();
    std::vector<uint8_t> padded = plain;
    padded.resize(padded_len, pad_byte);
    
    std::vector<uint8_t> cipher(padded.size());
    
    for (size_t i = 0; i < padded_len; i += TF_BLOCK_SIZE) {
        threefish_encrypt_block(padded.data() + i, cipher.data() + i, key_words);
    }
    
    // Расшифрование
    std::vector<uint8_t> decrypted(cipher.size());
    
    for (size_t i = 0; i < cipher.size(); i += TF_BLOCK_SIZE) {
        threefish_decrypt_block(cipher.data() + i, decrypted.data() + i, key_words);
    }
    
    // Удаление паддинга
    if (!decrypted.empty()) {
        uint8_t last_pad = decrypted.back();
        if (last_pad > 0 && last_pad <= decrypted.size()) {
            decrypted.resize(decrypted.size() - last_pad);
        }
    }
    
    // ===== ВЫВОД =====
    std::cout << "Исходный текст: " << bytes_to_string(plain) << "\n";
    print_hex("HEX (ASCII): ", plain.data(), plain.size());
    printf("Размер: %zu байт\n\n", plain.size());
    
    print_hex("Текст с паддингом: ", padded.data(), padded.size());
    printf("Паддинг: %d байт\n\n", pad_byte);
    
    print_hex("Шифротекст (HEX): ", cipher.data(), cipher.size());
    
    std::cout << "\nРасшифрованный текст: " << bytes_to_string(decrypted) << "\n";
    
    if (decrypted == plain) {
        std::cout << "\n✅ УСПЕШНО!\n";
    } else {
        std::cout << "\n❌ ОШИБКА!\n";
    }
    
    return 0;
}