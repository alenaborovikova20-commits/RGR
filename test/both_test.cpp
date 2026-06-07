#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>

// ==================== RC5 ====================
#define RC5_BLOCK_SIZE 8
#define RC5_ROUNDS 12
#define RC5_KEY_BYTES 16

uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

uint32_t rotr32(uint32_t x, int r) {
    return (x >> r) | (x << (32 - r));
}

void rc5_expand_key(const uint8_t* key, uint32_t* S) {
    const uint32_t P32 = 0xB7E15163;
    const uint32_t Q32 = 0x9E3779B9;
    
    uint32_t L[4];
    for (int i = 0; i < 4; i++) {
        L[i] = ((uint32_t)key[4*i + 0]) |
               ((uint32_t)key[4*i + 1] << 8) |
               ((uint32_t)key[4*i + 2] << 16) |
               ((uint32_t)key[4*i + 3] << 24);
    }
    
    S[0] = P32;
    for (int i = 1; i < 2 * RC5_ROUNDS + 2; i++) {
        S[i] = S[i-1] + Q32;
    }
    
    int i = 0, j = 0;
    uint32_t A = 0, B = 0;
    for (int k = 0; k < 78; k++) {
        A = S[i] = rotl32(S[i] + A + B, 3);
        B = L[j] = rotl32(L[j] + A + B, A + B);
        i = (i + 1) % (2 * RC5_ROUNDS + 2);
        j = (j + 1) % 4;
    }
}

void rc5_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* S) {
    uint32_t A = ((uint32_t)in[0]) | ((uint32_t)in[1] << 8) |
                 ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    uint32_t B = ((uint32_t)in[4]) | ((uint32_t)in[5] << 8) |
                 ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    A += S[0];
    B += S[1];
    
    for (int r = 1; r <= RC5_ROUNDS; r++) {
        A = rotl32(A ^ B, B) + S[2 * r];
        B = rotl32(B ^ A, A) + S[2 * r + 1];
    }
    
    out[0] = (A >> 0) & 0xFF;
    out[1] = (A >> 8) & 0xFF;
    out[2] = (A >> 16) & 0xFF;
    out[3] = (A >> 24) & 0xFF;
    out[4] = (B >> 0) & 0xFF;
    out[5] = (B >> 8) & 0xFF;
    out[6] = (B >> 16) & 0xFF;
    out[7] = (B >> 24) & 0xFF;
}

void rc5_decrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* S) {
    uint32_t A = ((uint32_t)in[0]) | ((uint32_t)in[1] << 8) |
                 ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    uint32_t B = ((uint32_t)in[4]) | ((uint32_t)in[5] << 8) |
                 ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    for (int r = RC5_ROUNDS; r >= 1; r--) {
        B = rotr32(B - S[2 * r + 1], A) ^ A;
        A = rotr32(A - S[2 * r], B) ^ B;
    }
    
    B -= S[1];
    A -= S[0];
    
    out[0] = (A >> 0) & 0xFF;
    out[1] = (A >> 8) & 0xFF;
    out[2] = (A >> 16) & 0xFF;
    out[3] = (A >> 24) & 0xFF;
    out[4] = (B >> 0) & 0xFF;
    out[5] = (B >> 8) & 0xFF;
    out[6] = (B >> 16) & 0xFF;
    out[7] = (B >> 24) & 0xFF;
}

// PKCS#7 паддинг
std::vector<uint8_t> add_padding(const std::vector<uint8_t>& data) {
    size_t block_size = RC5_BLOCK_SIZE;
    size_t padded_len = ((data.size() + block_size - 1) / block_size) * block_size;
    uint8_t pad_byte = padded_len - data.size();
    
    std::vector<uint8_t> result = data;
    result.resize(padded_len, pad_byte);
    return result;
}

// Удаление паддинга
std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& data) {
    if (data.empty()) return data;
    
    uint8_t pad_byte = data.back();
    if (pad_byte > RC5_BLOCK_SIZE || pad_byte > data.size()) {
        throw std::runtime_error("Invalid padding");
    }
    
    for (size_t i = data.size() - pad_byte; i < data.size(); i++) {
        if (data[i] != pad_byte) {
            throw std::runtime_error("Invalid padding");
        }
    }
    
    return std::vector<uint8_t>(data.begin(), data.end() - pad_byte);
}

// Шифрование файла
void encrypt_file(const std::string& input_file, const std::string& output_file, const uint8_t* key) {
    // Читаем входной файл в бинарном режиме
    std::ifstream in(input_file, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input file");
    
    std::vector<uint8_t> plain((std::istreambuf_iterator<char>(in)), {});
    in.close();
    
    // Добавляем паддинг
    std::vector<uint8_t> padded = add_padding(plain);
    
    // Разворачиваем ключ
    uint32_t S[2 * RC5_ROUNDS + 2];
    rc5_expand_key(key, S);
    
    // Шифруем поблочно
    std::vector<uint8_t> cipher(padded.size());
    for (size_t i = 0; i < padded.size(); i += RC5_BLOCK_SIZE) {
        rc5_encrypt_block(padded.data() + i, cipher.data() + i, S);
    }
    
    // Записываем выходной файл
    std::ofstream out(output_file, std::ios::binary);
    out.write(reinterpret_cast<const char*>(cipher.data()), cipher.size());
    out.close();
}

// Расшифрование файла
void decrypt_file(const std::string& input_file, const std::string& output_file, const uint8_t* key) {
    // Читаем зашифрованный файл
    std::ifstream in(input_file, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input file");
    
    std::vector<uint8_t> cipher((std::istreambuf_iterator<char>(in)), {});
    in.close();
    
    if (cipher.size() % RC5_BLOCK_SIZE != 0) {
        throw std::runtime_error("Ciphertext size is not multiple of block size");
    }
    
    // Разворачиваем ключ
    uint32_t S[2 * RC5_ROUNDS + 2];
    rc5_expand_key(key, S);
    
    // Расшифровываем
    std::vector<uint8_t> padded(cipher.size());
    for (size_t i = 0; i < cipher.size(); i += RC5_BLOCK_SIZE) {
        rc5_decrypt_block(cipher.data() + i, padded.data() + i, S);
    }
    
    // Удаляем паддинг
    std::vector<uint8_t> plain = remove_padding(padded);
    
    // Записываем результат
    std::ofstream out(output_file, std::ios::binary);
    out.write(reinterpret_cast<const char*>(plain.data()), plain.size());
    out.close();
}

// ==================== Threefish-512 ====================
#define TF_BLOCK_SIZE 64
#define TF_WORDS 8
#define TF_ROUNDS 72

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

// ==================== ТЕСТИРОВАНИЕ ====================
void test_rc5() {
    std::cout << "\n[RC5]" << std::endl;
    
    uint8_t key[RC5_KEY_BYTES] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    
    uint8_t plain[RC5_BLOCK_SIZE] = { 'H', 'e', 'l', 'l', 'o', '!', '!', '!' };
    uint8_t cipher[RC5_BLOCK_SIZE];
    uint8_t decrypted[RC5_BLOCK_SIZE];
    
    uint32_t S[2 * RC5_ROUNDS + 2];
    rc5_expand_key(key, S);
    
    rc5_encrypt_block(plain, cipher, S);
    rc5_decrypt_block(cipher, decrypted, S);
    
    bool ok = memcmp(plain, decrypted, RC5_BLOCK_SIZE) == 0;
    
    std::cout << "  Plaintext:  ";
    for (int i = 0; i < RC5_BLOCK_SIZE; i++) std::cout << (char)plain[i];
    std::cout << std::endl;
    
    std::cout << "  Decrypted:  ";
    for (int i = 0; i < RC5_BLOCK_SIZE; i++) std::cout << (char)decrypted[i];
    std::cout << std::endl;
    
    std::cout << "  Result: " << (ok ? "✅ PASS" : "❌ FAIL") << std::endl;
}

void test_threefish() {
    std::cout << "\n[Threefish-512]" << std::endl;
    
    uint64_t key[8];
    for (int i = 0; i < 8; i++) {
        key[i] = 0x0123456789ABCDEFull ^ (i * 0x1111111111111111ull);
    }
    
    uint8_t plain[TF_BLOCK_SIZE];
    for (int i = 0; i < TF_BLOCK_SIZE; i++) {
        plain[i] = i;
    }
    
    uint8_t cipher[TF_BLOCK_SIZE];
    uint8_t decrypted[TF_BLOCK_SIZE];
    
    threefish_encrypt_block(plain, cipher, key);
    threefish_decrypt_block(cipher, decrypted, key);
    
    bool ok = memcmp(plain, decrypted, TF_BLOCK_SIZE) == 0;
    
    std::cout << "  Plain first 16 bytes: ";
    for (int i = 0; i < 16; i++) std::cout << (int)plain[i] << " ";
    std::cout << std::endl;
    
    std::cout << "  Result: " << (ok ? "✅ PASS" : "❌ FAIL") << std::endl;
}

int main() {
    try {
        uint8_t key[RC5_KEY_BYTES] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };
        
        std::cout << "Encrypting image.jpg -> image.jpg.enc" << std::endl;
        encrypt_file("image.jpg", "image.jpg.enc", key);
        
        std::cout << "Decrypting image.jpg.enc -> image_dec.jpg" << std::endl;
        decrypt_file("image.jpg.enc", "image_dec.jpg", key);
        
        std::cout << "Done! Check if image_dec.jpg matches original." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}