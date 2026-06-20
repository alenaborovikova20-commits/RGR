#include <iostream>
#include <vector>
#include <cstring>
#include <cstdio>
#include <random>

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
        A = rotl32(A ^ B, B % 32) + S[2 * r];
        B = rotl32(B ^ A, A % 32) + S[2 * r + 1];
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
        B = rotr32(B - S[2 * r + 1], A % 32) ^ A;
        A = rotr32(A - S[2 * r], B % 32) ^ B;
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
    
    uint8_t key_bytes[RC5_KEY_BYTES] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t iv_bytes[RC5_BLOCK_SIZE] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    
    std::vector<uint8_t> key(key_bytes, key_bytes + RC5_KEY_BYTES);
    std::vector<uint8_t> iv(iv_bytes, iv_bytes + RC5_BLOCK_SIZE);
    
    uint32_t S[2 * RC5_ROUNDS + 2];
    rc5_expand_key(key.data(), S);
    
    size_t block_size = RC5_BLOCK_SIZE;
    size_t padded_len = ((plain.size() + block_size - 1) / block_size) * block_size;
    uint8_t pad_byte = padded_len - plain.size();
    std::vector<uint8_t> padded = plain;
    padded.resize(padded_len, pad_byte);
    
    std::vector<uint8_t> cipher(padded.size());
    uint8_t prev[RC5_BLOCK_SIZE];
    memcpy(prev, iv.data(), RC5_BLOCK_SIZE);
    
    size_t num_blocks = padded.size() / RC5_BLOCK_SIZE;
    
    for (size_t block_idx = 0; block_idx < num_blocks; block_idx++) {
        uint8_t block[RC5_BLOCK_SIZE];
        memcpy(block, padded.data() + block_idx * RC5_BLOCK_SIZE, RC5_BLOCK_SIZE);
        
        for (int i = 0; i < RC5_BLOCK_SIZE; i++) {
            block[i] ^= prev[i];
        }
        
        rc5_encrypt_block(block, cipher.data() + block_idx * RC5_BLOCK_SIZE, S);
        memcpy(prev, cipher.data() + block_idx * RC5_BLOCK_SIZE, RC5_BLOCK_SIZE);
    }
    
    // Расшифрование
    std::vector<uint8_t> decrypted(cipher.size());
    memcpy(prev, iv.data(), RC5_BLOCK_SIZE);
    
    for (size_t block_idx = 0; block_idx < num_blocks; block_idx++) {
        const uint8_t* block_in = cipher.data() + block_idx * RC5_BLOCK_SIZE;
        uint8_t* block_out = decrypted.data() + block_idx * RC5_BLOCK_SIZE;
        
        rc5_decrypt_block(block_in, block_out, S);
        
        for (int i = 0; i < RC5_BLOCK_SIZE; i++) {
            block_out[i] ^= prev[i];
        }
        
        memcpy(prev, block_in, RC5_BLOCK_SIZE);
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