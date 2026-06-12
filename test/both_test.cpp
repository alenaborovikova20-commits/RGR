#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iterator>
 
using namespace std;
 
// ==================== XTEA ====================
#define XTEA_BLOCK 8
#define XTEA_KEY 16
#define XTEA_ROUNDS 32
 
static const uint32_t DELTA = 0x9E3779B9;
 
void xtea_expand_key(const uint8_t* key, uint32_t* keys) {
    for (int i = 0; i < 4; i++) {
        keys[i] = 0;
        keys[i] |= (uint32_t)key[i*4];
        keys[i] |= (uint32_t)key[i*4+1] << 8;
        keys[i] |= (uint32_t)key[i*4+2] << 16;
        keys[i] |= (uint32_t)key[i*4+3] << 24;
    }
}
 
void xtea_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* keys) {
    uint32_t left = (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
                    ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    uint32_t right = (uint32_t)in[4] | ((uint32_t)in[5] << 8) |
                     ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    uint32_t sum = 0;
    for (int i = 0; i < XTEA_ROUNDS; i++) {
        left += (((right << 4) ^ (right >> 5)) + right) ^ (sum + keys[sum & 3]);
        sum += DELTA;
        right += (((left << 4) ^ (left >> 5)) + left) ^ (sum + keys[(sum >> 11) & 3]);
    }
    
    out[0] = left & 0xFF;
    out[1] = (left >> 8) & 0xFF;
    out[2] = (left >> 16) & 0xFF;
    out[3] = (left >> 24) & 0xFF;
    out[4] = right & 0xFF;
    out[5] = (right >> 8) & 0xFF;
    out[6] = (right >> 16) & 0xFF;
    out[7] = (right >> 24) & 0xFF;
}
 
void xtea_decrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* keys) {
    uint32_t left = (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
                    ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    uint32_t right = (uint32_t)in[4] | ((uint32_t)in[5] << 8) |
                     ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    uint32_t sum = DELTA * XTEA_ROUNDS;
    for (int i = 0; i < XTEA_ROUNDS; i++) {
        right -= (((left << 4) ^ (left >> 5)) + left) ^ (sum + keys[(sum >> 11) & 3]);
        sum -= DELTA;
        left -= (((right << 4) ^ (right >> 5)) + right) ^ (sum + keys[sum & 3]);
    }
    
    out[0] = left & 0xFF;
    out[1] = (left >> 8) & 0xFF;
    out[2] = (left >> 16) & 0xFF;
    out[3] = (left >> 24) & 0xFF;
    out[4] = right & 0xFF;
    out[5] = (right >> 8) & 0xFF;
    out[6] = (right >> 16) & 0xFF;
    out[7] = (right >> 24) & 0xFF;
}
 
// ==================== ГОСТ 28147-89 (ИСПРАВЛЕННЫЙ) ====================
#define GOST_BLOCK 8
#define GOST_KEY 32
 
static const uint8_t GOST_SBOX[8][16] = {
    {0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC},
    {0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC},
    {0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE},
    {0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2},
    {0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC},
    {0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC},
    {0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE},
    {0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2}
};
 
static uint32_t gost_rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
 
static uint32_t gost_substitute(uint32_t x) {
    uint32_t res = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t nibble = (x >> (i * 4)) & 0x0F;
        res |= (uint32_t)GOST_SBOX[i][nibble] << (i * 4);
    }
    return res;
}
 
void gost_expand_key(const uint8_t* key, uint32_t* keys) {
    for (int i = 0; i < 8; i++) {
        keys[i] = (uint32_t)key[i*4] |
                  (uint32_t)key[i*4+1] << 8 |
                  (uint32_t)key[i*4+2] << 16 |
                  (uint32_t)key[i*4+3] << 24;
    }
}
 
void gost_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* keys) {
    uint32_t n1, n2;
    
    n1 = (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
         ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    n2 = (uint32_t)in[4] | ((uint32_t)in[5] << 8) |
         ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    for (int i = 0; i < 32; i++) {
        uint32_t key_idx;
        if (i < 24) {
            key_idx = i % 8;
        } else {
            key_idx = 7 - (i % 8);
        }
        
        uint32_t round_key = keys[key_idx];
        uint32_t feistel = gost_rotl(gost_substitute(n1 + round_key), 11);
        uint32_t new_n1 = n2 ^ feistel;
        n2 = n1;
        n1 = new_n1;
    }
    
    out[0] = n1 & 0xFF;
    out[1] = (n1 >> 8) & 0xFF;
    out[2] = (n1 >> 16) & 0xFF;
    out[3] = (n1 >> 24) & 0xFF;
    out[4] = n2 & 0xFF;
    out[5] = (n2 >> 8) & 0xFF;
    out[6] = (n2 >> 16) & 0xFF;
    out[7] = (n2 >> 24) & 0xFF;
}
 
void gost_decrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* keys) {
    uint32_t n1, n2;
    
    n1 = (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
         ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    n2 = (uint32_t)in[4] | ((uint32_t)in[5] << 8) |
         ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    for (int i = 31; i >= 0; i--) {
        uint32_t key_idx;
        if (i < 24) {
            key_idx = i % 8;
        } else {
            key_idx = 7 - (i % 8);
        }
        
        uint32_t round_key = keys[key_idx];
        uint32_t feistel = gost_rotl(gost_substitute(n1 + round_key), 11);
        uint32_t new_n2 = n1 ^ feistel;
        n1 = n2;
        n2 = new_n2;
    }
    
    out[0] = n1 & 0xFF;
    out[1] = (n1 >> 8) & 0xFF;
    out[2] = (n1 >> 16) & 0xFF;
    out[3] = (n1 >> 24) & 0xFF;
    out[4] = n2 & 0xFF;
    out[5] = (n2 >> 8) & 0xFF;
    out[6] = (n2 >> 16) & 0xFF;
    out[7] = (n2 >> 24) & 0xFF;
}
 
// ==================== PKCS#7 ====================
vector<uint8_t> add_padding(const vector<uint8_t>& data, size_t block) {
    size_t pad = block - (data.size() % block);
    if (pad == 0) pad = block;
    
    vector<uint8_t> result = data;
    result.resize(data.size() + pad, pad);
    return result;
}
 
vector<uint8_t> remove_padding(const vector<uint8_t>& data) {
    if (data.empty()) return data;
    
    uint8_t pad = data.back();
    if (pad > data.size() || pad > 8) return data;
    
    return vector<uint8_t>(data.begin(), data.end() - pad);
}
 
// ==================== XTEA файловые операции ====================
void xtea_encrypt_file(const string& in_name, const string& out_name, const uint8_t* key) {
    ifstream in(in_name, ios::binary);
    vector<uint8_t> plain((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();
    
    vector<uint8_t> padded = add_padding(plain, XTEA_BLOCK);
    
    uint32_t keys[4];
    xtea_expand_key(key, keys);
    
    vector<uint8_t> cipher(padded.size());
    for (size_t i = 0; i < padded.size(); i += XTEA_BLOCK) {
        xtea_encrypt_block(&padded[i], &cipher[i], keys);
    }
    
    ofstream out(out_name, ios::binary);
    out.write((char*)cipher.data(), cipher.size());
    out.close();
}
 
void xtea_decrypt_file(const string& in_name, const string& out_name, const uint8_t* key) {
    ifstream in(in_name, ios::binary);
    vector<uint8_t> cipher((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();
    
    uint32_t keys[4];
    xtea_expand_key(key, keys);
    
    vector<uint8_t> padded(cipher.size());
    for (size_t i = 0; i < cipher.size(); i += XTEA_BLOCK) {
        xtea_decrypt_block(&cipher[i], &padded[i], keys);
    }
    
    vector<uint8_t> plain = remove_padding(padded);
    
    ofstream out(out_name, ios::binary);
    out.write((char*)plain.data(), plain.size());
    out.close();
}
 
// ==================== ГОСТ файловые операции ====================
void gost_encrypt_file(const string& in_name, const string& out_name, const uint8_t* key) {
    ifstream in(in_name, ios::binary);
    vector<uint8_t> plain((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();
    
    vector<uint8_t> padded = add_padding(plain, GOST_BLOCK);
    
    uint32_t keys[8];
    gost_expand_key(key, keys);
    
    vector<uint8_t> cipher(padded.size());
    for (size_t i = 0; i < padded.size(); i += GOST_BLOCK) {
        gost_encrypt_block(&padded[i], &cipher[i], keys);
    }
    
    ofstream out(out_name, ios::binary);
    out.write((char*)cipher.data(), cipher.size());
    out.close();
}
 
void gost_decrypt_file(const string& in_name, const string& out_name, const uint8_t* key) {
    ifstream in(in_name, ios::binary);
    vector<uint8_t> cipher((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();
    
    uint32_t keys[8];
    gost_expand_key(key, keys);
    
    vector<uint8_t> padded(cipher.size());
    for (size_t i = 0; i < cipher.size(); i += GOST_BLOCK) {
        gost_decrypt_block(&cipher[i], &padded[i], keys);
    }
    
    vector<uint8_t> plain = remove_padding(padded);
    
    ofstream out(out_name, ios::binary);
    out.write((char*)plain.data(), plain.size());
    out.close();
}
 
// ==================== Тесты ====================
void test_xtea() {
    cout << "\n[XTEA]" << endl;
    
    uint8_t key[XTEA_KEY] = {
        1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
    };
    
    uint8_t plain[8] = {'H','e','l','l','o','!','!','!'};
    uint8_t cipher[8], dec[8];
    
    uint32_t keys[4];
    xtea_expand_key(key, keys);
    
    xtea_encrypt_block(plain, cipher, keys);
    xtea_decrypt_block(cipher, dec, keys);
    
    bool ok = memcmp(plain, dec, 8) == 0;
    
    cout << "  Plaintext:  Hello!!!" << endl;
    cout << "  Decrypted:  " << string((char*)dec, 8) << endl;
    cout << "  Result: " << (ok ? "PASS" : "FAIL") << endl;
}
 
void test_gost() {
    cout << "\n[GOST 28147-89]" << endl;
    
    uint8_t key[GOST_KEY] = {
        1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
        17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
    };
    
    uint8_t plain[8] = {'H','e','l','l','o','!','!','!'};
    uint8_t cipher[8], dec[8];
    
    uint32_t keys[8];
    gost_expand_key(key, keys);
    
    gost_encrypt_block(plain, cipher, keys);
    gost_decrypt_block(cipher, dec, keys);
    
    bool ok = memcmp(plain, dec, 8) == 0;
    
    cout << "  Plaintext:  Hello!!!" << endl;
    cout << "  Decrypted:  " << string((char*)dec, 8) << endl;
    cout << "  Result: " << (ok ? "PASS" : "FAIL") << endl;
}
 
// ==================== Main ====================
int main() {
    try {
        test_xtea();
        test_gost();
        
        uint8_t xtea_key[XTEA_KEY] = {
            1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
        };
        
        cout << "\n[XTEA] Encrypting image.jpg -> image_xtea.enc" << endl;
        xtea_encrypt_file("image.jpg", "image_xtea.enc", xtea_key);
        
        cout << "[XTEA] Decrypting image_xtea.enc -> image_xtea_dec.jpg" << endl;
        xtea_decrypt_file("image_xtea.enc", "image_xtea_dec.jpg", xtea_key);
        
        uint8_t gost_key[GOST_KEY] = {
            1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
            17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
        };
        
        cout << "\n[GOST] Encrypting image.jpg -> image_gost.enc" << endl;
        gost_encrypt_file("image.jpg", "image_gost.enc", gost_key);
        
        cout << "[GOST] Decrypting image_gost.enc -> image_gost_dec.jpg" << endl;
        gost_decrypt_file("image_gost.enc", "image_gost_dec.jpg", gost_key);
        
        cout << "\nDone!" << endl;
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
