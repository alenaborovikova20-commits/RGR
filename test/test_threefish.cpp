#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <random>

#define TF_BLOCK_SIZE 64
#define TF_WORDS 8
#define TF_ROUNDS 72

// Константы вращения
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

// ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
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

// ========== ШИФРОВАНИЕ ОДНОГО БЛОКА ==========
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

// ========== РАСШИФРОВАНИЕ ОДНОГО БЛОКА ==========
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

// ========== ГЕНЕРАЦИЯ СЛУЧАЙНОГО IV ==========
void generate_iv(uint8_t* iv) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    
    for (int i = 0; i < TF_WORDS; i++) {
        uint64_t val = gen();
        for (int b = 0; b < 8; b++) {
            iv[i * 8 + b] = (val >> (b * 8)) & 0xFF;
        }
    }
}

// ========== PKCS#7 ==========
std::vector<uint8_t> add_padding(const std::vector<uint8_t>& data) {
    size_t block_size = TF_BLOCK_SIZE;
    size_t padded_len = ((data.size() + block_size - 1) / block_size) * block_size;
    uint8_t pad_byte = padded_len - data.size();
    
    std::vector<uint8_t> result = data;
    result.resize(padded_len, pad_byte);
    return result;
}

std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& data) {
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

// ========== CBC ШИФРОВАНИЕ ФАЙЛА ==========
void encrypt_file_cbc(const std::string& input_file, const std::string& output_file, const uint64_t* key) {
    // Читаем входной файл
    std::ifstream in(input_file, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input file");
    
    std::vector<uint8_t> plain((std::istreambuf_iterator<char>(in)), {});
    in.close();
    
    // Добавляем паддинг
    std::vector<uint8_t> padded = add_padding(plain);
    
    // Генерируем IV
    uint8_t iv[TF_BLOCK_SIZE];
    generate_iv(iv);
    
    // Открываем выходной файл
    std::ofstream out(output_file, std::ios::binary);
    
    // Сначала записываем IV (по ТЗ п.4.4.7.6)
    out.write(reinterpret_cast<const char*>(iv), TF_BLOCK_SIZE);
    
    // CBC шифрование
    uint8_t prev[TF_BLOCK_SIZE];
    memcpy(prev, iv, TF_BLOCK_SIZE);
    
    std::vector<uint8_t> cipher(padded.size());
    
    for (size_t block = 0; block < padded.size() / TF_BLOCK_SIZE; block++) {
        // XOR с предыдущим шифротекстом (или IV)
        uint8_t block_data[TF_BLOCK_SIZE];
        memcpy(block_data, padded.data() + block * TF_BLOCK_SIZE, TF_BLOCK_SIZE);
        
        for (int i = 0; i < TF_BLOCK_SIZE; i++) {
            block_data[i] ^= prev[i];
        }
        
        // Шифруем
        threefish_encrypt_block(block_data, cipher.data() + block * TF_BLOCK_SIZE, key);
        
        // Запоминаем для следующего блока
        memcpy(prev, cipher.data() + block * TF_BLOCK_SIZE, TF_BLOCK_SIZE);
    }
    
    // Записываем шифротекст
    out.write(reinterpret_cast<const char*>(cipher.data()), cipher.size());
    out.close();
}

// ========== CBC РАСШИФРОВАНИЕ ФАЙЛА ==========
void decrypt_file_cbc(const std::string& input_file, const std::string& output_file, const uint64_t* key) {
    // Читаем зашифрованный файл
    std::ifstream in(input_file, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input file");
    
    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(in)), {});
    in.close();
    
    // Проверяем размер
    if (encrypted.size() < TF_BLOCK_SIZE) {
        throw std::runtime_error("File too small to contain IV");
    }
    
    // Извлекаем IV
    uint8_t iv[TF_BLOCK_SIZE];
    memcpy(iv, encrypted.data(), TF_BLOCK_SIZE);
    
    // Шифротекст (без IV)
    std::vector<uint8_t> cipher(encrypted.begin() + TF_BLOCK_SIZE, encrypted.end());
    
    if (cipher.size() % TF_BLOCK_SIZE != 0) {
        throw std::runtime_error("Ciphertext size is not multiple of block size");
    }
    
    // Расшифровываем
    std::vector<uint8_t> padded(cipher.size());
    uint8_t prev[TF_BLOCK_SIZE];
    memcpy(prev, iv, TF_BLOCK_SIZE);
    
    for (size_t block = 0; block < cipher.size() / TF_BLOCK_SIZE; block++) {
        // Расшифровываем
        threefish_decrypt_block(cipher.data() + block * TF_BLOCK_SIZE, 
                                padded.data() + block * TF_BLOCK_SIZE, key);
        
        // XOR с предыдущим
        for (int i = 0; i < TF_BLOCK_SIZE; i++) {
            padded[block * TF_BLOCK_SIZE + i] ^= prev[i];
        }
        
        // Сохраняем текущий шифротекст для следующего блока
        memcpy(prev, cipher.data() + block * TF_BLOCK_SIZE, TF_BLOCK_SIZE);
    }
    
    // Удаляем паддинг
    std::vector<uint8_t> plain = remove_padding(padded);
    
    // Записываем результат
    std::ofstream out(output_file, std::ios::binary);
    out.write(reinterpret_cast<const char*>(plain.data()), plain.size());
    out.close();
}

// ========== ПРЕОБРАЗОВАНИЕ КЛЮЧА ИЗ БАЙТОВ ==========
void key_from_bytes(const uint8_t* key_bytes, uint64_t* key_words) {
    for (int i = 0; i < TF_WORDS; i++) {
        key_words[i] = 0;
        for (int b = 0; b < 8; b++) {
            key_words[i] |= (uint64_t)key_bytes[i * 8 + b] << (b * 8);
        }
    }
}

// ========== MAIN ==========
int main() {
    try {
        // Ключ 64 байта (можно любой)
        uint8_t key_bytes[TF_BLOCK_SIZE] = {0};
        for (int i = 0; i < TF_BLOCK_SIZE; i++) {
            key_bytes[i] = i;  // тестовый ключ
        }
        
        uint64_t key_words[TF_WORDS];
        key_from_bytes(key_bytes, key_words);
        
        std::cout << "Encrypting image.jpg -> image.jpg.enc" << std::endl;
        encrypt_file_cbc("image.jpg", "image.jpg.enc", key_words);
        
        std::cout << "Decrypting image.jpg.enc -> image_dec.jpg" << std::endl;
        decrypt_file_cbc("image.jpg.enc", "image_dec.jpg", key_words);
        
        std::cout << "Done! Check if image_dec.jpg matches original." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}