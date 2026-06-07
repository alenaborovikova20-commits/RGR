#include <iostream>
#include <cstring>
#include <cstdint>

#define BLOCK_SIZE 8      // 8 байт = 64 бита
#define ROUNDS 12         // 12 раундов
#define KEY_BYTES 16      // 16 байт = 128 бит

// Циклический сдвиг влево (32 бита)
uint32_t rotl(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

// Циклический сдвиг вправо (32 бита)
uint32_t rotr(uint32_t x, int r) {
    return (x >> r) | (x << (32 - r));
}
// S - массив раундовых ключей (26 слов по 4 байта)
void rc5_expand_key(const uint8_t* user_key, uint32_t* S) {
    const uint32_t P = 0xB7E15163;  // магическая константа
    const uint32_t Q = 0x9E3779B9;  // магическая константа
    
    // 1. Превращаем ключ 16 байт → 4 слова по 4 байта
    uint32_t L[4];
    for (int i = 0; i < 4; i++) {
        L[i] = ((uint32_t)user_key[4*i + 0]) |
               ((uint32_t)user_key[4*i + 1] << 8) |
               ((uint32_t)user_key[4*i + 2] << 16) |
               ((uint32_t)user_key[4*i + 3] << 24);
    }
    
    // 2. Инициализируем S константами
    S[0] = P;
    for (int i = 1; i < 2 * ROUNDS + 2; i++) {
        S[i] = S[i-1] + Q;
    }
    
    // 3. Перемешиваем S и L (78 итераций)
    int i = 0, j = 0;
    uint32_t A = 0, B = 0;
    for (int k = 0; k < 78; k++) {
        A = S[i] = rotl(S[i] + A + B, 3);
        B = L[j] = rotl(L[j] + A + B, A + B);
        i = (i + 1) % (2 * ROUNDS + 2);
        j = (j + 1) % 4;
    }
}

void rc5_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* S) {
    // 1. Разбираем 8 байт в 2 слова A и B (little-endian)
    uint32_t A = ((uint32_t)in[0]) | ((uint32_t)in[1] << 8) |
                 ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    uint32_t B = ((uint32_t)in[4]) | ((uint32_t)in[5] << 8) |
                 ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    // 2. Начальное сложение с ключами
    A += S[0];
    B += S[1];
    
    // 3. 12 раундов
    for (int r = 1; r <= ROUNDS; r++) {
        A = rotl(A ^ B, B) + S[2 * r];
        B = rotl(B ^ A, A) + S[2 * r + 1];
    }
    
    // 4. Собираем обратно в 8 байт
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
    // 1. Разбираем 8 байт в 2 слова
    uint32_t A = ((uint32_t)in[0]) | ((uint32_t)in[1] << 8) |
                 ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    uint32_t B = ((uint32_t)in[4]) | ((uint32_t)in[5] << 8) |
                 ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    
    // 2. Обратные раунды (с 12 до 1)
    for (int r = ROUNDS; r >= 1; r--) {
        B = rotr(B - S[2 * r + 1], A) ^ A;
        A = rotr(A - S[2 * r], B) ^ B;
    }
    
    // 3. Финальное вычитание
    B -= S[1];
    A -= S[0];
    
    // 4. Собираем обратно
    out[0] = (A >> 0) & 0xFF;
    out[1] = (A >> 8) & 0xFF;
    out[2] = (A >> 16) & 0xFF;
    out[3] = (A >> 24) & 0xFF;
    out[4] = (B >> 0) & 0xFF;
    out[5] = (B >> 8) & 0xFF;
    out[6] = (B >> 16) & 0xFF;
    out[7] = (B >> 24) & 0xFF;
}

int main() {
    // Ключ 16 байт (можно любые значения)
    uint8_t key[KEY_BYTES] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    
    // Открытый текст 8 байт
    uint8_t plain[BLOCK_SIZE] = { 'H', 'e', 'l', 'l', 'o', '!', '!', '!' };
    
    uint8_t cipher[BLOCK_SIZE];
    uint8_t decrypted[BLOCK_SIZE];
    
    // Раундовые ключи
    uint32_t S[2 * ROUNDS + 2];
    
    // Разворачиваем ключ
    rc5_expand_key(key, S);
    
    // Шифруем
    rc5_encrypt_block(plain, cipher, S);
    
    // Расшифровываем
    rc5_decrypt_block(cipher, decrypted, S);
    
    // Выводим результат
    std::cout << "Original: ";
    for (int i = 0; i < BLOCK_SIZE; i++) {
        std::cout << (char)plain[i];
    }
    std::cout << std::endl;
    
    std::cout << "Decrypted: ";
    for (int i = 0; i < BLOCK_SIZE; i++) {
        std::cout << (char)decrypted[i];
    }
    std::cout << std::endl;
    
    // Сравниваем
    if (memcmp(plain, decrypted, BLOCK_SIZE) == 0) {
        std::cout << "SUCCESS: Encryption + Decryption works!" << std::endl;
    } else {
        std::cout << "FAIL: Decrypted doesn't match original" << std::endl;
    }
    
    return 0;
}