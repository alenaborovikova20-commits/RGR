#include "algorithms/threefish/threefish.h"
#include <cstdio>
#include <cstring>

int main() {
    printf("=== THREEFISH BLOCK TEST ===\n");
    
    uint8_t key[TF_KEY_BYTES];
    uint8_t plaintext[TF_BLOCK_SIZE];
    uint8_t ciphertext[TF_BLOCK_SIZE];
    uint8_t decrypted[TF_BLOCK_SIZE];
    
    // Заполняем ключ
    for (int i = 0; i < TF_KEY_BYTES; i++) {
        key[i] = i & 0xFF;
    }
    
    // Заполняем данные
    for (int i = 0; i < TF_BLOCK_SIZE; i++) {
        plaintext[i] = i + 1;
    }
    
    printf("Key: ");
    for (int i = 0; i < 16; i++) printf("%02x ", key[i]);
    printf("\n");
    
    printf("Plaintext: ");
    for (int i = 0; i < 16; i++) printf("%02x ", plaintext[i]);
    printf("\n");
    
    // Разворачиваем ключ
    uint64_t round_keys[TF_ROUNDS * 8];
    uint64_t key_words[TF_WORDS];
    uint64_t tweak[2] = {0, 0};
    
    for (int i = 0; i < TF_WORDS; i++) {
        key_words[i] = 0;
        for (int b = 0; b < 8; b++) {
            key_words[i] |= (uint64_t)key[i * 8 + b] << (b * 8);
        }
    }
    threefish_key_schedule(key_words, tweak, round_keys);
    
    // Шифруем
    threefish_encrypt_block(plaintext, ciphertext, round_keys);
    printf("Ciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    printf("\n");
    
    // Расшифровываем
    threefish_decrypt_block(ciphertext, decrypted, round_keys);
    printf("Decrypted:  ");
    for (int i = 0; i < 16; i++) printf("%02x ", decrypted[i]);
    printf("\n");
    
    if (memcmp(plaintext, decrypted, TF_BLOCK_SIZE) == 0) {
        printf("✅ BLOCK WORKS!\n");
        return 0;
    } else {
        printf("❌ BLOCK BROKEN!\n");
        return 1;
    }
}