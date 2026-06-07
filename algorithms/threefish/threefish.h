#ifndef THREEFISH_H
#define THREEFISH_H

#include <cstdint>
#include <cstddef>

#define TF_BLOCK_SIZE 64      // 64 байта
#define TF_WORDS 8            // 8 слов по 8 байт
#define TF_ROUNDS 72          // 72 раунда
#define TF_KEY_BYTES 64       // 64 байта ключ
#define TF_TWEAK_BYTES 16     // 16 байт tweak

// Развертывание ключа + tweak → раундовые ключи
void threefish_key_schedule(const uint64_t* key, const uint64_t* tweak, uint64_t* round_keys);

// Шифрование одного блока
void threefish_encrypt_block(const uint8_t* in, uint8_t* out, const uint64_t* round_keys);

// Расшифрование одного блока
void threefish_decrypt_block(const uint8_t* in, uint8_t* out, const uint64_t* round_keys);

// Генерация случайного IV (для CBC режима)
void threefish_generate_iv(uint8_t* iv);

#endif