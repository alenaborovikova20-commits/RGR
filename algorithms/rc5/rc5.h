#ifndef RC5_H
#define RC5_H

#include <cstdint>
#include <cstddef>

#define RC5_BLOCK_SIZE 8
#define RC5_ROUNDS 12
#define RC5_KEY_BYTES 16

// Развертывание ключа: из 16 байт ключа получаем 26 раундовых ключей
void rc5_expand_key(const uint8_t* key, uint32_t* S);

// Шифрование одного блока (8 байт → 8 байт)
void rc5_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* S);

// Расшифрование одного блока (8 байт → 8 байт)
void rc5_decrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* S);

#endif