#ifndef GM_H
#define GM_H

#include <stdint.h>
#include <stddef.h>

#define GM_KEY_BYTES 32       // Размер каждого ключа
#define GM_PUBLIC_KEY_BYTES 16  // n (8 байт) + y (8 байт) = 16 байт
#define GM_PRIVATE_KEY_BYTES 16 // p (8 байт) + q (8 байт) = 16 байт

#ifdef __cplusplus
extern "C" {
#endif

// Генерирует пару ключей: публичный (первые 16 байт) и приватный (следующие 16 байт)
void gm_generate_keys(uint8_t* public_key, uint8_t* private_key);

// Шифрование: использует публичный ключ (n, y)
void gm_encrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* public_key);

// Расшифрование: использует приватный ключ (p, q)
void gm_decrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* private_key);

#ifdef __cplusplus
}
#endif

#endif