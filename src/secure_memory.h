#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Безопасная очистка памяти (запрещает оптимизацию компилятора)
void secure_erase(void* ptr, size_t size);
void secure_zero(void* ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif