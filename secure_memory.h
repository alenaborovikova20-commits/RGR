#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H
 
#include <cstdint>
#include <cstddef>
 
// Безопасно затирает память
void secure_zero(void* ptr, size_t size);
 
#endif
