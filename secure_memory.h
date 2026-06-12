#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H
 
#include <cstdint>
#include <cstddef>
 
// Безопасно затирает данные в памяти
void secure_erase(void* ptr, size_t size);
 
#endif
