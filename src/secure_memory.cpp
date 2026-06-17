#include "secure_memory.h"
#include <cstring>

void secure_erase(void* ptr, size_t size) {
    if (!ptr || size == 0) return;
    
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
}

void secure_zero(void* ptr, size_t size) {
    secure_erase(ptr, size);
}