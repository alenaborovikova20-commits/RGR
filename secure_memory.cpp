#include "secure_memory.h"
 
void secure_zero(void* ptr, size_t size) {
    if (ptr == NULL || size == 0) return;
    volatile uint8_t* v = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < size; i++) {
        v[i] = 0;
    }
}
