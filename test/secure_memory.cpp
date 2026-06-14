#include "secure_memory.h"
 
// Очистка памяти от секретных данных (ключей, паролей)
void secure_erase(void* ptr, size_t size) {
    if (ptr == NULL || size == 0) {
        return;
    }
    
    // volatile запрещает компилятору выкидывать этот код при оптимизации
    volatile uint8_t* byte_ptr = (volatile uint8_t*)ptr;
    
    for (size_t i = 0; i < size; i++) {
        byte_ptr[i] = 0;
    }
}