#ifndef CRYPTO_ABI_H
#define CRYPTO_ABI_H
 
#include <cstdint>
#include <cstddef>
 
// Входные данные
struct InputData {
    const uint8_t* bytes;
    size_t length;
};
 
// Выходные данные 
struct OutputData {
    uint8_t* bytes;
    size_t length;
};
 
// Информация об алгоритме
struct AlgorithmInfo {
    const char* name;
    size_t key_size;
};
 
#endif
