#ifndef CRYPTO_ABI_H
#define CRYPTO_ABI_H
 
#include <cstdint>
#include <cstddef>
 
// Входные данные (только читаем)
struct InputData {
    const uint8_t* bytes;   // байты данных
    size_t length;          // размер данных
};
 
// Выходные данные (можно писать)
struct OutputData {
    uint8_t* bytes;         // байты данных
    size_t length;          // размер данных
};
 
// Информация об алгоритме
struct AlgorithmInfo {
    const char* name;       // название алгоритма
    size_t key_size;        // размер ключа
};
 
#endif
