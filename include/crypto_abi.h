#ifndef CRYPTO_ABI_H
#define CRYPTO_ABI_H

#include <cstdint>
#include <cstddef>

struct ConstBuffer {
    const uint8_t* data;
    size_t size;
};

struct MutBuffer {
    uint8_t* data;
    size_t size;
};

struct AlgorithmInfo {
    const char* algorithm_name;
    size_t key_size;
};

#endif