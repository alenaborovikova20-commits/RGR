#ifndef CRYPTO_ABI_H
#define CRYPTO_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t* data;
    size_t size;
} ConstBuffer;

typedef struct {
    uint8_t* data;
    size_t size;
} MutBuffer;

typedef struct {
    const char* algorithm_name;
    size_t key_size;
} AlgorithmInfo;

#ifdef __cplusplus
}
#endif

#endif