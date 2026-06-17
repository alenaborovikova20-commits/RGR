#ifndef CRYPTO_ABI_H
#define CRYPTO_ABI_H
 
#include <cstdint>
#include <cstddef>
 
struct InputData {
    const uint8_t* bytes;   
    size_t length;        
};
 
struct OutputData {
    uint8_t* bytes;       
    size_t length;          
};
 
struct AlgorithmInfo {
    const char* name;      
    size_t key_size;        
};
 
#endif
