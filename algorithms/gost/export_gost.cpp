#include "crypto_abi.h"
#include "secure_memory.h"
#include "gost.h"
#include <cstring>
#include <random>
 
// Генератор случайных чисел (для IV)
static std::mt19937_64 rng(std::random_device{}());
 
// Метаинформация об алгоритме для главной программы
static AlgorithmInfo algo_info = {
    "gost28147",  
    GOST_KEY      
};
 
// PKCS#7
 
// Вычисляем размер после добавления паддинга
static size_t padded_length(size_t original) {
    size_t block = GOST_BLOCK;
    size_t pad = block - (original % block);
    
    // Если данные уже кратны блоку, добавляем целый блок паддинга
    if (pad == 0) {
        pad = block;
    }
    
    return original + pad;
}
 
// Добавляем паддинг в конец данных
static void add_padding(uint8_t* data, size_t old_len, size_t new_len) {
    uint8_t pad_byte = new_len - old_len;   
    
    for (size_t i = old_len; i < new_len; i++) {
        data[i] = pad_byte;
    }
}
 
// Удаляем паддинг после расшифрования
static int remove_padding(uint8_t* data, size_t* length) {
    if (*length == 0) {
        return -1;
    }
    
    uint8_t pad_byte = data[*length - 1];   
    
    // Проверяем корректность паддинга
    if (pad_byte == 0 || pad_byte > GOST_BLOCK || pad_byte > *length) {
        return -1;
    }
    
    // Убеждаемся, что все добавленные байты одинаковые
    for (size_t i = *length - pad_byte; i < *length; i++) {
        if (data[i] != pad_byte) {
            return -1;
        }
    }
    
    // Отрезаем паддинг
    *length -= pad_byte;
    return 0;
}
 
// Генерируем случайный вектор инициализации (8 байт)
static uint64_t random_iv() {
    std::uniform_int_distribution<uint64_t> dist;
    return dist(rng);
}
 
//  Экспортируемые функции
extern "C" {
 
// Вернуть информацию об алгоритме
const AlgorithmInfo* get_algorithm_info() {
    return &algo_info;
}
 
// Рассчитать размер выходного буфера
size_t get_output_size(size_t input_size, int mode) {
    (void)mode;  
    return padded_length(input_size) + GOST_BLOCK;   
}
 
// Зашифровать данные
int encrypt(InputData key, InputData input, OutputData* output) {
    // Проверяем размер ключа
    if (key.length != GOST_KEY) {
        return -1;
    }
    
    size_t data_with_padding = padded_length(input.length);
    size_t total = data_with_padding + GOST_BLOCK;
    
    // Проверяем, хватит ли места в выходном буфере
    if (output->length < total) {
        return -2;
    }
    
    // Кладём IV в начало шифротекста
    uint64_t iv = random_iv();
    memcpy(output->bytes, &iv, GOST_BLOCK);
    
    // Копируем исходные данные и добавляем паддинг
    memcpy(output->bytes + GOST_BLOCK, input.bytes, input.length);
    add_padding(output->bytes + GOST_BLOCK, input.length, data_with_padding);
    
    // Готовим раундовые ключи из пользовательского ключа
    uint32_t round_keys[8];
    gost_prepare_keys(key.bytes, round_keys);
    
    //Шифруем каждый блок (по 8 байт)
    for (size_t i = 0; i < data_with_padding; i += GOST_BLOCK) {
        gost_encrypt(
            output->bytes + GOST_BLOCK + i,
            output->bytes + GOST_BLOCK + i,
            round_keys
        );
    }
    
    output->length = total;
    
    // Затираем ключ в памяти (чтобы не остался после шифрования)
    secure_erase((void*)key.bytes, key.length);
    
    return 0;
}
 
// Расшифровать данные
int decrypt(InputData key, InputData input, OutputData* output) {
    // Проверяем ключ
    if (key.length != GOST_KEY) {
        return -1;
    }
    
    // Проверяем, что есть хотя бы IV
    if (input.length < GOST_BLOCK) {
        return -2;
    }
    
    // Проверяем, что длина шифротекста кратна блоку (после вычитания IV)
    if ((input.length - GOST_BLOCK) % GOST_BLOCK != 0) {
        return -3;
    }
    
    if (output->length < input.length) {
        return -4;
    }
    
    // Пропускаем IV (первые 8 байт) 
    size_t cipher_length = input.length - GOST_BLOCK;
    memcpy(output->bytes, input.bytes + GOST_BLOCK, cipher_length);
    
    // Готовим ключи
    uint32_t round_keys[8];
    gost_prepare_keys(key.bytes, round_keys);
    
    // Расшифровываем каждый блок
    for (size_t i = 0; i < cipher_length; i += GOST_BLOCK) {
        gost_decrypt(
            output->bytes + i,
            output->bytes + i,
            round_keys
        );
    }
    
    // Убираем паддинг
    size_t real_length = cipher_length;
    if (remove_padding(output->bytes, &real_length) != 0) {
        return -5;
    }
    
    output->length = real_length;
    
    // Затираем ключ
    secure_erase((void*)key.bytes, key.length);
    
    return 0;
}
 
// Для тестирования: шифрование с фиксированным IV 
int encrypt_fixed_iv(InputData key, InputData iv, InputData input, OutputData* output) {
    // Проверяем ключ
    if (key.length != GOST_KEY) {
        return -1;
    }
    
    // Проверяем размер IV (должен быть 8 байт)
    if (iv.length != GOST_BLOCK) {
        return -2;
    }
    
    size_t data_with_padding = padded_length(input.length);
    size_t total = data_with_padding + GOST_BLOCK;
    
    if (output->length < total) {
        return -3;
    }
    
    // Используем переданный IV, а не генерируем новый
    memcpy(output->bytes, iv.bytes, GOST_BLOCK);
    memcpy(output->bytes + GOST_BLOCK, input.bytes, input.length);
    add_padding(output->bytes + GOST_BLOCK, input.length, data_with_padding);
    
    uint32_t round_keys[8];
    gost_prepare_keys(key.bytes, round_keys);
    
    for (size_t i = 0; i < data_with_padding; i += GOST_BLOCK) {
        gost_encrypt(
            output->bytes + GOST_BLOCK + i,
            output->bytes + GOST_BLOCK + i,
            round_keys
        );
    }
    
    output->length = total;
    return 0;
}
 
}  // extern "C"
