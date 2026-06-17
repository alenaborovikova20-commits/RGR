#include "crypto_abi.h"
#include "secure_memory.h"
#include "xtea.h"
#include <cstring>
#include <random>
 
// Генератор случайных чисел для IV и ключей
static std::mt19937_64 rng(std::random_device{}());
 
// Информация об алгоритме для главной программы
static AlgorithmInfo algo_info = {
    "xtea",        // имя алгоритма
    XTEA_KEY       // размер ключа в байтах
};
 
//PKCS#7
 
// Сколько байт нужно добавить, чтобы длина стала кратной блоку
static size_t padded_length(size_t original) {
    size_t block = XTEA_BLOCK;
    size_t pad = block - (original % block);
    
    // Если уже кратно, добавляем целый блок
    if (pad == 0) {
        pad = block;
    }
    
    return original + pad;
}
 
// Добавляем паддинг в конец данных
static void add_padding(uint8_t* data, size_t old_len, size_t new_len) {
    uint8_t pad_byte = new_len - old_len;  // значение каждого добавляемого байта
    
    for (size_t i = old_len; i < new_len; i++) {
        data[i] = pad_byte;
    }
}
 
// Убираем паддинг после расшифрования
static int remove_padding(uint8_t* data, size_t* length) {
    if (*length == 0) {
        return -1;  // пустые данные
    }
    
    uint8_t pad_byte = data[*length - 1];  // последний байт = значение паддинга
    
    // Проверяем, что паддинг корректный
    if (pad_byte == 0 || pad_byte > XTEA_BLOCK || pad_byte > *length) {
        return -1;
    }
    
    // Проверяем, что все добавленные байты одинаковые
    for (size_t i = *length - pad_byte; i < *length; i++) {
        if (data[i] != pad_byte) {
            return -1;
        }
    }
    
    // Убираем паддинг
    *length -= pad_byte;
    return 0;
}
 
// Генерация случайного вектора инициализации (8 байт)
static uint64_t random_iv() {
    std::uniform_int_distribution<uint64_t> dist;
    return dist(rng);
}
 
// Функции, которые видит главная программа 
extern "C" {
 
// Вернуть информацию об алгоритме
const AlgorithmInfo* get_algorithm_info() {
    return &algo_info;
}
 
// Рассчитать размер выходного буфера
size_t get_output_size(size_t input_size, int mode) {
    (void)mode;  // параметр не используется, но нужен по ТЗ
    return padded_length(input_size) + XTEA_BLOCK;  // данные + IV
}
 
// Зашифровать данные
int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверка размера ключа
    if (key.size != XTEA_KEY) {
        return -1;
    }
    
    size_t data_with_padding = padded_length(input.size);
    size_t total = data_with_padding + XTEA_BLOCK;
    
    // Проверка, хватает ли места в выходном буфере
    if (output->size < total) {
        return -2;
    }
    
    //кладём IV в начало
    uint64_t iv = random_iv();
    memcpy(output->data, &iv, XTEA_BLOCK);
    
    //копируем данные и добавляем паддинг
    memcpy(output->data + XTEA_BLOCK, input.data, input.size);
    add_padding(output->data + XTEA_BLOCK, input.size, data_with_padding);
    
    //готовим раундовые ключи
    uint32_t round_keys[4];
    xtea_prepare_keys(key.data, round_keys);
    
    //шифруем каждый блок
    for (size_t i = 0; i < data_with_padding; i += XTEA_BLOCK) {
        xtea_encrypt(
            output->data + XTEA_BLOCK + i,
            output->data + XTEA_BLOCK + i,
            round_keys
        );
    }
    
    output->size = total;
    
    //затираем ключ в памяти (безопасность)
    
    return 0;
}
 
// Расшифровать данные
int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверка ключа
    if (key.size != XTEA_KEY) {
        return -1;
    }
    
    // Проверка размера входных данных (должен быть хотя бы IV)
    if (input.size < XTEA_BLOCK) {
        return -2;
    }
    
    // Проверка, что длина шифротекста кратна блоку
    if ((input.size - XTEA_BLOCK) % XTEA_BLOCK != 0) {
        return -3;
    }
    
    if (output->size < input.size) {
        return -4;
    }
    
    // Пропускаем IV (первые 8 байт)
    size_t cipher_length = input.size - XTEA_BLOCK;
    memcpy(output->data, input.data + XTEA_BLOCK, cipher_length);
    
    // Готовим ключи
    uint32_t round_keys[4];
    xtea_prepare_keys(key.data, round_keys);
    
    // Расшифровываем каждый блок
    for (size_t i = 0; i < cipher_length; i += XTEA_BLOCK) {
        xtea_decrypt(
            output->data + i,
            output->data + i,
            round_keys
        );
    }
    
    // Убираем паддинг
    size_t real_length = cipher_length;
    if (remove_padding(output->data, &real_length) != 0) {
        return -5;
    }
    
    output->size = real_length;
    
    // Затираем ключ
    
    return 0;
}
 
// Для тестирования: шифрование с фиксированным IV 
int encrypt_fixed_iv(ConstBuffer key, ConstBuffer iv, ConstBuffer input, MutBuffer* output) {
    // Проверки
    if (key.size != XTEA_KEY) {
        return -1;
    }
    
    if (iv.size != XTEA_BLOCK) {
        return -2;
    }
    
    size_t data_with_padding = padded_length(input.size);
    size_t total = data_with_padding + XTEA_BLOCK;
    
    if (output->size < total) {
        return -3;
    }
    
    // Используем переданный IV, а не случайный
    memcpy(output->data, iv.data, XTEA_BLOCK);
    memcpy(output->data + XTEA_BLOCK, input.data, input.size);
    add_padding(output->data + XTEA_BLOCK, input.size, data_with_padding);
    
    uint32_t round_keys[4];
    xtea_prepare_keys(key.data, round_keys);
    
    for (size_t i = 0; i < data_with_padding; i += XTEA_BLOCK) {
        xtea_encrypt(
            output->data + XTEA_BLOCK + i,
            output->data + XTEA_BLOCK + i,
            round_keys
        );
    }
    
    output->size = total;
    return 0;
}
 
}  // extern "C"
