#include <iostream>
#include <dlfcn.h>
#include "include/crypto_abi.h"

// Функция для загрузки библиотеки и вывода информации
bool load_and_test_library(const std::string& lib_path) {
    std::cout << "========================================" << std::endl;
    std::cout << "Загрузка: " << lib_path << std::endl;
    std::cout << "========================================" << std::endl;

    // 1. Загружаем библиотеку
    void* lib = dlopen(lib_path.c_str(), RTLD_LAZY);
    if (!lib) {
        std::cerr << "❌ Ошибка загрузки: " << dlerror() << std::endl;
        return false;
    }

    // 2. Загружаем функцию get_algorithm_info
    auto get_info = (const AlgorithmInfo*(*)())dlsym(lib, "get_algorithm_info");
    if (!get_info) {
        std::cerr << "❌ Не найдена get_algorithm_info" << std::endl;
        dlclose(lib);
        return false;
    }

    // 3. Получаем информацию об алгоритме
    const AlgorithmInfo* info = get_info();
    if (!info) {
        std::cerr << "❌ get_algorithm_info вернула nullptr" << std::endl;
        dlclose(lib);
        return false;
    }

    // 4. Выводим информацию
    std::cout << "✅ Загружено: " << info->algorithm_name << std::endl;
    std::cout << "✅ Размер ключа: " << info->key_size << " байт" << std::endl;

    // 5. Проверяем другие функции (опционально)
    auto get_out_size = (size_t(*)(size_t,int))dlsym(lib, "get_output_size");
    auto encrypt_func = (int(*)(ConstBuffer,ConstBuffer,MutBuffer*))dlsym(lib, "encrypt");
    auto decrypt_func = (int(*)(ConstBuffer,ConstBuffer,MutBuffer*))dlsym(lib, "decrypt");

    if (get_out_size && encrypt_func && decrypt_func) {
        std::cout << "✅ Все экспортируемые функции найдены" << std::endl;
    } else {
        std::cout << "⚠️ Некоторые функции не найдены" << std::endl;
    }

    std::cout << std::endl;

    // Не закрываем библиотеку, оставляем загруженной для теста
    // dlclose(lib);
    return true;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "    ТЕСТИРОВАНИЕ КРИПТОГРАФИЧЕСКИХ БИБЛИОТЕК" << std::endl;
    std::cout << "========================================" << std::endl << std::endl;

    // Загружаем RC5
    bool rc5_ok = load_and_test_library("./librc5.so");

    // Загружаем Threefish
    bool tf_ok = load_and_test_library("./libthreefish.so");

    // Итог
    std::cout << "========================================" << std::endl;
    std::cout << "ИТОГОВЫЙ РЕЗУЛЬТАТ" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "RC5:        " << (rc5_ok ? "✅ OK" : "❌ FAIL") << std::endl;
    std::cout << "Threefish:  " << (tf_ok ? "✅ OK" : "❌ FAIL") << std::endl;

    return (rc5_ok && tf_ok) ? 0 : 1;
}