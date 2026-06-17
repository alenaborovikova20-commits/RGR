// ============================================================
// cryptum.cpp — ГЛАВНАЯ ПРОГРАММА (консоль)
// ============================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <getopt.h>      // для разбора аргументов
#include <dlfcn.h>       // для загрузки .so
#include "crypto_abi.h"  // общий заголовок

// ============================================================
// 1. СТРУКТУРА ДЛЯ ХРАНЕНИЯ ЗАГРУЖЕННОЙ БИБЛИОТЕКИ
// ============================================================
struct CryptoLib {
    void* handle = nullptr;
    std::string name;
    size_t key_size = 0;
    
    // Указатели на функции
    const AlgorithmInfo* (*get_info)() = nullptr;
    size_t (*get_out_size)(size_t, int) = nullptr;
    int (*encrypt)(ConstBuffer, ConstBuffer, MutBuffer*) = nullptr;
    int (*decrypt)(ConstBuffer, ConstBuffer, MutBuffer*) = nullptr;
};

// ============================================================
// 2. ЗАГРУЗКА БИБЛИОТЕКИ
// ============================================================
CryptoLib load_library(const std::string& algo_name) {
    CryptoLib lib;
    
    // Формируем имя .so файла
    std::string so_path = "./lib" + algo_name + ".so";
    
    // 1. Загружаем
    lib.handle = dlopen(so_path.c_str(), RTLD_LAZY);
    if (!lib.handle) {
        std::cerr << "Ошибка загрузки " << so_path << ": " << dlerror() << std::endl;
        exit(1);
    }
    
    // 2. Загружаем функции
    lib.get_info = (const AlgorithmInfo*(*)())dlsym(lib.handle, "get_algorithm_info");
    lib.get_out_size = (size_t(*)(size_t,int))dlsym(lib.handle, "get_output_size");
    lib.encrypt = (int(*)(ConstBuffer,ConstBuffer,MutBuffer*))dlsym(lib.handle, "encrypt");
    lib.decrypt = (int(*)(ConstBuffer,ConstBuffer,MutBuffer*))dlsym(lib.handle, "decrypt");
    
    if (!lib.get_info || !lib.get_out_size || !lib.encrypt || !lib.decrypt) {
        std::cerr << "Не найдены экспортируемые функции в " << so_path << std::endl;
        dlclose(lib.handle);
        exit(1);
    }
    
    // 3. Узнаем инфу
    const AlgorithmInfo* info = lib.get_info();
    lib.name = info->algorithm_name;
    lib.key_size = info->key_size;
    
    std::cout << "[+] Загружено: " << lib.name 
              << " (ключ: " << lib.key_size << " байт)" << std::endl;
    
    return lib;
}

// ============================================================
// 3. ЧТЕНИЕ ФАЙЛА В БАЙТЫ
// ============================================================
std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Ошибка: не могу открыть " << path << std::endl;
        exit(1);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), {});
}

// ============================================================
// 4. ЗАПИСЬ БАЙТ В ФАЙЛ
// ============================================================
void write_file(const std::string& path, const uint8_t* data, size_t size) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Ошибка: не могу записать " << path << std::endl;
        exit(1);
    }
    file.write(reinterpret_cast<const char*>(data), size);
}

// ============================================================
// 5. ЧТЕНИЕ КЛЮЧА ИЗ ФАЙЛА
// ============================================================
std::vector<uint8_t> read_key(const std::string& path, size_t expected_size) {
    auto data = read_file(path);
    if (data.size() != expected_size) {
        std::cerr << "Ошибка: ключ должен быть " << expected_size 
                  << " байт, а не " << data.size() << std::endl;
        exit(1);
    }
    return data;
}

// ============================================================
// 6. ВЫВОД СПРАВКИ
// ============================================================
void print_help() {
    std::cout << "Использование: cryptum [ОПЦИИ]" << std::endl;
    std::cout << std::endl;
    std::cout << "  -a, --algorithm   Алгоритм: rc5, threefish" << std::endl;
    std::cout << "  -m, --mode        Режим: encrypt, decrypt, generate-key" << std::endl;
    std::cout << "  -k, --key         Файл с ключом" << std::endl;
    std::cout << "  -i, --input       Входной файл" << std::endl;
    std::cout << "  -o, --output      Выходной файл" << std::endl;
    std::cout << "  -g, --generate-key Сгенерировать ключ" << std::endl;
    std::cout << "  -s, --save-key    Сохранить ключ в файл" << std::endl;
    std::cout << "  -h, --help        Эта справка" << std::endl;
}

// ============================================================
// 7. ГЕНЕРАЦИЯ КЛЮЧА (заглушка)
// ============================================================
void generate_key(CryptoLib& lib, const std::string& save_path) {
    std::vector<uint8_t> key(lib.key_size);
    // В реальности — криптостойкий ГПСЧ, пока просто заполняем
    for (size_t i = 0; i < lib.key_size; i++) {
        key[i] = rand() & 0xFF;
    }
    write_file(save_path, key.data(), key.size());
    std::cout << "[+] Ключ сохранён в " << save_path << std::endl;
}

// ============================================================
// 8. MAIN — ГЛАВНАЯ ФУНКЦИЯ
// ============================================================
int main(int argc, char** argv) {
    // ========== ПАРСИМ АРГУМЕНТЫ ==========
    std::string algo, mode, key_path, input_path, output_path, save_key_path;
    bool generate_key_flag = false;
    
    static struct option long_opts[] = {
        {"algorithm",  required_argument, 0, 'a'},
        {"mode",       required_argument, 0, 'm'},
        {"key",        required_argument, 0, 'k'},
        {"input",      required_argument, 0, 'i'},
        {"output",     required_argument, 0, 'o'},
        {"generate-key", no_argument,       0, 'g'},
        {"save-key",   required_argument, 0, 's'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "a:m:k:i:o:gsh", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'a': algo = optarg; break;
            case 'm': mode = optarg; break;
            case 'k': key_path = optarg; break;
            case 'i': input_path = optarg; break;
            case 'o': output_path = optarg; break;
            case 'g': generate_key_flag = true; break;
            case 's': save_key_path = optarg; break;
            case 'h':
            default:
                print_help();
                return 0;
        }
    }
    
    // ========== СПРАВКА ЕСЛИ НЕТ АРГУМЕНТОВ ==========
    if (argc == 1) {
        print_help();
        return 0;
    }
    
    // ========== ЗАГРУЖАЕМ БИБЛИОТЕКУ ==========
    if (algo.empty()) {
        std::cerr << "Ошибка: нужен --algorithm" << std::endl;
        return 1;
    }
    CryptoLib lib = load_library(algo);
    
    // ========== РЕЖИМ ГЕНЕРАЦИИ КЛЮЧА ==========
    if (generate_key_flag || mode == "generate-key") {
        if (save_key_path.empty()) {
            std::cerr << "Ошибка: нужен --save-key" << std::endl;
            return 1;
        }
        generate_key(lib, save_key_path);
        return 0;
    }
    
    // ========== РЕЖИМ ШИФРОВАНИЯ/РАСШИФРОВАНИЯ ==========
    if (mode != "encrypt" && mode != "decrypt") {
        std::cerr << "Ошибка: режим должен быть encrypt или decrypt" << std::endl;
        return 1;
    }
    
    if (input_path.empty() || output_path.empty() || key_path.empty()) {
        std::cerr << "Ошибка: нужны --key, --input, --output" << std::endl;
        return 1;
    }
    
    // Читаем ключ
    std::vector<uint8_t> key = read_key(key_path, lib.key_size);
    
    // Читаем входной файл
    std::vector<uint8_t> input_data = read_file(input_path);
    std::cout << "[+] Входной файл: " << input_data.size() << " байт" << std::endl;
    
    // Вычисляем размер выхода
    int encrypt_mode = (mode == "encrypt") ? 1 : 0;
    size_t out_size = lib.get_out_size(input_data.size(), encrypt_mode);
    std::vector<uint8_t> output_data(out_size);
    
    // ========== ВЫЗЫВАЕМ ФУНКЦИЮ ИЗ БИБЛИОТЕКИ ==========
    ConstBuffer key_buf = {key.data(), key.size()};
    ConstBuffer in_buf = {input_data.data(), input_data.size()};
    MutBuffer out_buf = {output_data.data(), output_data.size()};
    
    int result;
    if (mode == "encrypt") {
        std::cout << "[+] Шифрование..." << std::endl;
        result = lib.encrypt(key_buf, in_buf, &out_buf);
    } else {
        std::cout << "[+] Расшифрование..." << std::endl;
        result = lib.decrypt(key_buf, in_buf, &out_buf);
    }
    
    if (result != 0) {
        std::cerr << "Ошибка в библиотеке: код " << result << std::endl;
        return 1;
    }
    
    // Сохраняем результат
    write_file(output_path, output_data.data(), out_buf.size);
    std::cout << "[+] Готово! Размер выхода: " << out_buf.size << " байт" << std::endl;
    
    // Закрываем библиотеку
    dlclose(lib.handle);
    
    return 0;
}