#include "cryptum.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <dlfcn.h>
#include <random>
#include <chrono>
#include <filesystem>
#include <limits>
#include <clocale>

namespace fs = std::filesystem;

// ==================== КОНСТРУКТОР / ДЕСТРУКТОР ====================

CryptumApp::CryptumApp() {
    std::setlocale(LC_ALL, "ru_RU.UTF-8");
    load_plugins();
}

CryptumApp::~CryptumApp() {
    unload_plugins();
}

// ==================== ЗАГРУЗКА ПЛАГИНОВ ====================

bool CryptumApp::load_plugins() {
    const std::vector<std::string> libs = {"rc5", "threefish", "xtea", "gost", "gm", "mo"};
    
    for (const auto& lib_name : libs) {
        std::string so_path = "./lib" + lib_name + ".so";
        auto plugin = std::make_unique<CryptoPlugin>();
        plugin->handle = dlopen(so_path.c_str(), RTLD_LAZY);
        if (!plugin->handle) {
            std::cerr << "[WARN] Не загружено: " << so_path << std::endl;
            continue;
        }
        
        plugin->get_info = (const AlgorithmInfo*(*)())dlsym(plugin->handle, "get_algorithm_info");
        plugin->get_out_size = (size_t(*)(size_t,int))dlsym(plugin->handle, "get_output_size");
        plugin->encrypt = (int(*)(ConstBuffer,ConstBuffer,MutBuffer*))dlsym(plugin->handle, "encrypt");
        plugin->decrypt = (int(*)(ConstBuffer,ConstBuffer,MutBuffer*))dlsym(plugin->handle, "decrypt");
        plugin->get_key_info = (const char*(*)())dlsym(plugin->handle, "get_key_info");
        plugin->generate_key = (int(*)(uint8_t*,size_t*,int))dlsym(plugin->handle, "generate_key");
        
        if (!plugin->get_info || !plugin->get_out_size || !plugin->encrypt || !plugin->decrypt) {
            dlclose(plugin->handle);
            continue;
        }
        
        auto info = plugin->get_info();
        plugin->name = info->algorithm_name;
        plugin->key_size = info->key_size;
        plugin->key_format_info = plugin->get_key_info ? plugin->get_key_info() : "Нет информации";
        
        std::cout << "[OK] Загружен: " << plugin->name << " (ключ: " << plugin->key_size << " байт)" << std::endl;
        plugins.push_back(std::move(plugin));
    }
    
    if (plugins.empty()) {
        std::cerr << "[ERROR] Не загружено ни одного плагина!" << std::endl;
        return false;
    }
    return true;
}

void CryptumApp::unload_plugins() {
    for (auto& p : plugins) {
        if (p && p->handle) dlclose(p->handle);
    }
    plugins.clear();
}

CryptoPlugin* CryptumApp::find_plugin(const std::string& name) {
    for (auto& p : plugins) {
        if (p && p->name == name) return p.get();
    }
    return nullptr;
}

bool CryptumApp::is_asymmetric_algorithm(const std::string& name) {
    return (name == "Goldwasser-Micali" || name == "Massey-Omura");
}

// ==================== ВЫБОР ПЛАГИНА ====================

CryptoPlugin* CryptumApp::select_plugin() {
    if (plugins.empty()) {
        std::cerr << "[ERROR] Нет доступных алгоритмов" << std::endl;
        return nullptr;
    }
    
    std::cout << "\n--- Доступные алгоритмы ---\n";
    for (size_t i = 0; i < plugins.size(); ++i) {
        std::cout << "  " << (i + 1) << ". " << plugins[i]->name 
                  << " (ключ: " << plugins[i]->key_size << " байт)" << std::endl;
    }
    std::cout << "  0. Назад\n";
    std::cout << "Выбор: ";
    
    int idx;
    std::cin >> idx;
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cerr << "[ERROR] Введите число!" << std::endl;
        return nullptr;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    if (idx == 0) return nullptr;
    if (idx < 1 || idx > static_cast<int>(plugins.size())) {
        std::cerr << "[ERROR] Неверный выбор!" << std::endl;
        return nullptr;
    }
    
    return plugins[idx - 1].get();
}

// ==================== ОБЩИЕ ФУНКЦИИ ====================

std::vector<uint8_t> CryptumApp::read_file(const std::string& path) {
    if (!fs::exists(path)) {
        throw std::runtime_error("Файл не найден: " + path);
    }
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл: " + path);
    }
    auto size = fs::file_size(path);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size))) {
        throw std::runtime_error("Ошибка чтения файла: " + path);
    }
    return data;
}

void CryptumApp::write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось создать файл: " + path);
    }
    if (!file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()))) {
        throw std::runtime_error("Ошибка записи в файл: " + path);
    }
}

std::vector<uint8_t> CryptumApp::read_key_from_file(const std::string& path) {
    return read_file(path);
}

// ==================== ШИФРОВАНИЕ (ВСЕ АЛГОРИТМЫ) ====================

std::vector<uint8_t> CryptumApp::encrypt_data(CryptoPlugin* plugin,
                                               const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& data) {
    if (!plugin) throw std::runtime_error("Плагин не выбран");
    
    bool is_asym = is_asymmetric_algorithm(plugin->name);
    std::vector<uint8_t> result;
    
    if (is_asym) {
        ConstBuffer key_buf = {key.data(), key.size()};
        ConstBuffer in_buf = {data.data(), data.size()};
        
        // Для MO и GM используем get_out_size
        size_t out_size = plugin->get_out_size(data.size(), 1);
        if (out_size == 0) {
            if (plugin->name == "Massey-Omura") {
                out_size = data.size() * sizeof(int64_t);
            } else {
                out_size = data.size() * 8 * sizeof(int64_t);
            }
        }
        
        std::vector<uint8_t> out_buf_data(out_size);
        MutBuffer out_buf = {out_buf_data.data(), out_buf_data.size()};
        
        int ret = plugin->encrypt(key_buf, in_buf, &out_buf);
        if (ret != 0) {
            throw std::runtime_error("Ошибка асимметричного шифрования: код " + std::to_string(ret));
        }
        
        out_buf_data.resize(out_buf.size);
        result = out_buf_data;
        
    } else {
        // Симметричное шифрование
        size_t out_size = plugin->get_out_size(data.size(), 1);
        if (out_size == 0 || out_size < data.size()) {
            out_size = data.size() * 2 + 1024;
        }
        std::vector<uint8_t> out_buf_data(out_size);
        MutBuffer out_buf = {out_buf_data.data(), out_buf_data.size()};
        ConstBuffer key_buf = {key.data(), key.size()};
        ConstBuffer in_buf = {data.data(), data.size()};
        
        int ret = plugin->encrypt(key_buf, in_buf, &out_buf);
        if (ret != 0) {
            throw std::runtime_error("Ошибка шифрования: код " + std::to_string(ret));
        }
        out_buf_data.resize(out_buf.size);
        result = out_buf_data;
    }
    
    return result;
}

std::vector<uint8_t> CryptumApp::decrypt_data(CryptoPlugin* plugin,
                                               const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& data) {
    if (!plugin) throw std::runtime_error("Плагин не выбран");
    
    bool is_asym = is_asymmetric_algorithm(plugin->name);
    std::vector<uint8_t> result;
    
    if (is_asym) {
        ConstBuffer key_buf = {key.data(), key.size()};
        
        // ===== ДЛЯ GM И MO: ПЕРЕДАЁМ ВСЁ СРАЗУ! =====
        // Не режем на блоки, а передаём целиком
        size_t out_size = data.size() * 4 + 4096;  // С запасом
        std::vector<uint8_t> out_buf_data(out_size);
        MutBuffer out_buf = {out_buf_data.data(), out_buf_data.size()};
        ConstBuffer in_buf = {data.data(), data.size()};
        
        int ret = plugin->decrypt(key_buf, in_buf, &out_buf);
        if (ret != 0) {
            throw std::runtime_error("Ошибка асимметричного расшифрования: код " + std::to_string(ret));
        }
        
        out_buf_data.resize(out_buf.size);
        result = out_buf_data;
        
    } else {
        // Симметричное расшифрование
        size_t out_size = data.size() * 4 + 4096;
        std::vector<uint8_t> out_buf_data(out_size);
        MutBuffer out_buf = {out_buf_data.data(), out_buf_data.size()};
        ConstBuffer key_buf = {key.data(), key.size()};
        ConstBuffer in_buf = {data.data(), data.size()};
        
        int ret = plugin->decrypt(key_buf, in_buf, &out_buf);
        if (ret != 0) {
            throw std::runtime_error("Ошибка расшифрования: код " + std::to_string(ret));
        }
        out_buf_data.resize(out_buf.size);
        result = out_buf_data;
    }
    
    return result;
}

// ==================== ОБРАБОТКА ТЕКСТА ====================

void CryptumApp::handle_text() {
    auto plugin = select_plugin();
    if (!plugin) return;
    
    bool is_asym = is_asymmetric_algorithm(plugin->name);
    
    std::cout << "\nФормат ключа: " << plugin->key_format_info << std::endl;
    std::cout << "1. Шифрование\n2. Дешифрование\n0. Назад\nВыбор: ";
    
    int action;
    std::cin >> action;
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cerr << "[ERROR] Введите число!" << std::endl;
        return;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    if (action == 0) return;
    if (action != 1 && action != 2) {
        std::cerr << "[ERROR] Неверный выбор!" << std::endl;
        return;
    }
    
    try {
        std::vector<uint8_t> key;
        KeyPair asym_keys;
        
        // ===== ШИФРОВАНИЕ =====
        if (action == 1) {
            if (is_asym) {
                
                std::cout << "\n--- Асимметричный алгоритм ---\n";
                std::cout << "1. Сгенерировать пару ключей (PUB + PRIV)\n";
                std::cout << "2. Ввести публичный ключ (HEX)\n";
                std::cout << "0. Назад\n";
                std::cout << "Выбор: ";
                
                int choice;
                std::cin >> choice;
                if (std::cin.fail()) {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    throw std::runtime_error("Введите число");
                }
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                
                if (choice == 0) return;
                
                std::vector<uint8_t> pub_key, priv_key;
                
                if (choice == 1) {
                    if (plugin->generate_key) {
                        size_t buf_size = 2048;
                        std::vector<uint8_t> buffer(buf_size);
                        size_t out_size = buf_size;
                        int result = plugin->generate_key(buffer.data(), &out_size, 0);
                        if (result != 0) {
                            throw std::runtime_error("Ошибка генерации ключей: " + std::to_string(result));
                        }
                        buffer.resize(out_size);
                        
                        // ПРОСТО СОХРАНЯЕМ ВЕСЬ БУФЕР КАК КЛЮЧ!
                        // GM возвращает 32 байта бинарных данных
                        if (buffer.size() >= plugin->key_size) {
                            pub_key.assign(buffer.data(), buffer.data() + plugin->key_size);
                            priv_key.assign(buffer.data(), buffer.data() + plugin->key_size);
                            // Для GM и MO публичный и приватный ключи — это одно и то же!
                            // Но для совместимости сохраняем оба
                        } else {
                            throw std::runtime_error("Сгенерирован ключ неправильного размера");
                        }
                        
                        std::cout << "[OK] Сгенерирована пара ключей." << std::endl;
                        std::cout << "[INFO] Публичный ключ (HEX): " << bytes_to_hex(pub_key) << std::endl;
                        std::cout << "[INFO] Приватный ключ сохранён в памяти." << std::endl;
                        
                    } else {
                        // fallback
                        pub_key = generate_random_key(plugin->key_size);
                        priv_key = generate_random_key(plugin->key_size);
                    }
                    
                    asym_keys.public_key = pub_key;
                    asym_keys.private_key = priv_key;
                    asym_keys.algorithm = plugin->name;
                    asym_keys.is_asymmetric = true;
                    last_key_pair = asym_keys;
                    last_algorithm = plugin->name;
                    last_is_asymmetric = true;
                    
                    // ШИФРУЕМ ПУБЛИЧНЫМ КЛЮЧОМ
                    std::cout << "Введите текст: ";
                    std::string text;
                    std::getline(std::cin, text);
                    auto data = string_to_bytes(text);
                    
                    auto result = encrypt_data(plugin, pub_key, data);
                    last_ciphertext = result;
                    last_plaintext = text;
                    std::cout << "[OK] Шифротекст (HEX): " << bytes_to_hex(result) << std::endl;
                }
                
            } else {
                std::cout << "\n--- Симметричный алгоритм ---\n";
                std::cout << "1. Сгенерировать случайный ключ\n";
                std::cout << "2. Ввести ключ (HEX)\n";
                std::cout << "3. Загрузить из файла\n";
                std::cout << "0. Назад\n";
                std::cout << "Выбор: ";
                
                int choice;
                std::cin >> choice;
                if (std::cin.fail()) {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    throw std::runtime_error("Введите число");
                }
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                
                if (choice == 0) return;
                
                switch (choice) {
                    case 1: {
                        key = generate_random_key(plugin->key_size);
                        std::cout << "[OK] Сгенерирован ключ (HEX): " << bytes_to_hex(key) << std::endl;
                        break;
                    }
                    case 2: {
                        std::cout << "Введите ключ (HEX): ";
                        std::string hex_key;
                        std::getline(std::cin, hex_key);
                        key = hex_to_bytes(hex_key);
                        if (key.size() != plugin->key_size) {
                            throw std::runtime_error("Размер ключа: ожидается " + std::to_string(plugin->key_size));
                        }
                        break;
                    }
                    case 3: {
                        std::cout << "Путь к файлу с ключом: ";
                        std::string path;
                        std::getline(std::cin, path);
                        key = read_key_from_file(path);
                        if (key.size() != plugin->key_size) {
                            throw std::runtime_error("Размер ключа: ожидается " + std::to_string(plugin->key_size));
                        }
                        break;
                    }
                    default:
                        throw std::runtime_error("Неверный выбор");
                }
                
                last_symmetric_key = key;
                last_algorithm = plugin->name;
                last_is_asymmetric = false;
                std::cout << "[INFO] Ключ сохранён в памяти для расшифрования." << std::endl;
                
                std::cout << "Введите текст: ";
                std::string text;
                std::getline(std::cin, text);
                auto data = string_to_bytes(text);
                
                auto result = encrypt_data(plugin, key, data);
                last_ciphertext = result;
                last_plaintext = text;
                std::cout << "[OK] Шифротекст (HEX): " << bytes_to_hex(result) << std::endl;
            }
        }
        
        // ===== ДЕШИФРОВАНИЕ =====
        else {
            std::vector<uint8_t> key_for_decrypt;
            bool has_key = false;
            
            if (is_asym) {
                    if (!last_key_pair.private_key.empty() && last_algorithm == plugin->name) {
                    has_key = true;
                    asym_keys = last_key_pair;
                    key_for_decrypt = asym_keys.public_key;      // ← ИСПОЛЬЗУЙ ЭТО!
                    std::cout << "[INFO] Найден сохранённый приватный ключ для " << plugin->name << std::endl;
                    std::cout << "Использовать сохранённый ключ? (y/n): ";
                    std::string answer;
                    std::getline(std::cin, answer);
                    if (answer == "y" || answer == "Y") {
                        std::cout << "[OK] Используется сохранённый приватный ключ." << std::endl;
                    } else {
                        has_key = false;
                    }
                }
            } else {
                if (!last_symmetric_key.empty() && last_algorithm == plugin->name) {
                    has_key = true;
                    key = last_symmetric_key;
                    key_for_decrypt = key;
                    std::cout << "[INFO] Найден сохранённый ключ для " << plugin->name << std::endl;
                    std::cout << "Использовать сохранённый ключ? (y/n): ";
                    std::string answer;
                    std::getline(std::cin, answer);
                    if (answer == "y" || answer == "Y") {
                        std::cout << "[OK] Используется сохранённый ключ." << std::endl;
                    } else {
                        has_key = false;
                    }
                }
            }
            
            if (!has_key) {
                std::cout << "\n--- Введите ключ для расшифрования ---\n";
                
                if (is_asym) {
                    std::cout << "1. Ввести приватный ключ (HEX)\n";
                    std::cout << "2. Загрузить приватный ключ из файла\n";
                    std::cout << "0. Назад\n";
                    std::cout << "Выбор: ";
                    
                    int choice;
                    std::cin >> choice;
                    if (std::cin.fail()) {
                        std::cin.clear();
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        throw std::runtime_error("Введите число");
                    }
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    
                    if (choice == 0) return;
                    
                    std::vector<uint8_t> priv_key;
                    
                    if (choice == 1) {
                        std::cout << "Введите приватный ключ (HEX): ";
                        std::string hex_key;
                        std::getline(std::cin, hex_key);
                        priv_key = hex_to_bytes(hex_key);
                    } else if (choice == 2) {
                        std::cout << "Путь к приватному ключу: ";
                        std::string path;
                        std::getline(std::cin, path);
                        priv_key = read_key_from_file(path);
                    } else {
                        throw std::runtime_error("Неверный выбор");
                    }
                    
                    asym_keys.private_key = priv_key;
                    asym_keys.algorithm = plugin->name;
                    asym_keys.is_asymmetric = true;
                    last_key_pair = asym_keys;
                    last_algorithm = plugin->name;
                    last_is_asymmetric = true;
                    key_for_decrypt = priv_key;
                    
                } else {
                    std::cout << "1. Ввести ключ (HEX)\n";
                    std::cout << "2. Загрузить ключ из файла\n";
                    std::cout << "0. Назад\n";
                    std::cout << "Выбор: ";
                    
                    int choice;
                    std::cin >> choice;
                    if (std::cin.fail()) {
                        std::cin.clear();
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        throw std::runtime_error("Введите число");
                    }
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    
                    if (choice == 0) return;
                    
                    if (choice == 1) {
                        std::cout << "Введите ключ (HEX): ";
                        std::string hex_key;
                        std::getline(std::cin, hex_key);
                        key = hex_to_bytes(hex_key);
                        if (key.size() != plugin->key_size) {
                            throw std::runtime_error("Размер ключа: ожидается " + std::to_string(plugin->key_size));
                        }
                    } else if (choice == 2) {
                        std::cout << "Путь к файлу с ключом: ";
                        std::string path;
                        std::getline(std::cin, path);
                        key = read_key_from_file(path);
                        if (key.size() != plugin->key_size) {
                            throw std::runtime_error("Размер ключа: ожидается " + std::to_string(plugin->key_size));
                        }
                    } else {
                        throw std::runtime_error("Неверный выбор");
                    }
                    
                    last_symmetric_key = key;
                    last_algorithm = plugin->name;
                    last_is_asymmetric = false;
                    key_for_decrypt = key;
                }
            }
            
            std::cout << "\n--- Источник шифротекста ---\n";
            if (!last_ciphertext.empty()) {
                std::cout << "1. Использовать последний зашифрованный текст\n";
            }
            std::cout << "2. Ввести HEX вручную\n";
            std::cout << "3. Загрузить из файла\n";
            std::cout << "0. Назад\n";
            std::cout << "Выбор: ";
            
            int src_choice;
            std::cin >> src_choice;
            if (std::cin.fail()) {
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                throw std::runtime_error("Введите число");
            }
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            
            std::vector<uint8_t> data;
            switch (src_choice) {
                case 0: return;
                case 1:
                    if (last_ciphertext.empty()) {
                        std::cerr << "[ERROR] Нет сохранённого шифротекста!" << std::endl;
                        return;
                    }
                    data = last_ciphertext;
                    std::cout << "[OK] Используется последний шифротекст." << std::endl;
                    break;
                case 2: {
                    std::cout << "Введите шифротекст (HEX): ";
                    std::string hex_cipher;
                    std::getline(std::cin, hex_cipher);
                    data = hex_to_bytes(hex_cipher);
                    break;
                }
                case 3: {
                    std::cout << "Путь к файлу с шифротекстом: ";
                    std::string path;
                    std::getline(std::cin, path);
                    data = read_file(path);
                    break;
                }
                default:
                    throw std::runtime_error("Неверный выбор");
            }
            // В handle_text, перед decrypt_data:
            std::cout << "[DEBUG] last_ciphertext.size() = " << last_ciphertext.size() << std::endl;
            std::cout << "[DEBUG] last_ciphertext first 20 bytes: ";
            for (size_t i = 0; i < (last_ciphertext.size() > 20 ? 20 : last_ciphertext.size()); i++) {
                printf("%02x ", last_ciphertext[i]);
            }
            std::cout << std::endl;
            auto result = decrypt_data(plugin, key_for_decrypt, data);

            // ===== ВЫВОДИМ ВСЁ В HEX =====
            std::cout << "[DEBUG] result.size() = " << result.size() << std::endl;
            std::cout << "[DEBUG] result HEX: ";
            for (size_t i = 0; i < result.size(); i++) {
                printf("%02x ", result[i]);
            }
            printf("\n");

            // ===== ВЫВОДИМ КАК СТРОКУ (БЕЗ ОБРЕЗАНИЯ) =====
            std::cout << "[OK] Расшифровано: ";
            for (size_t i = 0; i < result.size(); i++) {
                char c = result[i];
                if (c >= 32 && c <= 126) {
                    std::cout << c;
                } else {
                    std::cout << "\\x" << std::hex << (int)(unsigned char)c;
                }
            }
            std::cout << std::endl;
            std::cout << "[OK] Расшифровано: " << bytes_to_string(result) << std::endl;
            last_plaintext = bytes_to_string(result);
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
    }
}

// ==================== ОБРАБОТКА ФАЙЛА ====================

void CryptumApp::handle_file() {
    auto plugin = select_plugin();
    if (!plugin) return;
    
    bool is_asym = is_asymmetric_algorithm(plugin->name);
    
    std::cout << "\nФормат ключа: " << plugin->key_format_info << std::endl;
    std::cout << "1. Шифрование\n2. Дешифрование\n0. Назад\nВыбор: ";
    
    int action;
    std::cin >> action;
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cerr << "[ERROR] Введите число!" << std::endl;
        return;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    if (action == 0) return;
    if (action != 1 && action != 2) {
        std::cerr << "[ERROR] Неверный выбор!" << std::endl;
        return;
    }
    
    try {
        std::vector<uint8_t> key;
        KeyPair asym_keys;
        std::vector<uint8_t> key_for_encrypt;
        
        // ===== ШИФРОВАНИЕ =====
        if (action == 1) {
            if (is_asym) {
                std::cout << "\n--- Асимметричный алгоритм ---\n";
                std::cout << "1. Сгенерировать пару ключей (PUB + PRIV)\n";
                std::cout << "2. Ввести публичный ключ (HEX)\n";
                std::cout << "0. Назад\n";
                std::cout << "Выбор: ";
                
                int choice;
                std::cin >> choice;
                if (std::cin.fail()) {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    throw std::runtime_error("Введите число");
                }
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                
                if (choice == 0) return;
                
                std::vector<uint8_t> pub_key, priv_key;
                
                if (choice == 1) {
                    if (plugin->generate_key) {
                        size_t buf_size = 2048;
                        std::vector<uint8_t> buffer(buf_size);
                        size_t out_size = buf_size;
                        int result = plugin->generate_key(buffer.data(), &out_size, 0);
                        if (result != 0) {
                            throw std::runtime_error("Ошибка генерации ключей: " + std::to_string(result));
                        }
                        buffer.resize(out_size);
                        std::string key_str = bytes_to_string(buffer);
                        std::cout << "[OK] Сгенерирована пара ключей." << std::endl;
                        
                        size_t pub_pos = key_str.find("PUB:");
                        size_t priv_pos = key_str.find("PRIV:");
                        if (pub_pos != std::string::npos && priv_pos != std::string::npos) {
                            std::string pub_part = key_str.substr(pub_pos + 4, priv_pos - pub_pos - 4);
                            std::string priv_part = key_str.substr(priv_pos + 5);
                            pub_key = string_to_bytes(pub_part);
                            priv_key = string_to_bytes(priv_part);
                        } else {
                            pub_key = buffer;
                            priv_key = buffer;
                        }
                    } else {
                        pub_key = generate_random_key(plugin->key_size);
                        priv_key = generate_random_key(plugin->key_size);
                    }
                } else if (choice == 2) {
                    std::cout << "Введите публичный ключ (HEX): ";
                    std::string hex_key;
                    std::getline(std::cin, hex_key);
                    pub_key = hex_to_bytes(hex_key);
                } else {
                    throw std::runtime_error("Неверный выбор");
                }
                
                asym_keys.public_key = pub_key;
                asym_keys.private_key = priv_key;
                asym_keys.algorithm = plugin->name;
                asym_keys.is_asymmetric = true;
                last_key_pair = asym_keys;
                last_algorithm = plugin->name;
                last_is_asymmetric = true;
                key_for_encrypt = pub_key;
                
                std::cout << "[INFO] Приватный ключ сохранён в памяти." << std::endl;
                
            } else {
                std::cout << "\n--- Симметричный алгоритм ---\n";
                std::cout << "1. Сгенерировать случайный ключ\n";
                std::cout << "2. Ввести ключ (HEX)\n";
                std::cout << "3. Загрузить ключ из файла\n";
                std::cout << "0. Назад\n";
                std::cout << "Выбор: ";
                
                int choice;
                std::cin >> choice;
                if (std::cin.fail()) {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    throw std::runtime_error("Введите число");
                }
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                
                if (choice == 0) return;
                
                switch (choice) {
                    case 1: {
                        key = generate_random_key(plugin->key_size);
                        std::cout << "[OK] Сгенерирован ключ (HEX): " << bytes_to_hex(key) << std::endl;
                        break;
                    }
                    case 2: {
                        std::cout << "Введите ключ (HEX): ";
                        std::string hex_key;
                        std::getline(std::cin, hex_key);
                        key = hex_to_bytes(hex_key);
                        if (key.size() != plugin->key_size) {
                            throw std::runtime_error("Размер ключа: ожидается " + std::to_string(plugin->key_size));
                        }
                        break;
                    }
                    case 3: {
                        std::cout << "Путь к файлу с ключом: ";
                        std::string path;
                        std::getline(std::cin, path);
                        key = read_key_from_file(path);
                        if (key.size() != plugin->key_size) {
                            throw std::runtime_error("Размер ключа: ожидается " + std::to_string(plugin->key_size));
                        }
                        break;
                    }
                    default:
                        throw std::runtime_error("Неверный выбор");
                }
                
                last_symmetric_key = key;
                last_algorithm = plugin->name;
                last_is_asymmetric = false;
                key_for_encrypt = key;
                std::cout << "[INFO] Ключ сохранён в памяти." << std::endl;
            }
            
            std::cout << "Входной файл: ";
            std::string input_path;
            std::getline(std::cin, input_path);
            
            std::cout << "Выходной файл: ";
            std::string output_path;
            std::getline(std::cin, output_path);
            
            auto data = read_file(input_path);
            std::cout << "[OK] Прочитано " << data.size() << " байт" << std::endl;
            
            std::vector<uint8_t> result;
            if (is_asym) {
                result = encrypt_data(plugin, asym_keys.public_key, data);
            } else {
                result = encrypt_data(plugin, key_for_encrypt, data);
            }
            write_file(output_path, result);
            
            last_ciphertext = result;
            std::cout << "[OK] Зашифровано " << result.size() << " байт" << std::endl;
            std::cout << "[OK] Сохранено в: " << output_path << std::endl;
            
        } else {
            // ===== ДЕШИФРОВАНИЕ =====
            std::vector<uint8_t> key_for_decrypt;
            bool has_key = false;
            
            if (is_asym) {
                if (!last_key_pair.private_key.empty() && last_algorithm == plugin->name) {
                    has_key = true;
                    asym_keys = last_key_pair;
                    key_for_decrypt = asym_keys.private_key;
                    std::cout << "[INFO] Найден сохранённый приватный ключ для " << plugin->name << std::endl;
                    std::cout << "Использовать сохранённый ключ? (y/n): ";
                    std::string answer;
                    std::getline(std::cin, answer);
                    if (answer == "y" || answer == "Y") {
                        std::cout << "[OK] Используется сохранённый приватный ключ." << std::endl;
                    } else {
                        has_key = false;
                    }
                }
            } else {
                if (!last_symmetric_key.empty() && last_algorithm == plugin->name) {
                    has_key = true;
                    key = last_symmetric_key;
                    key_for_decrypt = key;
                    std::cout << "[INFO] Найден сохранённый ключ для " << plugin->name << std::endl;
                    std::cout << "Использовать сохранённый ключ? (y/n): ";
                    std::string answer;
                    std::getline(std::cin, answer);
                    if (answer == "y" || answer == "Y") {
                        std::cout << "[OK] Используется сохранённый ключ." << std::endl;
                    } else {
                        has_key = false;
                    }
                }
            }
            
            if (!has_key) {
                std::cout << "\n--- Введите ключ для расшифрования ---\n";
                
                if (is_asym) {
                    std::cout << "1. Ввести приватный ключ (HEX)\n";
                    std::cout << "2. Загрузить приватный ключ из файла\n";
                    std::cout << "0. Назад\n";
                    std::cout << "Выбор: ";
                    
                    int choice;
                    std::cin >> choice;
                    if (std::cin.fail()) {
                        std::cin.clear();
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        throw std::runtime_error("Введите число");
                    }
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    
                    if (choice == 0) return;
                    
                    std::vector<uint8_t> priv_key;
                    
                    if (choice == 1) {
                        std::cout << "Введите приватный ключ (HEX): ";
                        std::string hex_key;
                        std::getline(std::cin, hex_key);
                        priv_key = hex_to_bytes(hex_key);
                    } else if (choice == 2) {
                        std::cout << "Путь к приватному ключу: ";
                        std::string path;
                        std::getline(std::cin, path);
                        priv_key = read_key_from_file(path);
                    } else {
                        throw std::runtime_error("Неверный выбор");
                    }
                    
                    asym_keys.private_key = priv_key;
                    asym_keys.algorithm = plugin->name;
                    asym_keys.is_asymmetric = true;
                    last_key_pair = asym_keys;
                    last_algorithm = plugin->name;
                    last_is_asymmetric = true;
                    key_for_decrypt = priv_key;
                    
                } else {
                    std::cout << "1. Ввести ключ (HEX)\n";
                    std::cout << "2. Загрузить ключ из файла\n";
                    std::cout << "0. Назад\n";
                    std::cout << "Выбор: ";
                    
                    int choice;
                    std::cin >> choice;
                    if (std::cin.fail()) {
                        std::cin.clear();
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        throw std::runtime_error("Введите число");
                    }
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    
                    if (choice == 0) return;
                    
                    if (choice == 1) {
                        std::cout << "Введите ключ (HEX): ";
                        std::string hex_key;
                        std::getline(std::cin, hex_key);
                        key = hex_to_bytes(hex_key);
                        if (key.size() != plugin->key_size) {
                            throw std::runtime_error("Размер ключа: ожидается " + std::to_string(plugin->key_size));
                        }
                    } else if (choice == 2) {
                        std::cout << "Путь к файлу с ключом: ";
                        std::string path;
                        std::getline(std::cin, path);
                        key = read_key_from_file(path);
                        if (key.size() != plugin->key_size) {
                            throw std::runtime_error("Размер ключа: ожидается " + std::to_string(plugin->key_size));
                        }
                    } else {
                        throw std::runtime_error("Неверный выбор");
                    }
                    
                    last_symmetric_key = key;
                    last_algorithm = plugin->name;
                    last_is_asymmetric = false;
                    key_for_decrypt = key;
                }
            }
            
            std::cout << "Входной файл: ";
            std::string input_path;
            std::getline(std::cin, input_path);
            
            std::cout << "Выходной файл: ";
            std::string output_path;
            std::getline(std::cin, output_path);
            
            auto data = read_file(input_path);
            std::cout << "[OK] Прочитано " << data.size() << " байт" << std::endl;
            
            std::vector<uint8_t> result;
            if (is_asym) {
                result = decrypt_data(plugin, key_for_decrypt, data);
            } else {
                result = decrypt_data(plugin, key_for_decrypt, data);
            }
            write_file(output_path, result);
            
            std::cout << "[OK] Расшифровано " << result.size() << " байт" << std::endl;
            std::cout << "[OK] Сохранено в: " << output_path << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
    }
}

// ==================== ГЕНЕРАТОР КЛЮЧЕЙ ====================

void CryptumApp::handle_keygen() {
    auto plugin = select_plugin();
    if (!plugin) return;
    
    bool is_asym = is_asymmetric_algorithm(plugin->name);
    
    std::cout << "\nФормат ключа: " << plugin->key_format_info << std::endl;
    
    try {
        if (is_asym) {
            std::cout << "[INFO] Генерация пары асимметричных ключей...\n";
            if (plugin->generate_key) {
                size_t buf_size = 2048;
                std::vector<uint8_t> buffer(buf_size);
                size_t out_size = buf_size;
                int result = plugin->generate_key(buffer.data(), &out_size, 0);
                if (result != 0) {
                    throw std::runtime_error("Ошибка генерации: " + std::to_string(result));
                }
                buffer.resize(out_size);
                std::string key_str = bytes_to_string(buffer);
                std::cout << "[OK] Сгенерирована пара ключей:\n" << key_str << "\n";
            } else {
                auto pub_key = generate_random_key(plugin->key_size);
                auto priv_key = generate_random_key(plugin->key_size);
                std::cout << "[OK] Сгенерирована пара ключей:\n";
                std::cout << "  Публичный (HEX): " << bytes_to_hex(pub_key) << "\n";
                std::cout << "  Приватный (HEX): " << bytes_to_hex(priv_key) << "\n";
            }
        } else {
            auto key = generate_random_key(plugin->key_size);
            std::cout << "[OK] Сгенерирован ключ:\n";
            std::cout << "  HEX: " << bytes_to_hex(key) << "\n";
            std::cout << "  Размер: " << key.size() << " байт\n";
            std::cout << "Сохранить в файл? (y/n): ";
            std::string answer;
            std::getline(std::cin, answer);
            if (answer == "y" || answer == "Y") {
                std::cout << "Путь к файлу: ";
                std::string path;
                std::getline(std::cin, path);
                write_file(path, key);
                std::cout << "[OK] Сохранён в: " << path << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
    }
}

// ==================== ИНФОРМАЦИЯ О КЛЮЧАХ ====================

void CryptumApp::show_key_info() {
    auto plugin = select_plugin();
    if (!plugin) return;
    std::cout << "\n=== " << plugin->name << " ===\n";
    std::cout << "Размер ключа: " << plugin->key_size << " байт\n";
    std::cout << "Формат: " << plugin->key_format_info << "\n";
    std::cout << "Тип: " << (is_asymmetric_algorithm(plugin->name) ? "Асимметричный" : "Симметричный") << "\n";
}

// ==================== МЕНЮ ====================

void CryptumApp::run_menu() {
    if (plugins.empty()) {
        std::cerr << "[ERROR] Нет загруженных плагинов" << std::endl;
        return;
    }
    
    while (true) {
        std::cout << "\n============================================\n";
        std::cout << "       КРИПТОГРАФИЧЕСКИЙ ИНСТРУМЕНТ\n";
        std::cout << "============================================\n";
        std::cout << "  1. Шифрование/дешифрование текста\n";
        std::cout << "  2. Шифрование/дешифрование файла\n";
        std::cout << "  3. Генератор ключей\n";
        std::cout << "  4. Информация о формате ключей\n";
        std::cout << "  0. Выход\n";
        std::cout << "============================================\n";
        std::cout << "Выбор: ";
        
        int choice;
        std::cin >> choice;
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cerr << "[ERROR] Введите число!" << std::endl;
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        
        try {
            switch (static_cast<MainMenuOption>(choice)) {
                case MainMenuOption::EXIT:
                    std::cout << "Выход..." << std::endl;
                    return;
                case MainMenuOption::ENCRYPT_DECRYPT_TEXT:
                    handle_text();
                    break;
                case MainMenuOption::ENCRYPT_DECRYPT_FILE:
                    handle_file();
                    break;
                case MainMenuOption::KEY_GENERATOR:
                    handle_keygen();
                    break;
                case MainMenuOption::KEY_INFO:
                    show_key_info();
                    break;
                default:
                    std::cerr << "[ERROR] Неверный выбор!" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] " << e.what() << std::endl;
        }
    }
}

// ==================== ARGC/ARGV ====================

void CryptumApp::print_help() const {
    std::cout << "\n============================================\n";
    std::cout << "       КРИПТОГРАФИЧЕСКИЙ ИНСТРУМЕНТ\n";
    std::cout << "============================================\n";
    std::cout << "Использование: cryptum [ОПЦИИ]\n";
    std::cout << "\n  -a, --algorithm   Алгоритм (rc5, threefish, xtea, gost, gm, mo)\n";
    std::cout << "  -m, --mode        Режим (encrypt, decrypt, generate-key)\n";
    std::cout << "  -k, --key         Файл с ключом\n";
    std::cout << "  -i, --input       Входной файл\n";
    std::cout << "  -o, --output      Выходной файл\n";
    std::cout << "  -g, --generate-key Сгенерировать ключ\n";
    std::cout << "  -s, --save-key    Сохранить ключ в файл\n";
    std::cout << "  -h, --help        Справка\n";
}

int CryptumApp::run(int argc, char** argv) {
    print_help();
    return 0;
}

// ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    static const char* hex = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t b : data) {
        result.push_back(hex[(b >> 4) & 0x0F]);
        result.push_back(hex[b & 0x0F]);
    }
    return result;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::runtime_error("HEX строка должна иметь чётную длину");
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        char* end = nullptr;
        long val = strtol(hex.substr(i, 2).c_str(), &end, 16);
        if (*end != '\0') {
            throw std::runtime_error("Недопустимый HEX символ");
        }
        bytes.push_back(static_cast<uint8_t>(val));
    }
    return bytes;
}

std::string bytes_to_string(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

std::vector<uint8_t> string_to_bytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::vector<uint8_t> generate_random_key(size_t size) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd() + std::chrono::steady_clock::now().time_since_epoch().count());
    static std::uniform_int_distribution<uint64_t> dis(0, 0xFFFFFFFFFFFFFFFFULL);
    std::vector<uint8_t> key(size);
    for (size_t i = 0; i < size; ++i) {
        key[i] = static_cast<uint8_t>(dis(gen) & 0xFF);
    }
    return key;
}

// ==================== SECURE MEMORY ====================

extern "C" {
    void secure_erase(void* ptr, size_t size) {
        if (!ptr || size == 0) return;
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < size; ++i) {
            p[i] = 0;
        }
    }
    void secure_zero(void* ptr, size_t size) {
        secure_erase(ptr, size);
    }
}