#include "cryptum.h"
#include <iostream>

void CryptumApp::handle_keygen() {
    auto plugin = select_plugin();
    if (!plugin) return;

    bool is_asym = is_asymmetric_algorithm(plugin->name);


    try {
        if (is_asym) {
            std::cout << "[INFO] Генерация пары асимметричных ключей...\n";

            std::vector<uint8_t> pub_key, priv_key;

            if (plugin->generate_key) {
                size_t buf_size = 2048;
                std::vector<uint8_t> buffer(buf_size);
                size_t out_size = buf_size;
                int result = plugin->generate_key(buffer.data(), &out_size, 0);
                if (result != 0) {
                    throw std::runtime_error("Ошибка генерации: " + std::to_string(result));
                }
                buffer.resize(out_size);

                if (buffer.size() >= plugin->key_size * 2) {
                    pub_key.assign(buffer.data(), buffer.data() + plugin->key_size);
                    priv_key.assign(buffer.data() + plugin->key_size, buffer.data() + plugin->key_size * 2);
                } else {
                    pub_key = buffer;
                    priv_key = buffer;
                }
            } else {
                pub_key = generate_random_key(plugin->key_size);
                priv_key = generate_random_key(plugin->key_size);
            }

            std::cout << "[OK] Сгенерирована пара ключей:\n";
            std::cout << "  Публичный (HEX): " << bytes_to_hex(pub_key) << "\n";
            std::cout << "  Приватный (HEX): " << bytes_to_hex(priv_key) << "\n";

            std::cout << "Сохранить публичный ключ в файл? (y/n): ";
            std::string answer;
            std::getline(std::cin, answer);
            if (answer == "y" || answer == "Y") {
                std::cout << "Путь к файлу: ";
                std::string path;
                std::getline(std::cin, path);
                write_file(path, pub_key);
                std::cout << "[OK] Публичный ключ сохранён в: " << path << std::endl;
            }

            std::cout << "Сохранить приватный ключ в файл? (y/n): ";
            std::getline(std::cin, answer);
            if (answer == "y" || answer == "Y") {
                std::cout << "Путь к файлу: ";
                std::string path;
                std::getline(std::cin, path);
                write_file(path, priv_key);
                std::cout << "[OK] Приватный ключ сохранён в: " << path << std::endl;
            }

        } else {
            auto key = generate_random_key(plugin->key_size);
            std::cout << "[OK] Сгенерирован ключ:\n";
            std::cout << "  HEX: " << bytes_to_hex(key) << "\n";
            std::cout << "  Размер: " << key.size() << " байт\n";

            std::cout << "Сохранить ключ в файл? (y/n): ";
            std::string answer;
            std::getline(std::cin, answer);
            if (answer == "y" || answer == "Y") {
                std::cout << "Путь к файлу: ";
                std::string path;
                std::getline(std::cin, path);
                write_file(path, key);
                std::cout << "[OK] Ключ сохранён в: " << path << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
    }
}

void CryptumApp::show_key_info() {
    auto plugin = select_plugin();
    if (!plugin) return;
    std::cout << "\n=== " << plugin->name << " ===\n";
    std::cout << "Размер ключа: " << plugin->key_size << " байт\n";
    std::cout << "Тип: " << (is_asymmetric_algorithm(plugin->name) ? "Асимметричный" : "Симметричный") << "\n";
}