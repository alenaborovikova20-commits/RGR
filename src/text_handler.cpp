#include "cryptum.h"
#include <iostream>
#include <limits>

void CryptumApp::handle_text() {
    auto plugin = select_plugin();
    if (!plugin) return;

    bool is_asym = is_asymmetric_algorithm(plugin->name);

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

        if (action == 1) {
            if (is_asym) {
                std::cout << "1. Сгенерировать пару ключей (PUB + PRIV)\n";
                std::cout << "2. Загрузить публичный ключ из файла\n";
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

                        if (buffer.size() >= plugin->key_size) {
                            pub_key.assign(buffer.data(), buffer.data() + plugin->key_size);
                            priv_key.assign(buffer.data(), buffer.data() + plugin->key_size);
                        } else {
                            throw std::runtime_error("Сгенерирован ключ неправильного размера");
                        }

                        std::cout << "[OK] Сгенерирована пара ключей." << std::endl;
                        std::cout << "[INFO] Публичный ключ (HEX): " << bytes_to_hex(pub_key) << std::endl;
                        std::cout << "[INFO] Приватный ключ сохранён в памяти." << std::endl;
                    } else {
                        pub_key = generate_random_key(plugin->key_size);
                        priv_key = generate_random_key(plugin->key_size);
                    }
                } else if (choice == 2) {
                    std::cout << "Путь к файлу с публичным ключом: ";
                    std::string path;
                    std::getline(std::cin, path);
                    pub_key = read_key_from_file(path);
                    priv_key = pub_key;
                    if (pub_key.size() != plugin->key_size) {
                        throw std::runtime_error("Размер ключа: ожидается " + std::to_string(plugin->key_size));
                    }
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

                std::cout << "Введите текст (пустая строка для завершения):\n";
                std::string text, line;
                while (std::getline(std::cin, line) && !line.empty()) {
                    if (!text.empty()) text += "\n";
                    text += line;
                }

                auto data = string_to_bytes(text);
                auto result = encrypt_data(plugin, pub_key, data);
                last_ciphertext = result;
                last_plaintext = text;
                std::cout << "[OK] Шифротекст (HEX): " << bytes_to_hex(result) << std::endl;

            } else {
                std::cout << "1. Сгенерировать случайный ключ\n";
                std::cout << "2. Ввести ключ\n";
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

                switch (static_cast<SymmetricKeySource>(choice)) {
                    case SymmetricKeySource::GENERATE: {
                        key = generate_random_key(plugin->key_size);
                        std::cout << "[OK] Сгенерирован ключ (HEX): " << bytes_to_hex(key) << std::endl;
                        break;
                    }
                    case SymmetricKeySource::ENTER: {
                        std::cout << "Введите ключ: ";
                        std::string key_str;
                        std::getline(std::cin, key_str);
                        key = string_to_key(key_str, plugin->key_size);
                        break;
                    }
                    case SymmetricKeySource::LOAD_FILE: {
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
                std::cout << "[INFO] Ключ сохранён в памяти." << std::endl;

                std::cout << "Введите текст (пустая строка для завершения):\n";
                std::string text, line;
                while (std::getline(std::cin, line) && !line.empty()) {
                    if (!text.empty()) text += "\n";
                    text += line;
                }

                auto data = string_to_bytes(text);
                auto result = encrypt_data(plugin, key, data);
                last_ciphertext = result;
                last_plaintext = text;
                std::cout << "[OK] Шифротекст (HEX): " << bytes_to_hex(result) << std::endl;
            }
        } else {
            std::vector<uint8_t> key_for_decrypt;
            bool has_key = false;

            if (is_asym) {
                if (!last_key_pair.private_key.empty() && last_algorithm == plugin->name) {
                    has_key = true;
                    asym_keys = last_key_pair;
                    key_for_decrypt = asym_keys.private_key;
                    std::cout << "[OK] Используется сохранённый приватный ключ." << std::endl;
                } else {
                    std::cerr << "[ERROR] Нет сохранённого приватного ключа.\n";
                    std::cerr << "Сначала зашифруйте данные или сгенерируйте ключи.\n";
                    return;
                }
            } else {
                if (!last_symmetric_key.empty() && last_algorithm == plugin->name) {
                    has_key = true;
                    key = last_symmetric_key;
                    key_for_decrypt = key;
                    std::cout << "[OK] Используется сохранённый ключ." << std::endl;
                } else {
                    std::cerr << "[ERROR] Нет сохранённого ключа.\n";
                    std::cerr << "Сначала зашифруйте данные или сгенерируйте ключ.\n";
                    return;
                }
            }

            std::vector<uint8_t> data;

            if (!last_ciphertext.empty()) {
                std::cout << "[OK] Используется последний шифротекст." << std::endl;
                data = last_ciphertext;
            } else {
                std::cout << "1. Ввести HEX вручную\n";
                std::cout << "2. Загрузить из файла\n";
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

                switch (static_cast<CiphertextSource>(src_choice)) {
                    case CiphertextSource::BACK: return;
                    case CiphertextSource::HEX: {
                        std::cout << "Введите шифротекст (HEX): ";
                        std::string hex_cipher;
                        std::getline(std::cin, hex_cipher);
                        data = hex_to_bytes(hex_cipher);
                        break;
                    }
                    case CiphertextSource::FILE: {
                        std::cout << "Путь к файлу с шифротекстом: ";
                        std::string path;
                        std::getline(std::cin, path);
                        data = read_file(path);
                        break;
                    }
                    default:
                        throw std::runtime_error("Неверный выбор");
                }
            }

            auto result = decrypt_data(plugin, key_for_decrypt, data);
            std::cout << "[OK] Расшифровано: " << bytes_to_string(result) << std::endl;
            last_plaintext = bytes_to_string(result);
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
    }
}