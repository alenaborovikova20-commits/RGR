#include "cryptum.h"
#include <iostream>
#include <limits>
#include <vector>
#include <string>
#include <cstring>

void CryptumApp::run_menu() {
    if (plugins.empty()) {
        std::cerr << "[ERROR] Нет загруженных плагинов" << std::endl;
        return;
    }

    while (true) {
        std::cout << "\nКРИПТОГРАФИЧЕСКИЙ ИНСТРУМЕНТ\n";
        std::cout << "1. Шифрование/дешифрование текста\n";
        std::cout << "2. Шифрование/дешифрование файла\n";
        std::cout << "3. Генератор ключей\n";
        std::cout << "4. Информация о формате ключей\n";
        std::cout << "0. Выход\n";
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

void CryptumApp::print_help() const {
    std::cout << "\nКРИПТОГРАФИЧЕСКИЙ ИНСТРУМЕНТ\n";
    std::cout << "Использование: cryptum [ОПЦИИ]\n";
    std::cout << "  -a, --algorithm   Алгоритм (rc5, threefish, xtea, gost, gm, blowfish)\n";
    std::cout << "  -m, --mode        Режим (encrypt, decrypt, generate-key)\n";
    std::cout << "  -k, --key         Файл с ключом\n";
    std::cout << "  -i, --input       Входной файл\n";
    std::cout << "  -o, --output      Выходной файл\n";
    std::cout << "  -h, --help        Справка\n";
}

int CryptumApp::run(int argc, char** argv) {
    if (argc > 1) {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-h" || arg == "--help") {
                print_help();
                return 0;
            }
        }

        try {
            std::string algorithm, mode, key_file, input_file, output_file;

            for (int i = 1; i < argc; ++i) {
                std::string arg = argv[i];
                if ((arg == "-a" || arg == "--algorithm") && i + 1 < argc) {
                    algorithm = argv[++i];
                } else if ((arg == "-m" || arg == "--mode") && i + 1 < argc) {
                    mode = argv[++i];
                } else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
                    key_file = argv[++i];
                } else if ((arg == "-i" || arg == "--input") && i + 1 < argc) {
                    input_file = argv[++i];
                } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
                    output_file = argv[++i];
                }
            }

            if (algorithm.empty() || mode.empty() || input_file.empty() || output_file.empty()) {
                std::cerr << "[ERROR] Не все параметры указаны. Используйте -h для справки.\n";
                return 1;
            }

            auto plugin = find_plugin(algorithm);
            if (!plugin) {
                std::cerr << "[ERROR] Алгоритм не найден: " << algorithm << std::endl;
                return 1;
            }

            std::vector<uint8_t> key;
            if (!key_file.empty()) {
                key = read_key_from_file(key_file);
            } else {
                key = generate_random_key(plugin->key_size);
                std::cout << "[INFO] Сгенерирован случайный ключ (HEX): " << bytes_to_hex(key) << std::endl;
            }

            auto data = read_file(input_file);

            std::vector<uint8_t> result;
            if (mode == "encrypt") {
                result = encrypt_data(plugin, key, data);
                std::cout << "[OK] Зашифровано " << result.size() << " байт" << std::endl;
            } else if (mode == "decrypt") {
                result = decrypt_data(plugin, key, data);
                std::cout << "[OK] Расшифровано " << result.size() << " байт" << std::endl;
            } else {
                std::cerr << "[ERROR] Неизвестный режим: " << mode << std::endl;
                return 1;
            }

            write_file(output_file, result);
            std::cout << "[OK] Результат сохранён в: " << output_file << std::endl;

        } catch (const std::exception& e) {
            std::cerr << "[ERROR] " << e.what() << std::endl;
            return 1;
        }

        return 0;
    }

    run_menu();
    return 0;
}