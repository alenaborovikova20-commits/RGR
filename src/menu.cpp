#include "cryptum.h"
#include <iostream>
#include <limits>

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

void CryptumApp::print_help() const {
    std::cout << "\n============================================\n";
    std::cout << "       КРИПТОГРАФИЧЕСКИЙ ИНСТРУМЕНТ\n";
    std::cout << "============================================\n";
    std::cout << "Использование: cryptoApp [ОПЦИИ]\n";
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