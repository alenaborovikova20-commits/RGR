#include "cryptum.h"
#include <iostream>
#include <string>
#include <limits>

void CryptumApp::run_menu() {
    if (plugins.empty()) {
        std::cerr << "[ОШИБКА] Нет загруженных плагинов" << std::endl;
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
            std::cerr << "[ОШИБКА] Введите число!" << std::endl;
            continue;
        }

        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        try {
            // Используем enum
            MainMenuOption option = static_cast<MainMenuOption>(choice);
            
            switch (option) {
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
                    std::cerr << "[ОШИБКА] Неверный выбор!" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "[ОШИБКА] " << e.what() << std::endl;
        }
    }
}