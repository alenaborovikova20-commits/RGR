#include "cryptum.h"
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    std::string password;
    std::cout << "КРИПТОГРАФИЧЕСКИЙ ИНСТРУМЕНТ\n";
    std::cout << "Введите пароль: ";
    std::getline(std::cin, password);

    const std::string CORRECT_PASSWORD = "123";
    if (password != CORRECT_PASSWORD) {
        std::cerr << "[ERROR] Неверный пароль! Выход...\n";
        return 1;
    }
    std::cout << "[OK] Доступ разрешён.\n\n";
    
    try {
        CryptumApp app;
        return app.run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << std::endl;
        return 1;
    }
}