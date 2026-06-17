#include "cryptum.h"
#include <iostream>
#include <clocale>

int main(int argc, char** argv) {
    std::setlocale(LC_ALL, "ru_RU.UTF-8");
    
    try {
        CryptumApp app;
        
        if (argc > 1) {
            return app.run(argc, argv);
        }
        
        std::cout << "============================================\n";
        std::cout << "       КРИПТОГРАФИЧЕСКИЙ ИНСТРУМЕНТ\n";
        std::cout << "============================================\n";
        std::cout << "Введите пароль для доступа: ";
        
        std::string password;
        std::getline(std::cin, password);
        
        if (password != "admin") {
            std::cerr << "[ОШИБКА] Неверный пароль!" << std::endl;
            return 1;
        }
        
        std::cout << "[OK] Доступ разрешён.\n" << std::endl;
        app.run_menu();
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\n[КРИТИЧЕСКАЯ ОШИБКА] " << e.what() << std::endl;
        return 1;
    }
}