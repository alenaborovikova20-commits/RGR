#include "cryptum.h"
#include <iostream>

int main(int argc, char** argv) {
    // ===== ПРОВЕРКА ПАРОЛЯ =====
    std::string password;
    std::cout << "============================================\n";
    std::cout << "       КРИПТОГРАФИЧЕСКИЙ ИНСТРУМЕНТ\n";
    std::cout << "============================================\n";
    std::cout << "Введите пароль: ";
    std::getline(std::cin, password);
    
    const std::string CORRECT_PASSWORD = "123";
    
    if (password != CORRECT_PASSWORD) {
        std::cerr << "[ERROR] Неверный пароль! Выход...\n";
        return 1;
    }
    std::cout << "[OK] Доступ разрешён.\n\n";
    // =============================
    
    try {
        CryptumApp app;
        
        if (argc > 1) {
            return app.run(argc, argv);
        }
        
        app.run_menu();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << std::endl;
        return 1;
    }
}