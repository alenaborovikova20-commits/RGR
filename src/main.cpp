#include "cryptum.h"
#include <iostream>

int main(int argc, char** argv) {
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