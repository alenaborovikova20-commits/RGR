#include "cryptum.h"
#include <iostream>
#include <dlfcn.h>
#include <limits>


CryptumApp::CryptumApp() {
    load_plugins();
}

CryptumApp::~CryptumApp() {
    unload_plugins();
}

bool CryptumApp::load_plugins() {
    const std::vector<std::string> libs = {"rc5", "threefish", "xtea", "gost", "gm", "blowfish"};

    for (const auto& lib_name : libs) {
        std::string so_path = "./plugins/lib" + lib_name + ".so";
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
            std::cerr << "[WARN] Не хватает функций в " << so_path << std::endl;
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

CryptoPlugin* CryptumApp::select_plugin() {
    if (plugins.empty()) {
        std::cerr << "[ERROR] Нет доступных алгоритмов" << std::endl;
        return nullptr;
    }

    std::cout << "\nДоступные алгоритмы:\n";
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

bool CryptumApp::is_asymmetric_algorithm(const std::string& name) {
    return (name == "Goldwasser-Micali");
}