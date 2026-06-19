#include "cryptum.h"
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

std::vector<uint8_t> CryptumApp::read_file(const std::string& path) {
    if (!fs::exists(path)) {
        throw std::runtime_error("Файл не найден: " + path);
    }
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл: " + path);
    }
    auto size = fs::file_size(path);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size))) {
        throw std::runtime_error("Ошибка чтения файла: " + path);
    }
    return data;
}

void CryptumApp::write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось создать файл: " + path);
    }
    if (!file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()))) {
        throw std::runtime_error("Ошибка записи в файл: " + path);
    }
}

std::vector<uint8_t> CryptumApp::read_key_from_file(const std::string& path) {
    return read_file(path);
}