#include "cryptum.h"
#include <random>
#include <chrono>
#include <cstring>
#include <stdexcept>


std::vector<uint8_t> string_to_key(const std::string& input, size_t key_size) {
    std::vector<uint8_t> key(key_size, 0);
    for (size_t i = 0; i < input.size(); i++) {
        key[i % key_size] ^= static_cast<uint8_t>(input[i]);
    }
    for (size_t i = 0; i < key_size; i++) {
        key[i] ^= (input.size() >> (i % 4)) & 0xFF;
    }
    return key;
}

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    static const char* hex = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t b : data) {
        result.push_back(hex[(b >> 4) & 0x0F]);
        result.push_back(hex[b & 0x0F]);
    }
    return result;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::runtime_error("HEX строка должна иметь чётную длину");
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        char* end = nullptr;
        long val = strtol(hex.substr(i, 2).c_str(), &end, 16);
        if (*end != '\0') {
            throw std::runtime_error("Недопустимый HEX символ");
        }
        bytes.push_back(static_cast<uint8_t>(val));
    }
    return bytes;
}

std::string bytes_to_string(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

std::vector<uint8_t> string_to_bytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::vector<uint8_t> generate_random_key(size_t size) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd() + std::chrono::steady_clock::now().time_since_epoch().count());
    static std::uniform_int_distribution<uint64_t> dis(0, 0xFFFFFFFFFFFFFFFFULL);
    std::vector<uint8_t> key(size);
    for (size_t i = 0; i < size; ++i) {
        key[i] = static_cast<uint8_t>(dis(gen) & 0xFF);
    }
    return key;
}