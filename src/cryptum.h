#ifndef CRYPTUM_H
#define CRYPTUM_H

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include "crypto_abi.h"

enum class MainMenuOption : int {
    EXIT = 0,
    ENCRYPT_DECRYPT_TEXT = 1,
    ENCRYPT_DECRYPT_FILE = 2,
    KEY_GENERATOR = 3,
    KEY_INFO = 4
};

struct CryptoPlugin {
    std::string name;
    void* handle = nullptr;
    size_t key_size = 0;
    std::string key_format_info;
    
    const AlgorithmInfo* (*get_info)() = nullptr;
    size_t (*get_out_size)(size_t, int) = nullptr;
    int (*encrypt)(ConstBuffer, ConstBuffer, MutBuffer*) = nullptr;
    int (*decrypt)(ConstBuffer, ConstBuffer, MutBuffer*) = nullptr;
    const char* (*get_key_info)() = nullptr;
    int (*generate_key)(uint8_t*, size_t*, int) = nullptr;
};

struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
    std::string algorithm;
    bool is_asymmetric = false;
};

class CryptumApp {
public:
    CryptumApp();
    ~CryptumApp();
    
    int run(int argc, char** argv);
    void run_menu();
    
private:
    std::vector<std::unique_ptr<CryptoPlugin>> plugins;
    
    std::vector<uint8_t> last_symmetric_key;
    KeyPair last_key_pair;
    std::string last_algorithm;
    bool last_is_asymmetric = false;
    std::vector<uint8_t> last_ciphertext;
    std::string last_plaintext;
    
    bool load_plugins();
    void unload_plugins();
    CryptoPlugin* find_plugin(const std::string& name);
    CryptoPlugin* select_plugin();
    bool is_asymmetric_algorithm(const std::string& name);
    
    void handle_text();
    void handle_file();
    void handle_keygen();
    void show_key_info();
    
    std::vector<uint8_t> encrypt_data(CryptoPlugin* plugin, 
                                       const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& data);
    std::vector<uint8_t> decrypt_data(CryptoPlugin* plugin,
                                       const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& data);
    
    std::vector<uint8_t> get_symmetric_key(CryptoPlugin* plugin);  // <--- ДОБАВЛЯЕМ!
    
    std::vector<uint8_t> read_key_from_file(const std::string& path);
    std::vector<uint8_t> read_file(const std::string& path);
    void write_file(const std::string& path, const std::vector<uint8_t>& data);
    
    void print_help() const;
};

std::string bytes_to_hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> hex_to_bytes(const std::string& hex);
std::string bytes_to_string(const std::vector<uint8_t>& data);
std::vector<uint8_t> string_to_bytes(const std::string& str);
std::vector<uint8_t> generate_random_key(size_t size);

#endif