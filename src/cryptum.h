#ifndef CRYPTUM_H
#define CRYPTUM_H

#include "crypto_abi.h"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

struct CryptoPlugin {
    void* handle;
    std::string name;
    size_t key_size;
    std::string key_format_info;
    
    const AlgorithmInfo* (*get_info)();
    size_t (*get_out_size)(size_t, int);
    int (*encrypt)(ConstBuffer, ConstBuffer, MutBuffer*);
    int (*decrypt)(ConstBuffer, ConstBuffer, MutBuffer*);
    const char* (*get_key_info)();
    int (*generate_key)(uint8_t*, size_t*, int);
};

struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
    std::string algorithm;
    bool is_asymmetric;
};

enum class MainMenuOption {
    EXIT = 0,
    ENCRYPT_DECRYPT_TEXT = 1,
    ENCRYPT_DECRYPT_FILE = 2,
    KEY_GENERATOR = 3,
    KEY_INFO = 4
};

enum class TextAction {
    ENCRYPT = 1,
    DECRYPT = 2,
    BACK = 0
};

enum class SymmetricKeySource {
    GENERATE = 1,
    ENTER = 2,
    LOAD_FILE = 3,
    BACK = 0
};

enum class AsymmetricKeySource {
    GENERATE = 1,
    LOAD_FILE = 2,
    BACK = 0
};

enum class CiphertextSource {
    LAST = 1,
    HEX = 2,
    FILE = 3,
    BACK = 0
};

class CryptumApp {
public:
    CryptumApp();
    ~CryptumApp();
    
    void run_menu();
    int run(int argc, char** argv);
    void print_help() const;
    
private:
    std::vector<std::unique_ptr<CryptoPlugin>> plugins;
    
    std::vector<uint8_t> last_ciphertext;
    std::string last_plaintext;
    std::vector<uint8_t> last_symmetric_key;
    KeyPair last_key_pair;
    std::string last_algorithm;
    bool last_is_asymmetric = false;
    
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
    
    std::vector<uint8_t> read_file(const std::string& path);
    void write_file(const std::string& path, const std::vector<uint8_t>& data);
    std::vector<uint8_t> read_key_from_file(const std::string& path);
};

std::string bytes_to_hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> hex_to_bytes(const std::string& hex);
std::string bytes_to_string(const std::vector<uint8_t>& data);
std::vector<uint8_t> string_to_bytes(const std::string& str);
std::vector<uint8_t> generate_random_key(size_t size);
std::vector<uint8_t> string_to_key(const std::string& input, size_t key_size);

#endif