#include "cryptum.h"
#include <cstdio>
#include <stdexcept>


std::vector<uint8_t> CryptumApp::encrypt_data(CryptoPlugin* plugin,
                                               const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& data) {
    if (!plugin) throw std::runtime_error("Плагин не выбран");

    bool is_asym = is_asymmetric_algorithm(plugin->name);
    std::vector<uint8_t> result;

    if (is_asym) {
        ConstBuffer key_buf = {key.data(), key.size()};
        ConstBuffer in_buf = {data.data(), data.size()};

        size_t out_size = plugin->get_out_size(data.size(), 1);
        if (out_size == 0) {
            out_size = data.size() * 8 * sizeof(int64_t);
        }

        std::vector<uint8_t> out_buf_data(out_size);
        MutBuffer out_buf = {out_buf_data.data(), out_buf_data.size()};

        int ret = plugin->encrypt(key_buf, in_buf, &out_buf);
        if (ret != 0) {
            throw std::runtime_error("Ошибка асимметричного шифрования: код " + std::to_string(ret));
        }

        out_buf_data.resize(out_buf.size);
        result = out_buf_data;

    } else {
        size_t out_size = plugin->get_out_size(data.size(), 1);
        if (out_size == 0 || out_size < data.size()) {
            out_size = data.size() * 2 + 1024;
        }
        std::vector<uint8_t> out_buf_data(out_size);
        MutBuffer out_buf = {out_buf_data.data(), out_buf_data.size()};
        ConstBuffer key_buf = {key.data(), key.size()};
        ConstBuffer in_buf = {data.data(), data.size()};

        int ret = plugin->encrypt(key_buf, in_buf, &out_buf);
        if (ret != 0) {
            throw std::runtime_error("Ошибка шифрования: код " + std::to_string(ret));
        }
        out_buf_data.resize(out_buf.size);
        result = out_buf_data;
    }

    return result;
}

std::vector<uint8_t> CryptumApp::decrypt_data(CryptoPlugin* plugin,
                                               const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& data) {
    if (!plugin) throw std::runtime_error("Плагин не выбран");

    bool is_asym = is_asymmetric_algorithm(plugin->name);
    std::vector<uint8_t> result;

    if (is_asym) {
        ConstBuffer key_buf = {key.data(), key.size()};
        size_t out_size = data.size() * 4 + 4096;
        std::vector<uint8_t> out_buf_data(out_size);
        MutBuffer out_buf = {out_buf_data.data(), out_buf_data.size()};
        ConstBuffer in_buf = {data.data(), data.size()};

        int ret = plugin->decrypt(key_buf, in_buf, &out_buf);
        if (ret != 0) {
            throw std::runtime_error("Ошибка асимметричного расшифрования: код " + std::to_string(ret));
        }

        out_buf_data.resize(out_buf.size);
        result = out_buf_data;

    } else {
        size_t out_size = plugin->get_out_size(data.size(), 0);
        if (out_size == 0 || out_size < data.size()) {
            out_size = data.size() * 4 + 4096;
        }

        std::vector<uint8_t> out_buf_data(out_size);
        MutBuffer out_buf = {out_buf_data.data(), out_buf_data.size()};
        ConstBuffer key_buf = {key.data(), key.size()};
        ConstBuffer in_buf = {data.data(), data.size()};

        int ret = plugin->decrypt(key_buf, in_buf, &out_buf);
        if (ret != 0) {
            throw std::runtime_error("Ошибка расшифрования: код " + std::to_string(ret));
        }
        out_buf_data.resize(out_buf.size);
        result = out_buf_data;
    }

    return result;
}