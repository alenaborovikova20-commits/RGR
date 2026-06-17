#include "supporting_funcs.h"
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <ctime>
#include <fstream>
#include <sstream>

class GoldwasserMicali {
private:
    int64_t p, q;       // секретные простые числа
    int64_t n;          // публичный модуль n = p*q
    int64_t y;          // публичный невычет
    std::mt19937_64 rng;
    
    // Символ Лежандра
    int64_t legendre(int64_t a, int64_t p) {
        int64_t res = mod_pow(a, (p - 1) / 2, p);
        if (res == 0) return 0;
        return (res == 1) ? 1 : -1;
    }
    
    // Поиск y (невычет по модулю p И невычет по модулю q)
    int64_t find_y() {
        for (int64_t candidate = 2; candidate < n; candidate++) {
            int64_t leg_p = legendre(candidate, p);
            int64_t leg_q = legendre(candidate, q);
            if (leg_p == -1 && leg_q == -1) {
                return candidate;
            }
        }
        return 2;
    }
    
    // строки в биты
    std::vector<int> string_to_bits(const std::string& text) {
        std::vector<int> bits;
        for (unsigned char ch : text) {
            for (int bit_pos = 7; bit_pos >= 0; --bit_pos) {
                bits.push_back((ch >> bit_pos) & 1);
            }
        }
        return bits;
    }
    
    // биты в строку
    std::string bits_to_string(const std::vector<int>& bits) {
        std::string result;
        for (size_t i = 0; i < bits.size(); i += 8) {
            char ch = 0;
            for (int j = 0; j < 8 && i + j < bits.size(); ++j) {
                ch = (ch << 1) | bits[i + j];
            }
            result.push_back(ch);
        }
        return result;
    }
    
    // шифротекст из строки с числами
    std::vector<int64_t> parse_ciphertext(const std::string& input) {
        std::vector<int64_t> result;
        std::stringstream ss(input);
        int64_t num;
        while (ss >> num) {
            result.push_back(num);
        }
        return result;
    }
    
    // сохранение зашифрованных данных в бинарник
    void save_encrypted(const std::vector<int64_t>& data, const std::string& filename) {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Ошибка: не могу создать " << filename << std::endl;
            return;
        }
        
        size_t count = data.size();
        file.write(reinterpret_cast<const char*>(&count), sizeof(count));
        
        for (int64_t num : data) {
            file.write(reinterpret_cast<const char*>(&num), sizeof(num));
        }
        
        file.close();
        std::cout << "Сохранено " << data.size() << " чисел в " << filename << " (бинарный)" << std::endl;
    }
    
    // загрузка зашифрованных данных из бинарника
    std::vector<int64_t> load_encrypted_binary(const std::string& filename) {
        std::vector<int64_t> result;
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Ошибка: не могу открыть " << filename << std::endl;
            return result;
        }
        
        size_t count;
        file.read(reinterpret_cast<char*>(&count), sizeof(count));
        
        if (file.fail()) {
            std::cerr << "Ошибка: неверный формат бинарного файла" << std::endl;
            return result;
        }
        
        result.resize(count);
        for (size_t i = 0; i < count; ++i) {
            file.read(reinterpret_cast<char*>(&result[i]), sizeof(int64_t));
            if (file.fail()) {
                std::cerr << "Ошибка: файл поврежден" << std::endl;
                return std::vector<int64_t>();
            }
        }
        
        file.close();
        std::cout << "Загружено " << result.size() << " чисел из бинарного файла " << filename << std::endl;
        return result;
    }
    
    // загрузка зашифрованных данных из текстового файла
    std::vector<int64_t> load_encrypted_text(const std::string& filename) {
        std::vector<int64_t> result;
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Ошибка: не могу открыть " << filename << std::endl;
            return result;
        }
        
        int64_t num;
        while (file >> num) {
            result.push_back(num);
        }
        
        file.close();
        std::cout << "Загружено " << result.size() << " чисел из текстового файла " << filename << std::endl;
        return result;
    }
    
    // проверка, является ли файл бинарным 
    bool is_binary_encrypted(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) return false;
        
        size_t count;
        file.read(reinterpret_cast<char*>(&count), sizeof(count));
        
        if (file.fail()) {
            file.close();
            return false;
        }
        
        // Проверка размера
        if (count > 100 * 1024 * 1024) {
            file.close();
            return false;
        }
        
        file.close();
        return true;
    }
    
    // автоматическое определение формата и загрузка
    std::vector<int64_t> load_encrypted_auto(const std::string& filename) {
        if (is_binary_encrypted(filename)) {
            return load_encrypted_binary(filename);
        } else {
            return load_encrypted_text(filename);
        }
    }
    
    // чтение файла в байты
    std::vector<unsigned char> file_to_bytes(const std::string& filename) {
        std::vector<unsigned char> bytes;
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Ошибка: не могу открыть " << filename << std::endl;
            return bytes;
        }
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        bytes.resize(size);
        file.read(reinterpret_cast<char*>(bytes.data()), size);
        file.close();
        
        std::cout << "Прочитано " << bytes.size() << " байт из " << filename << std::endl;
        return bytes;
    }
    
    // запись байтов в файл
    void bytes_to_file(const std::vector<unsigned char>& bytes, const std::string& filename) {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Ошибка: не могу создать " << filename << std::endl;
            return;
        }
        
        file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        file.close();
        std::cout << "Сохранено " << bytes.size() << " байт в " << filename << std::endl;
    }
    
    // генерация ключей
    void generate_keys() {
        do {
            p = random_prime(50, 200, rng);
            q = random_prime(50, 200, rng);
        } while (p == q);
        
        n = p * q;
        y = find_y();
        
        std::cout << "  secret p = " << p << std::endl;
        std::cout << "  secret q = " << q << std::endl;
        std::cout << "  public n = " << n << std::endl;
        std::cout << "  public y = " << y << std::endl;
    }
    
    // сохранение ключей в файл
    void save_keys(const std::string& filename = "gm_keys.txt") {
        std::ofstream key_file(filename);
        if (key_file.is_open()) {
            key_file << p << "\n" << q << "\n" << n << "\n" << y << "\n";
            key_file.close();
            std::cout << "Ключи сохранены в " << filename << std::endl;
        } else {
            std::cerr << "Ошибка: не могу сохранить ключи!" << std::endl;
        }
    }
    
    // загрузка ключей из файла
    bool load_keys(const std::string& filename) {
        std::ifstream key_file(filename);
        if (!key_file.is_open()) {
            std::cerr << "Ошибка: не могу открыть файл ключей " << filename << std::endl;
            return false;
        }
        key_file >> p >> q >> n >> y;
        key_file.close();
        
        if (p == 0 || q == 0 || n == 0 || y == 0) {
            std::cerr << "Ошибка: файл ключей поврежден!" << std::endl;
            return false;
        }
        
        std::cout << "Загружены ключи: p=" << p << ", q=" << q << ", n=" << n << ", y=" << y << std::endl;
        return true;
    }
    
    // шифрование одного бита
    int64_t encrypt_bit(int bit, int64_t r) {
        int64_t r_sq = mod_pow(r, 2, n);
        if (bit == 0) {
            return r_sq;
        } else {
            return (y * r_sq) % n;
        }
    }
    
    // расшифрование одного бита
    int decrypt_bit(int64_t c) {
        int64_t leg_p = legendre(c, p);
        int64_t leg_q = legendre(c, q);
        
        // c вычет по модулю n вычет по p и по q
        if (leg_p == 1 && leg_q == 1) {
            return 0;
        } else {
            return 1;
        }
    }
    
public:
    GoldwasserMicali() {
        rng.seed(static_cast<unsigned int>(time(nullptr)));
    }
    
    // ШИФРОВАНИЕ ТЕКСТА
    void encrypt_text() {
        std::cin.ignore();
        std::string input;
        std::cout << "\nВведите текст для шифрования: ";
        getline(std::cin, input);
        
        if (input.empty()) {
            std::cout << "Текст не может быть пустым!\n";
            return;
        }
        
        std::cout << "\n  ШИФРОВАНИЕ ТЕКСТА \n";
        
        generate_keys();
        
        std::vector<int> bits = string_to_bits(input);
        std::vector<int64_t> ciphertext;
        std::uniform_int_distribution<int64_t> dist(2, n - 1);
        
        for (int bit : bits) {
            int64_t r = dist(rng);
            while (gcd(r, n) != 1) {
                r = dist(rng);
            }
            ciphertext.push_back(encrypt_bit(bit, r));
        }
        
        std::cout << "\nШифротекст:\n";
        for (size_t i = 0; i < ciphertext.size() && i < 10; ++i) {
            std::cout << ciphertext[i] << " ";
        }
        if (ciphertext.size() > 10) std::cout << "...";
        std::cout << std::endl;
        std::cout << "Всего чисел в шифротексте: " << ciphertext.size() << std::endl;
        
        // сохраняем также в текстовом формате для удобства
        std::ofstream text_file("gm_encrypted_text.txt");
        if (text_file.is_open()) {
            for (size_t i = 0; i < ciphertext.size(); ++i) {
                text_file << ciphertext[i];
                if (i < ciphertext.size() - 1) text_file << " ";
            }
            text_file.close();
            std::cout << "Текстовая копия сохранена в gm_encrypted_text.txt" << std::endl;
        }
        
        save_encrypted(ciphertext, "gm_encrypted.bin");
        save_keys();
    }
    
    // РАСШИФРОВАНИЕ ТЕКСТА
    void decrypt_text() {
        std::cout << "\n  РАСШИФРОВАНИЕ ТЕКСТА \n";
        std::string file_with_keys;
        std::cout << "Введите название файла с ключами: ";
        std::cin >> file_with_keys;
        
        if (!load_keys(file_with_keys)) return;
        
        std::cin.ignore();
        std::string input_line;
        std::cout << "Введите шифротекст (числа через пробел): ";
        getline(std::cin, input_line);
        
        if (input_line.empty()) {
            std::cout << "Шифротекст не может быть пустым!\n";
            return;
        }
        
        std::vector<int64_t> ciphertext = parse_ciphertext(input_line);
        
        std::vector<int> decrypted_bits;
        for (int64_t c : ciphertext) {
            decrypted_bits.push_back(decrypt_bit(c));
        }
        
        std::string result = bits_to_string(decrypted_bits);
        std::cout << "\n  РАСШИФРОВАННЫЙ ТЕКСТ  \n";
        std::cout << result << std::endl;
        
        std::ofstream out("gm_decrypted.txt");
        if (out.is_open()) {
            out << result;
            out.close();
            std::cout << "\nСохранено в gm_decrypted.txt" << std::endl;
        }
    }
    
    // ШИФРОВАНИЕ ФАЙЛА
    void encrypt_file() {
        std::string infile, outfile;
        std::cout << "\n  ШИФРОВАНИЕ ФАЙЛА  \n";
        std::cout << "Входной файл: ";
        std::cin >> infile;
        std::cout << "Выходной файл (без расширения): ";
        std::cin >> outfile;
        
        generate_keys();
        
        std::vector<unsigned char> original = file_to_bytes(infile);
        if (original.empty()) {
            std::cout << "Не удалось прочитать файл!\n";
            return;
        }
        
        std::cout << "Размер файла: " << original.size() << " байт" << std::endl;
        std::cout << "После шифрования будет " << original.size() * 8 << " чисел" << std::endl;
        
        std::vector<int64_t> encrypted;
        encrypted.reserve(original.size() * 8);
        std::uniform_int_distribution<int64_t> dist(2, n - 1);
        
        for (unsigned char byte : original) {
            for (int bit_pos = 7; bit_pos >= 0; --bit_pos) {
                int bit = (byte >> bit_pos) & 1;
                int64_t r = dist(rng);
                while (gcd(r, n) != 1) {
                    r = dist(rng);
                }
                encrypted.push_back(encrypt_bit(bit, r));
            }
        }
        
        save_encrypted(encrypted, outfile + ".bin");
        
        // сохраняем также в текстовом формате
        std::string text_outfile = outfile + ".txt";
        std::ofstream text_file(text_outfile);
        if (text_file.is_open()) {
            for (size_t i = 0; i < encrypted.size(); ++i) {
                text_file << encrypted[i];
                if (i < encrypted.size() - 1) text_file << " ";
            }
            text_file.close();
            std::cout << "Текстовая копия сохранена в " << text_outfile << std::endl;
        }
        
        save_keys();
        std::cout << "Файл зашифрован в " << outfile << ".bin" << std::endl;
    }
    
    // РАСШИФРОВАНИЕ ФАЙЛА 
    void decrypt_file() {
        std::cout << "\n  РАСШИФРОВАНИЕ ФАЙЛА  \n";
        std::string file_with_keys;
        std::cout << "Введите название файла с ключами: ";
        std::cin >> file_with_keys;
        
        if (!load_keys(file_with_keys)) return;
        
        std::string infile, outfile;
        std::cout << "Зашифрованный файл (бинарник или txt с числами): ";
        std::cin >> infile;
        std::cout << "Выходной файл: ";
        std::cin >> outfile;
        
        // Автоматически определяем формат и загружаем
        std::vector<int64_t> encrypted = load_encrypted_auto(infile);
        if (encrypted.empty()) {
            std::cout << "Не удалось прочитать зашифрованный файл!\n";
            return;
        }
        
        std::cout << "Найдено " << encrypted.size() << " чисел для расшифровки..." << std::endl;
        std::cout << "Ожидаемый размер файла: " << encrypted.size() / 8 << " байт" << std::endl;
        
        std::vector<int> decrypted_bits;
        decrypted_bits.reserve(encrypted.size());
        
        for (int64_t c : encrypted) {
            decrypted_bits.push_back(decrypt_bit(c));
        }
        
        std::vector<unsigned char> decrypted_bytes;
        for (size_t i = 0; i < decrypted_bits.size(); i += 8) {
            unsigned char byte = 0;
            for (int j = 0; j < 8 && i + j < decrypted_bits.size(); ++j) {
                byte = (byte << 1) | decrypted_bits[i + j];
            }
            decrypted_bytes.push_back(byte);
        }
        
        bytes_to_file(decrypted_bytes, outfile);
        
        // Показываем превью для текстовых файлов
        bool looks_like_text = true;
        for (size_t i = 0; i < std::min(decrypted_bytes.size(), size_t(100)); ++i) {
            unsigned char c = decrypted_bytes[i];
            if (c != 10 && c != 13 && (c < 32 || c > 126)) {
                looks_like_text = false;
                break;
            }
        }
        
        if (looks_like_text && decrypted_bytes.size() > 0) {
            std::cout << "\nРАСШИФРОВАННЫЕ ДАННЫЕ\n";
            size_t show_len = std::min(decrypted_bytes.size(), size_t(200));
            std::string preview(decrypted_bytes.begin(), decrypted_bytes.begin() + show_len);
            std::cout << preview;
            if (decrypted_bytes.size() > 200) std::cout << "...";
            std::cout << "\n" << std::endl;
        } else {
            std::cout << "\nФайл содержит бинарные данные (" << decrypted_bytes.size() << " байт)" << std::endl;
        }
        std::cout << "Расшифровано в " << outfile << std::endl;
    }
    
    void run() {
        int choice;
        
        std::cout << "   ПРОТОКОЛ ГОЛЬДВАССЕРА-МИКАЛИ\n";
        std::cout << "1 - Шифрование текста (консоль)\n";
        std::cout << "2 - Расшифрование текста (консоль)\n";
        std::cout << "3 - Шифрование файла\n";
        std::cout << "4 - Расшифрование файла (автоопределение формата)\n";
        std::cout << "Выбор: ";
        std::cin >> choice;
        
        switch(choice) {
            case 1:
                encrypt_text();
                break;
            case 2:
                decrypt_text();
                break;
            case 3:
                encrypt_file();
                break;
            case 4:
                decrypt_file();
                break;
            default:
                std::cout << "Неверный выбор!\n";
        }
        
        if (choice != 0) {
            std::cout << "\n";
            run();
        }
    }
};

int main() {
    GoldwasserMicali gm;
    gm.run();
    return 0;
}