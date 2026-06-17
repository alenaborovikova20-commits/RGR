#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <random>
#include <ctime>
#include <algorithm>
#include "supporting_funcs.h"

class MasseyOmura {
private:
    int64_t p;          // публичное простое число
    int64_t a;          // секретный ключ Алисы
    int64_t b;          // секретный ключ Боба
    std::mt19937_64 rng;
    
    // строки в блоки (байты)
    std::vector<int64_t> string_to_blocks(const std::string& text) {
        std::vector<int64_t> blocks;
        for (unsigned char c : text) {
            blocks.push_back(static_cast<int64_t>(c));
        }
        return blocks;
    }
    
    // блоки в строку
    std::string blocks_to_string(const std::vector<int64_t>& blocks) {
        std::string result;
        for (int64_t block : blocks) {
            result.push_back(static_cast<char>(block));
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
        std::cout << "Сохранено " << data.size() << " чисел в " << filename << std::endl;
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
    
    // проверка, является ли файл бинарным (нашим форматом)
    bool is_binary_encrypted(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) return false;
        
        size_t count;
        file.read(reinterpret_cast<char*>(&count), sizeof(count));
        
        if (file.fail()) {
            file.close();
            return false;
        }
        
        // Проверяем, что размер разумный (не больше 100 МБ)
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
        p = random_prime(1000, 10000, rng);
        int64_t phi = p - 1;
        
        do {
            std::uniform_int_distribution<int64_t> dist(2, phi - 1);
            a = dist(rng);
        } while (gcd(a, phi) != 1);
        
        do {
            std::uniform_int_distribution<int64_t> dist(2, phi - 1);
            b = dist(rng);
        } while (gcd(b, phi) != 1);
    }
    
    // сохранение ключей в файл
    void save_keys(const std::string& filename = "keys.txt") {
        std::ofstream key_file(filename);
        if (key_file.is_open()) {
            key_file << p << "\n" << a << "\n" << b << "\n";
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
        key_file >> p >> a >> b;
        key_file.close();
        
        if (p == 0 || a == 0 || b == 0) {
            std::cerr << "Ошибка: файл ключей поврежден!" << std::endl;
            return false;
        }
        
        std::cout << "Загружены ключи: p=" << p << ", a=" << a << ", b=" << b << std::endl;
        return true;
    }
    
public:
    MasseyOmura() {
        rng.seed(static_cast<unsigned int>(time(nullptr)));
    }
    
    //ШИФРОВАНИЕ ТЕКСТА
    void encrypt_text() {
        std::cin.ignore();
        std::string input;
        std::cout << "\nВведите текст для шифрования: ";
        getline(std::cin, input);
        
        if (input.empty()) {
            std::cout << "Текст не может быть пустым!\n";
            return;
        }
        
        std::cout << "\n  ШИФРОВАНИЕ ТЕКСТА  \n";
        
        generate_keys();
        std::cout << "p = " << p << std::endl;
        std::cout << "a = " << a << std::endl;
        std::cout << "b = " << b << std::endl;
        
        std::vector<int64_t> blocks = string_to_blocks(input);
        std::vector<int64_t> ciphertext;
        
        for (int64_t M : blocks) {
            int64_t C1 = mod_pow(M, a, p);
            int64_t C2 = mod_pow(C1, b, p);
            ciphertext.push_back(C2);
        }
        
        std::cout << "\nШифротекст:\n";
        for (size_t i = 0; i < ciphertext.size() && i < 10; ++i) {
            std::cout << ciphertext[i] << " ";
        }
        if (ciphertext.size() > 10) std::cout << "...";
        std::cout << std::endl;
        
        // сохраняем также в текстовом формате для удобства
        std::ofstream text_file("encrypted_text.txt");
        if (text_file.is_open()) {
            for (size_t i = 0; i < ciphertext.size(); ++i) {
                text_file << ciphertext[i];
                if (i < ciphertext.size() - 1) text_file << " ";
            }
            text_file.close();
            std::cout << "Текстовая копия сохранена в encrypted_text.txt" << std::endl;
        }
        
        save_encrypted(ciphertext, "encrypted.bin");
        save_keys();
    }
    
    //РАСШИФРОВАНИЕ ТЕКСТА
    void decrypt_text() {
        std::cout << "\n  РАСШИФРОВАНИЕ ТЕКСТА  \n";
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
        
        int64_t b_inv = mod_inverse(b, p - 1);
        int64_t a_inv = mod_inverse(a, p - 1);
        
        std::vector<int64_t> decrypted;
        for (int64_t C2 : ciphertext) {
            int64_t D1 = mod_pow(C2, b_inv, p);
            int64_t M = mod_pow(D1, a_inv, p);
            decrypted.push_back(M);
        }
        
        std::string result = blocks_to_string(decrypted);
        std::cout << "\n  РАСШИФРОВАННЫЙ ТЕКСТ  \n";
        std::cout << result << std::endl;
        
        std::ofstream out("decrypted.txt");
        if (out.is_open()) {
            out << result;
            out.close();
            std::cout << "\nСохранено в decrypted.txt" << std::endl;
        }
    }
    
    //ШИФРОВАНИЕ ФАЙЛА
    void encrypt_file() {
        std::string infile, outfile;
        std::cout << "\n  ШИФРОВАНИЕ ФАЙЛА  \n";
        std::cout << "Входной файл: ";
        std::cin >> infile;
        std::cout << "Выходной файл (без расширения): ";
        std::cin >> outfile;
        
        generate_keys();
        std::cout << "p = " << p << std::endl;
        std::cout << "a = " << a << std::endl;
        std::cout << "b = " << b << std::endl;
        
        std::vector<unsigned char> original = file_to_bytes(infile);
        if (original.empty()) {
            std::cout << "Не удалось прочитать файл!\n";
            return;
        }
        
        std::cout << "Размер файла: " << original.size() << " байт" << std::endl;
        
        std::vector<int64_t> encrypted;
        encrypted.reserve(original.size());
        
        for (unsigned char M : original) {
            int64_t C1 = mod_pow(M, a, p);
            int64_t C2 = mod_pow(C1, b, p);
            encrypted.push_back(C2);
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
        std::cout << "Файл зашифрован в " << outfile << std::endl;
    }
    
    // РАСШИФРОВАНИЕ ФАЙЛА 
    void decrypt_file() {
        std::cout << "\n  РАСШИФРОВАНИЕ ФАЙЛА  \n";
        std::string file_with_keys;
        std::cout << "Введите название файла с ключами: ";
        std::cin >> file_with_keys;
        
        if (!load_keys(file_with_keys)) return;
        
        std::string infile, outfile;
        std::cout << "Зашифрованный файл: ";
        std::cin >> infile;
        std::cout << "Выходной файл: ";
        std::cin >> outfile;
        
        // автоматически опрделяем формат и загружаем
        std::vector<int64_t> encrypted = load_encrypted_auto(infile);
        if (encrypted.empty()) {
            std::cout << "Не удалось прочитать зашифрованный файл!\n";
            std::cout << "Файл должен содержать числа через пробел \n";
            std::cout << "или быть в бинарном формате \n";
            return;
        }
        
        std::cout << "Найдено " << encrypted.size() << " блоков для расшифровки..." << std::endl;
        
        int64_t b_inv = mod_inverse(b, p - 1);
        int64_t a_inv = mod_inverse(a, p - 1);
        
        std::vector<unsigned char> decrypted;
        decrypted.reserve(encrypted.size());
        
        for (int64_t C2 : encrypted) {
            int64_t D1 = mod_pow(C2, b_inv, p);
            int64_t M = mod_pow(D1, a_inv, p);
            decrypted.push_back(static_cast<unsigned char>(M));
        }
        
        bytes_to_file(decrypted, outfile);
        
        // Показываем превью для текстовых файлов
        bool looks_like_text = true;
        for (size_t i = 0; i < std::min(decrypted.size(), size_t(100)); ++i) {
            unsigned char c = decrypted[i];
            if (c != 10 && c != 13 && (c < 32 || c > 126)) {
                looks_like_text = false;
                break;
            }
        }
        
        if (looks_like_text && decrypted.size() > 0) {
            std::cout << "\nРАСШИФРОВАННЫЕ ДАННЫЕ\n";
            size_t show_len = std::min(decrypted.size(), size_t(200));
            std::string preview(decrypted.begin(), decrypted.begin() + show_len);
            std::cout << preview;
            if (decrypted.size() > 200) std::cout << "...";
            std::cout << "\n" << std::endl;
        } else {
            std::cout << "\nФайл содержит бинарные данные (" << decrypted.size() << " байт)" << std::endl;
        }
        std::cout << "Расшифровано в " << outfile << std::endl;
    }
    
    void run() {
        int choice;
        
        std::cout << "       ПРОТОКОЛ МЭССИ-ОМУРА\n";
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
    MasseyOmura mo;
    mo.run();
    return 0;
}