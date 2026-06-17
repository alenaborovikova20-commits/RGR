#include "mo.h"
#include <random>
#include <ctime>

static int64_t mod_pow(int64_t base, int64_t power, int64_t modulo) {
    base %= modulo;
    int64_t result = 1;
    for (int64_t i = 0; i < power; ++i) {
        result = (result * base) % modulo;
    }
    return result;
}

static int64_t mod_inverse(int64_t a, int64_t m) {
    int64_t u0 = 0, u1 = 1, m0 = m;
    while (a != 0) {
        int64_t q = m / a;
        int64_t temp = a;
        a = m % a;
        m = temp;
        temp = u1;
        u1 = u0 - q * u1;
        u0 = temp;
    }
    return (u0 < 0) ? u0 + m0 : u0;
}

static int64_t gcd(int64_t a, int64_t b) {
    while (b) {
        int64_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

static bool is_prime(int64_t n) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    for (int64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return false;
    }
    return true;
}

static int64_t random_prime(int64_t min_val, int64_t max_val, std::mt19937_64& rng) {
    std::uniform_int_distribution<int64_t> dist(min_val, max_val);
    int64_t candidate;
    do {
        candidate = dist(rng);
    } while (!is_prime(candidate));
    return candidate;
}

struct MOKeys {
    int64_t p, a, b;
};

static void keys_to_buffer(const MOKeys& keys, uint8_t* buffer) {
    int64_t* ptr = reinterpret_cast<int64_t*>(buffer);
    ptr[0] = keys.p;
    ptr[1] = keys.a;
    ptr[2] = keys.b;
}

static MOKeys buffer_to_keys(const uint8_t* buffer) {
    const int64_t* ptr = reinterpret_cast<const int64_t*>(buffer);
    MOKeys keys;
    keys.p = ptr[0];
    keys.a = ptr[1];
    keys.b = ptr[2];
    return keys;
}

void mo_generate_keys(uint8_t* key) {
    static std::mt19937_64 rng(static_cast<unsigned int>(time(nullptr)));
    MOKeys keys;
    keys.p = random_prime(1000, 10000, rng);
    int64_t phi = keys.p - 1;
    
    do {
        std::uniform_int_distribution<int64_t> dist(2, phi - 1);
        keys.a = dist(rng);
    } while (gcd(keys.a, phi) != 1);
    
    do {
        std::uniform_int_distribution<int64_t> dist(2, phi - 1);
        keys.b = dist(rng);
    } while (gcd(keys.b, phi) != 1);
    
    keys_to_buffer(keys, key);
}

void mo_encrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* key) {
    MOKeys keys = buffer_to_keys(key);
    int64_t M = static_cast<int64_t>(*in);
    int64_t C1 = mod_pow(M, keys.a, keys.p);
    int64_t C2 = mod_pow(C1, keys.b, keys.p);
    
    int64_t* out_ptr = reinterpret_cast<int64_t*>(out);
    out_ptr[0] = C2;
}

void mo_decrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* key) {
    MOKeys keys = buffer_to_keys(key);
    const int64_t* in_ptr = reinterpret_cast<const int64_t*>(in);
    int64_t b_inv = mod_inverse(keys.b, keys.p - 1);
    int64_t a_inv = mod_inverse(keys.a, keys.p - 1);
    
    int64_t D1 = mod_pow(in_ptr[0], b_inv, keys.p);
    int64_t M = mod_pow(D1, a_inv, keys.p);
    *out = static_cast<uint8_t>(M);
}

void mo_generate_iv(uint8_t* iv) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (int i = 0; i < 8; i++) {
        uint64_t val = gen();
        for (int b = 0; b < 8; b++)
            iv[i * 8 + b] = (val >> (b * 8)) & 0xFF;
    }
}