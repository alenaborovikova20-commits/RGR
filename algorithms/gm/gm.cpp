#include "gm.h"
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

static int64_t legendre(int64_t a, int64_t p) {
    int64_t res = mod_pow(a, (p - 1) / 2, p);
    if (res == 0) return 0;
    return (res == 1) ? 1 : -1;
}

static int64_t find_y(int64_t p, int64_t q, int64_t n) {
    for (int64_t candidate = 2; candidate < n; ++candidate) {
        if (legendre(candidate, p) == -1 && legendre(candidate, q) == -1) {
            return candidate;
        }
    }
    return 2;
}

struct GMKeys {
    int64_t p, q, n, y;
};

static void keys_to_buffer(const GMKeys& keys, uint8_t* buffer) {
    int64_t* ptr = reinterpret_cast<int64_t*>(buffer);
    ptr[0] = keys.p;
    ptr[1] = keys.q;
    ptr[2] = keys.n;
    ptr[3] = keys.y;
}

static GMKeys buffer_to_keys(const uint8_t* buffer) {
    const int64_t* ptr = reinterpret_cast<const int64_t*>(buffer);
    GMKeys keys;
    keys.p = ptr[0];
    keys.q = ptr[1];
    keys.n = ptr[2];
    keys.y = ptr[3];
    return keys;
}

static int encrypt_bit(int bit, int64_t r, int64_t n, int64_t y) {
    int64_t r_sq = mod_pow(r, 2, n);
    return (bit == 0) ? r_sq : (y * r_sq) % n;
}

static int decrypt_bit(int64_t c, int64_t p, int64_t q) {
    int64_t leg_p = legendre(c, p);
    int64_t leg_q = legendre(c, q);
    return (leg_p == 1 && leg_q == 1) ? 0 : 1;
}

void gm_generate_keys(uint8_t* key) {
    static std::mt19937_64 rng(static_cast<unsigned int>(time(nullptr)));
    GMKeys keys;
    do {
        keys.p = random_prime(50, 200, rng);
        keys.q = random_prime(50, 200, rng);
    } while (keys.p == keys.q);
    keys.n = keys.p * keys.q;
    keys.y = find_y(keys.p, keys.q, keys.n);
    keys_to_buffer(keys, key);
}

void gm_encrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* key) {
    static std::mt19937_64 rng(static_cast<unsigned int>(time(nullptr)));
    GMKeys keys = buffer_to_keys(key);
    std::uniform_int_distribution<int64_t> dist(2, keys.n - 1);
    
    int64_t* out_ptr = reinterpret_cast<int64_t*>(out);
    
    for (int bit_pos = 7; bit_pos >= 0; --bit_pos) {
        int bit = (*in >> bit_pos) & 1;
        int64_t r = dist(rng);
        while (gcd(r, keys.n) != 1) {
            r = dist(rng);
        }
        out_ptr[7 - bit_pos] = encrypt_bit(bit, r, keys.n, keys.y);
    }
}

void gm_decrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* key) {
    GMKeys keys = buffer_to_keys(key);
    const int64_t* in_ptr = reinterpret_cast<const int64_t*>(in);
    
    uint8_t byte = 0;
    for (int i = 0; i < 8; ++i) {
        int bit = decrypt_bit(in_ptr[i], keys.p, keys.q);
        byte = (byte << 1) | bit;
    }
    *out = byte;
}

void gm_generate_iv(uint8_t* iv) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (int i = 0; i < 8; i++) {
        uint64_t val = gen();
        for (int b = 0; b < 8; b++)
            iv[i * 8 + b] = (val >> (b * 8)) & 0xFF;
    }
}