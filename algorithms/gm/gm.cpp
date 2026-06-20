#include "gm.h"
#include <random>
#include <ctime>
#include <cstring>
#include <cstdio>

static int64_t mod_pow(int64_t base, int64_t exp, int64_t mod) {
    int64_t result = 1;
    base = base % mod;
    if (base < 0) base += mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

static int64_t gcd(int64_t a, int64_t b) {
    while (b) { int64_t t = b; b = a % b; a = t; }
    return a;
}

static bool is_prime(int64_t n) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    for (int64_t i = 3; i * i <= n; i += 2)
        if (n % i == 0) return false;
    return true;
}

static int64_t random_prime(int64_t min_val, int64_t max_val, std::mt19937_64& rng) {
    std::uniform_int_distribution<int64_t> dist(min_val, max_val);
    int64_t candidate;
    do { candidate = dist(rng); } while (!is_prime(candidate));
    return candidate;
}

static int64_t legendre(int64_t a, int64_t p) {
    a = a % p;
    if (a < 0) a += p;
    return mod_pow(a, (p - 1) / 2, p);
}

void gm_generate_keys(uint8_t* public_key, uint8_t* private_key) {
    static std::mt19937_64 rng(std::random_device{}());
    
    int64_t p, q, n, y;
    do {
        p = random_prime(100, 300, rng);
        q = random_prime(100, 300, rng);
    } while (p == q);
    n = p * q;
    
    for (y = 2; y < n; y++) {
        if (legendre(y, p) == p - 1 && legendre(y, q) == q - 1)
            break;
    }
    
    int64_t* pub = (int64_t*)public_key;
    pub[0] = n;
    pub[1] = y;
    
    int64_t* priv = (int64_t*)private_key;
    priv[0] = p;
    priv[1] = q;
}

void gm_encrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* public_key) {
    static std::mt19937_64 rng(std::random_device{}());
    
    const int64_t* pub = (const int64_t*)public_key;
    int64_t n = pub[0];
    int64_t y = pub[1];
    
    std::uniform_int_distribution<int64_t> dist(2, n - 1);
    int64_t* out_ptr = (int64_t*)out;
    uint8_t byte = *in;
    
    for (int bit_pos = 0; bit_pos < 8; bit_pos++) {
        int bit = (byte >> bit_pos) & 1;
        int64_t r;
        do { r = dist(rng); } while (gcd(r, n) != 1);
        
        int64_t r_sq = mod_pow(r, 2, n);
        out_ptr[bit_pos] = (bit == 0) ? r_sq : (y * r_sq) % n;
    }
}

void gm_decrypt_block(const uint8_t* in, uint8_t* out, const uint8_t* private_key) {
    const int64_t* priv = (const int64_t*)private_key;
    int64_t p = priv[0];
    int64_t q = priv[1];
    
    const int64_t* in_ptr = (const int64_t*)in;
    
    uint8_t byte = 0;
    for (int bit_pos = 0; bit_pos < 8; bit_pos++) {
        int64_t c = in_ptr[bit_pos];
        
        int64_t leg_p = legendre(c, p);
        int64_t leg_q = legendre(c, q);
        
        int bit = (leg_p == 1 && leg_q == 1) ? 0 : 1;
        byte |= (bit << bit_pos);
    }
    *out = byte;
}