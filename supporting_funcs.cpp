#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <ctime>
#include <sstream>


int64_t mod_pow(int64_t base, int64_t power, int64_t modulo) {
    base %= modulo;
    int64_t result = 1;
    for (int64_t i = 0; i < power; ++i) {
        result *= base;
        result %= modulo;}
    return result;}


int64_t mod_inverse(int64_t a, int64_t m) {
    int64_t u0 = 0, u1 = 1, m0 = m;
    int64_t q, current;
    while (a != 0) {
        q = m / a;
        current = a;
        a = m % a;
        m = current;
        
        current = u1;
        u1 = u0 - q * u1;
        u0 = current;}
    if (u0 < 0) {return u0 + m0;}
    return u0;}


int64_t gcd(int64_t a, int64_t b) {
    while (b) {
        int64_t t = b;
        b = a % b;
        a = t;}
    return a;}


bool is_prime(int64_t n) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    for (int64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return false;}
    return true;}


int64_t random_prime(int64_t min_val, int64_t max_val, std::mt19937_64& rng) {
    std::uniform_int_distribution<int64_t> dist(min_val, max_val);
    int64_t candidate;
    do {candidate = dist(rng);} while (!is_prime(candidate));
    return candidate;}