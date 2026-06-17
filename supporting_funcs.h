#ifndef STUPID_FUNCS_H
#define STUPID_FUNCS_H
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <ctime>
#include <sstream>

int64_t mod_pow(int64_t base, int64_t exp, int64_t mod);
int64_t mod_inverse(int64_t a, int64_t m);
int64_t gcd(int64_t a, int64_t b) ;
bool is_prime(int64_t n);
int64_t random_prime(int64_t min_val, int64_t max_val, std::mt19937_64& rng);

#endif