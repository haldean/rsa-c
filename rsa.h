#ifndef __HALDEAN_RSA_H__

#include <stdio.h>
#include <gmp.h>

// Caller is responsible for initializing all mpz arguments, including output.

void rsac_init_randstate();

// in: bit_size, out: x
void rsac_random_prime(unsigned int bit_size, mpz_t x);

// out: e
void rsac_public_exponent(mpz_t e);

// in: a, b, out: x
void rsac_inverse_modulo(mpz_t a, mpz_t b, mpz_t x);

// (n, e) is public key, (n, d) is private key. p and q are provided for testing
// out: n, e, d, p, q
void rsac_keygen(mpz_t n, mpz_t e, mpz_t d, mpz_t p, mpz_t q);

#endif
