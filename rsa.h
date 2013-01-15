#ifndef __HALDEAN_RSA_H__

#include <stdio.h>
#include <gmp.h>

void rsac_init_randstate();
void rsac_random_prime(unsigned int bit_size, mpz_t* x);
void rsac_public_exponent(mpz_t* e);
void rsac_inverse_modulo(mpz_t a, mpz_t b, mpz_t x);
void rsac_generate_keys(mpz_t* n, mpz_t* e, mpz_t* z);

#endif
