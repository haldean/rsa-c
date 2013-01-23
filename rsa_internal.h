// Users of the rsac API shouldn't include this header; it's broken out for
// testing of internal functions only.

// Caller is responsible for initializing all mpz arguments, including output.
// Caller is not responsible for initializing struct arguments.

#ifndef __HALDEAN_RSA_INTERNAL_H__

#include <gmp.h>

void rsac_init_randstate();

// in: bit_size, out: x
void rsac_random_prime(unsigned int bit_size, mpz_t x);

// out: e
void rsac_public_exponent(mpz_t e);

// in: a, b, out: x
void rsac_inverse_modulo(mpz_t a, mpz_t b, mpz_t x);

// (n, e) is public key, (n, d) is private key. p and q are provided for
// testing. Consumers of the API should use rsac_keygen(pub, priv).
// Returns 0 if successful.
// out: n, e, d, p, q
int rsac_keygen_internal(mpz_t n, mpz_t e, mpz_t d, mpz_t p, mpz_t q);

// in: pub, m, out: c
void rsac_encrypt_internal(public_key *pub, mpz_t m, mpz_t c);

// in: priv, c, out: m
void rsac_decrypt_internal(private_key *priv, mpz_t c, mpz_t m);

#endif
