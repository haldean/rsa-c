#include "rsa.h"
#include "rsa_internal.h"
#include <time.h>

#define PQ_PRIME_SIZE_BITS 512

gmp_randstate_t state;

void rsac_init_randstate() {
  gmp_randinit_default(state);
  gmp_randseed_ui(state, time(NULL));
}

void rsac_random_prime(unsigned int bit_size, mpz_t x) {
  mpz_urandomb(x, state, bit_size);
  mpz_nextprime(x, x);
}

void rsac_public_exponent(mpz_t e) {
  // chosen by fair dice roll.
  // guaranteed to be random.
  mpz_set_ui(e, 65537);
}

// let x = a^-1 mod b
void rsac_inverse_modulo(mpz_t a, mpz_t b, mpz_t x) {
  mpz_invert(x, a, b);
}

int rsac_keygen_internal(mpz_t n, mpz_t e, mpz_t d, mpz_t p, mpz_t q) {
  // t1 and t2 are temp variables
  mpz_t phi, t1, t2;
  mpz_inits(t1, t2, phi, NULL);

  mpz_set_ui(d, 0);
  rsac_public_exponent(e);

  int rounds;
  for (rounds = 0; mpz_cmp_ui(d, 0) == 0 && rounds < 100; rounds++) {
    rsac_init_randstate();
    rsac_random_prime(PQ_PRIME_SIZE_BITS, p);
    rsac_random_prime(PQ_PRIME_SIZE_BITS, q);

    // the public modulus n := p * q
    mpz_mul(n, p, q);

    // phi := (p - 1)(q - 1). Phi is the number of integers less than n that are
    // relatively prime to n.
    mpz_sub_ui(t1, p, 1);
    mpz_sub_ui(t2, q, 1);
    mpz_mul(phi, t1, t2);

    rsac_inverse_modulo(e, phi, d);
  }
  mpz_clears(t1, t2, phi, NULL);

  if (rounds == 100) {
    return -1;
  }
  return 0;
}

int rsac_keygen(public_key *pub, private_key *priv) {
  mpz_t n, e, d, p, q;
  mpz_inits(n, e, d, p, q, NULL);

  int success = rsac_keygen_internal(n, e, d, p, q);
  if (success != 0) return success;

  mpz_init_set(pub->n, n);
  mpz_init_set(pub->e, e);
  mpz_init_set(priv->n, n);
  mpz_init_set(priv->d, d);

  mpz_clears(n, e, d, p, q, NULL);
  return 0;
}

void rsac_encrypt_internal(public_key *pub, mpz_t m, mpz_t c) {
  mpz_powm(c, m, pub->e, pub->n);
}

void rsac_decrypt_internal(private_key *priv, mpz_t c, mpz_t m) {
  mpz_powm(m, c, priv->d, priv->n);
}

void rsac_encrypt(
    public_key *pub,
    const char *m, size_t m_len,
    char **c, size_t *c_len) {
  mpz_t m_int, c_int;
  mpz_inits(m_int, c_int, NULL);
  mpz_import(
      m_int, m_len, /* MS word first */ 1, /* bytes per word */ 1,
      /* big-endian */ 1, /* skip bits */ 0, m);
  rsac_encrypt_internal(pub, m_int, c_int);
  *c = mpz_export(NULL, c_len, 1, 1, 1, 0, c_int);
  mpz_clears(m_int, c_int, NULL);
}

void rsac_decrypt(
    private_key *priv,
    const char *c, size_t c_len,
    char **m, size_t *m_len) {
  mpz_t m_int, c_int;
  mpz_inits(m_int, c_int, NULL);
  mpz_import(
      c_int, c_len, /* MS word first */ 1, /* bytes per word */ 1,
      /* big-endian */ 1, /* skip bits */ 0, c);
  rsac_decrypt_internal(priv, c_int, m_int);
  *m = mpz_export(NULL, m_len, 1, 1, 1, 0, m_int);
  mpz_clears(m_int, c_int, NULL);
}
