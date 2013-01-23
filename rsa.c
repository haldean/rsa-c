#include "rsa.h"
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
  mpz_set_ui(e, 65537);
}

// let x = a^-1 mod b
void rsac_inverse_modulo(mpz_t a, mpz_t b, mpz_t x) {
  mpz_invert(x, a, b);
}

void rsac_keygen(mpz_t n, mpz_t e, mpz_t d, mpz_t p, mpz_t q) {
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

  if (rounds == 100) {
    printf("Failed to find a d/e/n combination after 100 attempts.\n");
  }

  mpz_clears(t1, t2, phi, NULL);
}
