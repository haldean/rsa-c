#include "rsa.h"
#include <time.h>

#define PQ_PRIME_SIZE_BITS 512

gmp_randstate_t state;

void rsac_init_randstate() {
  gmp_randinit_default(state);
  gmp_randseed_ui(state, time(NULL));
}

void rsac_random_prime(unsigned int bit_size, mpz_t* x) {
  mpz_init(*x);
  mpz_urandomb(*x, state, bit_size);
}

void rsac_public_exponent(mpz_t* e) {
  mpz_init_set_ui(*e, 1 << 16 + 1);
}

void rsac_inverse_modulo(mpz_t a, mpz_t b, mpz_t x) {
  // q, r, s, t are temporary variables; q and r are used for quotient and
  // remainder, and s is used for swapping.
  mpz_t y, lastx, lasty, q, r, s, t;

  mpz_set_ui(x, 0);
  mpz_init_set_si(lastx, 1);
  mpz_init_set_si(y, 1);
  mpz_init_set_si(lasty, 0);
  mpz_init(q);
  mpz_init(r);
  mpz_init(s);
  mpz_init(t);

  while (mpz_cmp_ui(a, 0)) {
    // q = floor(b / a), r = b mod a
    mpz_fdiv_qr(q, r, b, a);
    mpz_set(b, a);
    mpz_set(a, r);

    // x, lastx = lastx - q * x, x
    mpz_set(s, x);
    mpz_mul(t, q, x);
    mpz_sub(x, lastx, t);
    mpz_set(lastx, s);

    // y, lasty = lasty - q * y, y
    mpz_set(s, y);
    mpz_mul(t, q, y);
    mpz_sub(y, lasty, t);
    mpz_set(lasty, s);
  }
}

void rsac_generate_keys(mpz_t* n, mpz_t* e, mpz_t* d) {
  // t1 and t2 are temp variables
  mpz_t p, q, phi, t1, t2;

  rsac_init_randstate();
  rsac_random_prime(PQ_PRIME_SIZE_BITS, &p);
  rsac_random_prime(PQ_PRIME_SIZE_BITS, &q);

  // the public modulus n := p * q
  mpz_mul(*n, p, q);

  // phi := (p - 1)(q - 1). Phi is the number of integers less than n that are
  // relatively prime to n.
  mpz_sub_ui(t1, p, 1);
  mpz_sub_ui(t2, q, 1);
  mpz_mul(phi, t1, t2);

  rsac_public_exponent(e);
  rsac_inverse_modulo(*e, phi, *d);
}
