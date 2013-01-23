#include "rsa.h"

int test_rsac_inverse_modulo() {
  mpz_t a, b, c;

  // Test rsac_inverse_modulo
  mpz_init_set_ui(a, 3);
  mpz_init_set_ui(b, 11);
  mpz_init(c);
  rsac_inverse_modulo(a, b, c);
  if (mpz_cmp_ui(c, 4) != 0) {
    printf("FAIL: rsac_inverse_modulo expected 4, got ");
    mpz_out_str(NULL, 10, c);
    printf("\n");
    return 1;
  } else {
    printf("PASS: rsac_inverse_modulo\n");
  }

  return 0;
}

int test_rsac_random_prime() {
  mpz_t a;
  mpz_init(a);

  rsac_init_randstate();
  for (int i = 1; i < 100; i += 10) {
    rsac_random_prime(i, a);
    if (!mpz_probab_prime_p(a, 25)) {
      printf("FAIL: rsac_random_prime returned composite number for bit size %d\n", i);
      return 1;
    }
    size_t size = mpz_sizeinbase(a, 2);
    if (size > i + 1) {
      printf("FAIL: rsac_random_prime returned %lu bits, expected %d\n", size, i);
      return 1;
    }
  }

  printf("PASS: rsac_random_prime\n");
  return 0;
}

int test_rsac_keygen() {
  mpz_t n, e, d, p, q, t1, t2, phi;
  mpz_inits(n, e, d, p, q, t1, t2, phi, NULL);

  for (int i = 0; i < 100; i++) {
    rsac_keygen(n, e, d, p, q);

    mpz_sub_ui(t1, p, 1);
    mpz_sub_ui(t2, q, 1);
    mpz_mul(phi, t1, t2);

    // Check that ed = 1 (mod phi)
    mpz_mul(t1, e, d);
    mpz_tdiv_r(t2, t1, phi);

    if (mpz_cmp_si(t2, 1)) {
      printf("FAIL: rsac_keygen output should satisfy de = 1 (mod phi) but de %% phi was ");
      mpz_out_str(NULL, 10, t2);
      printf("\n d:   ");
      mpz_out_str(NULL, 10, d);
      printf("\n e:   ");
      mpz_out_str(NULL, 10, e);
      printf("\n phi: ");
      mpz_out_str(NULL, 10, phi);
      printf("\n p:   ");
      mpz_out_str(NULL, 10, p);
      printf("\n q:   ");
      mpz_out_str(NULL, 10, q);
      printf("\n");
      return 1;
    }
  }

  mpz_clears(n, e, d, p, q, phi, t1, t2, NULL);

  printf("PASS: rsac_keygen\n");
  return 0;
}

int main() {
  int failures = 0;

  failures += test_rsac_inverse_modulo();
  failures += test_rsac_random_prime();
  failures += test_rsac_keygen();

  printf("%d failures\n", failures);
  return failures > 0;
}
