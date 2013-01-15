#include "rsa.h"

int main() {
  mpz_t a, b, c;
  int failures = 0;

  // Test rsac_inverse_modulo
  mpz_init_set_ui(a, 3);
  mpz_init_set_ui(b, 11);
  mpz_init(c);
  rsac_inverse_modulo(a, b, c);
  if (mpz_cmp_ui(c, 4) != 0) {
    printf("FAIL: rsac_inverse_modulo expected 4, got ");
    mpz_out_str(NULL, 10, c);
    printf("\n");
    ++failures;
  } else {
    printf("PASS: rsac_inverse_modulo");
  }

  printf("%d failures\n", failures);
  return failures > 0;
}
