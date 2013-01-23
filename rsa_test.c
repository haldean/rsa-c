#include "rsa.h"
#include "rsa_internal.h"
#include <time.h>
#include "stdlib.h"
#include "string.h"

int test_rsac_inverse_modulo() {
  int fail = 0;
  mpz_t a, b, c;

  mpz_init_set_ui(a, 3);
  mpz_init_set_ui(b, 11);
  mpz_init(c);
  rsac_inverse_modulo(a, b, c);
  if (mpz_cmp_ui(c, 4) != 0) {
    printf("FAIL: rsac_inverse_modulo expected 4, got ");
    mpz_out_str(NULL, 10, c);
    printf("\n");
    fail++;
  } else {
    printf("PASS: rsac_inverse_modulo\n");
  }
  mpz_clears(a, b, c, NULL);
  return fail;
}

int test_rsac_random_prime() {
  int fail = 0;
  mpz_t a;
  mpz_init(a);

  rsac_init_randstate();
  for (int i = 1; i < 100; i += 10) {
    rsac_random_prime(i, a);
    if (!mpz_probab_prime_p(a, 25)) {
      printf("FAIL: rsac_random_prime returned composite number for bit size %d\n", i);
      fail++;
      break;
    }
    size_t size = mpz_sizeinbase(a, 2);
    if (size > i + 1) {
      printf("FAIL: rsac_random_prime returned %lu bits, expected %d\n", size, i);
      fail++;
      break;
    }
  }
  mpz_clear(a);

  if (fail == 0) {
    printf("PASS: rsac_random_prime\n");
  }
  return fail;
}

int check_keygen_result(mpz_t e, mpz_t d, mpz_t p, mpz_t q) {
  int fail = 0;
  mpz_t t1, t2, phi;
  mpz_inits(t1, t2, phi, NULL);

  mpz_sub_ui(t1, p, 1);
  mpz_sub_ui(t2, q, 1);
  mpz_mul(phi, t1, t2);

  // Check that ed = 1 (mod phi)
  mpz_mul(t1, e, d);
  mpz_tdiv_r(t2, t1, phi);

  if (mpz_cmp_si(t2, 1)) {
    printf("FAIL: rsac_keygen_internal output should satisfy de = 1 (mod phi) but de %% phi was ");
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
    fail++;
  }
  mpz_clears(t1, t2, phi, NULL);
  return fail;
}

int test_rsac_keygen_internal() {
  mpz_t n, e, d, p, q;
  mpz_inits(n, e, d, p, q, NULL);
  int fail = 0;

  for (int i = 0; i < 100; i++) {
    rsac_keygen_internal(n, e, d, p, q);
    if (check_keygen_result(e, d, p, q) != 0) {
      fail++;
      break;
    }
  }

  mpz_clears(n, e, d, p, q, NULL);

  if (fail == 0) {
    printf("PASS: rsac_keygen_internal\n");
  }
  return fail;
}

int test_rsac_keygen() {
  int fail = 0;
  public_key* pub = calloc(sizeof(public_key), 1);
  private_key* priv = calloc(sizeof(private_key), 1);
  if (pub == NULL || priv == NULL) {
    printf("FAIL: rsac_keygen could not allocate public or private key struct\n");
    return 1;
  }

  int res = rsac_keygen(pub, priv);
  if (res != 0) {
    printf("FAIL: rsac_keygen returned %d, expected 0\n", res);
    fail++;
  }

  // Just test for sane values; test_rsac_keygen_internal does most of the
  // real testing.
  if (mpz_cmp(pub->n, priv->n) != 0) {
    printf("FAIL: rsac_keygen public and private keys have different moduli\n");
    fail++;
  }
  if (mpz_cmp_ui(pub->n, 0) == 0) {
    printf("FAIL: rsac_keygen modulus is zero\n");
    fail++;
  }
  if (mpz_cmp_ui(pub->e, 0) == 0) {
    printf("FAIL: rsac_keygen public exponent is zero\n");
    fail++;
  }
  if (mpz_cmp_ui(priv->d, 0) == 0) {
    printf("FAIL: rsac_keygen private exponent is zero\n");
    fail++;
  }

  mpz_clears(pub->n, pub->e, priv->n, priv->d, NULL);
  free(pub);
  free(priv);

  if (fail == 0) {
    printf("PASS: rsac_keygen\n");
  }
  return fail;
}

int test_rsac_encrypt_decrypt_inverses() {
  int fail = 0;
  public_key* pub = calloc(sizeof(public_key), 1);
  private_key* priv = calloc(sizeof(private_key), 1);
  if (pub == NULL || priv == NULL) {
    printf("FAIL: rsac_encrypt_decrypt_inverse could not allocate public or private key struct\n");
    return 1;
  }

  int res = rsac_keygen(pub, priv);
  if (res != 0) {
    printf("FAIL: rsac_encrypt_decrypt_inverse rsac_keygen returned %d, expected 0\n", res);
    fail++;
  }

  // Generate 100 random integer messages, and ensure that
  // decrypt(encrypt(M)) == M for each.
  mpz_t m, m_cycled, c;
  mpz_inits(m, m_cycled, c, NULL);
  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, time(NULL));
  for (int i = 1; i < 100; i++) {
    mpz_urandomb(m, state, 20);
    rsac_encrypt_internal(pub, m, c);
    rsac_decrypt_internal(priv, c, m_cycled);
    if (mpz_cmp(m, m_cycled) != 0) {
      printf("FAIL: rsac_encrypt_decrypt_inverse the message was different after encrypting and decrypting");
      printf("\noriginal message M:        ");
      mpz_out_str(NULL, 10, m);
      printf("\nmessage after dec(enc(M)): ");
      mpz_out_str(NULL, 10, m_cycled);
      fail++;
      break;
    }
  }

  mpz_clears(m, m_cycled, c, pub->n, pub->e, priv->n, priv->d, NULL);
  free(pub);
  free(priv);

  if (fail == 0) {
    printf("PASS: rsac_encrypt_decrypt_inverse\n");
  }
  return fail;
}

int test_rsac_string_encrypt_decrypt() {
  char m[] = "stop slacking off.";
  size_t c_len, m_len = strlen(m), result_len;
  char **c = calloc(sizeof(char *), 1);
  char **m_result = calloc(sizeof(char *), 1);
  int fail = 0;
  public_key* pub = calloc(sizeof(public_key), 1);
  private_key* priv = calloc(sizeof(private_key), 1);

  if (pub == NULL || priv == NULL) {
    printf("FAIL: rsac_string_encrypt_decrypt could not allocate public or private key struct\n");
    return 1;
  }

  int res = rsac_keygen(pub, priv);
  if (res != 0) {
    printf("FAIL: rsac_string_encrypt_decrypt rsac_keygen returned %d, expected 0\n", res);
    fail++;
  }

  rsac_encrypt(pub, m, m_len, c, &c_len);
  rsac_decrypt(priv, *c, c_len, m_result, &result_len);
  if (strlen(*m_result) != m_len || strncmp(m, *m_result, m_len) != 0) {
    printf("FAIL: rsac_string_encrypt_decrypt message did not match after encryption and decryption.\n");
    printf("expected '%s' but got '%s'\n", m, *m_result);
    fail++;
  }

  free(pub);
  free(priv);
  free(*c);
  free(*m_result);
  if (fail == 0) {
    printf("PASS: rsac_string_encrypt_decrypt\n");
  }
  return fail;
}

int main() {
  int failures = 0;

  failures += test_rsac_inverse_modulo();
  failures += test_rsac_random_prime();
  failures += test_rsac_keygen_internal();
  failures += test_rsac_keygen();
  failures += test_rsac_encrypt_decrypt_inverses();
  failures += test_rsac_string_encrypt_decrypt();

  printf("%d failures\n", failures);
  return failures > 0;
}
