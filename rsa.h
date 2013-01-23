#ifndef __HALDEAN_RSA_H__

#include <stdio.h>
#include <gmp.h>

typedef struct {
  mpz_t n, e;
} public_key;

typedef struct {
  mpz_t n, d;
} private_key;

// Returns 0 if successful.
// out: pub, priv
int rsac_keygen(public_key *pub, private_key *priv);

// in: pub, m, m_len, out: c, c_len
void rsac_encrypt(
    public_key *pub,
    const char *m, size_t m_len,
    char **c, size_t *c_len);

// in: priv, c, c_len, out: m, m_len
void rsac_decrypt(
    private_key *priv,
    const char *c, size_t c_len,
    char **m, size_t *m_len);

#endif
