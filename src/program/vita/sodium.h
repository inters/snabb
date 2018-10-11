/* Use of this source code is governed by the GNU AGPL license; see COPYING. */

/* Bindings for libsodium @ 1.0.15 */

// core.h
int sodium_init(void);

// randombytes.h:
void randombytes_buf(void * const buf, const size_t size);

// utils.h
int sodium_memcmp(const void * const b1_, const void * const b2_, size_t len);

// crypto_hash_sha512.h
struct crypto_hash_sha512_state {
  uint64_t state[8];
  uint64_t count[2];
  uint8_t  buf[128];
};

// crypto_auth_hmacsha512256.h
enum {
  crypto_auth_hmacsha512256_BYTES = 32U,
  crypto_auth_hmacsha512256_KEYBYTES = 32U
};
struct crypto_auth_hmacsha512256_state {
  struct crypto_hash_sha512_state ictx;
  struct crypto_hash_sha512_state octx;
};
int crypto_auth_hmacsha512256_init(struct crypto_auth_hmacsha512256_state *state,
                                   const unsigned char *key,
                                   size_t keylen);
int crypto_auth_hmacsha512256_update(struct crypto_auth_hmacsha512256_state *state,
                                     const unsigned char *in,
                                     unsigned long long inlen);
int crypto_auth_hmacsha512256_final(struct crypto_auth_hmacsha512256_state *state,
                                    unsigned char *out);

// crypto_scalarmult_curve25519.h
enum {
  crypto_scalarmult_curve25519_BYTES = 32U,
  crypto_scalarmult_curve25519_SCALARBYTES = 32U
};
int crypto_scalarmult_curve25519_base(unsigned char *q,
                                      const unsigned char *n);
int crypto_scalarmult_curve25519(unsigned char *q,
                                 const unsigned char *n,
                                 const unsigned char *p);

// crypto_generichash_blake2b.h
enum {
  crypto_generichash_blake2b_BYTES_MIN = 16U,
  crypto_generichash_blake2b_BYTES_MAX = 64U
};
struct crypto_generichash_blake2b_state {
  uint64_t h[8];
  uint64_t t[2];
  uint64_t f[2];
  uint8_t  buf[2 * 128];
  size_t   buflen;
  uint8_t  last_node;
} __attribute__ ((aligned(64)));
int crypto_generichash_blake2b_init(struct crypto_generichash_blake2b_state *state,
                                    const unsigned char *key,
                                    const size_t keylen, const size_t outlen);
int crypto_generichash_blake2b_update(struct crypto_generichash_blake2b_state *state,
                                      const unsigned char *in,
                                      unsigned long long inlen);
int crypto_generichash_blake2b_final(struct crypto_generichash_blake2b_state *state,
                                     unsigned char *out,
                                     const size_t outlen);
