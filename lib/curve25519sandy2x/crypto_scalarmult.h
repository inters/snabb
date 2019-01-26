#define crypto_scalarmult_base crypto_scalarmult_base_curve25519
#define crypto_scalarmult crypto_scalarmult_curve25519

int crypto_scalarmult_base(unsigned char *q,const unsigned char *n);

int crypto_scalarmult(unsigned char *q,
  const unsigned char *n,
  const unsigned char *p);
