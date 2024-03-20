#ifndef API_H
#define API_H

#include "params.h"

#define CRYPTO_SECRETKEYBYTES  XWING_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  XWING_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES XWING_CIPHERTEXTBYTES
#define CRYPTO_BYTES           XWING_SSBYTES

#define CRYPTO_ALGNAME "x-wing"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
