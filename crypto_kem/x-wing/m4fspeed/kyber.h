#ifndef KYBER_H
#define KYBER_H

#include "params.h"

// #define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
// #define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
// #define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
// #define CRYPTO_BYTES           KYBER_SSBYTES

int kyber_kem_keypair(unsigned char *pk, unsigned char *sk);

int kyber_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int kyber_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

// int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

// int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
