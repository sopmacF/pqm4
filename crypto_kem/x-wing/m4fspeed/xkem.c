#include "api.h"
#include "kyber.h"
#include "indcpa.h"
#include "params.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"

#include "x25519-cortex-m4.h"

#include <stdlib.h>

#include <stdlib.h>

#include <string.h>

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {   
    kyber_kem_keypair(pk, sk);

    uint8_t x25519_pk[X25519_PUBLICKEYBYTES];
    uint8_t x25519_sk[X25519_SECRETKEYBYTES];

    randombytes(x25519_sk, X25519_SECRETKEYBYTES);

    X25519_calc_public_key(x25519_pk, x25519_sk);

    memcpy(sk + KYBER_SECRETKEYBYTES, x25519_sk, X25519_SECRETKEYBYTES);
    memcpy(sk + KYBER_SECRETKEYBYTES + X25519_SECRETKEYBYTES, x25519_pk, X25519_PUBLICKEYBYTES);

    memcpy(pk + KYBER_PUBLICKEYBYTES, x25519_pk, X25519_PUBLICKEYBYTES);

    return 0;
}


/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)5c2e2f2f5e5c
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
        uint8_t *ss,
        const uint8_t *pk) {
    
    kyber_kem_enc(ct, ss, pk);

    // calculate c2 and k2 see Figure 12 from https://eprint.iacr.org/2024/039.pdf
    uint8_t x25519_sk_e[X25519_SECRETKEYBYTES];
    uint8_t k2[X25519_PUBLICKEYBYTES];
    uint8_t c2[X25519_PUBLICKEYBYTES];
    randombytes(x25519_sk_e, X25519_SECRETKEYBYTES);
    X25519_calc_public_key(c2, x25519_sk_e);
    X25519_calc_shared_secret(k2, x25519_sk_e, pk + KYBER_PUBLICKEYBYTES);

    // concat everything
    uint8_t s[XWING_SBYTES] = {0x5C,0x2E,0x2F,0x2F,0x5E,0x5C};
    memcpy(s + XWING_LABELBYTES, ss, KYBER_SSBYTES);
    memcpy(s + XWING_LABELBYTES + KYBER_SSBYTES, k2, X25519_PUBLICKEYBYTES);
    memcpy(s + XWING_LABELBYTES + KYBER_SSBYTES + X25519_PUBLICKEYBYTES, c2, X25519_PUBLICKEYBYTES);
    memcpy(s + XWING_LABELBYTES + KYBER_SSBYTES + X25519_PUBLICKEYBYTES + X25519_PUBLICKEYBYTES, pk + KYBER_PUBLICKEYBYTES, X25519_PUBLICKEYBYTES);

    uint8_t k[XWING_SSBYTES];
    hash_h(k, s, XWING_SBYTES);

    memcpy(ct + KYBER_CIPHERTEXTBYTES, c2, X25519_PUBLICKEYBYTES);
    memcpy(ss, k, XWING_SSBYTES);

    return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *ct: pointer to input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - const unsigned char *sk: pointer to input private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {

    kyber_kem_dec(ss, ct, sk);

    uint8_t k2[X25519_PUBLICKEYBYTES];
    X25519_calc_shared_secret(k2, sk + KYBER_SECRETKEYBYTES, ct + KYBER_CIPHERTEXTBYTES);

    // concat everything
    uint8_t s[XWING_SBYTES] = {0x5C,0x2E,0x2F,0x2F,0x5E,0x5C};
    memcpy(s + XWING_LABELBYTES, ss, KYBER_SSBYTES);
    memcpy(s + XWING_LABELBYTES + KYBER_SSBYTES, k2, X25519_PUBLICKEYBYTES);
    memcpy(s + XWING_LABELBYTES + KYBER_SSBYTES + X25519_PUBLICKEYBYTES, ct + KYBER_CIPHERTEXTBYTES, X25519_PUBLICKEYBYTES);
    memcpy(s + XWING_LABELBYTES + KYBER_SSBYTES + X25519_PUBLICKEYBYTES + X25519_PUBLICKEYBYTES, sk + KYBER_SECRETKEYBYTES + X25519_SECRETKEYBYTES, X25519_PUBLICKEYBYTES);

    uint8_t k[XWING_SSBYTES];
    hash_h(k, s, XWING_SBYTES);

    memcpy(ss, k, XWING_SSBYTES);    

    return 0;
}
