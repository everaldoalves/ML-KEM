#ifndef API_H
#define API_H

#include <stdint.h>
#include "kem.h"

// Em api.h
#define everaldo_kyber512_keypair crypto_kem_keypair
#define everaldo_kyber512_enc crypto_kem_enc
#define everaldo_kyber512_dec crypto_kem_dec

#define everaldo_kyber512_SECRETKEYBYTES 1632
#define everaldo_kyber512_PUBLICKEYBYTES 800
#define everaldo_kyber512_CIPHERTEXTBYTES 768
#define everaldo_kyber512_KEYPAIRCOINBYTES 64
#define everaldo_kyber512_ENCCOINBYTES 32
#define everaldo_kyber512_BYTES 32

#define everaldo_kyber512_SECRETKEYBYTES everaldo_kyber512_SECRETKEYBYTES
#define everaldo_kyber512_PUBLICKEYBYTES everaldo_kyber512_PUBLICKEYBYTES
#define everaldo_kyber512_CIPHERTEXTBYTES everaldo_kyber512_CIPHERTEXTBYTES
#define everaldo_kyber512_KEYPAIRCOINBYTES everaldo_kyber512_KEYPAIRCOINBYTES
#define everaldo_kyber512_ENCCOINBYTES everaldo_kyber512_ENCCOINBYTES
#define everaldo_kyber512_BYTES everaldo_kyber512_BYTES

int everaldo_kyber512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int everaldo_kyber512_keypair(uint8_t *pk, uint8_t *sk);
int everaldo_kyber512_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int everaldo_kyber512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int everaldo_kyber512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define everaldo_kyber768_SECRETKEYBYTES 2400
#define everaldo_kyber768_PUBLICKEYBYTES 1184
#define everaldo_kyber768_CIPHERTEXTBYTES 1088
#define everaldo_kyber768_KEYPAIRCOINBYTES 64
#define everaldo_kyber768_ENCCOINBYTES 32
#define everaldo_kyber768_BYTES 32

#define everaldo_kyber768_SECRETKEYBYTES everaldo_kyber768_SECRETKEYBYTES
#define everaldo_kyber768_PUBLICKEYBYTES everaldo_kyber768_PUBLICKEYBYTES
#define everaldo_kyber768_CIPHERTEXTBYTES everaldo_kyber768_CIPHERTEXTBYTES
#define everaldo_kyber768_KEYPAIRCOINBYTES everaldo_kyber768_KEYPAIRCOINBYTES
#define everaldo_kyber768_ENCCOINBYTES everaldo_kyber768_ENCCOINBYTES
#define everaldo_kyber768_BYTES everaldo_kyber768_BYTES

int everaldo_kyber768_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int everaldo_kyber768_keypair(uint8_t *pk, uint8_t *sk);
int everaldo_kyber768_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int everaldo_kyber768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int everaldo_kyber768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define everaldo_kyber1024_SECRETKEYBYTES 3168
#define everaldo_kyber1024_PUBLICKEYBYTES 1568
#define everaldo_kyber1024_CIPHERTEXTBYTES 1568
#define everaldo_kyber1024_KEYPAIRCOINBYTES 64
#define everaldo_kyber1024_ENCCOINBYTES 32
#define everaldo_kyber1024_BYTES 32

#define everaldo_kyber1024_SECRETKEYBYTES everaldo_kyber1024_SECRETKEYBYTES
#define everaldo_kyber1024_PUBLICKEYBYTES everaldo_kyber1024_PUBLICKEYBYTES
#define everaldo_kyber1024_CIPHERTEXTBYTES everaldo_kyber1024_CIPHERTEXTBYTES
#define everaldo_kyber1024_KEYPAIRCOINBYTES everaldo_kyber1024_KEYPAIRCOINBYTES
#define everaldo_kyber1024_ENCCOINBYTES everaldo_kyber1024_ENCCOINBYTES
#define everaldo_kyber1024_BYTES everaldo_kyber1024_BYTES

int everaldo_kyber1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int everaldo_kyber1024_keypair(uint8_t *pk, uint8_t *sk);
int everaldo_kyber1024_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int everaldo_kyber1024_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int everaldo_kyber1024_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
