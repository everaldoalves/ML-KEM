#ifndef SYMMETRICX2_H
#define SYMMETRICX2_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#include "fips202x2.h"

typedef keccakx2_state xofx2_state;

/* Absorção de dados em paralelo para duas instâncias */
#define shake128x2_absorb KYBER_NAMESPACE(shake128x2_absorb)
void  shake128x2_absorb(keccakx2_state *state,
                       const uint8_t *in0,
                       const uint8_t *in1,
                       size_t inlen);

/* PRF com SHAKE256 em paralelo para duas instâncias */
#define shake256x2_prf KYBER_NAMESPACE(shake256x2_prf)
void shake256x2_prf(uint8_t *out1, uint8_t *out2,
                          size_t outlen, 
                          const uint8_t key[KYBER_SYMBYTES], 
                          uint8_t nonce1, uint8_t nonce2);

/* RKPRF com SHAKE256 em paralelo para duas instâncias */
#define shake256x2_rkprf KYBER_NAMESPACE(shake256x2_rkprf)
void shake256x2_rkprf(uint8_t out1[KYBER_SSBYTES], uint8_t out2[KYBER_SSBYTES], 
                            const uint8_t key[KYBER_SYMBYTES], 
                            const uint8_t input1[KYBER_CIPHERTEXTBYTES], 
                            const uint8_t input2[KYBER_CIPHERTEXTBYTES]);

/* Definições paralelas para XOF e hash */
#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h_x2(OUT1, OUT2, IN1, IN2, INBYTES) \
    sha3_256x2(OUT1, OUT2, IN1, IN2, INBYTES)

#define hash_g_x2(OUT1, OUT2, IN1, IN2, INBYTES) \
    sha3_512x2(OUT1, OUT2, IN1, IN2, INBYTES)

/* Absorção de XOF para duas instâncias paralelas */
#define xof_absorbx2(STATE, SEED, X1, Y1, X2, Y2) \
    shake128x2_absorb(STATE, SEED, X1, Y1, X2, Y2)

/* Squeezing de blocos em paralelo para duas instâncias */
#define xof_squeezeblocksx2(OUT1, OUT2, OUTBLOCKS, STATE) \
    shake128x2_squeezeblocks(OUT1, OUT2, OUTBLOCKS, STATE)

/* PRF em paralelo para duas instâncias */
#define prfx2(OUT1, OUT2, OUTBYTES, KEY, NONCE1, NONCE2) \
    shake256x2_prf(OUT1, OUT2, OUTBYTES, KEY, NONCE1, NONCE2)

/* RKPRF em paralelo para duas instâncias */
#define rkprfx2(OUT1, OUT2, KEY, INPUT1, INPUT2) \
    shake256x2_rkprf(OUT1, OUT2, KEY, INPUT1, INPUT2)


void kyber_shake128x2_absorb(keccakx2_state *state,
                             const uint8_t seed[KYBER_SYMBYTES],
                             uint8_t x1, uint8_t y1,
                             uint8_t x2, uint8_t y2);

void kyber_shake256x2_prf(uint8_t *out1, uint8_t *out2, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce1, uint8_t nonce2);

void kyber_shake256x2_rkprf(uint8_t out1[KYBER_SSBYTES], uint8_t out2[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input1[KYBER_CIPHERTEXTBYTES], const uint8_t input2[KYBER_CIPHERTEXTBYTES]);

#endif /* SYMMETRICX2_H */
