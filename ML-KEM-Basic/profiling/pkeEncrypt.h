#include "parametros.h"
#include <stdint.h>

#ifndef PKEENCRYPT_H
#define PKEENCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

void decompressMu(const uint8_t *m, uint16_t mu[KYBER_N]);

void compressAndEncode(const uint16_t u[KYBER_K][KYBER_N], const uint16_t v[KYBER_N], uint8_t c1[], uint8_t c2[]);

void calculaU(uint16_t A[KYBER_K][KYBER_K][KYBER_N], uint16_t r_vector[KYBER_K][KYBER_N], uint16_t e1[KYBER_K][KYBER_N], uint16_t u[KYBER_K][KYBER_N]);

void calculaV(uint16_t t_hat[KYBER_K][KYBER_N], uint16_t r_vector[KYBER_K][KYBER_N], uint16_t e2[KYBER_N], uint16_t mu[KYBER_N], uint16_t v[KYBER_N]);

void pkeEncrypt(const uint8_t *ekPKE, const uint8_t *m, const uint8_t *r, uint8_t *c);

void generateRandomVectors(const uint8_t *r, uint16_t r_vector[KYBER_K][KYBER_N], uint16_t e1[KYBER_K][KYBER_N] , uint16_t e2[KYBER_N], uint8_t N);
  
#ifdef __cplusplus
}
#endif

#endif 
