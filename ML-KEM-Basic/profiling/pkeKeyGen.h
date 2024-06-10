#include "parametros.h"
#include <stdio.h>
#include <stdint.h>


#ifndef PKEKEYGEN_H
#define PKEKEYGEN_H

#ifdef __cplusplus
extern "C" {
#endif

// Define a estrutura para armazenar um par de chaves
typedef struct {
    uint8_t ek[384 * KYBER_K + 32];
    uint8_t dk[384 * KYBER_K];
} chavesPKE;

// Calcula t ← Aˆ ◦ sˆ + eˆ
void calculaT_hat(const uint16_t (*A)[KYBER_K][KYBER_N], const uint16_t s[KYBER_K][KYBER_N], const uint16_t e[KYBER_K][KYBER_N], uint16_t t_hat[KYBER_K][KYBER_N]);

// Gera as chaves ek e dk
chavesPKE pkeKeyGen();

#ifdef __cplusplus
}
#endif

#endif