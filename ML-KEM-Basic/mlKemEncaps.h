#include <stdint.h>
#include "parametros.h"

/*******************************************************************************
Algorithm 16 ML-KEM.Encaps(ek)
Uses the encapsulation key to generate a shared key and an associated ciphertext.
Validated input: encapsulation key ek ∈ B384k+32.
Output: shared key K ∈ B32.
Output: ciphertext c ∈ B32(duk+dv)
********************************************************************************/

#ifndef MLKEMENCAPS_H
#define MLKEMENCAPS_H

// Define a estrutura para armazenar K, c
typedef struct {
    uint8_t K[32];
    uint8_t c[32 * (KYBER_DU * KYBER_K + KYBER_DV)]; 
} encaps;

// Função para verificar o tamanho da chave de encapsulamento
int isValidEncapsSize(const uint8_t* ek, size_t size);

// Gera as chaves ek e dk
encaps mlKemEncaps(uint8_t encapsKey[384*KYBER_K+32]);

#endif