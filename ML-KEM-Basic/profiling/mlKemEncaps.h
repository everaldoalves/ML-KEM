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

#ifdef __cplusplus
extern "C" {
#endif

// Define a estrutura para armazenar K, c
typedef struct {
    uint8_t K[32];
    uint8_t c[32 * (KYBER_DU * KYBER_K + KYBER_DV)]; 
} encaps;



// Gera as chaves ek e dk
//encaps mlKemEncaps(uint8_t encapsKey[384*KYBER_K+32]);
encaps mlKemEncaps(uint8_t* encapsKey, size_t size); 

#ifdef __cplusplus
}
#endif

#endif