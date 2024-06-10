#include <string.h>
#include "auxiliares.h"
#include "parametros.h"

/*******************************************************************************
Algorithm 17 ML-KEM.Decaps(c,dk)
Uses the decapsulation key to produce a shared key from a ciphertext.
Validated input: ciphertext c B32(d k ∈ u +dv)
Validated input: decapsulation key B768k+96 dk ∈ 
Output: shared key K ∈ B32 
********************************************************************************/


#ifdef __cplusplus
extern "C" {
#endif

void mlKemDecaps(const uint8_t *c, const uint8_t *dk, uint8_t *K_linha);

#ifdef __cplusplus
}
#endif