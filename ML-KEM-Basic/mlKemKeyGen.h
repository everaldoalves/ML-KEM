#include <stdint.h>
#include "parametros.h"

#ifndef MLKEMKEYGEN_H
#define MLKEMKEYGEN_H

// Define a estrutura para armazenar um par de chaves
typedef struct {
    uint8_t ek[384 * KYBER_K + 32];
    uint8_t dk[768 * KYBER_K + 96]; // z[32]+h[32]
} chavesKEM;

// Gera as chaves ek e dk
chavesKEM mlKemKeyGen();

#endif