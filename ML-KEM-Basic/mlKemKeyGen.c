#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include "amostragem.h"
#include "auxiliares.h"
#include "ntt.h"
#include "parametros.h"
#include "pkeKeyGen.h"
#include "pkeEncrypt.h"
#include "mlKemKeyGen.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

/*******************************************************************************
Algorithm 15 ML-KEM.KeyGen()
Generates an encapsulation key and a corresponding decapsulation key.
Output: Encapsulation key ek ∈ B^384k+32.
Output: Decapsulation key dk ∈ B^768k+96
********************************************************************************/


chavesKEM mlKemKeyGen() {    
    uint8_t z[32] = {0};
    generateRandomBytes(z,32);
    uint16_t tamanhoChaveEK = 384 * KYBER_K + 32;
    uint16_t tamanhoChaveDK = 384 * KYBER_K;
 
    chavesPKE chavesPKE = {0};  // ekPKE ∈ B^384k+32. dkPKE ∈ B^384k.     
    chavesPKE = pkeKeyGen();  

    chavesKEM chavesKEM = {0};
    memcpy(chavesKEM.ek + 0,chavesPKE.ek,tamanhoChaveEK);  // A chave de encapsulamento é a pke.ek

    // dk ← (dkPKE∥ek∥H(ek)∥z) ▷ A chave de desencapsulamento inclui PKE decryption key, H(ek) e z
    unsigned char h[32] = {0};

    // Copia pke.dk para kem.dk
    memcpy(chavesKEM.dk + 0,chavesPKE.dk,tamanhoChaveDK);

    // Concatena dkPKE com ek
    memcpy(chavesKEM.dk + tamanhoChaveDK, chavesKEM.ek, tamanhoChaveEK);

    // Calcula o hash de ek com SHA3-256
    H(chavesKEM.ek, tamanhoChaveEK, h); 

    // Concatena dkpke,ek com H(ek)
    memcpy(chavesKEM.dk + (tamanhoChaveDK+tamanhoChaveEK), h, 32);

    // Concatena com z
    memcpy(chavesKEM.dk + (tamanhoChaveDK + tamanhoChaveEK + 32), z, 32);

    return (chavesKEM);
}