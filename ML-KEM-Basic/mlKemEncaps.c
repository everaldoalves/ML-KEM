
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include "auxiliares.h"
#include "parametros.h"
#include "pkeEncrypt.h"
#include "mlKemEncaps.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

/*******************************************************************************
Algorithm 16 ML-KEM.Encaps(ek)
Uses the encapsulation key to generate a shared key and an associated ciphertext.
Validated input: encapsulation key ek ∈ B384k+32.
Output: shared key K ∈ B32.
Output: ciphertext c ∈ B32(duk+dv)
********************************************************************************/

// Função para verificar o tamanho da chave de encapsulamento
int isValidEncapsSize(const uint8_t* ek, size_t size) {
    return (size == ENCAPS_SIZE);
}

encaps mlKemEncaps(uint8_t encapsKey[384*KYBER_K+32]) {
    // Verifica se o tamanho da chave de encapsulamento é válido
    if (!isValidEncapsSize(encapsKey, ENCAPS_SIZE)) {
        fprintf(stderr, "Erro: Tamanho da chave de encapsulamento inválido.\n");
        exit(EXIT_FAILURE);
    }

    uint8_t m[32] = {0};
    generateRandomBytes(m,32);

    encaps kemEncaps = {0};
    uint8_t r[32] = {0};
    uint8_t mHek[64];
    uint8_t output[32];

    // (K,r) ← G(m∥H(ek)) ▷ derive shared secret key K and randomness r
    H(encapsKey,384*KYBER_K+32,output);
    memcpy(mHek,m,32);
    memcpy(mHek + 32, output,32);
    G(mHek,64,kemEncaps.K,r);

    // c ← K-PKE.Encrypt(ek,m,r) ▷ encrypt m using K-PKE with randomness r
    pkeEncrypt(encapsKey,m,r,kemEncaps.c);
    
    //return (K, c)
    return(kemEncaps);
}