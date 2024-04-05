#include <stdio.h>
#include <stdlib.h>
#include "amostragem.h"
#include "auxiliares.h"
#include "ntt.h"
#include "parametros.h"
#include "pkeKeyGen.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

/***********************************************************************
Testa a implementação do Algoritmo 12 - KeyGen() -  ML-KEM FIPS 203 ipd
Generates an encryption key and a corresponding decryption key.
Output: encryption key ekPKE ∈ B^384k+32.
Output: decryption key dkPKE ∈ B^384k. 
***********************************************************************/



void imprimirChaves(const uint8_t chave[], size_t tamanho, const char* rotulo) {
    printf("\n%s: ", rotulo);
    for (size_t i = 0; i < tamanho; i++) {
        printf("%d ", chave[i]);
    }
    printf("\nTotal de bytes: %zu\n", tamanho);
}


int main() {

    chavesPKE chavesCriptograficas;
    chavesCriptograficas = pkeKeyGen();
    imprimirChaves(chavesCriptograficas.ek, 384 * KYBER_K + 32, "Chave de Encriptação");
    imprimirChaves(chavesCriptograficas.dk, 384 * KYBER_K, "Chave de Decriptação"); 
    
}