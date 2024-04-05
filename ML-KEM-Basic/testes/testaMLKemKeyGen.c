#include <stdio.h>
#include <stdlib.h>
#include "auxiliares.h"
#include "parametros.h"
#include "mlKemKeyGen.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

/******************************************************************************
Testa a implementação do Algoritmo 15 - ML-KEM.KeyGen() -  ML-KEM FIPS 203 ipd
Generates an encapsulation key and a corresponding decapsulation key.
Output: Encapsulation key ek ∈ B^384k+32.
Output: Decapsulation key dk ∈ B^768k+96
******************************************************************************/



void imprimirChaves(const uint8_t chave[], size_t tamanho, const char* rotulo) {
    printf("\n%s: ", rotulo);
    for (size_t i = 0; i < tamanho; i++) {
        printf("%d ", chave[i]);
    }
    printf("\nTotal de bytes: %zu\n", tamanho);
}


int main() {

    chavesKEM chavesCriptograficas;
    chavesCriptograficas = mlKemKeyGen();
    imprimirChaves(chavesCriptograficas.ek, 384 * KYBER_K + 32, "Chave de Encapsulamento");
    imprimirChaves(chavesCriptograficas.dk, (768 * KYBER_K + 96), "Chave de Desencapsulamento"); 
    
}