#include <stdio.h>
#include <stdint.h>
#include "cpucycles.h"
#include "parametros.h"
#include "speed_print.h"
#include <stdlib.h> // Para rand()
#include "libMLKEM-Basic.h"  

#define NTESTS 1000
uint8_t seed[32] = {0};

void imprimirChaves(const uint8_t chave[], size_t tamanho, const char* rotulo) {
    printf("\n%s: ", rotulo);
    for (size_t i = 0; i < tamanho; i++) {
        printf("%d ", chave[i]);
    }
    printf("\nTotal de bytes: %zu\n", tamanho);
}

int main(void) {
    uint64_t t[NTESTS];
    int i;
    uint8_t pk[384*KYBER_K+32];
    uint8_t sk[384*KYBER_K];
    uint8_t ct[32*(KYBER_DU*KYBER_K+KYBER_DV)];
    uint8_t K[32];
    uint8_t msg[32];
    uint8_t r[32];
    uint16_t vetor[256];
    uint16_t matriz[KYBER_K][KYBER_K][KYBER_N];
    chavesKEM chavesKEM;
    chavesPKE chavesPKE;
    encaps resultadosEncaps;    
    uint16_t tamanhoChaveEncaps = 384 * KYBER_K + 32;
   

// Inicialização do vetor com valores aleatórios
for (int j = 0; j < 256; j++) {
    vetor[j] = rand() % KYBER_Q; 
}

/*
    // Teste para Geração da matriz A
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        geraMatrizA(matriz);
    }
    print_results("Geração da Matriz A: ", t, NTESTS);

*/
   

    // Teste para Geração de Chaves PKE
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        chavesPKE = pkeKeyGen();        
    }
    print_results("Geração de Chaves: ", t, NTESTS);

    // Teste para Encritação
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        pkeEncrypt(chavesPKE.ek,msg,r,ct);
    }
    print_results("Encriptação: ", t, NTESTS);

    // Teste para Decriptação
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        pkeDecrypt(chavesPKE.dk,ct,msg);
    }
    print_results("Decriptação: ", t, NTESTS);


    // Teste para Geração de Chaves KEM
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        chavesKEM = mlKemKeyGen();  

    }
    print_results("Geração de Chaves KEM: ", t, NTESTS);

    // Teste para Encapsulamento
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        mlKemEncaps(chavesKEM.ek, tamanhoChaveEncaps);             
    }
    print_results("Encapsulamento: ", t, NTESTS);

    // Teste para Dsencapsulamento
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        mlKemDecaps(resultadosEncaps.c,chavesKEM.dk,resultadosEncaps.K);
    }
    print_results("Desencapsulamento: ", t, NTESTS);

     // Teste para NTT
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        ntt(vetor);
    }
    print_results("NTT: ", t, NTESTS);

    // Teste para INTT
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        invntt(vetor);
    }
    print_results("INV_NTT: ", t, NTESTS);


    return 0;
}