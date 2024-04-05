#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "amostragem.h"
#include "auxiliares.h"
#include "ntt.h"
#include "parametros.h"
#include "pke.h"
#include "fips202.h"
#include <openssl/sha.h>
#include <openssl/evp.h>


/*******************************************************************
TESTES PARA PKE.C
Algoritmo 12 - KeyGen() -  ML-KEM FIPS 203 ipd
Generates an encryption key and a corresponding decryption key.
Output: encryption key ekPKE ∈ B^384k+32.
Output: decryption key dkPKE ∈ B^384k. 
********************************************************************/


void calculaT_hat(const uint8_t A[KYBER_K][KYBER_K][KYBER_N], const uint8_t s[KYBER_K][KYBER_N], const uint8_t e[KYBER_K][KYBER_N], uint8_t t_hat[KYBER_K][KYBER_N]) {
    uint16_t tempResultado[KYBER_K][KYBER_N] = {{0}}; // Usa uint16_t para evitar overflow

    // Multiplicação de matrizes A ◦ s
    for (int i = 0; i < KYBER_K; ++i) {
        for (int k = 0; k < KYBER_K; ++k) {
            uint16_t tempMultiplicacao[KYBER_N] = {0};
            multiplicaNTT(A[i][k], s[k], tempMultiplicacao);

            // Adiciona tempMultiplicacao ao tempResultado[i], com redução modular
            for (int n = 0; n < KYBER_N; ++n) {
                tempResultado[i][n] = (tempResultado[i][n] + tempMultiplicacao[n]) % KYBER_Q;
            }
        }
    }

    // Adiciona e a tempResultado para obter t_hat com redução modular
    for (int i = 0; i < KYBER_K; ++i) {
        for (int n = 0; n < KYBER_N; ++n) {
            uint16_t sum = (tempResultado[i][n] + e[i][n]) % KYBER_Q;
            t_hat[i][n] = sum; // Aqui, assumimos que sum nunca excede 255, considerando KYBER_Q
        }
    }
}


int main() {
    // Inicializa o gerador de números aleatórios com uma semente diferente a cada execução
    srand(time(NULL));

    unsigned char d[32];                          // Array para armazenar os 32 bytes aleatórios  
    unsigned char rho[32], sigma[32];            // saídas de G
    unsigned char ekPKE[384 * KYBER_K + 32];    // Chave de encriptação
    unsigned char dkPKE[384 * KYBER_K];        // Chave de decriptação
    unsigned char output[64 * KYBER_ETA1];    // Bytes aleatórios para SamplePolyCBD

    uint8_t N = 0;        
    uint8_t f[KYBER_N];
    uint8_t a_hat[KYBER_N];
    uint8_t s[KYBER_K][KYBER_N];
    uint8_t e[KYBER_K][KYBER_N];
    uint8_t A[KYBER_K][KYBER_K][KYBER_N];
    uint8_t t[KYBER_K][KYBER_N]; 
    unsigned char md[EVP_MAX_MD_SIZE];   // Vetor para armazenar o resultado de SHAKE128(ρ|i|j)    

    // Gera bytes aleatórios para semente
    generateRandomBytes(d, sizeof(d));                  

    // Aplica a função G em d para obter rho e sigma
    G(d, sizeof(d), rho, sigma);
        
    // Gera os elementos da matriz A^ pertencente a (Zq256)^k*k
    for (int i=0; i < KYBER_K; i++) {     
        unsigned char i_char = (unsigned char)i;        
        for (int j=0; j < KYBER_K; j++) {              
           memset(md, 0, sizeof(md));              // Reseta o vetor md                  
           unsigned char j_char = (unsigned char)j;           
           XOF(rho, i_char, j_char, md);               
           memset(a_hat, 0, sizeof(a_hat));      // Reinicializa a_hat para garantir que seja único em cada iteração
           sampleNTT(md, a_hat);                // Preenche a_hat com os coeficientes NTT                                                     
           for (int k=0; k < KYBER_N; k++) {                         
                // Copia a_hat para a terceira dimensão da matriz A
                A[i][j][k] = a_hat[k];                                                                                           
           }          
        }    
    }

    // TESTA A GERAÇÃO DE ELEMENTOS PARA MATRIZ
    for (int i=0; i<KYBER_K; i++) {
        for (int j=0; j < KYBER_K; j++) {    
            printf("\n Matriz A^[%d][%d] : ",i,j);
            for (int k=0; k < KYBER_N; j++) {    
                printf(" ",A[i][j][k]);
            }
    }

   // Gera os elementos do vetor s
   for (int i=0; i < KYBER_K; i++)    {                      // generate s ∈ (Zq256)^k                                                                 
        for (int j=0; j<KYBER_N; j++) {
            PRF(KYBER_ETA1,sigma,N,output);      
            //printf(" \noutput",output[j]);      
            SamplePolyCBD(output, f, KYBER_ETA1);            
            s[i][j] = f[j];                                 // s[i] ∈ Zq256 sampled from CBD PRF takes a parameter η ∈ {2,3}  PRFn1
            N = N + 1;
            printf(" %d  ",s[i][j]);
        }
    }

    // Gera os elementos do vetor e
    for (int i=0; i < KYBER_K; i++)    {                      // generate e ∈ (Zq256)^k                                                                 
        for (int j=0; j<KYBER_N; j++) {
            PRF(KYBER_ETA1,sigma,N,output);
            SamplePolyCBD(output, f, KYBER_ETA1);
            e[i][j] = f[j];                                 // e[i] ∈ Zq256 sampled from CBD PRF takes a parameter η ∈ {2,3}  PRFn1
            N = N + 1;
        }
    }

    
    // Transforma "s" e "e" para o domínio NTT
    for (int i=0; i < KYBER_K; i++) {        
        ntt(s[i]);                         // NTT is run k times (once for each coordinate of s)
        ntt(e[i]);                         // NTT is run k times
        
    }

    calculaT_hat(A,s,e,t);          // t = A ◦ s + e   noisy linear system in NTT domain


     printf("\n\n");
    for(int i=0; i < KYBER_K; i++) {
        printf("\nVETOR T[%d]:",i);
        for (int j=0; j <KYBER_N; j++) {
            printf(" %d",t[i][j]);
        }
        printf("\n");
    }


/*
    

    for (int i=0; i < KYBER_K; i++) { 
        chavesPKE.ek[i] = byteEncode12(t[i])||rho;       // ▷ ByteEncode12 is run k times; include seed for Aˆ
        chavesPKE.dk[i] = byteEncode12(s[i]);            // ▷ ByteEncode12 is run k times
    }

    return (chavesPKE);
    */
    
}
