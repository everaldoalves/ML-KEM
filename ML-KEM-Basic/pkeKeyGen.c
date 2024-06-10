#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "amostragem.h"
#include "auxiliares.h"
#include "ntt.h"
#include "parametros.h"
#include "pkeKeyGen.h"
#include "fips202.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

/*******************************************************************
Algoritmo 12 - KeyGen() -  ML-KEM FIPS 203 ipd
Generates an encryption key and a corresponding decryption key.
Output: encryption key ekPKE ∈ B^384k+32.
Output: decryption key dkPKE ∈ B^384k. 
********************************************************************/

/*
void calculaT_hat(const uint16_t (*A)[KYBER_K][KYBER_N], const uint16_t s[KYBER_K][KYBER_N], const uint16_t e[KYBER_K][KYBER_N], uint16_t t_hat[KYBER_K][KYBER_N]) {
    uint16_t tempResultado[KYBER_K][KYBER_N] = {{0}};      

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

    // Adiciona "e" a tempResultado para obter t_hat com redução modular
    for (int i = 0; i < KYBER_K; ++i) {
        for (int n = 0; n < KYBER_N; ++n) {
            t_hat[i][n] = (tempResultado[i][n] + e[i][n]) % KYBER_Q;
        }
    }
}
*/

// Função inline para adição modular
static inline uint16_t add_mod(uint16_t a, uint16_t b, uint16_t mod) {
    uint16_t res = a + b;
    if (res >= mod) res -= mod;
    return res;
}

void calculaT_hat(const uint16_t (*A)[KYBER_K][KYBER_N], const uint16_t s[KYBER_K][KYBER_N], const uint16_t e[KYBER_K][KYBER_N], uint16_t t_hat[KYBER_K][KYBER_N]) {
    uint16_t tempResultado[KYBER_K][KYBER_N] = {{0}};
    uint16_t tempMultiplicacao[KYBER_N] = {0};

    for (int i = 0; i < KYBER_K; ++i) {
        for (int k = 0; k < KYBER_K; ++k) {            
            multiplicaNTT1(A[i][k], s[k], tempMultiplicacao); 

            for (int n = 0; n < KYBER_N; ++n) {
                tempResultado[i][n] = add_mod(tempResultado[i][n], tempMultiplicacao[n], KYBER_Q);
            }
        }

        for (int n = 0; n < KYBER_N; ++n) {
            t_hat[i][n] = add_mod(tempResultado[i][n], e[i][n], KYBER_Q);
        }
    }
}



void exibeVetorPolinomios(uint16_t vetor[2][256], char* nomeVetor){
    printf("\n Vetor %s : ", nomeVetor);
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_N; j++)
        {
            printf("%d ,",vetor[i][j]);
        }
        printf("\n");
    }
    
}

void exibeMatrizA(uint16_t (*A)[KYBER_K][KYBER_N]) {
    printf("\n A : ");
    for (int i = 0; i < KYBER_K; i++)    {
        for (int j = 0; j < KYBER_K; j++)  {
            for (int k = 0; k < KYBER_N; k++)  {
                printf("%hu ",A[i][j][k]);
            }
            printf("\n");
            
        }        
    }
    printf("\n");
}

void verificaCalculoT(uint16_t t1[2][256],uint16_t t2[2][256]) {
     if((memcmp(t1[0],t2[0],sizeof(t1[0]))==0) && (memcmp(t1[1],t2[1],sizeof(t1[1]))==0)) {
        printf("\n\n Vetor t foi calculado corretamente!!!! \n");
    }
    else {
        printf("\n\n Falha no cálculo do vetor t \n");
    }
}

void exibeChaves(chavesPKE chaves) {  
    printf("chave ek : ");
    uint16_t tamanhoChaveEK = sizeof(chaves.ek)/sizeof(chaves.ek[0]);
    uint16_t tamanhoChaveDK = sizeof(chaves.dk)/sizeof(chaves.dk[0]);
    for (uint8_t i = 0; i < tamanhoChaveEK; i++)
    {
        printf("%02x", chaves.ek[i]);
    }
    printf("\n \nchave dk : ");
    for (uint16_t i = 0; i < tamanhoChaveDK; i++)
    {
        printf("%02x", chaves.dk[i]);
    }
}
void exibeByte32(uint16_t rhoSigma[32], char* texto) {
    printf("\n %s : ", texto);
    for (int i = 0; i < 32; i++) {
        printf(" %02x", rhoSigma[i]);
    }    
    printf("\n");
}


// início da função de Geração de Chaves
chavesPKE pkeKeyGen() {
    
    unsigned char d[32];                          // Array para armazenar os 32 bytes aleatórios      
    unsigned char rho[32], sigma[32];            // saídas de G
    chavesPKE chaves = {0};   
    unsigned char output[64 * KYBER_ETA1] = {0};    // Bytes aleatórios para SamplePolyCBD
    uint8_t N = 0;        
    //uint16_t f[KYBER_N] = {0};
    uint16_t s[KYBER_K][KYBER_N] = {{0}};
    uint16_t e[KYBER_K][KYBER_N] = {{0}};    
    //uint16_t a_hat[KYBER_N] = {0}; 
    uint16_t t[KYBER_K][KYBER_N] = {{0}}; 
    unsigned char md[EVP_MAX_MD_SIZE];   // Vetor para armazenar o resultado de SHAKE128(ρ|i|j)    

    // Declaração e Alocação dinâmica da matriz A
    uint16_t (*A)[KYBER_K][KYBER_N] = malloc(KYBER_K * KYBER_K * KYBER_N * sizeof(uint16_t));
    uint16_t tamanhoA = KYBER_K*KYBER_K*KYBER_N;

    if (A == NULL) {
        fprintf(stderr, "Falha na alocação de memória\n");
        //return EXIT_FAILURE;
    }

    // Inicialização da matriz A
    memset(A, 0, tamanhoA * sizeof(uint16_t));       
  
    // Gera bytes aleatórios para semente
    generateRandomBytes(d, sizeof(d));                  

    // Aplica a função G em d para obter rho e sigma
    G(d, sizeof(d), rho, sigma);
  
 
    // Gera os elementos da matriz A^ pertencente a (Zq256)^k*k
    for (uint8_t i=0; i < KYBER_K; i++) {                     
        for (uint8_t j=0; j < KYBER_K; j++) {                         
           XOF(rho, j, i, md);                         
           sampleNTT(md, A[i][j]);                // Preenche a_hat com os coeficientes NTT                   
        }    
    }

    //geraMatrizA(rho,A);
    //geraMatrizAOtimizada(rho,A);

   // Gera os elementos do vetor s
   for (int i=0; i < KYBER_K; i++)    {                      // generate s ∈ (Zq256)^k              
        PRF(KYBER_ETA1,sigma,N,output);                        
        samplePolyCBD(output, s[i], KYBER_ETA1);                                                                                 
        N = N + 1;
        ntt(s[i]);                         // NTT is run k times (once for each coordinate of s)
        
    }  
    
    // Gera os elementos do vetor e
    for (int i=0; i < KYBER_K; i++)    {                      // generate e ∈ (Zq256)^k                                                                 
        PRF(KYBER_ETA1,sigma,N,output);
        samplePolyCBD(output, e[i], KYBER_ETA1);        
        N = N + 1;                 
        ntt(e[i]);                         // NTT is run k times    
    }              

    calculaT_hat(A,s,e,t);          // t = A ◦ s + e   noisy linear system in NTT domain       

    // Geração das CHAVES
    for (int i=0; i < KYBER_K; i++) {         
        // Codifica t[i]                        // ▷ ByteEncode12 is run k times; include seed for Aˆ        
        byteEncode(t[i], chaves.ek + (i * 384), 12);                                              

        // Codifica s[i] para dk              chaves.dk[i] = byteEncode(s[i]);            // ▷ ByteEncode12 is run k times     
        byteEncode(s[i], chaves.dk + (i * 384), 12);
    }

    // Concatena rho ao final de ek - byteEncode(t[i])||rho;   
    memcpy(chaves.ek + (384 * KYBER_K), rho, 32);   

    return chaves; 

    // Liberar a memória alocada
    free(A);  
}