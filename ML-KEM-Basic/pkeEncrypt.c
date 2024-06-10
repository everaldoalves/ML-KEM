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
#include "fips202.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

/*******************************************************************************
Algoritmo 13 - Encrypt() -  ML-KEM FIPS 203 ipd
Uses the encryption key to encrypt a plaintext message using the randomness r.
Uses the encryption key to encrypt a plaintext message using the randomness r.
Input: encryption key ekPKE ∈ B^384k+32.
Input: message m ∈ B^32.
Input: encryption randomness r ∈ B^32.
Output: ciphertext c ∈ B^32(duk+dv)
********************************************************************************/

/*
void calculaU(uint16_t A[KYBER_K][KYBER_K][KYBER_N], uint16_t r_hat[KYBER_K][KYBER_N], uint16_t e1[KYBER_K][KYBER_N], uint16_t u[KYBER_K][KYBER_N]) {
    uint16_t tempResultado[KYBER_K][KYBER_N] = {{0}};
    uint16_t tempMultiplicacao[KYBER_N] = {0}; 

    for (int i = 0; i < KYBER_K; ++i) {
        for (int k = 0; k < KYBER_K; ++k) {            
            multiplicaNTT(A[k][i], r_hat[k], tempMultiplicacao); 
            invntt(tempMultiplicacao); 

            // Soma os resultados ao tempResultado[i]
            for (int n = 0; n < KYBER_N; ++n) {
                tempResultado[i][n] = (tempResultado[i][n] + tempMultiplicacao[n]) % KYBER_Q;
            }
        }
    }

    // Soma e1 ao resultado para obter u
    for (int i = 0; i < KYBER_K; ++i) {
        for (int n = 0; n < KYBER_N; ++n) {
            u[i][n] = (tempResultado[i][n] + e1[i][n]) % KYBER_Q;
        }
    }
    
}
*/
void calculaU(uint16_t A[KYBER_K][KYBER_K][KYBER_N], uint16_t r_hat[KYBER_K][KYBER_N], uint16_t e1[KYBER_K][KYBER_N], uint16_t u[KYBER_K][KYBER_N]) {
    uint16_t tempResultado[KYBER_K][KYBER_N] = {{0}};

    // Computar a matriz U usando multiplicação e soma otimizada
    for (int i = 0; i < KYBER_K; ++i) {
        for (int k = 0; k < KYBER_K; ++k) {
            uint16_t tempMultiplicacao[KYBER_N];
            multiplicaNTT(A[k][i], r_hat[k], tempMultiplicacao);

            for (int n = 0; n < KYBER_N; ++n) {
                tempResultado[i][n] += tempMultiplicacao[n];
                if (tempResultado[i][n] >= KYBER_Q) {  // Reduzir a frequência de operações módulo
                    tempResultado[i][n] -= KYBER_Q;
                }
            }
        }

        // Aplicar a inversa NTT e somar e1 diretamente aqui para evitar loops extras
        invntt(tempResultado[i]);
        for (int n = 0; n < KYBER_N; ++n) {
            u[i][n] = (tempResultado[i][n] + e1[i][n]) % KYBER_Q;
        }
    }
}

void calculaUBarretReduce(uint16_t A[KYBER_K][KYBER_K][KYBER_N], uint16_t r_hat[KYBER_K][KYBER_N], uint16_t e1[KYBER_K][KYBER_N], uint16_t u[KYBER_K][KYBER_N]) {
    u_int16_t tempResultado[KYBER_K][KYBER_N] = {{0}};

    for (int i = 0; i < KYBER_K; ++i) {
        for (int k = 0; k < KYBER_K; ++k) {
            u_int16_t tempMultiplicacao[KYBER_N];
            multiplicaNTT(A[k][i], r_hat[k], tempMultiplicacao);

            for (int n = 0; n < KYBER_N; ++n) {
                u_int32_t sum = tempResultado[i][n] + tempMultiplicacao[n];
                tempResultado[i][n] = barrett_reduce1(sum);  // Aplicando barrett_reduce aqui
            }
        }

        invntt(tempResultado[i]);
        for (int n = 0; n < KYBER_N; ++n) {
            u[i][n] = barrett_reduce1(tempResultado[i][n] + e1[i][n]);  // Redução final após soma
        }
    }
}



void calculaUOLD(uint16_t A[KYBER_K][KYBER_K][KYBER_N], uint16_t r_hat[KYBER_K][KYBER_N], uint16_t e1[KYBER_K][KYBER_N], uint16_t u[KYBER_K][KYBER_N]) {
    uint16_t tempResultado[KYBER_K][KYBER_N] = {{0}};
    uint16_t tempMultiplicacao[KYBER_N] = {0}; 

    // Computar a matriz U usando a multiplicação e a soma otimizada
    for (int i = 0; i < KYBER_K; ++i) {
        for (int k = 0; k < KYBER_K; ++k) {            
            multiplicaNTT(A[k][i], r_hat[k], tempMultiplicacao);
            // Soma os resultados diretamente em tempResultado após a multiplicação
            for (int n = 0; n < KYBER_N; ++n) {
                tempResultado[i][n] = (tempResultado[i][n] + tempMultiplicacao[n]) % KYBER_Q;
            }
        }

        // Aplicar a inversa NTT e somar e1 diretamente aqui para evitar loops extras
        invntt(tempResultado[i]);
        for (int n = 0; n < KYBER_N; ++n) {
            u[i][n] = (tempResultado[i][n] + e1[i][n]) % KYBER_Q;
        }
    }
}



void calculaV(uint16_t t_hat[KYBER_K][KYBER_N], uint16_t r_vector[KYBER_K][KYBER_N], uint16_t e2[KYBER_N], uint16_t mu[KYBER_N], uint16_t v[KYBER_N]) {
    uint16_t temp[KYBER_N] = {0};
    uint16_t v_ntt[KYBER_N] = {0}; // Temporariamente armazena o resultado da soma NTT antes da inversa.

    for (int i = 0; i < KYBER_K; i++) {
        multiplicaNTT(t_hat[i], r_vector[i], temp);

        // Acumula o resultado em v_ntt
        for (int j = 0; j < KYBER_N; j++) {
            v_ntt[j] = (v_ntt[j] + temp[j]) % KYBER_Q;
        }
    }

    invntt(v_ntt); // Aplica NTT inversa uma vez, depois de acumular todos os resultados em v_ntt.

    // Adiciona e2 e mu ao resultado da NTT inversa
    for (int i = 0; i < KYBER_N; i++) {        
        v[i] = (v_ntt[i] + e2[i] + mu[i]) % KYBER_Q;
    }
}


void decompressMu(const uint8_t *m, uint16_t mu[KYBER_N]) {
    
    uint16_t m_decoded[KYBER_N]; // Buffer temporário para o resultado decodificado
    
    // Decodifica 'm' para um array de inteiros com d=1
    
    byteDecode(m, m_decoded, 1); // byteDecode1 realiza a decodificação com d=1

    // Decompressão de cada elemento decodificado em 'mu' com d=1
    for (int i = 0; i < KYBER_N; i++) {
        mu[i] = decompress_d(m_decoded[i], 1);    
    }
}

/*
void generateRandomVectors(const uint8_t *r, uint16_t r_vector[KYBER_K][KYBER_N], uint16_t e1[KYBER_K][KYBER_N], uint16_t e2[KYBER_N], uint8_t N) {
    unsigned char prfOutput_eta1[64 * KYBER_ETA1]; // Buffer para a saída da PRFn1
    unsigned char prfOutput_eta2[64 * KYBER_ETA2]; // Buffer para a saída da PRFn2

    // Geração de r_vector
    for (int i = 0; i < KYBER_K; i++) {
        PRF(KYBER_ETA1, r, N++, prfOutput_eta1);
        samplePolyCBD(prfOutput_eta1, r_vector[i], KYBER_ETA1);
    }

    // Geração de e1
    for (int i = 0; i < KYBER_K; i++) {
        PRF(KYBER_ETA2, r, N++, prfOutput_eta2);
        samplePolyCBD(prfOutput_eta2, e1[i], KYBER_ETA2);
    }    

    // Geração de e2
    memset(prfOutput_eta2,0,64*KYBER_ETA2); // resetando o output
    PRF(KYBER_ETA2, r, N, prfOutput_eta2);
    samplePolyCBD(prfOutput_eta2, e2, KYBER_ETA2);  
}
*/

void generateRandomVectors(const uint8_t *r, uint16_t r_vector[KYBER_K][KYBER_N], uint16_t e1[KYBER_K][KYBER_N], uint16_t e2[KYBER_N], uint8_t N) {
    unsigned char prfOutput[64 * KYBER_ETA1 * KYBER_K + 64 * KYBER_ETA2 * (KYBER_K + 1)]; // Buffer grande o suficiente para todas as saídas

    // Geração de todas as saídas PRF em uma única chamada para cada tipo de ETA
    PRF(KYBER_ETA1, r, N, prfOutput);
    N += KYBER_K; // Atualizar N após usar KYBER_K vezes ETA1
    PRF(KYBER_ETA2, r, N, prfOutput + 64 * KYBER_ETA1 * KYBER_K); // Usa offset apropriado
    N += KYBER_K; // Atualizar N novamente

    // Geração de r_vector e e1
    for (int i = 0; i < KYBER_K; i++) {
        samplePolyCBD_neon(prfOutput + i * 64 * KYBER_ETA1, r_vector[i], KYBER_ETA1);
        samplePolyCBD_neon(prfOutput + 64 * KYBER_ETA1 * KYBER_K + i * 64 * KYBER_ETA2, e1[i], KYBER_ETA2);
    }

    // Geração de e2 usando a última parte do buffer de PRF
    samplePolyCBD_neon(prfOutput + 64 * KYBER_ETA1 * KYBER_K + 64 * KYBER_ETA2 * KYBER_K, e2, KYBER_ETA2);
}


void compressAndEncode(const uint16_t u[KYBER_K][KYBER_N], const uint16_t v[KYBER_N], uint8_t c1[], uint8_t c2[]) {
    // Compressão e codificação de u para c1
    for (int i = 0; i < KYBER_K; i++) {
        uint16_t compressedU[KYBER_N];
        for (int j = 0; j < KYBER_N; j++) {
            compressedU[j] = compress_d(u[i][j], KYBER_DU);
        }
        byteEncode(compressedU, c1 + i * (KYBER_N * KYBER_DU / 8), KYBER_DU);
    }

    // Compressão e codificação de v para c2
    uint16_t compressedV[KYBER_N];
    for (int i = 0; i < KYBER_N; i++) {
        compressedV[i] = compress_d(v[i], KYBER_DV);
    }
    byteEncode(compressedV, c2, KYBER_DV);
}


void pkeEncrypt(const uint8_t *ekPKE, const uint8_t *m, const uint8_t *r, uint8_t *c) {
    uint16_t t_hat[KYBER_K][KYBER_N] = {{0}};    
    uint16_t A[KYBER_K][KYBER_K][KYBER_N] = {{{0}}};
    uint16_t r_vector[KYBER_K][KYBER_N] = {{0}};
    uint16_t e1[KYBER_K][KYBER_N] = {{0}};
    uint16_t e2[KYBER_N] = {0};     
    uint16_t u[KYBER_K][KYBER_N] = {{0}};
    uint16_t v[KYBER_N] = {0};
    uint16_t a_hat[KYBER_N] = {0};
    uint8_t rho[32], c1[KYBER_K * KYBER_N * KYBER_DU / 8], c2[KYBER_N * KYBER_DV / 8];
    uint16_t mu[KYBER_N]; // Decodificar e descomprimir 'm' para 'mu'  
    unsigned char md[EVP_MAX_MD_SIZE];   // Vetor para armazenar o resultado de SHAKE128(ρ|i|j)  
    uint8_t N = 0;

       
    // Passo 2: ByteDecode do ekPKE para t_hat
    // 2.1 Calcula o tamanho do subarray baseado em KYBER_K
    int subarraySize = 384 * KYBER_K;

    // 2.2 Cria um buffer temporário para armazenar os 384*KYBER_K bytes de ekPKE
    uint8_t ekPKE_Subarray[subarraySize];

    // 2.3 Copia os primeiros 384*KYBER_K bytes de ekPKE para ekPKE_Subarray
    memcpy(ekPKE_Subarray, ekPKE, subarraySize);   

    // 2.4 Decodificando para t_hat com d=12
    uint8_t auxiliar[384];
    for (int i = 0; i < KYBER_K; i++)
    {
        if (i==0)
        {
            memcpy(auxiliar,ekPKE_Subarray, 384);              
        }
        else {
            memcpy(auxiliar,ekPKE_Subarray + i* 384, 384);  
        }
                
        byteDecode(auxiliar, t_hat[i], 12);
    }

    
    // Passo 3: Extração de rho
    memcpy(rho, ekPKE + 384 * KYBER_K, 32);
    
    /*
    // Passo 4-8: Geração da matriz A
    for (uint8_t i=0; i < KYBER_K; i++) {                     
        for (uint8_t j=0; j < KYBER_K; j++) {                         
           XOF(rho, j, i, md);                         
           sampleNTT(md, A[i][j]);                              
        }    
    }
    */
   geraMatrizAOtimizada(rho,A);

   // Uso da função generateRandomVectors para gerar r_vector, e1, e2
    generateRandomVectors(r, r_vector, e1, e2, 0); // N inicializado como 0

    // Passo 18: Aplicação de NTT a r
    // Aplicação de NTT a r_vector antes de computeU e computeV
    for (int i = 0; i < KYBER_K; i++) {
        ntt(r_vector[i]);
    }   

    // Passo 19: Calcular u
    calculaU(A, r_vector, e1, u);    

    // 20: µ ← Decompress1(ByteDecode1(m)))    
    decompressMu(m, mu);
    
    // 21: v ← NTT−1(t^⊺ ◦ rˆ) +e2 + µ
    calculaV(t_hat, r_vector, e2, mu, v);

    // Compressão e codificação de u e v para c1 e c2
    compressAndEncode(u, v, c1, c2);

    // 24: return c ← (c1∥c2)
    memcpy(c, c1, sizeof(c1)); // Copia 'c1' para 'c'
    memcpy(c + sizeof(c1), c2, sizeof(c2)); // Concatena 'c2' após 'c1' em 'c'

}
