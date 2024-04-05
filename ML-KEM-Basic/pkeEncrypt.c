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

void calculaU(uint16_t A[KYBER_K][KYBER_K][KYBER_N], uint16_t r_hat[KYBER_K][KYBER_N], uint16_t e1[KYBER_K][KYBER_N], uint16_t u[KYBER_K][KYBER_N]) {
    uint16_t tempResultado[KYBER_K][KYBER_N] = {{0}};
    uint16_t tempMultiplicacao[KYBER_N] = {0}; // Agora é um vetor unidimensional.

    for (int i = 0; i < KYBER_K; ++i) {
        for (int k = 0; k < KYBER_K; ++k) {            
            multiplicaNTT(A[k][i], r_hat[k], tempMultiplicacao); // Corrigido para corresponder à nova assinatura.
            invntt(tempMultiplicacao); // Corretamente ajustado para invntt.

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
    printf("\nFinalizou calculaU");
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
    printf("\n\nEntrando em decompressMu");
    uint16_t m_decoded[KYBER_N]; // Buffer temporário para o resultado decodificado
    
    // Decodifica 'm' para um array de inteiros com d=1
    printf("\n ByteDecode(m,m_decoded,1) m=%02x m_decoded=%d",m,m_decoded);
    byteDecode(m, m_decoded, 1); // byteDecode1 realiza a decodificação com d=1

    // Decompressão de cada elemento decodificado em 'mu' com d=1
    for (int i = 0; i < KYBER_N; i++) {
        mu[i] = decompress_d(m_decoded[i], 1);
        printf("%04x ",mu[i]);
    }
}

void generateRandomVectors(const uint8_t *r, uint16_t r_vector[KYBER_K][KYBER_N], uint16_t e1[KYBER_K][KYBER_N], uint16_t e2[KYBER_N], uint8_t N) {
    unsigned char prfOutput[64 * KYBER_ETA1]; // Buffer para a saída da PRF

    // Geração de r_vector
    for (int i = 0; i < KYBER_K; i++) {
        PRF(KYBER_ETA1, r, N++, prfOutput);
        samplePolyCBD(prfOutput, r_vector[i], KYBER_ETA1);
    }

    // Geração de e1
    for (int i = 0; i < KYBER_K; i++) {
        PRF(KYBER_ETA2, r, N++, prfOutput);
        samplePolyCBD(prfOutput, e1[i], KYBER_ETA2);
    }

    // Geração de e2
    PRF(KYBER_ETA2, r, N, prfOutput);
    samplePolyCBD(prfOutput, e2, KYBER_ETA2);
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
            printf("OI");
        }
        else {
            memcpy(auxiliar,ekPKE_Subarray + i* 384, 384);  
        }
                
        byteDecode(auxiliar, t_hat[i], 12);
    }

    
    // Passo 3: Extração de rho
    memcpy(rho, ekPKE + 384 * KYBER_K, 32);
    
    
    printf("\n ekpke: ");
    for (int i=384*KYBER_K; i<384*KYBER_K+32; i++) {
        printf("%02x ",ekPKE[i]);        
    }
    
    printf("\n rho: ");
    for (int i=0; i<32; i++) {     
        printf("%d ", rho[i]);
    }

    printf("\nIniciando a geração da Matriz A ...");
    // Passo 4-8: Geração da matriz A
    for (int i = 0; i < KYBER_K; i++) {
        unsigned char i_char = (unsigned char)i;    
        for (int j = 0; j < KYBER_K; j++) {       
           memset(md, 0, sizeof(md));              // Reseta o vetor md                  
           unsigned char j_char = (unsigned char)j;            
           XOF(rho, i_char, j_char, md);               
           memset(a_hat, 0, sizeof(a_hat));      // Reinicializa a_hat para garantir que seja único em cada iteração
           sampleNTT(md, a_hat);                // Preenche a_hat com os coeficientes NTT                                                        
           for (int k=0; k < KYBER_N; k++) {                         
                // Copia a_hat para a terceira dimensão da matriz A
                A[i][j][k] = a_hat[k];     
                printf("%d ", A[i][j][k]) ;             
           } 
           printf("\n\n");
        }
    }
    printf("\n\nMatriz A gerada....\n");
           
    /*
     // Passo 9-12: Geração de r
    for (int i = 0; i < KYBER_K; i++) {
        unsigned char prfOutput[64 * KYBER_ETA1]; // Buffer para a saída da PRF, adequado para a geração de polinômios.
        
        // A função PRF é chamada com KYBER_ETA1, o nonce 'N', e o resultado é armazenado em prfOutput.
        // Assumindo que 'r' é uma fonte de entropia adequada para a PRF.
        PRF(KYBER_ETA1, r, N, prfOutput); // Utiliza N como parte do input para PRF.
        
        // 'SamplePolyCBD' gera o polinômio r_vector[i] baseado na saída da PRF.
        // A função SamplePolyCBD preenche r_vector[i] com valores amostrados de acordo com uma distribuição CBD.
        samplePolyCBD(prfOutput, r_vector[i], KYBER_ETA1);
        
        N += 1; // Incrementa N após cada geração de polinômio.
    }

    // Passo 13-16: Geração de e1
    for (int i = 0; i < KYBER_K; i++) {
        unsigned char prfOutput[64 * KYBER_ETA2]; // saída de PRF
        PRF(KYBER_ETA2, r, N, prfOutput); // N (nonce) para garantir uma nova saída
        samplePolyCBD(prfOutput, e1[i], KYBER_ETA2);
        N += 1; 
    }

    // Passo 17: Geração de e2
    unsigned char prfOutput[64 * KYBER_ETA2]; // Tamanho de saída de PRF ajustado para KYBER_ETA2
    PRF(KYBER_ETA2, r, N, prfOutput); 
    samplePolyCBD(prfOutput, e2, KYBER_ETA2);
*/

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
/*
    // 22: c1 ← ByteEncode_du(Compress_du(u))
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_N; j++) {
            printf("\nComprimindo u %02x",u[i][j]);
            u[i][j] = compress_d(u[i][j], KYBER_DU); // Comprime cada elemento de 'u'
        }
        byteEncode(u[i], &c1[i * (KYBER_N * KYBER_DU / 8)], KYBER_DU); // Codifica 'u' comprimido em 'c1'
    }

    // 23: c2 ← ByteEncode_dv(Compress_dv(v))
    for (int i = 0; i < KYBER_N; i++) {
        v[i] = compress_d(v[i], KYBER_DV); // Comprime 'v'
    }
    byteEncode(v, c2, KYBER_DV); // Codifica 'v' comprimido em 'c2'
*/

    // Compressão e codificação de u e v para c1 e c2
    compressAndEncode(u, v, c1, c2);

    // 24: return c ← (c1∥c2)
    memcpy(c, c1, sizeof(c1)); // Copia 'c1' para 'c'
    memcpy(c + sizeof(c1), c2, sizeof(c2)); // Concatena 'c2' após 'c1' em 'c'


}
