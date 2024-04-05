#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include "amostragem.h"
#include "auxiliares.h"
#include "ntt.h"
#include "parametros.h"
#include "pkeDecrypt.h"
#include "fips202.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

/*******************************************************************************
Algoritmo 14 - Decrypt() -  ML-KEM FIPS 203 ipd
Uses the decryption key to decrypt a ciphertext.
Input: decryption key dkPKE ∈ B^384k.
Input: ciphertext c ∈ B^32(duk+dv).
Output: message m ∈ B^32.  
********************************************************************************/

void pkeDecrypt(const uint8_t *dkPKE, const uint8_t *c, uint8_t *m) {
    uint8_t c1[32 * KYBER_DU];
    uint8_t c2[32 * KYBER_DV];
    uint16_t u[KYBER_K][KYBER_N];
    uint16_t v[KYBER_N];
    uint16_t s_hat[KYBER_K][KYBER_N];
    uint16_t w[KYBER_N];

    // Passo 1 e 2: Extrair c1 e c2 do texto cifrado c
    memcpy(c1, c, sizeof(c1));
    memcpy(c2, c + 32 * KYBER_DU, sizeof(c2));

    // Passo 3: Decompress e ByteDecode para u
    for (int i = 0; i < KYBER_K; i++) {
        uint16_t temp[KYBER_N]; // Ajustar de acordo com a dimensão esperada
        byteDecode(c1 + i * (32 * KYBER_DU / KYBER_K), temp, KYBER_DU);
        for (int j = 0; j < KYBER_N; j++) {
            u[i][j] = decompress_d(temp[j], KYBER_DU);
        }
    }

    // Passo 4: Decompress e ByteDecode para v
    uint16_t temp_v[KYBER_N]; // Ajustar de acordo com a dimensão esperada
    byteDecode(c2, temp_v, KYBER_DV);
    for (int i = 0; i < KYBER_N; i++) {
        v[i] = decompress_d(temp_v[i], KYBER_DV);
    }

    // Passo 5: ByteDecode para s_hat
    for (int i = 0; i < KYBER_K; i++) {
        byteDecode(dkPKE + i * (384 * KYBER_K / KYBER_K), s_hat[i], 12); // Usando 12 como d para s_hat
    }

    // Aplica NTT a u e s_hat
    ntt(u);
    ntt(s_hat);

    // Passo 6: Calcula z_hat = ∑j=0^k-1 uˆ[j] ×Tq vˆ[j]
    // Multiplicação NTT de s_hat por u e soma dos resultados
    uint16_t z_hat[KYBER_N] = {0}; // Inicializa z_hat com zeros
    for (int i = 0; i < KYBER_K; i++) {
        uint16_t product[KYBER_N];
        multiplicaNTT(s_hat[i], u[i], product); // Calcula o produto no domínio NTT
        for (int j = 0; j < KYBER_N; j++) {
            z_hat[j] += product[j];
            z_hat[j] %= KYBER_Q; // Garante que esteja dentro do limite do módulo
        }
    }

    // Aplica invNTT a z_hat para voltar ao domínio do tempo
    invntt(z_hat);

    // Subtrai z_hat de v para obter w
    for (int i = 0; i < KYBER_N; i++) {
        int32_t sub = (v[i] + KYBER_Q - z_hat[i]) % KYBER_Q;
        w[i] = sub < 0 ? sub + KYBER_Q : sub; // Corrige se sub for negativo
    }

    // Passo 7: Compress e ByteEncode para obter m
    uint16_t compressed_w[KYBER_N];
    for (int i = 0; i < KYBER_N; i++) {
        compressed_w[i] = compress_d(w[i], 1); // Comprime cada elemento de w
    }
    byteEncode(compressed_w, m, 1); // Codifica w comprimido em m
}
