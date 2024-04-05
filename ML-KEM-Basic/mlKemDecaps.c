#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include "auxiliares.h"
#include "parametros.h"
#include "pkeEncrypt.h"
#include "pkeDecrypt.h" 
#include "mlKemEncaps.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

/*******************************************************************************
Algorithm 17 ML-KEM.Decaps(c,dk)
Uses the decapsulation key to produce a shared key from a ciphertext.
Validated input: ciphertext c ∈ B32(du*k + dv)
Validated input: decapsulation key dk ∈ B768k+96   
Output: shared key K ∈ B32 
********************************************************************************/

void mlKemDecaps(const uint8_t *c, const uint8_t *dk, uint8_t *K_linha) {
    // 1: Extrai dkPKE
    uint8_t dkPKE[384*KYBER_K];
    memcpy(dkPKE, dk, 384*KYBER_K);

    // 2: Extrai ekPKE
    uint8_t ekPKE[384*KYBER_K + 32];
    memcpy(ekPKE, dk + 384*KYBER_K, 384*KYBER_K + 32);

    // 3: Extrai h
    uint8_t h[32];
    memcpy(h, dk + 768*KYBER_K + 32, 32);

    // 4: Extrai z
    uint8_t z[32];
    memcpy(z, dk + 768*KYBER_K + 64, 32);

    // 5: Decriptar c para obter m'
    uint8_t m_linha[32]; 
    pkeDecrypt(dkPKE, c, m_linha);

    // 6: Deriva K' e r' de G(m'||h)
    uint8_t r_linha[32];
    uint8_t m_linha_h[64];
    memcpy(m_linha_h, m_linha, 32);
    memcpy(m_linha_h + 32, h, 32);
    G(m_linha_h, 64, K_linha, r_linha);

    // 7: Calcula K̄ usando J(z||c, 32)
    uint16_t tamanhoTextoCifrado = 32 * (KYBER_DU * KYBER_K + KYBER_DV);
    uint8_t K_bar[32];
    uint8_t z_c[tamanhoTextoCifrado+32];
    
    memcpy(z_c, z, 32);
    memcpy(z_c + 32, c, tamanhoTextoCifrado); 
    J(z_c, tamanhoTextoCifrado+32, K_bar);

    // 8: Re-criptografa m' usando r' para obter c'
    uint8_t c_linha[tamanhoTextoCifrado]; 
    pkeEncrypt(ekPKE, m_linha, r_linha, c_linha);

    // 9: Verifica se c é igual a c'. Se não, usa K̄
    if (memcmp(c, c_linha, tamanhoTextoCifrado) != 0) {
        memcpy(K_linha, K_bar, 32); // Usa K̄ se os textos cifrados não coincidirem
    }

    // K' é retornado através do parâmetro K_linha
}

