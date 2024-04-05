/* Algorithm 14 K-PKE.Decrypt(dkPKE, c)
Uses the decryption key to decrypt a ciphertext.
Input: decryption key dkPKE ∈ B^384k.
Input: ciphertext c ∈ B^32(duk+dv).
Output: message m ∈ B32.
1: c1 ← c[0 : 32duk]
2: c2 ← c[32duk : 32(duk +dv)]
3: u ← Decompressdu (ByteDecodedu (c1)) ▷ ByteDecodedu invoked k times
4: v ← Decompressdv(ByteDecodedv(c2))
5: sˆ ← ByteDecode12(dkPKE)
6: w ← v−NTT−1(sˆ⊺ ◦NTT(u)) ▷ NTT−1 and NTT invoked k times
7: m ← ByteEncode1(Compress1(w)) ▷ decode plaintext m from polynomial v
8: return m
*/
#include <string.h>
#include "amostragem.h"
#include "auxiliares.h"
#include "ntt.h"
#include "parametros.h"
#include "pkeKeyGen.h"
#include "fips202.h"

/*******************************************************************************
Algoritmo 14 - Decrypt() -  ML-KEM FIPS 203 ipd
Uses the decryption key to decrypt a ciphertext.
Input: decryption key dkPKE ∈ B^384k.
Input: ciphertext c ∈ B^32(duk+dv).
Output: message m ∈ B^32.  
********************************************************************************/

void pkeDecrypt(const uint8_t *dkPKE, const uint8_t *c, uint8_t *m);

void calcularProduto(uint16_t s[KYBER_K][KYBER_N], uint16_t u[KYBER_K][KYBER_N], uint16_t product[KYBER_N]); 