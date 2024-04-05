
#include <stdio.h>
#include <stdint.h>
#include "parametros.h"
#include "amostragem.h"
#include "auxiliares.h"

/**********************************************************************
Funções referentes aos algorítmos de amostragem do ML-KEM FIPS 203 ipd
***********************************************************************/


/*
If the input is a stream of uniformly random bytes, the output is a uniformly random element of Tq.
Input  : byte stream B ∈ B^∗ 
Output : array aˆ ∈ Zq256
*/
void sampleNTT(const unsigned char B[], uint16_t a[]) {
    int i = 0;
    int j = 0;    

    while (j < 256) {
        int d1 = B[i] + 256 * (B[i + 1] % 16);
        int d2 = (B[i + 1] / 16) + 16 * B[i + 2];

        if (d1 < KYBER_Q) {            
            a[j] = d1;
            j++;
        }

        if (d2 < KYBER_Q && j < 256) {            
            a[j] = d2;
            j++;
        }

        i += 3;
    }

}

/*
If the input is a stream of uniformly random bytes, outputs a sample from the distribution Dη(Rq).
Input:  byte array B ∈ B^64η.
Output: array f ∈ Zq256. ▷ the coeffcients of the sampled polynomial 
*/
void samplePolyCBD(unsigned char B[], uint16_t f[], uint8_t eta) {
    uint8_t bits[64 * eta * 8]; // Cada byte se torna 8 bits
    bytesToBits(B, bits, 64 * eta);

    for (int i = 0; i < 256; i++) {
        int x = 0;
        int y = 0;

        for (int j = 0; j < eta; j++) {
            x += bits[2 * i * eta + j];
            y += bits[2 * i * eta + eta + j];
        }       
        f[i] = ((x - y) % KYBER_Q + KYBER_Q) % KYBER_Q; // Calcula os coeficientes do polinômio        
    }
}

