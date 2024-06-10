#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cores.h"
#include "ntt.h"
#include "parametros.h"

/*********************************************************************************
Funções referentes aos algorítmos NTT do ML-KEM FIPS 203 ipd
Input: array f ∈ ZKYBER_Q256.   ▷ the coeffcients of the input polynomial KYBER_Q
Output: array fˆ ∈ ZKYBER_Q256 
*********************************************************************************/



// Calcula a^b mod q
int power(int x, int y) { 
    int result = 1;  
    while (y > 0) {
        result = (result * x) % KYBER_Q;
        y--;
    }
    return (result < 0) ? result + KYBER_Q : result;
}

// Calcula o bit reverso
int BitRev7(int i) {
    int reverse = 0;
    for (int j = 0; j < 7; j++) {
        reverse = (reverse << 1) | (i & 1);
        i >>= 1;
    }
    return reverse % KYBER_Q;
}

/*
Computes the NTT representation fˆ of the given polynomial f ∈ Rq.
Input: array f ∈ Zq256. ▷ the coeffcients of the input polynomial 
Output: array fˆ ∈ Zq256. ▷ the coeffcients of the NTT of the input polynomial 
*/
#include <stdint.h>

#define KYBER_Q 3329
#define KYBER_N 256

void ntt(uint16_t f[KYBER_N]) {
    int len, start, j, k = 1;
    uint16_t t, zeta;

    for (len = 128; len >= 2; len /= 2) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = power(KYBER_Z, BitRev7(k)); 
            k++;
            for (j = start; j < start + len; j++) {
                t = (zeta * f[j + len]) % KYBER_Q;
                f[j + len] = (f[j] + KYBER_Q - t) % KYBER_Q;
                f[j] = (f[j] + t) % KYBER_Q;
            }
        }
    }
}

/*
Computes the polynomial f ∈ Rq corresponding to the given NTT representation fˆ ∈ Tq.
Input:  array fˆ ∈ Zq256. ▷ the coeffcients of input NTT representation 
Output: array f ∈ Zq256. ▷ the coeffcients of the inverse-NTT of the input 
*/
void invntt(uint16_t f[KYBER_N]) {
    int len, start, j, k = 127;
    uint16_t t, zeta;

    for (len = 2; len <= 128; len *= 2) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = power(KYBER_Z, BitRev7(k)); 
            k--;
            for (j = start; j < start + len; j++) {
                t = f[j];
                f[j] = (t + f[j + len]) % KYBER_Q;
                f[j + len] = (zeta * (KYBER_Q + f[j + len] - t)) % KYBER_Q;
            }
        }
    }

    // Normalização
    for (j = 0; j < KYBER_N; j++) {
        f[j] = (f[j] * 3303) % KYBER_Q; // 3303 é o inverso de 256 mod KYBER_Q
    }
}
// Verifica se a NTT e a INTT correspondem
void validaTransformada(uint16_t vetor[KYBER_N]) {
    int vetorAux[KYBER_N];
    int aux=0;
    for (int i =0; i < KYBER_K; i++) {         
        vetorAux[i] = vetor[i];
         
    }

    ntt(vetor);    
    invntt(vetor);
    

         for (int j=0; j < KYBER_N; j++) {
            if (vetor[j]!=vetorAux[j]) {
                printf("\n\n Atenção! \n vetorA[%d]!=vetorA'[%d] %d!=%d \n Lamento, mas Transformada INCORRETA!!!",j,j,vetor[j],vetorAux[j]);
                aux =1;
            }
         }   
    
    if (aux==0) {
        printf("\n\nTransformada Correta!!!");
    }
}


/*
Computes the product of two degree-one polynomials with respect to a quadratic modulus.
Input:  a0,a1,b0,b1 ∈ Zq. ▷ the coeffcients of a0 + a1X and b0 + b1X
Input:  γ ∈ Zq. ▷ the modulus is X^2 −γ
Output: c0,c1 ∈ Zq. ▷ the coeffcients of the product of the two polynomials 
*/
nt baseCaseMultiplica(uint16_t a0, uint16_t a1, uint16_t b0, uint16_t b1, uint16_t y) {
    nt result;
    result.c0 = ((a0 * b0) % KYBER_Q + ((a1 * b1) % KYBER_Q * y) % KYBER_Q) % KYBER_Q;
    result.c1 = ((a0 * b1) % KYBER_Q + (a1 * b0) % KYBER_Q) % KYBER_Q;
    return result;
}


/*
Computes the product (in the ring Tq) of two NTT representations.
Input:  Two arrays fˆ ∈ Zq256 and gˆ ∈ Zq256. ▷ the coeffcients of two NTT representations 
Output: An array h^ ∈ Zq256. ▷ the coeffcients of the product of the inputs
*/
void multiplicaNTT(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]) {   

    for (int j=0; j<128; j++) {
            nt result = baseCaseMultiplica(f[2*j],f[2*j+1],g[2*j],g[2*j+1],power(KYBER_Z,(2*BitRev7(j)+1)));
            h[2*j] = result.c0;
            h[2*j+1] = result.c1;
    }
       
}
