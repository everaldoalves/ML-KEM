#include "parametros.h"
#include <stdint.h>

#ifndef NTT_H
#define NTT_H

// Define a estrutura para armazenar um par de inteiros
typedef struct {
    int c0;
    int c1;
} BaseCaseResult;

//Gera os elementos para matriz
void geraElementosParaMatriz(uint16_t matriz[KYBER_K][KYBER_K]);

//gera os elementos para vetor
void geraElementosParaVetor(uint16_t vetor[KYBER_K][KYBER_N]);

//Mostra o vetor na tela
void exibeVetor(uint16_t vetor[KYBER_K][KYBER_N]) ;

// transformada NTT
void ntt(uint16_t vetor[KYBER_N]);

// Calcula os elementos em Rq a partir de um vetor em Tq
void invntt(uint16_t vetor[KYBER_N]);

// Verificação da corretude da transformada
void validaTransformada(uint16_t vetor[KYBER_N]);

// Caso base para multiplicação no domínio NTT
BaseCaseResult baseCaseMultiplica(uint16_t a0, uint16_t a1, uint16_t b0, uint16_t b1, uint16_t y) ;

//Multiplica dois polinômios no domínio NTT
void multiplicaNTT(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]);

// Redução modular com NEON
uint16x8_t reduce_mod_q(uint16x8_t val);

#endif