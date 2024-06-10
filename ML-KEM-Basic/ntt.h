#include "parametros.h"
#include <arm_neon.h>

#ifndef NTT_H
#define NTT_H

#ifdef __cplusplus
extern "C" {
#endif

// Define a estrutura para armazenar um par de inteiros
typedef struct {
    int c0;
    int c1;
} nt;

//Gera os elementos para matriz
void geraElementosParaMatriz(uint16_t matriz[KYBER_K][KYBER_K]);

//gera os elementos para vetor
void geraElementosParaVetor(uint16_t vetor[KYBER_K][KYBER_N]);

//Mostra o vetor na tela
void exibeVetor(uint16_t vetor[KYBER_K][KYBER_N]) ;

// transformada NTT
void ntt(uint16_t vetor[KYBER_N]);
void ntt_neon(uint16_t vetor[KYBER_N]);

// Calcula os elementos em Rq a partir de um vetor em Tq
void invntt(uint16_t vetor[KYBER_N]);
void invntt_neon(uint16_t vetor[KYBER_N]);

// Verificação da corretude da transformada
void validaTransformada(uint16_t vetor[KYBER_N]);


// Caso base para multiplicação no domínio NTT
static inline nt baseCaseMultiplica(uint16_t a0, uint16_t a1, uint16_t b0, uint16_t b1, uint16_t y) ;


//Multiplica dois polinômios no domínio NTT
void multiplicaNTT(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]);
void multiplicaNTT1(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]); // tentativa de otimização sem neon
void multiplicaNTT_neon(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]);

// A partir daqui são assinaturas de funções que servem apenas para teste usando geração de valores cujos resultados das transformações para o domínio NTT são conhecidos
void geraDoidoElementosParaVetor(uint16_t vetor[KYBER_K][KYBER_N]);
void inverteElementosDoido(uint16_t vetor[KYBER_K][KYBER_N]);

static inline int16x8_t barrett_reduce_neon(int16x8_t x);

#ifdef __cplusplus
}
#endif

#endif