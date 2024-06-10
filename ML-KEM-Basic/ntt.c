#include <arm_neon.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cores.h"
#include "ntt.h"
#include "parametros.h"
#include <stdint.h>


/*********************************************************************************
Implementação utilizando zetas pré-calculados
Funções referentes aos algorítmos NTT do ML-KEM FIPS 203 ipd
Input: array f ∈ ZKYBER_Q256.   ▷ the coeffcients of the input polynomial KYBER_Q
Output: array fˆ ∈ ZKYBER_Q256 
*********************************************************************************/

// ζ^BitRev7(i) 
const uint16_t zetas[128] = {1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 
    1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 
    33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409,
    2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 
    2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 
    2110, 2935, 885, 2154};

// ζ^2*BitRev7(i)+1 
const uint16_t zetas2[128] = {17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 
1173, 3015, 314, 3050, 279, 1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 
992, 268, 3061, 641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 
2768, 2466, 863, 2594, 735, 2804, 525,1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 
394, 885, 2444, 2154, 1175};


#define BARRETT_MU (1ULL << 32) / KYBER_Q  // BARRETT_MU é calculado com base no valor de KYBER_Q

uint16_t barrett_reduce(uint32_t a) {
    uint32_t q = (a * BARRETT_MU) >> 32;
    a -= q * KYBER_Q;
    if (a >= KYBER_Q) a -= KYBER_Q;
    return a;
}

// Função NEON para realizar a redução de Barrett em vetores
static inline int16x8_t barrett_reduce_neon(int16x8_t x) {
    int32x4_t mu = vdupq_n_s32(BARRETT_MU);
    int32x4_t q1, q2, r1, r2, kq1, kq2;
    int16x8_t result;

    // Convertendo o vetor de entrada para 32 bits para multiplicação de alta precisão
    int32x4_t high_bits = vmovl_s16(vget_high_s16(x));
    int32x4_t low_bits = vmovl_s16(vget_low_s16(x));

    // Multiplicação por BARRETT_MU
    q1 = vshrq_n_s32(vmulq_s32(low_bits, mu), 32);
    q2 = vshrq_n_s32(vmulq_s32(high_bits, mu), 32);

    // q = (x * mu) >> 32
    // x = x - q * KYBER_Q
    kq1 = vmulq_n_s32(q1, KYBER_Q);
    kq2 = vmulq_n_s32(q2, KYBER_Q);

    // Reduzindo de volta para 16 bits
    r1 = vsubq_s32(low_bits, kq1);
    r2 = vsubq_s32(high_bits, kq2);

    // Reagrupar e verificar se ainda é necessário reduzir
    result = vcombine_s16(vmovn_s32(r1), vmovn_s32(r2));
    result = vaddq_s16(result, vreinterpretq_s16_u16(vcltq_s16(result, vdupq_n_s16(0))));  // Se for negativo, adicionar KYBER_Q
    result = vsubq_s16(result, vreinterpretq_s16_u16(vcgeq_s16(result, vdupq_n_s16(KYBER_Q))));  // Se for >= KYBER_Q, subtrair KYBER_Q

    return result;
}

// Função para reduzir um número sob KYBER_Q
static inline int16_t reduce(int32_t a) {
    int16_t t = (a % KYBER_Q);
    if (t < 0) t += KYBER_Q;
    return t;
}

// Função para calcular a multiplicação e a redução modular
static inline int16_t mod_mul(int16_t a, int16_t b) {
    return reduce((int32_t)a * b);
}

// Função para redução modular
static inline uint16_t mod(uint32_t x) {
    uint16_t r = x % KYBER_Q;
    return r;
}

// Transformada numérica teórica (NTT)
void ntt(uint16_t r[KYBER_N]) {
    unsigned int len, start, j, k = 0;
    int16_t t, zeta;

    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; j++) {
                t = mod_mul(zeta, r[j + len]);
                r[j + len] = reduce(r[j] - t);
                r[j] = reduce(r[j] + t);
            }
        }
    }
}
void ntt_neon(uint16_t r[KYBER_N]) {
    uint16_t len, start, j;
    int16x8_t zeta, t, rj, rjlen, result1, result2;
    int k = 0;

    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = vdupq_n_s16(zetas[k++]);
            for (j = start; j < start + len; j += 8) {
                int16x8_t rj = vld1q_s16((int16_t*)&r[j]);
                int16x8_t rjlen = vld1q_s16((int16_t*)&r[j + len]);

                t = vmulq_s16(zeta, rjlen);
                result1 = vsubq_s16(rj, t);
                result2 = vaddq_s16(rj, t);

                vst1q_s16((int16_t*)&r[j + len], result1);
                vst1q_s16((int16_t*)&r[j], result2);
            }
        }
    }
}

// testada - Está correta.
void invntt(uint16_t f[KYBER_N]) {
    int len, start, j, k = 126;
    uint16_t t, zeta;

    for (len = 2; len <= KYBER_N/2; len <<= 1) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = zetas[k--];
            for (j = start; j < start + len; j++) {
                t = f[j];
                f[j] = barrett_reduce(t + f[j + len]);
                f[j + len] = barrett_reduce(zeta * barrett_reduce(f[j + len] - t + KYBER_Q));
            }
        }
    }

    for (j = 0; j < KYBER_N; j++) {
        f[j] = barrett_reduce(f[j] * 3303);  
    }
}
void invntt_neon(uint16_t f[KYBER_N]) {
    int len, start, j, k = 126;
    int16x8_t t, zeta, fj, fjlen, temp1, temp2;

    for (len = 2; len <= KYBER_N/2; len <<= 1) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = vdupq_n_s16(zetas[k--]);
            for (j = start; j < start + len; j += 8) {
                fj = vld1q_s16((int16_t*)&f[j]);
                fjlen = vld1q_s16((int16_t*)&f[j + len]);

                t = vsubq_s16(fjlen, fj);
                t = vmulq_s16(zeta, barrett_reduce_neon(t + KYBER_Q));
                temp1 = vaddq_s16(fj, fjlen);
                temp2 = vsubq_s16(fjlen, t);

                vst1q_s16((int16_t*)&f[j], barrett_reduce_neon(temp1));
                vst1q_s16((int16_t*)&f[j + len], barrett_reduce_neon(temp2));
            }
        }
    }

    // Normalize
    int16x8_t factor = vdupq_n_s16(3303); // Normalization factor
    for (j = 0; j < KYBER_N; j += 8) {
        int16x8_t val = vld1q_s16((int16_t*)&f[j]);
        val = vmulq_s16(val, factor);
        vst1q_s16((int16_t*)&f[j], barrett_reduce_neon(val));
    }
}


/*
Computes the product of two degree-one polynomials with respect to a quadratic modulus.
Input:  a0,a1,b0,b1 ∈ Zq. ▷ the coeffcients of a0 + a1X and b0 + b1X
Input:  γ ∈ Zq. ▷ the modulus is X^2 −γ
Output: c0,c1 ∈ Zq. ▷ the coeffcients of the product of the two polynomials 
*/
// Função otimizada para multiplicação de polinômios de grau um
static inline nt baseCaseMultiplica(uint16_t a0, uint16_t a1, uint16_t b0, uint16_t b1, uint16_t y) {
    nt result;
    result.c0 = mod(mod_mul(a0, b0) + mod_mul(mod_mul(a1, b1), y));
    result.c1 = mod(mod_mul(a0, b1) + mod_mul(a1, b0));
    return result;
}


/*
Computes the product (in the ring Tq) of two NTT representations.
Input:  Two arrays fˆ ∈ Zq256 and gˆ ∈ Zq256. ▷ the coeffcients of two NTT representations 
Output: An array h^ ∈ Zq256. ▷ the coeffcients of the product of the inputs
*/
void multiplicaNTT(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]) {       
    for (int j=0; j<128; j++) {       
            nt result = baseCaseMultiplica(f[2*j],f[2*j+1],g[2*j],g[2*j+1],zetas2[j]);
            h[2*j] = result.c0;
            h[2*j+1] = result.c1;
    }
       
}
void multiplicaNTT_neon2(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]) {
    int j;
    int16x8_t f0, f1, g0, g1, zeta, c0, c1;

    for (j = 0; j < 128; j += 8) {
        f0 = vld1q_s16((int16_t*)&f[2*j]);
        f1 = vld1q_s16((int16_t*)&f[2*j+1]);
        g0 = vld1q_s16((int16_t*)&g[2*j]);
        g1 = vld1q_s16((int16_t*)&g[2*j+1]);
        zeta = vld1q_s16((int16_t*)&zetas2[j]);

        c0 = vmlaq_s16(vmulq_s16(f0, g0), vmulq_s16(f1, g1), zeta);
        c1 = vaddq_s16(vmulq_s16(f0, g1), vmulq_s16(f1, g0));

        vst1q_s16((int16_t*)&h[2*j], barrett_reduce_neon(c0));
        vst1q_s16((int16_t*)&h[2*j+1], barrett_reduce_neon(c1));
    }
}


// Função modular para reduzir o resultado dentro do intervalo de um módulo especificado
static inline uint16_t mod_neon(int32_t x) {
    x = x % KYBER_Q;
    if (x < 0) {
        x += KYBER_Q;
    }
    return (uint16_t)x;
}

// Função para multiplicação modular
static inline uint16_t mod_mul_neon(uint16_t a, uint16_t b) {
    int32_t temp = a;
    temp *= b;
    return mod_neon(temp);
}

// Realiza a multiplicação de dois polinômios de grau 1 e retorna o resultado em nt
static inline nt baseCaseMultiplicaNeon(uint16_t a0, uint16_t a1, uint16_t b0, uint16_t b1, uint16_t y) {
    nt result;
    result.c0 = mod_neon(mod_mul_neon(a0, b0) + mod_mul_neon(mod_mul_neon(a1, b1), y));
    result.c1 = mod_neon(mod_mul_neon(a0, b1) + mod_mul_neon(a1, b0));
    return result;
}

// Multiplicação de polinômios usando NEON para otimização
void multiplicaNTT_neon(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]) {
   
    
    for (int j = 0; j < KYBER_N / 2; j += 4) { // Processa quatro pares por iteração
        uint16x8_t f_vec = vld1q_u16(&f[2 * j]);       // Carrega f[2j] até f[2j+7]
        uint16x8_t g_vec = vld1q_u16(&g[2 * j]);       // Carrega g[2j] até g[2j+7]
        uint16x8_t z_vec = vld1q_u16(&zetas2[j]);      // Carrega zetas2[j] até zetas2[j+3]

        // Calculando manualmente cada par de índices
        nt result0 = baseCaseMultiplicaNeon(vgetq_lane_u16(f_vec, 0), vgetq_lane_u16(f_vec, 1),
                                        vgetq_lane_u16(g_vec, 0), vgetq_lane_u16(g_vec, 1),
                                        vgetq_lane_u16(z_vec, 0));
        h[2 * j] = result0.c0;
        h[2 * j + 1] = result0.c1;

        nt result1 = baseCaseMultiplicaNeon(vgetq_lane_u16(f_vec, 2), vgetq_lane_u16(f_vec, 3),
                                        vgetq_lane_u16(g_vec, 2), vgetq_lane_u16(g_vec, 3),
                                        vgetq_lane_u16(z_vec, 1));
        h[2 * (j + 1)] = result1.c0;
        h[2 * (j + 1) + 1] = result1.c1;

        nt result2 = baseCaseMultiplicaNeon(vgetq_lane_u16(f_vec, 4), vgetq_lane_u16(f_vec, 5),
                                        vgetq_lane_u16(g_vec, 4), vgetq_lane_u16(g_vec, 5),
                                        vgetq_lane_u16(z_vec, 2));
        h[2 * (j + 2)] = result2.c0;
        h[2 * (j + 2) + 1] = result2.c1;

        nt result3 = baseCaseMultiplicaNeon(vgetq_lane_u16(f_vec, 6), vgetq_lane_u16(f_vec, 7),
                                        vgetq_lane_u16(g_vec, 6), vgetq_lane_u16(g_vec, 7),
                                        vgetq_lane_u16(z_vec, 3));
        h[2 * (j + 3)] = result3.c0;
        h[2 * (j + 3) + 1] = result3.c1;
    }

}

// Tentativa de otimização sem neon

/*
08/06/2024
 Geração de Chaves antes dessa otimização: 
    median: 984 cycles/ticks
    average: 1358 cycles/ticks

Geração de Chaves após essa otimização: 
median: 867 cycles/ticks
average: 1319 cycles/ticks
Todavia, há muitas oscilações nesses resultados chegando até a ultrapassar os valores anteriores quando o teste é repetido
Buscar outra abordagem
*/

// Função para realizar a multiplicação e a redução modular em uma única etapa.
static inline uint16_t mod_mul1(uint16_t a, uint16_t b) {
    int32_t product = (int32_t)a * b;
    return (product + (product >> 15) * KYBER_Q) & 0x7FFF;
}

// Estrutura para armazenar os resultados de multiplicação com dois coeficientes
typedef struct {
    uint16_t c0, c1;
} nt1;

// Função otimizada para multiplicar e reduzir usando a estrutura nt
static inline nt1 baseCaseMultiplica1(uint16_t a0, uint16_t a1, uint16_t b0, uint16_t b1, uint16_t y) {
    nt1 result;
    result.c0 = mod_mul1(a0, b0) + mod_mul1(mod_mul1(a1, b1), y);
    result.c1 = mod_mul1(a0, b1) + mod_mul1(a1, b0);
    result.c0 = mod_mul1(result.c0, 1);  // Redução final para c0
    result.c1 = mod_mul1(result.c1, 1);  // Redução final para c1
    return result;
}

// Função de multiplicação NTT que utiliza a otimização na baseCaseMultiplica
void multiplicaNTT1(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]) {    
    for (int j = 0; j < KYBER_N / 2; j++) {
        nt1 result = baseCaseMultiplica1(f[2*j], f[2*j+1], g[2*j], g[2*j+1], zetas2[j]);
        h[2*j] = result.c0;
        h[2*j+1] = result.c1;
    }
}
