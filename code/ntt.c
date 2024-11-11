#include <stdint.h>
#include <arm_neon.h>
#include "params.h"
#include "ntt.h"
#include "reduce.h"

#define F_INV 1441 // mont^2/128

const int16_t zetas[128] = {
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
};


/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*
* Arguments:   - int32_t a: input integer to be reduced;
*              - int16_t t: integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
*
* Returns integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q. 
**************************************************/

// Função de redução de Montgomery para 4 elementos de 32 bits retornando 4x16 bits
static inline int16x4_t montgomery_reduce_neon_4(int32x4_t a)
{
    int16x4_t m;
    int32x4_t t, u;

    // Constantes
    const int16x4_t qinv_vec = vdup_n_s16(QINV);   // QINV = -3327
    const int16x4_t q_vec = vdup_n_s16(KYBER_Q);   // KYBER_Q = 3329

    // Passo 1: m = (int16_t)a
    m = vmovn_s32(a);

    // Passo 2: t = m * QINV
    t = vmull_s16(m, qinv_vec);

    // Passo 3: m = (int16_t)t
    m = vmovn_s32(t);

    // Passo 4: u = m * KYBER_Q
    u = vmull_s16(m, q_vec);

    // Passo 5: t = a - u
    t = vsubq_s32(a, u);

    // Passo 6: t >>= 16
    t = vshrq_n_s32(t, 16);

    // Passo 7: Retornar (int16_t)t
    return vmovn_s32(t);
}


// Função vetorizada de Barrett Reduce para 4 elementos de 16 bits
static inline int16x4_t barrett_reduce_neon_4(int16x4_t a_vec) {
  const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
  const int32x4_t v_vec = vdupq_n_s32(v);

  int32x4_t t_vec, a_ext_vec;
  int16x4_t result;

  // Estende os elementos de 16 bits para 32 bits para as operações
  a_ext_vec = vmovl_s16(a_vec); 

  // t = ((int32_t)v * a + (1 << 25)) >> 26
  t_vec = vmlaq_s32(vdupq_n_s32(1 << 25), v_vec, a_ext_vec);
  t_vec = vshrq_n_s32(t_vec, 26);

  // t *= KYBER_Q
  t_vec = vmulq_n_s32(t_vec, KYBER_Q);

  // Resultado final: a - t
  a_ext_vec = vsubq_s32(a_ext_vec, t_vec);
  
  // Reduzir de volta para 16 bits e retornar o resultado
  result = vmovn_s32(a_ext_vec);
  return result;
}

// Função vetorizada de Barrett Reduce para 8 elementos de 16 bits usando int32x4x2_t
static inline int16x8_t barrett_reduce_neon_8_2(int16x8_t a_vec) {
  const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
  const int32x4_t v_vec = vdupq_n_s32(v);

  int32x4x2_t t_vec, a_ext_vec;
  int16x8_t result;

  // Estende os elementos de 16 bits para 32 bits para as operações
  a_ext_vec.val[0] = vmovl_s16(vget_low_s16(a_vec));
  a_ext_vec.val[1] = vmovl_s16(vget_high_s16(a_vec));

  // t = ((int32_t)v * a + (1 << 25)) >> 26
  t_vec.val[0] = vmlaq_s32(vdupq_n_s32(1 << 25), v_vec, a_ext_vec.val[0]);
  t_vec.val[1] = vmlaq_s32(vdupq_n_s32(1 << 25), v_vec, a_ext_vec.val[1]);
  t_vec.val[0] = vshrq_n_s32(t_vec.val[0], 26);
  t_vec.val[1] = vshrq_n_s32(t_vec.val[1], 26);

  // t *= KYBER_Q
  t_vec.val[0] = vmulq_n_s32(t_vec.val[0], KYBER_Q);
  t_vec.val[1] = vmulq_n_s32(t_vec.val[1], KYBER_Q);

  // Resultado final: a - t
  a_ext_vec.val[0] = vsubq_s32(a_ext_vec.val[0], t_vec.val[0]);
  a_ext_vec.val[1] = vsubq_s32(a_ext_vec.val[1], t_vec.val[1]);

  // Reduzir de volta para 16 bits e retornar o resultado
  result = vcombine_s16(vmovn_s32(a_ext_vec.val[0]), vmovn_s32(a_ext_vec.val[1]));
  return result;
}

/*************************************************
* Name:        fqmul
*
* Description: Multiplication followed by Montgomery reduction
*
* Arguments:   - int16_t a: first factor
*              - int16_t b: second factor
*
* Returns 16-bit integer congruent to a*b*R^{-1} mod q
**************************************************/

static int16_t fqmul(int16_t a, int16_t b) {
  return montgomery_reduce((int32_t)a*b);
}

// Versão vetorizada de fqmul que usa montgomery_reduce_neon_4
static int16x4_t fqmul_neon_4(int16x4_t a_vec, int16x4_t b_vec) {
  int32x4_t product_vec = vmull_s16(a_vec, b_vec);
  return montgomery_reduce_neon_4(product_vec);
}


/*************************************************
* Name:        ntt
*
* Description: Inplace number-theoretic transform (NTT) in Rq.
*              input is in standard order, output is in bitreversed order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/

void ntt(int16_t r[256]) {
    unsigned int len, start, j, k;
    int16_t zeta;
    k = 1;

    // Estágios maiores, onde podemos usar NEON para processar 8 elementos por vez
    for (len = 128; len >= 8; len >>= 1) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = zetas[k++];

            // Carregar zeta em um vetor NEON para operações vetorizadas
            int16x8_t zeta_vec = vdupq_n_s16(zeta);

            for (j = start; j < start + len; j += 8) {
                // Carregar os coeficientes r[j] e r[j + len] em vetores NEON
                int16x8_t r_vec = vld1q_s16(&r[j]);           // r[j] (8 coeficientes)
                int16x8_t r_len_vec = vld1q_s16(&r[j + len]); // r[j + len] (8 coeficientes)

                // Multiplicar r[j + len] por zeta (Montgomery reduction)
                int32x4x2_t prod_vec;
                prod_vec.val[0] = vmull_s16(vget_low_s16(r_len_vec), vget_low_s16(zeta_vec));
                prod_vec.val[1] = vmull_s16(vget_high_s16(r_len_vec), vget_high_s16(zeta_vec));
                int16x8_t t_vec = montgomery_reduce_neon_8(prod_vec);

                // Realizar as operações da borboleta (NTT butterfly)
                int16x8_t r_new_len = vsubq_s16(r_vec, t_vec);  // r[j + len] = r[j] - t
                int16x8_t r_new = vaddq_s16(r_vec, t_vec);      // r[j] = r[j] + t

                // Armazenar os resultados de volta no array
                vst1q_s16(&r[j + len], r_new_len);  // Atualizar r[j + len]
                vst1q_s16(&r[j], r_new);            // Atualizar r[j]
            }
        }
    }

    // Estágios menores, onde o uso de NEON não faz sentido (len = 2, 1)
    for (len = 4; len > 1; len >>= 1) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = zetas[k++];

            for (j = start; j < start + len; ++j) {
                int16_t t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}


/*************************************************
* Name:        invntt_tomont
*
* Description: Inplace inverse number-theoretic transform in Rq and
*              multiplication by Montgomery factor 2^16.
*              Input is in bitreversed order, output is in standard order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/

// Versão para 4 elementos por vez. Funciona corretamente e é mais eficiente do que a versão para 8 elementos por vez
void invntt(int16_t r[256]) {
  unsigned int len, start, j, k;
  int16_t zeta;
  const int16_t f = 1441; // mont^2/128
  int16x4_t f_vec = vdup_n_s16(f); // Vetor com os valores de f  
  int32x4_t prod_vec;
  k = 127;

  // Caso especial: len = 2
  len = 2;
    for(start = 0; start < 256; start += 2 * len) {
      zeta = zetas[k--];
      for(j = start; j < start + len; j++) {
        int16_t t = r[j];
        r[j] = barrett_reduce(t + r[j + len]);      
        r[j + len] = r[j + len] - t;
        r[j + len] = fqmul(zeta, r[j + len]);
      }
    }

  // Para len >= 8, utilizamos vetorização
  for(len = 4; len <= 128; len <<= 1) {
    for(start = 0; start < 256; start += 2 * len) {
      zeta = zetas[k--];
      int16x4_t zeta_vec = vdup_n_s16(zeta); // Vetor com os valores de zeta
      
      for(j = start; j < start + len; j += 4) {
        // Carrega os coeficientes
        int16x4_t t_vec = vld1_s16(&r[j]);
        int16x4_t r_vec = vld1_s16(&r[j + len]);

        // Calcula r[j] = barrett_reduce(t + r[j + len]);
        int16x4_t sum_vec = vadd_s16(t_vec, r_vec);
        sum_vec = barrett_reduce_neon_4(sum_vec);
        vst1_s16(&r[j], sum_vec);

        // Calcula r[j + len] = t - r[j + len];        
        int16x4_t diff_vec = vsub_s16(r_vec, t_vec);

        // Calcula r[j + len] = fqmul(zeta, r[j + len]);
        prod_vec = vmull_s16(diff_vec, zeta_vec);
        diff_vec = montgomery_reduce_neon_4(prod_vec);
        vst1_s16(&r[j + len], diff_vec);
      }
    }
  }

  // Multiplicação final por f
  for(j = 0; j < 256; j += 4) {
    int16x4_t r_vec = vld1_s16(&r[j]);
    prod_vec = vmull_s16(r_vec, f_vec);
    r_vec = montgomery_reduce_neon_4(prod_vec);
    vst1_s16(&r[j], r_vec);
  }
}


/*************************************************
* Name:        basemul
*
* Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
*              used for multiplication of elements in Rq in NTT domain
*
* Arguments:   - int16_t r[2]: pointer to the output polynomial
*              - const int16_t a[2]: pointer to the first factor
*              - const int16_t b[2]: pointer to the second factor
*              - int16_t zeta: integer defining the reduction polynomial
**************************************************/
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
  r[0]  = fqmul(a[1], b[1]);
  r[0]  = fqmul(r[0], zeta);
  r[0] += fqmul(a[0], b[0]);
  r[1]  = fqmul(a[0], b[1]);
  r[1] += fqmul(a[1], b[0]);
}


// Esta versão de otimização está correta. Foi testada com sucesso
void basemul_neon(int16_t r[8], const int16_t a[8], const int16_t b[8], int16_t zeta, int16_t zeta_next) {    
     // Carrega os elementos de a e b necessários para as multiplicações em vetores de 16 bits
    int16x4_t a_vals = {a[1], a[3], a[5], a[7]};
    int16x4_t b_vals = {b[1], b[3], b[5], b[7]};

    // Realiza a multiplicação vetorizada, produzindo resultados de 32 bits
    int32x4_t intermediates = vmull_s16(a_vals, b_vals);

    // Aplica a redução Montgomery em paralelo
    int16x4_t reduced_vals = montgomery_reduce_neon_4(intermediates);

    // Multiplicação com zetas    
    //int16x4_t zeta_vals = {zeta, -zeta, zeta_next, -zeta_next};
    int16x4_t zeta_vals = {zeta,static_cast<int16_t>(-zeta), zeta_next,static_cast<int16_t>(-zeta_next)};
    int32x4_t final_intermediates = vmull_s16(reduced_vals, zeta_vals);

    // Realiza a segunda redução Montgomery em paralelo nos produtos com zeta
    int16x4_t final_reduced_vals = montgomery_reduce_neon_4(final_intermediates);

    // Carrega os elementos a[0], a[2], a[4], a[6] e b[0], b[2], b[4], b[6] para multiplicação adicional
    int16x4_t a_base_vals = {a[0], a[2], a[4], a[6]};
    int16x4_t b_base_vals = {b[0], b[2], b[4], b[6]};

    // Multiplicação adicional e redução em paralelo
    int32x4_t base_intermediates = vmull_s16(a_base_vals, b_base_vals);
    int16x4_t base_reduced_vals = montgomery_reduce_neon_4(base_intermediates);

    // Soma dos resultados reduzidos ao resultado final
    int16x4_t final_result = vadd_s16(final_reduced_vals, base_reduced_vals);

    // Extração dos valores finais
    int16_t r0 = vget_lane_s16(final_result, 0);
    int16_t r2 = vget_lane_s16(final_result, 1);
    int16_t r4 = vget_lane_s16(final_result, 2);
    int16_t r6 = vget_lane_s16(final_result, 3);


   // Carrega os elementos necessários para as multiplicações cruzadas em vetores de 16 bits
    int16x4_t a_even = {a[0], a[2], a[4], a[6]};
    int16x4_t a_odd = {a[1], a[3], a[5], a[7]};
    int16x4_t b_odd = {b[1], b[3], b[5], b[7]};
    int16x4_t b_even = {b[0], b[2], b[4], b[6]};

    // Multiplicação cruzada
    int32x4_t cross_mult1 = vmull_s16(a_even, b_odd); // a[0]*b[1], a[2]*b[3], a[4]*b[5], a[6]*b[7]
    int32x4_t cross_mult2 = vmull_s16(a_odd, b_even); // a[1]*b[0], a[3]*b[2], a[5]*b[4], a[7]*b[6]

    // Armazena os resultados em um vetor int32x4x2
    int32x4x2_t cross_results = {cross_mult1, cross_mult2};

    // Redução Montgomery em paralelo
    int16x4_t reduced_cross1 = montgomery_reduce_neon_4(cross_results.val[0]);
    int16x4_t reduced_cross2 = montgomery_reduce_neon_4(cross_results.val[1]);

    // Somando resultados reduzidos das multiplicações cruzadas
    int16x4_t combined_cross = vadd_s16(reduced_cross1, reduced_cross2);

    // Extração dos valores finais
    int16_t r1 = vget_lane_s16(combined_cross, 0);
    int16_t r3 = vget_lane_s16(combined_cross, 1);
    int16_t r5 = vget_lane_s16(combined_cross, 2);
    int16_t r7 = vget_lane_s16(combined_cross, 3);

// Carregar todos os resultados em um vetor Neon de 8 elementos
    int16x8_t result = {r0, r1, r2, r3, r4, r5, r6, r7};

    // Armazena o vetor no array de saída
    vst1q_s16(r, result);
}

