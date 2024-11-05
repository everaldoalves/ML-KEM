#include <stdint.h>
#include <arm_neon.h>
#include "params.h"
#include "reduce.h"

/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q, where R=2^16
*
* Arguments:   - int32_t a: input integer to be reduced;
*                           has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
**************************************************/
int16_t montgomery_reduce(int32_t a)
{
  int16_t t;

  t = (int16_t)a*QINV;
  t = (a - (int32_t)t*KYBER_Q) >> 16;
  return t;
}

/*************************************************************************************
 * Name:        montgomery_reduce_neon_8
 * 
 * Description: Função de redução de Montgomery para 8 elementos de 16 bits
 * 
 * Arguments:   - prod: vetor de 8 elementos de 32 bits com os produtos a serem reduzidos
 * 
 * Returns:     vetor de 8 elementos de 16 bits com os valores reduzidos
 * ***********************************************************************************/

int16x8_t montgomery_reduce_neon_8(int32x4x2_t prod) {
    int32x4_t low = prod.val[0];
    int32x4_t high = prod.val[1];

    // Passo 1: m = (int16_t)a
    int16x4_t m_low = vmovn_s32(low);
    int16x4_t m_high = vmovn_s32(high);

    // Passo 2: t = m * QINV
    int32x4_t t_low = vmull_s16(m_low, vdup_n_s16(QINV));
    int32x4_t t_high = vmull_s16(m_high, vdup_n_s16(QINV));

    // Passo 3: m = (int16_t)t
    m_low = vmovn_s32(t_low);
    m_high = vmovn_s32(t_high);

    // Passo 4: u = m * KYBER_Q
    int32x4_t u_low = vmull_s16(m_low, vdup_n_s16(KYBER_Q));
    int32x4_t u_high = vmull_s16(m_high, vdup_n_s16(KYBER_Q));

    // Passo 5: t = a - u
    t_low = vsubq_s32(low, u_low);
    t_high = vsubq_s32(high, u_high);

    // Passo 6: t >>= 16
    t_low = vshrq_n_s32(t_low, 16);
    t_high = vshrq_n_s32(t_high, 16);

    // Passo 7: Retornar (int16_t)t
    int16x4_t result_low = vmovn_s32(t_low);
    int16x4_t result_high = vmovn_s32(t_high);

    return vcombine_s16(result_low, result_high);
}

/*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
*
* Arguments:   - int16_t a: input integer to be reduced
*
* Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
**************************************************/
int16_t barrett_reduce(int16_t a) {
  int16_t t;
  const int16_t v = ((1<<26) + (KYBER_Q >> 1))/KYBER_Q;

  t  = ((int32_t)v*a + (1<<25)) >> 26;
  t *= KYBER_Q;
  return a - t;
}

/*************************************************************************************
 * Name:        barret_reduce_neon_8
 * 
 * Description: Função de redução de Barrett para 8 elementos de 16 bits
 * 
 * Arguments:   - ponteiro para poly: polinômio com elementos de 16 bits a serem reduzidos
 * 
 * Returns:     vetor de 8 elementos de 16 bits com os valores reduzidos
 * ***********************************************************************************/

void barrett_reduce_neon_8(int16_t *coeffs) {
  const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
  const int32x4_t v_vec = vdupq_n_s32(v);

  int32x4_t t_vec_low, t_vec_high, a_ext_vec_low, a_ext_vec_high;
  int16x8_t a_vec, result;

  for (unsigned int i = 0; i < KYBER_N; i += 8) {
    // Carregar 8 coeficientes em um vetor NEON
    a_vec = vld1q_s16(&coeffs[i]);

    // Estende os elementos de 16 bits para 32 bits para as operações
    a_ext_vec_low = vmovl_s16(vget_low_s16(a_vec)); 
    a_ext_vec_high = vmovl_s16(vget_high_s16(a_vec));

    // t = ((int32_t)v * a + (1 << 25)) >> 26
    t_vec_low = vmlaq_s32(vdupq_n_s32(1 << 25), v_vec, a_ext_vec_low);
    t_vec_high = vmlaq_s32(vdupq_n_s32(1 << 25), v_vec, a_ext_vec_high);
    t_vec_low = vshrq_n_s32(t_vec_low, 26);
    t_vec_high = vshrq_n_s32(t_vec_high, 26);

    // t *= KYBER_Q
    t_vec_low = vmulq_n_s32(t_vec_low, KYBER_Q);
    t_vec_high = vmulq_n_s32(t_vec_high, KYBER_Q);

    // Resultado final: a - t
    a_ext_vec_low = vsubq_s32(a_ext_vec_low, t_vec_low);
    a_ext_vec_high = vsubq_s32(a_ext_vec_high, t_vec_high);
    
    // Reduzir de volta para 16 bits e armazenar o resultado
    result = vcombine_s16(vmovn_s32(a_ext_vec_low), vmovn_s32(a_ext_vec_high));
    vst1q_s16(&coeffs[i], result);
  }
}
