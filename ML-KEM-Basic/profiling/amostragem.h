#include "parametros.h"
#include <stdint.h>
#include <arm_neon.h>

#ifndef AMOSTRAGEM_H
#define AMOSTRAGEM_H

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************************************
If the input is a stream of uniformly random bytes, outputs a sample from the distribution Dη(Rq).
Input:  byte array B ∈ B^(64η).
Output: array f ∈ Zq256. ▷ the coeffcients of the sampled polynomial 
*/
void samplePolyCBD(unsigned char B[], uint16_t f[], uint8_t eta);
static inline uint16x8_t modQ_neon(int16x8_t x);   
void samplePolyCBD_neon(unsigned char B[], uint16_t f[], uint8_t eta);
//*****************************************************************************************************


/*****************************************************************************************************
If the input is a stream of uniformly random bytes, the output is a uniformly random element of Tq.
Input:  byte stream B ∈ B^∗.
Output: array a ∈ Zˆ256 q . ▷ the coeffcients of the NTT of a polynomial 
*/
void sampleNTT(const unsigned char B[], uint16_t a_hat[]);
//void sampleNTT_neon(const unsigned char B[], uint16_t a_hat[], size_t len);
void sampleNTT_neon(const unsigned char B[], uint16_t a_hat[]);
//*****************************************************************************************************

#ifdef __cplusplus
}
#endif

#endif