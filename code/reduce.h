#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "params.h"

#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16

#define montgomery_reduce KYBER_NAMESPACE(montgomery_reduce)
int16_t montgomery_reduce(int32_t a);

#define barrett_reduce KYBER_NAMESPACE(barrett_reduce)
int16_t barrett_reduce(int16_t a);

#define barrett_reduce_neon_8 KYBER_NAMESPACE(barrett_reduce_neon_8)
void barrett_reduce_neon_8(int16_t *coeffs);

#define montgomery_reduce_neon_8 KYBER_NAMESPACE(montgomery_reduce_neon_8)
int16x8_t montgomery_reduce_neon_8(int32x4x2_t prod);

#endif
