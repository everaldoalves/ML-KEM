#include <stdint.h>
#include <arm_neon.h>
#include "params.h"
#include "cbd.h"

/*************************************************
* Name:        load32_littleendian
*
* Description: load 4 bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/
static uint32_t load32_littleendian(const uint8_t x[4])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}

/*************************************************
* Name:        load24_littleendian
*
* Description: load 3 bytes into a 32-bit integer
*              in little-endian order.
*              This function is only needed for Kyber-512
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
**************************************************/
#if KYBER_ETA1 == 3
static uint32_t load24_littleendian(const uint8_t x[3])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}
#endif


/*************************************************
* Name:        cbd2
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=2
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
static void cbd2(poly *r, const uint8_t buf[2 * KYBER_N / 4]) {
    unsigned int i;
    uint32_t t, d;
    int16_t a0, b0, a1, b1, a2, b2, a3, b3, a4, b4, a5, b5, a6, b6, a7, b7;

    for (i = 0; i < KYBER_N / 8; i++) {
        // Carrega e processa os bits com uma única operação, mantendo as máscaras aplicadas
        t = load32_littleendian(buf + 4 * i);
        d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        // Pré-calcula os valores `a` e `b` para cada posição `j`
        a0 = (d >> 0) & 0x3;
        b0 = (d >> 2) & 0x3;
        r->coeffs[8 * i + 0] = a0 - b0;

        a1 = (d >> 4) & 0x3;
        b1 = (d >> 6) & 0x3;
        r->coeffs[8 * i + 1] = a1 - b1;

        a2 = (d >> 8) & 0x3;
        b2 = (d >> 10) & 0x3;
        r->coeffs[8 * i + 2] = a2 - b2;

        a3 = (d >> 12) & 0x3;
        b3 = (d >> 14) & 0x3;
        r->coeffs[8 * i + 3] = a3 - b3;

        a4 = (d >> 16) & 0x3;
        b4 = (d >> 18) & 0x3;
        r->coeffs[8 * i + 4] = a4 - b4;

        a5 = (d >> 20) & 0x3;
        b5 = (d >> 22) & 0x3;
        r->coeffs[8 * i + 5] = a5 - b5;

        a6 = (d >> 24) & 0x3;
        b6 = (d >> 26) & 0x3;
        r->coeffs[8 * i + 6] = a6 - b6;

        a7 = (d >> 28) & 0x3;
        b7 = (d >> 30) & 0x3;
        r->coeffs[8 * i + 7] = a7 - b7;
        
    }
}

/*************************************************
* Name:        cbd3
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=3.
*              This function is only needed for Kyber-512
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
#if KYBER_ETA1 == 3

static void cbd3(poly *r, const uint8_t buf[3 * KYBER_N / 4]) {
    unsigned int i;
    uint32_t t, d;
    int16_t a0, a1, a2, a3, b0, b1, b2, b3;

    for (i = 0; i < KYBER_N / 4; i++) {
        // Carrega 24 bits de buf
        t = load24_littleendian(buf + 3 * i);

        // Passo de máscara e soma de bits
        d  = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        // Desenrolando o loop
        a0 = (d >> (6 * 0 + 0)) & 0x7;
        b0 = (d >> (6 * 0 + 3)) & 0x7;
        r->coeffs[4 * i + 0] = a0 - b0;

        a1 = (d >> (6 * 1 + 0)) & 0x7;
        b1 = (d >> (6 * 1 + 3)) & 0x7;
        r->coeffs[4 * i + 1] = a1 - b1;

        a2 = (d >> (6 * 2 + 0)) & 0x7;
        b2 = (d >> (6 * 2 + 3)) & 0x7;
        r->coeffs[4 * i + 2] = a2 - b2;

        a3 = (d >> (6 * 3 + 0)) & 0x7;
        b3 = (d >> (6 * 3 + 3)) & 0x7;
        r->coeffs[4 * i + 3] = a3 - b3;    
    }
}
#endif

void poly_cbd_eta1(poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4])
{
#if KYBER_ETA1 == 2
  cbd2(r, buf);
#elif KYBER_ETA1 == 3
  cbd3(r, buf);
#else
#error "This implementation requires eta1 in {2,3}"
#endif
}

void poly_cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4])
{
#if KYBER_ETA2 == 2
  cbd2(r, buf);
#else
#error "This implementation requires eta2 = 2"
#endif
}

