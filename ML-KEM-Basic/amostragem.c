
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "parametros.h"
#include "amostragem.h"
#include "auxiliares.h"
#include <arm_neon.h>
#include "fips202.h"

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
// Implementação usando a especificação FIPS 202
void sampleNTT_XOF(uint16_t *a, const uint8_t *rho, uint8_t i, uint8_t j) {    
    uint8_t buffer[3 * KYBER_N]; // Tamanho inicial
    size_t buffer_index = 0;
    size_t a_index = 0;

    // Preparando para o uso de SHAKE128
    keccak_state state;
    uint8_t input[34];
    memcpy(input, rho, 32);
    input[32] = i;
    input[33] = j;

    shake128_absorb(&state, input, 34);
    shake128_squeezeblocks(buffer, 1, &state);

    // Preencher todos os coeficientes
    while (a_index < KYBER_N) {
        if (buffer_index + 2 >= sizeof(buffer)) {
            shake128_squeezeblocks(buffer, 1, &state);
            buffer_index = 0;
        }

        uint16_t d1 = buffer[buffer_index] + 256 * (buffer[buffer_index + 1] & 0x0F);
        uint16_t d2 = (buffer[buffer_index + 1] >> 4) + 16 * buffer[buffer_index + 2];

        if (d1 < KYBER_Q) {
            a[a_index++] = d1;
        }

        if (d2 < KYBER_Q && a_index < KYBER_N) {
            a[a_index++] = d2;
        }

        buffer_index += 3;
    }
}

void sampleNTT_neon(const unsigned char B[], uint16_t a[]) {
    int i = 0;
    int j = 0;
    uint16x8_t q_vector = vdupq_n_u16(KYBER_Q);  // Carrega KYBER_Q em todos os elementos do vetor

    while (j < KYBER_N) {
        uint8x16_t B_vector = vld1q_u8(&B[i]); // Carrega 16 bytes

        // Extrai e combina os bytes para formar os valores
        uint16x8_t d1 = vmovl_u8(vget_low_u8(B_vector));
        uint16x8_t d2 = vmovl_u8(vget_high_u8(B_vector));

        // Aplica a máscara e shift para obter os valores finais de d1 e d2
        uint16x8_t mask = vdupq_n_u16(0x0F);
        uint16x8_t d1_low = vandq_u16(d1, mask);
        uint16x8_t d1_high = vshrq_n_u16(d1, 4);

        // Valores finais
        d1 = vaddq_u16(vmulq_n_u16(d1_low, 256), d1_high);
        d2 = vaddq_u16(vmulq_n_u16(vshrq_n_u16(d2, 4), 256), vandq_u16(d2, mask));

        // Verifica se os valores são menores que KYBER_Q
        uint16x8_t cmp1 = vcgtq_u16(q_vector, d1); // Comparação para d1
        uint16x8_t cmp2 = vcgtq_u16(q_vector, d2); // Comparação para d2

        // Store se menor que KYBER_Q
        vst1q_u16(&a[j], vbslq_u16(cmp1, d1, vdupq_n_u16(0))); // Armazena d1 se verdadeiro
        vst1q_u16(&a[j + 8], vbslq_u16(cmp2, d2, vdupq_n_u16(0))); // Armazena d2 se verdadeiro

        i += 16;
        j += 16; // Atualiza o índice do array 'a'
    }
}

/*
If the input is a stream of uniformly random bytes, outputs a sample from the distribution Dη(Rq).
Input:  byte array B ∈ B^64η.
Output: array f ∈ Zq256. ▷ the coeffcients of the sampled polynomial 
*/
/*
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
    
    printf("\n \n Exibição do vetor f dentro da função samplePolyCBD :\n");
    for (int i=0; i< 256; i++) {
        printf(" %d", f[i]);
    }
    
}
*/

// Função static inline para calcular módulo KYBER_Q
static inline int16_t modQ(int16_t x) {
    x = x % KYBER_Q;
    if (x < 0)
        x += KYBER_Q;
    return x;
}

// Função otimizada para amostragem do polinômio
void samplePolyCBD(unsigned char B[], uint16_t f[], uint8_t eta) {
    int i, j, x, y, idx;

    for (i = 0; i < 256; i++) {
        x = 0;
        y = 0;

        for (j = 0; j < eta; j++) {
            idx = 2 * i * eta + j;
            x += (B[idx / 8] >> (idx % 8)) & 1;
            y += (B[(idx + eta) / 8] >> ((idx + eta) % 8)) & 1;
        }

        // Usa a função inline para o cálculo do módulo
        f[i] = modQ(x - y);
    }
}

static inline uint16x8_t modQ_neon(int16x8_t x) {
    int16x8_t q_vector = vdupq_n_s16(KYBER_Q);
    uint16x8_t less_zero = vcltq_s16(x, vdupq_n_s16(0));
    int16x8_t adjusted = vaddq_s16(x, q_vector);
    return vbslq_u16(less_zero, adjusted, x);
}

void samplePolyCBD_neon(unsigned char B[], uint16_t f[], uint8_t eta) {
    uint8x16_t mask = vdupq_n_u8(0x01); // Máscara para isolar o bit menos significativo
    uint16x8_t zero = vdupq_n_u16(0); // Zero vector
    int16x8_t q_vector = vdupq_n_s16(KYBER_Q);

    for (int i = 0; i < 256; i += 8) {
        uint16x8_t x = zero, y = zero;

        for (int j = 0; j < eta; j++) {
            uint8x16_t b = vld1q_u8(&B[(2*i*eta + j) / 8]);
            uint8x16_t x_bits = vandq_u8(b, mask);
            uint8x16_t y_bits = vandq_u8(vld1q_u8(&B[(2*i*eta + eta + j) / 8]), mask);

            // Convert bit counts to 16-bit integers and accumulate
            x = vaddq_u16(x, vpaddlq_u8(x_bits));
            y = vaddq_u16(y, vpaddlq_u8(y_bits));
        }

        // Compute x - y for each set of 8 coefficients
        int16x8_t diff = vsubq_s16(vreinterpretq_s16_u16(x), vreinterpretq_s16_u16(y));

        // Modular reduction
        uint16x8_t result = modQ_neon(diff);

        // Store the result
        vst1q_u16(&f[i], result);
    }
}
