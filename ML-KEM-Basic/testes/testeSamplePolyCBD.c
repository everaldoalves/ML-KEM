#include <arm_neon.h>
#include <stdio.h>
#include "parametros.h"
#include <stdlib.h>
#include <time.h>

// Teste Unitário da Função SamplePolyCBD
// 08/06/2024 - Os testes foram insatisfatórios. Os resultados sempre retornam 175 elementos diferentes entre as funções.


void gerar_bytes_aleatorios_vetor(int N, unsigned char vetor[]) {
    // Inicializa a semente com o tempo atual
    srand(time(NULL));

    // Gera N bytes aleatórios e armazena no vetor
    for (int i = 0; i < N; i++) {
        vetor[i] = rand() % 256;
    }
}

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


int main() {
    printf("Testando a função samplePolyCBD \n\n");
    uint16_t poly1[KYBER_N],poly2[KYBER_N];
    uint8_t bytes[64*KYBER_ETA1];
    uint8_t erros= 0;
    uint16_t lenghtTeste = 1000;

    for (int n=0; n < lenghtTeste; n++) {
        erros = 0;
        printf("\n Teste %d \n", n);

        gerar_bytes_aleatorios_vetor(64*KYBER_ETA1,bytes); 

        samplePolyCBD(bytes,poly1,KYBER_ETA1);
        samplePolyCBD_neon(bytes,poly2,KYBER_ETA1);

        for (int i=0; i<KYBER_N; i++) {
            printf("\n Índice %d : poly1 x poly2 => %d x %d", i, poly1[i], poly2[i]);
            if (poly1[i]!=poly2[i]) {
                printf("\n Erro encontrado!");
                erros = erros +1;
            }
        }
        
        printf("\n\n ERROS = %d \n\n",erros);
        if (erros==0) {
            printf("BEM-SUCEDIDO!\n");
        }    
    }

}

