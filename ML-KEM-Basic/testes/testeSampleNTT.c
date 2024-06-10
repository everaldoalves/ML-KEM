#include <arm_neon.h>
#include <stdio.h>
#include "parametros.h"
#include <stdlib.h>
#include <time.h>


void gerar_bytes_aleatorios_vetor(int N, unsigned char vetor[]) {
    // Inicializa a semente com o tempo atual
    srand(time(NULL));

    // Gera N bytes aleatórios e armazena no vetor
    for (int i = 0; i < N; i++) {
        vetor[i] = rand() % 256;
    }
}

/*
If the input is a stream of uniformly random bytes, the output is a uniformly random element of Tq.
Input  : byte stream B ∈ B^∗ 
Output : array aˆ ∈ Zq256
*/

void sampleNTT_generica(const unsigned char B[], uint16_t a[]) {    

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


void sampleNTT_otimizada(const uint8_t B[], uint16_t a[], size_t len) {
    size_t i = 0, j = 0;

    while (j < KYBER_N && i + 2 < len) {
        uint8x8x3_t vec = vld3_u8(&B[i]);

        uint16_t d1 = vec.val[0][0] + 256 * (vec.val[1][0] & 0x0F);
        uint16_t d2 = (vec.val[1][0] >> 4) + 16 * vec.val[2][0];

        if (d1 < KYBER_Q) {
            a[j++] = d1;
        }

        if (d2 < KYBER_Q && j < KYBER_N) {
            a[j++] = d2;
        }

        i += 3;
    }
}

int main() {
    printf("Testando a função SampleNTT \n\n");
    uint16_t poly1[KYBER_N],poly2[KYBER_N];
    uint8_t bytes[738];
    uint8_t erros= 0;
    uint16_t lenghtTeste = 1000;

    for (int n=0; n < lenghtTeste; n++) {
        erros = 0;
        printf("\n Teste %d \n", n);

        gerar_bytes_aleatorios_vetor(738,bytes); 

        sampleNTT_generica(bytes,poly1);
        sampleNTT_otimizada(bytes,poly2,sizeof(bytes));

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

