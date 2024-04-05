#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "cores.h"
#include "ntt.h"
#include "parametros.h"

/*********************************************************************************
TESTE das Funções referentes aos algorítmos NTT do ML-KEM FIPS 203 ipd
Input: array f ∈ Zq256.   ▷ the coeffcients of the input polynomial KYBER_Q
Output: array fˆ ∈ Zq256 
*********************************************************************************/


void geraElementosParaMatriz(uint16_t matriz[KYBER_K][KYBER_K]) {    
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_K; j++) {
           matriz[i][j] = rand() % KYBER_Q;
        }
    }    
}

void geraElementosParaVetor(uint16_t vetor[KYBER_K][KYBER_N]) {
    for (int i = 0; i < KYBER_K; i++) {      
        for (int j=0; j < KYBER_N; j++) {
            vetor[i][j] = rand() % KYBER_Q;
        }
    }    
}

// Esta função só está aqui para ajudar a preencher os vetores com números cuja NTT é conhecida. Pode ser removida
void geraDoidoElementosParaVetor(uint16_t vetor[KYBER_K][KYBER_N]) {
    for (int i = 0; i < KYBER_K; i++) {              
        for (int j=0; j < KYBER_N; j++) {
            if (i==1) {
                vetor[i][j] = j;
            }
            else {
                if (j==0 || j==1) {
                    vetor[i][j] = 1;
                }
                else {
                    vetor[i][j] = 0;
                }
            }
        }
    }    
}
// Idem a anterior para auxiliar no cálculo da multiplicação com valores conhedidos ou seja a inversão dos valores gerados na função anterior
void inverteElementosDoido(uint16_t vetor[KYBER_K][KYBER_N]) {
    int aux[KYBER_N];
    for (int i=0; i< KYBER_K; i++) {
        for (int j=0; j < KYBER_N; j++) {
            if (i==0) {
                aux[j] = vetor[i][j];
                vetor[i][j] = vetor[i+1][j];
            }
            else {
                vetor[i][j] = aux[j];    
            }
        }
    }
}

void exibeVetor(uint16_t vetor[KYBER_K][KYBER_N]) {
    printf("\n \x1b[97;1m Exibição do Vetor de %d posições e %d elementos : \x1b[0m", KYBER_K,KYBER_N);
    for(int i=0; i < KYBER_K; i++) {     
        printf("\n \x1b[33m Elementos da posição %d : \x1b[0m", i);
        for (int j=0; j < KYBER_N; j++) {
            printf("%5d ", vetor[i][j]);            
        
        }
    }
}

int main () {
    setlocale(LC_ALL, "Portuguese"); // define acentuação para língua portuguesa

    uint16_t v[KYBER_K][KYBER_N];
    uint16_t u[KYBER_K][KYBER_N];
    uint16_t x[KYBER_K][KYBER_N];

    memset(v, 0, sizeof(v)); // Inicializa o vetor com zero
    memset(u, 0, sizeof(v)); // Inicializa o vetor com zero
    memset(x, 0, sizeof(v)); // Inicializa o vetor com zero

    // Armazena o valor atual retornado por time(NULL) em uma variável
    time_t seed = time(NULL);
    
    // Mostra o valor da semente na tela
    printf("Valor da semente: %ld\n", (long)seed);
    
    // Inicializa o gerador de números aleatórios com a semente
    srand(seed);

    geraDoidoElementosParaVetor(v);
    memcpy(u, v, sizeof(v));
    inverteElementosDoido(u);

    printf("\n\n \x1b[36m ****************************************************************************\n"); 
    printf("  *                                 Elementos originais  (f,g)                    * ");
    printf("\n  **************************************************************************** \x1b[0m \n"); 

    exibeVetor(v);
    printf("\n");
    exibeVetor(u);
    

    printf("\n\n \x1b[32m ****************************************************************************\n"); 
    printf("  *  Elementos no domínio Tq   (f^,g^))  * ");
    printf("\n  **************************************************************************** \x1b[0m \n"); 
    ntt(v);     
    ntt(u);
    exibeVetor(v);
    exibeVetor(u);

    printf("\n\n \x1b[29m ****************************************************************************\n"); 
    printf("  *  Multiplicação no domínio Tq  (h^ = f^ x g^)         * ");
    printf("\n  **************************************************************************** \x1b[0m \n"); 
    multiplicaNTT(u,v,x);
    exibeVetor(x);
    

    printf("\n\n \x1b[35m ****************************************************************************\n"); 
    printf("  *  Resultado da multiplicação transformado para o domínio Rq  (InvNTT(h^))   * ");
    printf("\n  **************************************************************************** \x1b[0m \n"); 
    invntt(x);
    exibeVetor(x);
    
   // v = [[606, 1507, 1110, 2747, 212, 32, 1723, 961, 1675, 2392, 2690, 1874, 337, 2816, 2740, 2980, 3030, 479, 3224, 556, 2228, 2463, 3298, 549, 1736, 1492, 112, 2078, 1604, 3017, 2234, 2019, 1893, 1947, 2745, 1344, 1664, 167, 249, 2637, 2546, 3248, 146, 2387, 2112, 3043, 1322, 2946, 1020, 1235, 1729, 2617, 3006, 2530, 752, 916, 457, 2782, 1594, 953, 2991, 2450, 2901, 446, 1233, 1143, 1268, 2643, 2269, 1374, 1018, 561, 835, 1644, 1590, 1662, 1085, 1400, 3287, 1336, 141, 1510, 1886, 2696, 1855, 1291, 515, 657, 2833, 1455, 172, 2632, 284, 1775, 3119, 263, 2299, 2948, 867, 1642, 519, 3151, 374, 2618, 2567, 39, 1936, 1344, 635, 1451, 3238, 466, 507, 1533, 1855, 2651, 875, 538, 3139, 1663, 2842, 1317, 1652, 718, 192, 1165, 231, 352, 922, 211, 2355, 318, 1243, 2904, 1336, 2741, 481, 218, 1099, 2327, 673, 919, 248, 2887, 2057, 1008, 298, 2992, 510, 1537, 369, 588, 372, 1424, 1173, 1001, 2412, 1377, 248, 1520, 3188, 2865, 2676, 936, 431, 2046, 2217, 1216, 1940, 1964, 1815, 1439, 409, 2334, 1979, 1315, 2126, 2666, 1589, 2327, 513, 1666, 2331, 1892, 1939, 2872, 1458, 1753, 1489, 2931, 2733, 3019, 2191, 3030, 1692, 710, 2514, 348, 786, 2219, 1227, 2399, 146, 3149, 3038, 1142, 820, 350, 1606, 2989, 1606, 460, 3114, 2765, 3060, 1755, 2104, 1818, 2700, 2134, 2764, 2496, 1180, 1143, 176, 1168, 1344, 1813, 565, 761, 2982, 1471, 1453, 1594, 2556, 1844, 56, 3128, 719, 113, 3031, 1561, 1612, 2396, 2888, 2143, 2703, 752, 16, 694, 509, 2140, 2593, 785, 3124, 11],[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]];
   invntt(v);
   exibeVetor(v);

  // validaTransformada(v);
  
   
}
