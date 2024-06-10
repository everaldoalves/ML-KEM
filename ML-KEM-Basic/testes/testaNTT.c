#include <arm_neon.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "cores.h"
#include "parametros.h"
#include <arm_neon.h>

/*********************************************************************************
TESTE das Funções referentes aos algorítmos NTT do ML-KEM FIPS 203 ipd
Input: array f ∈ Zq256.   ▷ the coeffcients of the input polynomial KYBER_Q
Output: array fˆ ∈ Zq256 
Utiliza uma implementação não performática, porém correta para realizar a compara-
ção dos resultados
*********************************************************************************/

// Define a estrutura para armazenar um par de inteiros
typedef struct {
    int c0;
    int c1;
} nt;

/*********************************************************************************
Funções referentes à implementação CORRETA
Implementação A
*********************************************************************************/

// Calcula a^b mod q
int power(int x, int y) { 
    int result = 1;  
    while (y > 0) {
        result = (result * x) % KYBER_Q;
        y--;
    }
    return (result < 0) ? result + KYBER_Q : result;
}

// Calcula o bit reverso
int BitRev7(int i) {
    int reverse = 0;
    for (int j = 0; j < 7; j++) {
        reverse = (reverse << 1) | (i & 1);
        i >>= 1;
    }
    return reverse % KYBER_Q;
}

/*
Computes the NTT representation fˆ of the given polynomial f ∈ Rq.
Input: array f ∈ Zq256. ▷ the coeffcients of the input polynomial 
Output: array fˆ ∈ Zq256. ▷ the coeffcients of the NTT of the input polynomial 
*/
void nttA(uint16_t f[KYBER_N]) {
    int len, start, j, k = 1;
    uint16_t t, zeta;

    for (len = 128; len >= 2; len /= 2) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = power(KYBER_Z, BitRev7(k)); 
            k++;
            for (j = start; j < start + len; j++) {
                t = (zeta * f[j + len]) % KYBER_Q;
                f[j + len] = (f[j] + KYBER_Q - t) % KYBER_Q;
                f[j] = (f[j] + t) % KYBER_Q;
            }
        }
    }
}

/*
Computes the polynomial f ∈ Rq corresponding to the given NTT representation fˆ ∈ Tq.
Input:  array fˆ ∈ Zq256. ▷ the coeffcients of input NTT representation 
Output: array f ∈ Zq256. ▷ the coeffcients of the inverse-NTT of the input 
*/
void invnttA(uint16_t f[KYBER_N]) {
    int len, start, j, k = 127;
    uint16_t t, zeta;
   // printf("INVNTTA - zeta = ");
    for (len = 2; len <= 128; len *= 2) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = power(KYBER_Z, BitRev7(k)); 
            //printf("INVNTTA - zeta = %d \n",zeta);
            k--;
            for (j = start; j < start + len; j++) {
                t = f[j];
                f[j] = (t + f[j + len]) % KYBER_Q;
                f[j + len] = (zeta * (KYBER_Q + f[j + len] - t)) % KYBER_Q;
            }
        }
    }

    // Normalização
    for (j = 0; j < KYBER_N; j++) {
        f[j] = (f[j] * 3303) % KYBER_Q; // 3303 é o inverso de 256 mod KYBER_Q
    }
}
// Verifica se a NTT e a INTT correspondem
void validaTransformadaA(uint16_t vetor[KYBER_N]) {
    int vetorAux[KYBER_N];
    int aux=0;
    for (int i =0; i < KYBER_K; i++) {         
        vetorAux[i] = vetor[i];
         
    }

    nttA(vetor);    
    invnttA(vetor);
    

    for (int j=0; j < KYBER_N; j++) {
        if (vetor[j]!=vetorAux[j]) {
            printf("\n\n Atenção! \n vetorA[%d]!=vetorA'[%d] %d!=%d \n Lamento, mas Transformada INCORRETA!!!",j,j,vetor[j],vetorAux[j]);
            aux =1;
        }
    }   
    
    if (aux==0) {
        printf("\n\nTransformada Correta!!!");
    }
}


/*
Computes the product of two degree-one polynomials with respect to a quadratic modulus.
Input:  a0,a1,b0,b1 ∈ Zq. ▷ the coeffcients of a0 + a1X and b0 + b1X
Input:  γ ∈ Zq. ▷ the modulus is X^2 −γ
Output: c0,c1 ∈ Zq. ▷ the coeffcients of the product of the two polynomials 
*/
nt baseCaseMultiplicaA(uint16_t a0, uint16_t a1, uint16_t b0, uint16_t b1, uint16_t y) {
    nt result;
    result.c0 = ((a0 * b0) % KYBER_Q + ((a1 * b1) % KYBER_Q * y) % KYBER_Q) % KYBER_Q;
    result.c1 = ((a0 * b1) % KYBER_Q + (a1 * b0) % KYBER_Q) % KYBER_Q;
    return result;
}


/*
Computes the product (in the ring Tq) of two NTT representations.
Input:  Two arrays fˆ ∈ Zq256 and gˆ ∈ Zq256. ▷ the coeffcients of two NTT representations 
Output: An array h^ ∈ Zq256. ▷ the coeffcients of the product of the inputs
*/
void multiplicaNTTA(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]) {   

    for (int j=0; j<128; j++) {
            nt result = baseCaseMultiplicaA(f[2*j],f[2*j+1],g[2*j],g[2*j+1],power(KYBER_Z,(2*BitRev7(j)+1)));
            h[2*j] = result.c0;
            h[2*j+1] = result.c1;
    }
       
}

/*********************************************************************************
Funções referentes à implementação em teste
Implementação B
*********************************************************************************/

/*********************************************************************************
Implementação otimizada para ARMv8
Funções referentes aos algorítmos NTT do ML-KEM FIPS 203 ipd
Input: array f ∈ ZKYBER_Q256.   ▷ the coeffcients of the input polynomial KYBER_Q
Output: array fˆ ∈ ZKYBER_Q256 
*********************************************************************************/

// ζ^BitRev7(i)
const uint16_t zetas[128] = {1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 
    2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 
    1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 
    33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 
    3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409,
    2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 
    952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 
    2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 
    2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 
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

// Transformada numérica de Theorell (NTT)
void nttB(uint16_t r[KYBER_N]) {
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


void invnttB(uint16_t f[KYBER_N]) {
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


/*
Computes the product of two degree-one polynomials with respect to a quadratic modulus.
Input:  a0,a1,b0,b1 ∈ Zq. ▷ the coeffcients of a0 + a1X and b0 + b1X
Input:  γ ∈ Zq. ▷ the modulus is X^2 −γ
Output: c0,c1 ∈ Zq. ▷ the coeffcients of the product of the two polynomials 
*/
// Função otimizada para multiplicação de polinômios de grau um
static inline nt baseCaseMultiplicaB(uint16_t a0, uint16_t a1, uint16_t b0, uint16_t b1, uint16_t y) {
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
void multiplicaNTTB(const uint16_t f[KYBER_N], const uint16_t g[KYBER_N], uint16_t h[KYBER_N]) {       
    for (int j=0; j<128; j++) {       
            nt result = baseCaseMultiplicaB(f[2*j],f[2*j+1],g[2*j],g[2*j+1],zetas2[j]);
            h[2*j] = result.c0;
            h[2*j+1] = result.c1;
    }
       
}

//--------------------------------

// Funções genéricas para A e B
void exibeVetor(uint16_t vetor[KYBER_N], char* nome) {
    printf("\n Vetor %s : \n", nome);
    for (int i=0; i<KYBER_N; i++) {
        printf(" %d", vetor[i]);
    }
    printf("\n");
}

void comparaVetores(uint16_t vetor1[KYBER_N], uint16_t vetor2[KYBER_N],char* texto ) {
    printf("\n Comparação dos vetores %s  \n", texto);
    for (int i=0; i<KYBER_N; i++) {
        if (vetor1[i]!=vetor2[i]) {
            printColor(" ERRO: Os vetores são diferentes \n",RED);
            return;
        }
        
    }
    printf(" Os vetores são iguais! \n");
}

void verificaTransformada(uint16_t vetor1[KYBER_N], uint16_t vetor2[KYBER_N],char* texto ) {
    uint8_t diferentes = 0;
    uint16_t elementosDiferentes[KYBER_N] = {0};
    printf("\n Verificação da transformada NTT e INVNTT do vetor %s  \n", texto);
    for (int i=0; i<KYBER_N; i++) {
        if (vetor1[i]!=vetor2[i]) {           
            diferentes++;
            elementosDiferentes[i] = vetor1[i];            
        }        
    }
    if (diferentes==0) {
        printColor(" Transformada bem-sucedida! \n",GREEN);    
    }
    else {
        printf(" ERRO: Transformada realizada com %d erros !!!! \n Elementos diferentes: ",diferentes);
        for (int i=0;i<diferentes; i++) {
            printf(" %u", elementosDiferentes[i]);
        }
        printf("\n");
    }
    
}


/*********************************************************************************
INÍCIO dos testes
MAIN()
*********************************************************************************/


int main () {
    setlocale(LC_ALL, "Portuguese"); // define acentuação para língua portuguesa

    uint16_t v[KYBER_N];
    uint16_t v_temp[KYBER_N];
    uint16_t u[KYBER_N];
    uint16_t u_temp[KYBER_N];
    uint16_t v_linha[KYBER_N];
    uint16_t v_linha_temp[KYBER_N];
    uint16_t u_linha[KYBER_N];
    uint16_t u_linha_temp[KYBER_N];
    uint16_t x[KYBER_N];
    uint16_t x_linha[KYBER_N];

    // Inicializa os vetores com zero
    memset(v, 0, sizeof(v)); 
    memset(u, 0, sizeof(u)); 
    memset(v_linha, 0, sizeof(v_linha)); 
    memset(u_linha, 0, sizeof(u_linha)); 
    memset(v_temp, 0, sizeof(v_temp)); 
    memset(u_temp, 0, sizeof(u_temp)); 
    memset(v_linha_temp, 0, sizeof(v_linha_temp)); 
    memset(u_linha_temp, 0, sizeof(u_linha_temp)); 
    memset(x, 0, sizeof(x)); 
    memset(x_linha, 0, sizeof(x_linha)); 

    // Armazena o valor atual retornado por time(NULL) em uma variável
    time_t seed = time(NULL);
    
    // Mostra o valor da semente na tela
    printf("Valor da semente: %ld\n", (long)seed);
    
    // Inicializa o gerador de números aleatórios com a semente
    srand(seed);

    for (int i = 0; i < KYBER_N; ++i) {
        u[i] = rand() % KYBER_Q; 
        v[i] = rand() % KYBER_Q;
    }

    // Duplicando os arrays para viabilizar as comparações dos retornos das funções de NTT básica e otimizada
    memcpy(u_linha,u,sizeof(u));
    memcpy(v_linha,v,sizeof(v));

    // Preservando os elementos originais para análise da invntt
    memcpy(u_temp,u,sizeof(u)); 
    memcpy(v_temp,v,sizeof(v));
    memcpy(u_linha_temp,u_linha,sizeof(u_linha));
    memcpy(v_linha_temp,v_linha,sizeof(v_linha));

    printColor("Elementos Originais",YELLOW);
    exibeVetor(u, "u");    
    exibeVetor(u_linha,"u_linha");    
    printf("\n");
    exibeVetor(v,"v");
    exibeVetor(v_linha,"v_linha");
    printf("======================================================================================================================================================\n");
    
    printColor("\n Elementos no domínio Tq",GREEN);
    // NTT Básica
    nttA(u);
    nttA(v); 
    // NTT Otimizada
    nttB(u_linha);        
    nttB(v_linha);
   
    // Exibe os vetores u para comparação dos resultados da NTT Básica x NTT Otimizada
    exibeVetor(u,"u_hat");
    exibeVetor(u_linha,"u_linha_hat");
    // Exibe os vetores v para comparação dos resultados da NTT Básica x NTT Otimizada
    exibeVetor(v,"v_hat");
    exibeVetor(v_linha,"v_linha^");
    // Compara se os vetores são iguais após a aplicação das diferentes NTT
    comparaVetores(u,u_linha,"u,u_linha");  
    comparaVetores(v,v_linha,"v,v_linha");  
    printf("======================================================================================================================================================\n");
  
    printColor("\n Multiplicação no domínio Tq  (x^ = u^ x v^)", CYAN);
    multiplicaNTTA(u,v,x);
    exibeVetor(x,"x");
    multiplicaNTTB(u_linha,v_linha,x_linha);
    exibeVetor(x_linha,"x_linha");
    comparaVetores(x,x_linha,"x,x_linha");  
    printf("======================================================================================================================================================\n");

    printColor("\n NTT Inversa", MAGENTA); 
    invnttA(u);
    invnttB(u_linha);

    exibeVetor(u_temp," u ORIGINAL");
    exibeVetor(u,"u após invNTT");
    exibeVetor(u_linha_temp," u_linha ORIGINAL");
    exibeVetor(u_linha,"u_linha após invNTT");

    invnttA(v);
    invnttB(v_linha);
    exibeVetor(v,"v após invNTT");
    exibeVetor(v_linha,"v_linha após invNTT");

    printf("======================================================================================================================================================\n");
    
    comparaVetores(u,u_linha,"u,u_linha");  
    comparaVetores(v,v_linha,"v,v_linha");  

    printf("======================================================================================================================================================\n");

    verificaTransformada(u,u_temp,"u - Função NTT Básica Original");
    verificaTransformada(v,v_temp,"v - Função NTT Básica Original");  
    verificaTransformada(u_linha,u_linha_temp,"u_linha - Função NTT Otimizada");   
    verificaTransformada(v_linha,v_linha_temp,"v_linha - Função NTT Otimizada");  
   
}
