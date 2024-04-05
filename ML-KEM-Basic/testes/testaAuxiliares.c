#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "parametros.h"


void bitsToBytes(const uint8_t bits[], uint8_t* bytes, int num_bits) {
    int num_bytes = (num_bits + 7) / 8;

    // Inicializa bytes com zero
    memset(bytes, 0, num_bytes * sizeof(uint8_t));

    // Laço para converter bits em bytes
    for (int i = 0; i < num_bits; i++) {
        bytes[i / 8] |= (bits[i] << (i % 8));      
    }    
}

/*
Performs the inverse of bitsToBytes, converting a byte array into a bit array.
Input: byte array B ∈ B^ℓ
Output: bit array b ∈ {0,1}^8·ℓ
*/
void bytesToBits(const uint8_t bytes[], uint8_t bits[], size_t num_bytes) {
    printf("Função BytesToBits! para num_bytes=%d \n Vetor de Bytes : ",num_bytes);
      for(int i=0; i<sizeof(bytes); i++) {
        printf("%d ",bytes[i]);
    }
    printf("\nFim de bytes[]  \nVetor de bits[] (espera-se que esteja vazio aqui): ");
    for(int i=0; i<sizeof(bits); i++) {
        printf("%02x ",bits[i]);
    }


    size_t num_bits = num_bytes * 8;

    for (size_t i = 0; i < num_bits; i++) {
        size_t byteIndex = i / 8;
        size_t bitIndex = i % 8;
        bits[i] = (bytes[byteIndex] >> bitIndex) & 1;
    }

    printf("\n\nVetor de bits[] (espera-se que esteja PREENCHIDO aqui): ");
    for(int i=0; i<sizeof(bits); i++) {
        printf("%02x ",bits[i]);
    }
}


/*
Encodes an array of d-bit integers into a byte array, for 1 ≤ d ≤ 12.
Input: integer array F ∈ Zm256, where m = 2^d if d < 12 and m = q if d = 12.
Output: byte array B ∈ B^32d
*/
void byteEncode(const uint16_t F[], uint8_t B[], int d) {
    int num_bits = 256 * d; // Total de bits
    uint8_t b[num_bits]; // Array temporário para armazenar os bits

    for (int i = 0; i < 256; i++) {
        uint16_t a = F[i] % (d == 12 ? KYBER_Q : (1 << d)); // Modular para d=12 ou 2^d para d<12
        for (int j = 0; j < d; j++) {
            b[i * d + j] = (a >> j) & 1; // Ajuste para little-endian
        }
    }

    bitsToBytes(b, B, num_bits); // Converte os bits para bytes
}

/*
Decodes a byte array into an array of d-bit integers, for 1 ≤ d ≤ 12.
Input: byte array B ∈ B^32d.
Output: integer array F ∈ Zm256, where m = 2^d if d < 12 and m = q if d = 12.
*/
void byteDecode(const uint8_t B[], uint16_t F[], int d) {
    int num_bits = 256 * d; // Total de bits
    uint8_t b[num_bits]; // Array temporário para armazenar os bits
    memset(b, 0, sizeof(b)); 

    printf("\n ByteDecode(B[],F[],d) d=%d \n",d);
    printf("Aqui espera-se que F esteja vazio \n");
    for(int i=0; i<sizeof(F); i++) {
        printf("%d ",F[i]);
    }
    printf("\nFim do F[] e Início do B[]\n");
    for(int i=0; i<sizeof(B); i++) {
        printf("%02x ",B[i]);
    }

    bytesToBits(B, b, 256 * d); // Correção: Precisa ser num_bits / 8

    for (int i = 0; i < 256; i++) {
        F[i] = 0;
        for (int j = 0; j < d; j++) {
            F[i] += b[i * d + j] * (1U << j); // Agregando valor com base em little-endian
        }
        // Removido aplicação de módulo aqui, pois F[i] é construído dentro do limite.
    }

    printf("\n ByteDecode(B[],F[],d) d=%d \n",d);
    printf("Aqui espera-se que F esteja preenchido \n");
    for(int i=0; i<sizeof(F); i++) {
        printf("%d ",F[i]);
    }
    printf("\nFim do F[] e início do b[]\n");
    for(int i=0; i<sizeof(b); i++) {
        printf("%02x ",b[i]);
    }
}


// Função de arredondamento adaptada para operar com valores inteiros
int rounding(int numerator, int denominator) {
    // Calcula o quociente e o resto da divisão
    int quotient = numerator / denominator;
    int remainder = numerator % denominator;

    // Verifica se a parte fracionária é maior ou igual a 0.5 e ajusta o quociente adequadamente
    if (2 * remainder >= denominator) {
        return quotient + 1;
    } else {
        return quotient;
    }
}

// Função Compress_d 
uint16_t compress_d(uint16_t x, uint16_t d) {
    uint64_t product = ((uint64_t)x * (1U << d) + KYBER_Q / 2) / KYBER_Q; // Adiciona meio para arredondamento
    return (uint16_t)product;
}



// Função Decompress_d 
uint16_t decompress_d(uint16_t y, uint16_t d) {
    uint64_t numerator = (uint64_t)KYBER_Q * y + (1U << (d - 1)); // Adiciona metade do divisor para arredondamento
    uint16_t decompressed = (uint16_t)(numerator / (1U << d));
    return decompressed;
}


// Função de teste
void testByteEncode() {
    const int d = 12; // Exemplo com d=4 bits
    uint16_t F[KYBER_N]; // Array de inteiros d-bit
    uint8_t B[384*KYBER_K+32]; // Array de bytes resultante (256*4 bits = 1024 bits = 128 bytes)

    // Preenchimento do array F com valores de teste
    for (int i = 0; i < KYBER_N; i++) {
        F[i] = i % KYBER_Q; // Valores de 0 a 3328 (representáveis com 4 bits)
        printf("%d ",F[i]);
    }

    // Chama byteEncode para codificar F em B
    byteEncode(F, B, d);

    // Imprime os bytes resultantes para verificação manual
    printf("\n\nBytes codificados:\n");
    for (int i = 0; i < sizeof(B); i++) {
        printf("%02x ", B[i]);
        if ((i + 1) % KYBER_Q == 0) printf("\n");
    }
     printf("\nQuantidade de Bytes codificados: %u \n",sizeof(B));
}


int main() {
    uint8_t bytes[] = {0xFF, 0x0F}; // Exemplo simples
    size_t num_bytes = sizeof(bytes);
    uint8_t bits[16]; // Suficiente para 2 bytes -> 16 bits

    bytesToBits(bytes, bits, num_bytes);

    for (int i = 0; i < num_bytes * 8; i++) {
        printf("%u ", bits[i]);
    }
    printf("\n");

  
    testByteEncode();
    return 0;
}