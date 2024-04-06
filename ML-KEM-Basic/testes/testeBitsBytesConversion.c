#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


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
    size_t num_bits = num_bytes * 8;

    for (size_t i = 0; i < num_bits; i++) {
        size_t byteIndex = i / 8;
        size_t bitIndex = i % 8;
        bits[i] = (bytes[byteIndex] >> bitIndex) & 1;
    }
}


void test_deterministic() {
    // Teste 1: Todos os bits a 0
    uint8_t bits1[8] = {0};
    uint8_t bytes1[1];
    bitsToBytes(bits1, bytes1, 8);
    assert(bytes1[0] == 0x00);

    // Teste 2: Todos os bits a 1
    uint8_t bits2[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    uint8_t bytes2[1];
    bitsToBytes(bits2, bytes2, 8);
    assert(bytes2[0] == 0xFF);

    // Teste 3: Alternando bits    
    uint8_t bits3[8] = {1, 0, 1, 0, 1, 0, 1, 0};
    uint8_t bytes3[1];
    bitsToBytes(bits3, bytes3, 8);
    printf("bytes3[0]: 0x%02X\n", bytes3[0]);
    assert(bytes3[0] == 0x55);

    // Teste reverso para verificar bytesToBits
    uint8_t bits_out[8];
    bytesToBits(bytes3, bits_out, 1);
    for (int i = 0; i < 8; i++) {
        assert(bits3[i] == bits_out[i]);
    }

    printf("Deterministic tests passed!\n");
}


void test_random() {
    srand((unsigned)time(NULL)); // Inicializa a semente de números aleatórios
    const int num_bits = 8 * 10; // Exemplo para 10 bytes
    uint8_t bits[num_bits];
    uint8_t bytes[10];
    uint8_t bits_out[num_bits];

    // Gera bits aleatórios e preenche o array
    for (int i = 0; i < num_bits; i++) {
        bits[i] = rand() % 2;
    }

    // Converte de bits para bytes e volta
    bitsToBytes(bits, bytes, num_bits);
    bytesToBits(bytes, bits_out, 10);

    // Verifica se os bits originais são preservados após a conversão ida e volta
    for (int i = 0; i < num_bits; i++) {
        assert(bits[i] == bits_out[i]);
    }

    printf("Random tests passed!\n");
}

int main() {
    test_deterministic();
    test_random();
    return 0;
}
