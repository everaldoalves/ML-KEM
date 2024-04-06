#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#define KYBER_Q 3329

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


void test_compress_decompress() {
    const uint16_t d_values[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,12}; // Testar para todos os valores de d < 13
    const uint16_t test_values[] = {0, 1, 1024, 2048, 3072, KYBER_Q - 1}; // Valores de teste representativos

    for (int i = 0; i < sizeof(d_values) / sizeof(d_values[0]); i++) {
        uint16_t d = d_values[i];
        printf("Testing d = %d\n", d);
        for (int j = 0; j < sizeof(test_values) / sizeof(test_values[0]); j++) {
            uint16_t x = test_values[j];
            uint16_t compressed = compress_d(x, d);
            uint16_t decompressed = decompress_d(compressed, d);
            uint16_t recompressed = compress_d(decompressed, d);

            // Verificar se a compressão seguida por descompressão preserva o valor
            assert(compressed == recompressed);

            // Verificar a propriedade específica de alteração mínima para decompress seguido por compress
            uint16_t difference = decompressed > x ? decompressed - x : x - decompressed;
            assert(difference <= (KYBER_Q / (1 << (d + 1))) + 1);
        }
    }

    printf("All tests passed!\n");
}

int main() {
    test_compress_decompress();
    return 0;
}
