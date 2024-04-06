#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TEST_LENGTH 256
#define KYBER_Q 3329

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

    bytesToBits(B, b, 32 * d); 

    for (int i = 0; i < 256; i++) {
        F[i] = 0;
        for (int j = 0; j < d; j++) {
            F[i] += b[i * d + j] * (1U << j); // Agregando valor com base em little-endian
        }
        
    }

}

// Testes determinísticos
void test_encode_decode() {
    const int d_values[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    const int test_length = 256; // Com base na especificação de entrada/saída

    for (int index = 0; index < sizeof(d_values) / sizeof(d_values[0]); index++) {
        int d = d_values[index];
        uint16_t F[test_length], F_decoded[test_length];
        uint8_t B[32 * d];

        // Inicialização de F com valores representativos para o teste
        for (int i = 0; i < test_length; i++) {
            F[i] = i % (d == 12 ? KYBER_Q : (1 << d));
        }

        // Codifica F em B
        byteEncode(F, B, d);

        // Decodifica B de volta em F_decoded
        byteDecode(B, F_decoded, d);

        // Verifica se F e F_decoded são iguais
        for (int i = 0; i < test_length; i++) {
            assert(F[i] == F_decoded[i]);
        }
    }

    printf("Todos os testes determinísticos passaram!\n");
}

void fill_random_values(uint16_t F[], int d, int length) {
    for (int i = 0; i < length; i++) {
        uint16_t max_val = d == 12 ? KYBER_Q : (1U << d);
        F[i] = rand() % max_val;
    }
}

// Testes aleatórios
void test_encode_decode_with_random_values() {
    const int d_values[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint16_t F[TEST_LENGTH], F_decoded[TEST_LENGTH];
    uint8_t B[32 * 12]; // Max size for d=12

    srand((unsigned int)time(NULL)); // Seed para geração de números aleatórios

    for (int d_index = 0; d_index < sizeof(d_values) / sizeof(d_values[0]); d_index++) {
        int d = d_values[d_index];
        printf("Testing d = %d with random values\n", d);

        // Preenche F com valores aleatórios apropriados para o valor de d atual
        fill_random_values(F, d, TEST_LENGTH);

        // Codifica F em B
        byteEncode(F, B, d);

        // Decodifica B de volta em F_decoded
        byteDecode(B, F_decoded, d);

        // Verifica se F e F_decoded são iguais
        for (int i = 0; i < TEST_LENGTH; i++) {
            assert(F[i] == F_decoded[i]);
        }
    }

    printf("Todos os testes aleatórios passaram!\n");
}

int main() {
    test_encode_decode();
    test_encode_decode_with_random_values();
    return 0;
}
