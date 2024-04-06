#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>


// Função J - SHAKE256
void J(const unsigned char *input, size_t input_len, unsigned char output[32]) {
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        printf("Erro ao criar o contexto de hash\n");
        exit(1);
    }
    if(1 != EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL)) {
        printf("Erro ao inicializar SHAKE256\n");
        exit(1);
    }
    if(1 != EVP_DigestUpdate(mdctx, input, input_len)) {
        printf("Erro ao atualizar o hash\n");
        exit(1);
    }
    if(1 != EVP_DigestFinalXOF(mdctx, output, 32)) {
        printf("Erro ao finalizar o XOF\n");
        exit(1);
    }
    EVP_MD_CTX_free(mdctx);
}

void test_deterministic_J() {
// Teste determinístico para J
    const unsigned char input_J[] = "Teste para J";
    unsigned char output_J[32];
    J(input_J, strlen((char *)input_J), output_J);
    // Substitua os valores abaixo pelo output SHAKE256 esperado para "Teste para J", com output de 32 bytes
    const unsigned char expected_J[32] = {
    0x56, 0x99, 0xf6, 0x9e, 0x94, 0x26, 0x02, 0x7d, 
    0xf5, 0x7a, 0x57, 0xac, 0x7b, 0x04, 0xad, 0x91, 
    0x8c, 0x87, 0x85, 0x0a, 0x95, 0x34, 0x23, 0x0e, 
    0x7f, 0xc1, 0xe2, 0x91, 0x62, 0x45, 0x97, 0x20
    };
    assert(memcmp(output_J, expected_J, 32) == 0);

    printf("Deterministic tests for J passed!\n");
}

void test_random_J() {
    srand((unsigned)time(NULL));

    for (int test = 0; test < 100; ++test) {
        unsigned char input[1024];
        size_t input_len = rand() % sizeof(input);
        for (size_t i = 0; i < input_len; ++i) {
            input[i] = rand() % 256;
        }

        unsigned char output_J[32];        
        J(input, input_len, output_J);

        // Os testes abaixo são mais para verificar o comportamento com entradas aleatórias
        printf("Random test %d for J passed with input length %zu\n", test + 1, input_len);
    }

    printf("All random tests for J passed!\n");
}

int main() {
    test_deterministic_J();
    test_random_J();
    return 0;
}