#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>


// Função H - SHA3-256
void H(const unsigned char *input, size_t input_len, unsigned char output[32]) {
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        printf("Erro ao criar o contexto de hash\n");
        exit(1);
    }
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL)) {
        printf("Erro ao inicializar SHA3-256\n");
        exit(1);
    }
    if(1 != EVP_DigestUpdate(mdctx, input, input_len)) {
        printf("Erro ao atualizar o hash\n");
        exit(1);
    }
    if(1 != EVP_DigestFinal_ex(mdctx, output, NULL)) {
        printf("Erro ao finalizar o hash\n");
        exit(1);
    }
    EVP_MD_CTX_free(mdctx);
}


void test_deterministic_H() {
    // Teste determinístico para H
    const unsigned char input_H[] = "Teste para H";
    unsigned char output_H[32];
    H(input_H, strlen((char *)input_H), output_H);    
    const unsigned char expected_H[32] = {
    0x6a, 0x44, 0xd0, 0x58, 0x0f, 0xa8, 0x5c, 0xa9,
    0x1a, 0x5b, 0x5f, 0xaa, 0x83, 0x05, 0x55, 0xe6, 
    0x17, 0xed, 0x25, 0x17, 0x78, 0x13, 0xc4, 0x1a, 
    0xa4, 0x71, 0x5b, 0x98, 0x44, 0x6e, 0xe9, 0x09};
    
    assert(memcmp(output_H, expected_H, 32) == 0);

    printf("Deterministic tests for H passed!\n");
}


void test_random_H() {
    srand((unsigned)time(NULL));

    for (int test = 0; test < 100; ++test) {
        unsigned char input[1024];
        size_t input_len = rand() % sizeof(input);
        for (size_t i = 0; i < input_len; ++i) {
            input[i] = rand() % 256;
        }

        unsigned char output_H[32];
        H(input, input_len, output_H);       

        // Os testes abaixo são mais para verificar o comportamento com entradas aleatórias
        printf("Random test %d for H passed with input length %zu\n", test + 1, input_len);
    }

    printf("All random tests for H passed!\n");
}

int main() {
    test_deterministic_H();
    test_random_H();
    return 0;
}