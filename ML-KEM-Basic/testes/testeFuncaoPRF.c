#include <openssl/evp.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
Função PRF - Shake256 utilizando openssl
The function PRF takes a parameter η ∈ {2,3}, one 32-byte input, and one 1-byte input. It produces one (64 · η)-byte output. It will be denoted by PRF :
{2,3} ×B32 ×B → B64η, and it shall be instantiated as
PRFη(s,b) := SHAKE256(s∥b,64 · η)
*/
void PRF(uint8_t eta, const uint8_t s[32], uint8_t b, uint8_t *output) {
    if (eta < 2 || eta > 3) {
        printf("ERRO: Valor inválido de ETA!\n");
        return;
    }

    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_shake256();
    size_t output_length = 64 * eta; // Calcula o comprimento de saída com base em eta.

    uint8_t input[33]; // 32 bytes de s e 1 byte de b.
    memcpy(input, s, 32);
    input[32] = b; // Concatena 'b' no final de 's'.

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, sizeof(input));
    EVP_DigestFinalXOF(mdctx, output, output_length);

    EVP_MD_CTX_free(mdctx);
}

bool check_output(const uint8_t *output, size_t actual_length, size_t expected_length) {
    if (output == NULL) {
        printf("ERRO: Saída inválida!\n");
        return false;
    }

    // Verifica se o comprimento da saída é o esperado
    if (actual_length != expected_length) {
        printf("ERRO: Comprimento da saída incorreto!\n");
        return false;
    }

    // Você pode adicionar sua lógica de verificação adicional aqui, se necessário

    return true; // A saída está correta
}

int main () {
    srand(time(NULL)); // Inicializar a semente para geração de números aleatórios

    uint8_t s_test_1[32] = {0};
    uint8_t b_test_1 = 0x01;
    uint8_t output_test_1[64 * 2]; // 64 bytes para eta 2

    PRF(2, s_test_1, b_test_1, output_test_1);
    if (check_output(output_test_1, sizeof(output_test_1), 64 * 2)) {
        printf("Teste Determinístico 1: Passou\n");
    } else {
        printf("Teste Determinístico 1: Falhou\n");
    }

    uint8_t s_test_2[32] = {0xFF};
    uint8_t b_test_2 = 0xFF;
    uint8_t output_test_2[64 * 3]; // 64 bytes para eta 3

    PRF(3, s_test_2, b_test_2, output_test_2);
    if (check_output(output_test_2, sizeof(output_test_2), 64 * 3)) {
        printf("Teste Determinístico 2: Passou\n");
    } else {
        printf("Teste Determinístico 2: Falhou\n");
    }

    // Gerar valores aleatórios para s e b
    uint8_t s_random[32];
    uint8_t b_random = (uint8_t)(rand() % 256);

    // Selecionar aleatoriamente o valor de eta entre 2 e 3
    uint8_t eta_random = (uint8_t)(2 + rand() % 2);

    uint8_t output_random[64 * eta_random]; // 64 bytes para cada valor de eta

    PRF(eta_random, s_random, b_random, output_random);
    if (check_output(output_random, sizeof(output_random), 64 * eta_random)) {
        printf("Teste Aleatório: Passou\n");
    } else {
        printf("Teste Aleatório: Falhou\n");
    }

    return 0;
}
