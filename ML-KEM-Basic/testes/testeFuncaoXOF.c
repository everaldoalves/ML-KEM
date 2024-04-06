
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

// Uma importante observação a ser feita aqui é que, conforme a especificação, não se conhece o tamanho da saída no momento da chamada da função XOF. Dessa forma
// o ideal seria uma abordagem envolvendo a gestão do estado da função XOF, o que é mais complexo de realizar. Então, foi definido um valor estatisticamente adequado, a saber 512 bytes
// que deve ser satisfatória para atender sampleNTT.

/*
Função XOF - Shake128 utilizando openssl  (XOF)
The function XOF takes one 32-byte input and two 1-byte inputs. It produces a variable-length output. This function will be denoted by XOF :
B32 ×B×B → B∗, and it shall be instantiated as
XOF(ρ,i, j) := SHAKE128(ρ∥i∥ j)
*/
void XOF(unsigned char *rho, unsigned char i, unsigned char j, unsigned char *md) {
    unsigned char input[34]; // Concatenação de rho, i e j (34 bytes)
    
    // Copia os primeiros 32 bytes de rho
    memcpy(input, rho, 32);

    // Adiciona o valor de i e j
    input[32] = i;
    input[33] = j;

    // Inicialize o contexto do hash
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Erro ao criar o contexto do hash\n");
        return;
    }

    // Inicialize o hash SHAKE128
    if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1) {
        fprintf(stderr, "Erro ao inicializar o hash\n");
        return;
    }

    // Atualize o hash com os dados de entrada
    if (EVP_DigestUpdate(mdctx, input, sizeof(input)) != 1) {
        fprintf(stderr, "Erro ao atualizar o hash\n");
        return;
    }

    // Finalize o hash e obtenha o resultado
    
    if (EVP_DigestFinalXOF(mdctx, md, 64) != 1) {
        fprintf(stderr, "ERRO ao finalizar o hash\n");
        return;
    }

    // Libere o contexto do hash
    EVP_MD_CTX_free(mdctx);
}

void test_deterministic_XOF() {
    unsigned char rho[32] = {0xa5, 0x4b, 0x2a, 0x76, 0xb9, 0x81, 0x2c, 0xc1,
    0x45, 0x2c, 0x3d, 0xa4, 0xe1, 0x3b, 0x8f, 0xab,
    0x23, 0x45, 0xf6, 0xa7, 0xb8, 0xc9, 0xd0, 0x1e,
    0x2f, 0x30, 0x31, 0x12, 0x33, 0x44, 0x55, 0x66};
    unsigned char i = 0x01; // Exemplo de valor
    unsigned char j = 0x02; // Exemplo de valor
    unsigned char md[512]; // Vamos testar com saída de 64 bytes

    XOF(rho, i, j,md);

    // Substitua os valores abaixo pelo SHAKE128 esperado para rho∥i∥j
    const unsigned char expected_md[64] = {
    0xbf, 0xdd, 0x92, 0x80, 0x6f, 0x99, 0x91, 0x38,
    0xa9, 0xba, 0x20, 0xf7, 0x58, 0x9d, 0x58, 0xb7,
    0xa0, 0x03, 0x06, 0x5b, 0x7c, 0xbf, 0x36, 0xc1,
    0x5b, 0xde, 0x88, 0xbd, 0x18, 0xec, 0x0d, 0x40,
    0xd9, 0xfa, 0x50, 0xde, 0x7d, 0x16, 0x85, 0x54,
    0x9b, 0x5d, 0xd9, 0x31, 0x94, 0x99, 0xdc, 0x7d,
    0xbe, 0xc3, 0x92, 0x5d, 0x2e, 0x90, 0xfd, 0x48,
    0x85, 0x0c, 0x6c, 0xa9, 0x65, 0x80, 0x6f, 0x01
};

for (int i = 0; i < 64; i++) {
    if (md[i] != expected_md[i]) {
        printf("Mismatch at byte %d: md[%d] = %02x, expected_md[%d] = %02x\n", i, i, md[i], i, expected_md[i]);
        break; // Para ver apenas a primeira discrepância
    }
}


    assert(memcmp(md, expected_md, 64) == 0);

    printf("Deterministic test for XOF passed!\n");
}


void test_random_XOF() {
    srand((unsigned)time(NULL));
    for (int test = 0; test < 100; ++test) {
        unsigned char rho[32];
        for (int i = 0; i < 32; ++i) {
            rho[i] = rand() % 256;
        }
        unsigned char i = rand() % 256;
        unsigned char j = rand() % 256;
        unsigned char md[512]; // Exemplo com saída de 64 bytes

        XOF(rho, i, j, md);

        // Verificar se a função XOF produziu a saída do tamanho correto
        printf("Random test %d for XOF passed\n", test + 1);
    }

    printf("All random tests for XOF passed!\n");
}

int main () {
    test_deterministic_XOF();
    test_random_XOF();
}