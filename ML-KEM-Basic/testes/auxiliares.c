#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>      // Para alocação de memória dinâmica
#include <string.h>      // Para uso de memcpy
#include "parametros.h"
#include "auxiliares.h"
#include "amostragem.h"
#include <math.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h> 

/*******************************************************************
Funções referentes aos algorítmos auxiliares do ML-KEM FIPS 203 ipd
********************************************************************/


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
/*
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
*/

void byteEncode(const uint16_t F[], uint8_t B[], int d) {
    uint32_t tmp = 0;
    int bit_count = 0;

    int pos = 0; // posição no array de bytes B
    for (int i = 0; i < 256; i++) {
        uint16_t a = F[i] % (d == 12 ? KYBER_Q : (1 << d));
        tmp |= ((uint32_t)a << bit_count);
        bit_count += d;

        while (bit_count >= 8) {
            B[pos++] = tmp & 0xFF; // extrai o byte menos significativo
            tmp >>= 8;             // descarta os bits já processados
            bit_count -= 8;
        }
    }

    if (bit_count > 0) { // Se sobrarem bits que não completaram um byte
        B[pos] = tmp & 0xFF;
    }
}


/*
Decodes a byte array into an array of d-bit integers, for 1 ≤ d ≤ 12.
Input: byte array B ∈ B^32d.
Output: integer array F ∈ Zm256, where m = 2^d if d < 12 and m = q if d = 12.
*/
/*
void byteDecode(const uint8_t B[], uint16_t F[], int d) {
    int num_bits = 256 * d; // Total de bits
    uint8_t b[num_bits]; // Array temporário para armazenar os bits

    bytesToBits(B, b, 32 * d); 

    for (int i = 0; i < 256; i++) {
        F[i] = 0;
        for (int j = 0; j < d; j++) {
            F[i] += b[i * d + j] * (1U << j); // Agregando valor com base em little-endian
        }
        // Removido aplicação de módulo aqui, pois F[i] é construído dentro do limite.
    }

}
*/

void byteDecode(const uint8_t B[], uint16_t F[], int d) {
    uint32_t tmp = 0;
    int bits_in_tmp = 0;

    int byte_pos = 0;
    for (int i = 0; i < 256; i++) {
        while (bits_in_tmp < d) {
            tmp |= ((uint32_t)B[byte_pos++] << bits_in_tmp);
            bits_in_tmp += 8;
        }

        F[i] = tmp & ((1 << d) - 1); // Assume d <= 12
        tmp >>= d;
        bits_in_tmp -= d;
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


// Função G - SHA-3 512
void G(const unsigned char *input, size_t input_len, unsigned char *a, unsigned char *b) {
    unsigned char hash[SHA512_DIGEST_LENGTH]; // SHA3-512 tem 64 bytes de saída

    // Computa o hash SHA3-512 da entrada
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) return;
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL)) return;
    if (1 != EVP_DigestUpdate(mdctx, input, input_len)) return;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, NULL)) return;
    EVP_MD_CTX_free(mdctx);

    // Divida o hash de 64 bytes em duas partes de 32 bytes
    memcpy(a, hash, 32);
    memcpy(b, hash + 32, 32);
}

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
    //unsigned int md_len;
    if (EVP_DigestFinalXOF(mdctx, md, 1024) != 1) {
        fprintf(stderr, "ERRO ao finalizar o hash\n");
        return;
    }

    // Libere o contexto do hash
    EVP_MD_CTX_free(mdctx);
}

void XOF_per_row_OLD(unsigned char *rho, unsigned char row, unsigned char *md, size_t md_size) {
    unsigned char input[33]; // Concatenação de rho e row (33 bytes)

    // Copia os primeiros 32 bytes de rho
    memcpy(input, rho, 32);

    // Adiciona o valor da linha
    input[32] = row;

    // Inicialize o contexto do hash
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Erro ao criar o contexto do hash\n");
        return;
    }

    // Inicialize o hash SHAKE128
    if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Erro ao inicializar o hash\n");
        return;
    }

    // Atualize o hash com os dados de entrada
    if (EVP_DigestUpdate(mdctx, input, sizeof(input)) != 1) {
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Erro ao atualizar o hash\n");
        return;
    }

    // Finalize o hash e obtenha o resultado
    if (EVP_DigestFinalXOF(mdctx, md, md_size) != 1) {
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "ERRO ao finalizar o hash\n");
        return;
    }

    // Libere o contexto do hash
    EVP_MD_CTX_free(mdctx);
}

void XOF_per_row(unsigned char *rho, unsigned char row, unsigned char *md, size_t md_size) {
    EVP_MD_CTX *mdctx;
    unsigned char input[33]; // Entrada de 32 bytes de rho + 1 byte da linha

    // Configuração do contexto de hash
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Erro ao criar o contexto do hash\n");
        return;
    }

    memcpy(input, rho, 32);
    input[32] = row;

    // Inicialização do XOF SHAKE128
    if (!EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Erro ao inicializar SHAKE128\n");
        return;
    }

    // Processamento do input
    if (!EVP_DigestUpdate(mdctx, input, sizeof(input))) {
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Erro ao processar input\n");
        return;
    }

    // Extração dos dados de saída
    if (!EVP_DigestFinalXOF(mdctx, md, md_size)) {
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Erro ao finalizar XOF\n");
        return;
    }

    // Liberação do contexto de hash
    EVP_MD_CTX_free(mdctx);
}


/*
Função PRF - Shake256 utilizando openssl
The function PRF takes a parameter η ∈ {2,3}, one 32-byte input, and one 1-byte input. It produces one (64 · η)-byte output. It will be denoted by PRF :
{2,3} ×B32 ×B → B64η, and it shall be instantiated as
PRFη(s,b) := SHAKE256(s∥b,64 · η)
*/
void PRF(uint8_t eta, const uint8_t s[32], uint8_t b, uint8_t *output) {
    if (eta < 2 || eta > 3) {
        // Valor inválido de eta; 
        printf("ERRO: Valor inválido de ETA!");
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

// Função para gerar bytes aleatórios
void generateRandomBytes(unsigned char *buffer, int length) {
    if (RAND_bytes(buffer, length) == 1) {
        // A geração foi bem-sucedida       
    } else {
        // Falha ao gerar bytes aleatórios
       printf("ERRO: Falha na geração de bytes aleatórios!!!!");
    }
}

void geraMatrizA(uint8_t rho[32], uint16_t A[KYBER_K][KYBER_K][KYBER_N]) {
    // Supõe que cada linha de A precisa de um buffer suficiente para gerar todos os elementos dessa linha.
    // O buffer precisa ser suficientemente grande para lidar com a rejeição do sampleNTT.
    unsigned char md[KYBER_K * 3 * KYBER_N]; // Tamanho estimado do buffer para cada linha

    for (int i = 0; i < KYBER_K; i++) {
        XOF_per_row(rho, i, md, sizeof(md)); // Gera dados suficientes para toda a linha i de uma só vez

        // Processa o buffer md para preencher cada coluna j da linha i da matriz A
        for (int j = 0; j < KYBER_K; j++) {
            // Cada coluna j usa uma parte específica do buffer
            // A função sampleNTT assume que há dados suficientes para lidar com a rejeição.
            sampleNTT_neon(md + j * 3 * KYBER_N, A[i][j]); 
        }
    }
}

void geraMatrizAOtimizada(uint8_t rho[32], uint16_t A[KYBER_K][KYBER_K][KYBER_N]) {
    // Alinha a alocação de memória para otimização com NEON
    unsigned char *md = aligned_alloc(16, KYBER_K * 3 * KYBER_N);
    if (!md) {
        fprintf(stderr, "Falha na alocação de memória\n");
        return;
    }

    for (int i = 0; i < KYBER_K; i++) {
        XOF_per_row(rho, i, md, KYBER_K * 3 * KYBER_N);

        for (int j = 0; j < KYBER_K; j++) {
            // Chama a função otimizada com NEON para processamento dos dados
            sampleNTT_neon(md + j * 3 * KYBER_N, A[i][j]);
        }
    }

    free(md); // Libera a memória alocada
}


// Função de redução de Barrett
int16_t barrett_reduce1(int16_t a) {
  int16_t t;
  const int16_t v = ((1<<26) + KYBER_Q/2)/KYBER_Q;

  t  = ((int32_t)v*a + (1<<25)) >> 26;
  t *= KYBER_Q;
  return a - t;
}

   