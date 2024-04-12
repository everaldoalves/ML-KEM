#include <stdio.h>
#include <stdlib.h>
#include "auxiliares.h" 
#include "ntt.h"        
#include "parametros.h" 
#include "pkeEncrypt.h" 
#include "pkeDecrypt.h"
#include "pkeKeyGen.h"

/*******************************************************************************
Teste do Algoritmo 14 - Decrypt() -  ML-KEM FIPS 203 ipd
Uses the decryption key to decrypt a ciphertext.
Input: decryption key dkPKE ∈ B^384k.
Input: ciphertext c ∈ B^32(duk+dv).
Output: message m ∈ B^32.  
********************************************************************************/


// void pkeEncrypt(const uint8_t *ekPKE, const uint8_t *mensagem, uint8_t *ciphertext);
// void pkeDecrypt(const uint8_t *dkPKE, const uint8_t *ciphertext, uint8_t *mensagemDecifrada);

void imprimirHexa(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main() {
    printf("\n  Iniciando a função de Decriptação.....\n Gerando valores para encriptar a mensagem .... \n");

    chavesPKE chaves;
    uint8_t r[32];
    
    chaves = pkeKeyGen();
    
    // Mensagem de exemplo para ser encriptada
    uint8_t mensagem[32]; 
    generateRandomBytes(mensagem,32);
    generateRandomBytes(r,32);

    // Buffer para o texto cifrado
    uint8_t ciphertext[32 * (KYBER_DU * KYBER_K + KYBER_DV)]; 

    // Buffer para a mensagem decifrada
    uint8_t mensagemDecifrada[32];

    

    // Encripta a mensagem
    pkeEncrypt(chaves.ek, mensagem, r, ciphertext);

    printf("\n\nChave de encriptação: ");
    imprimirHexa(chaves.ek,384*KYBER_K+32);
    
    printf("\nMensagem original: ");
    imprimirHexa(mensagem, 32);

    printf("\nValor aleatório r: ");
    imprimirHexa(r, 32);

    printf("\n\nTexto cifrado gerado com pkeEncrypt(): ");
    imprimirHexa(ciphertext, sizeof(ciphertext));

    printf("Mensagem encriptada com sucesso! \n Iniciando processo de decriptação..... \n");

    // Decripta o texto cifrado
    pkeDecrypt(chaves.dk, ciphertext, mensagemDecifrada);
    printf("\nChave de decriptação: ");
    imprimirHexa(chaves.dk,384*KYBER_K);

    printf("\nTexto cifrado: ");
    imprimirHexa(ciphertext,384*KYBER_K);

    printf("\nMensagem decifrada: ");
    imprimirHexa(mensagemDecifrada, 32);

    // Compara a mensagem original com a decifrada
    if (memcmp(mensagem, mensagemDecifrada, 32) == 0) {
        printf("\nA decriptação foi bem-sucedida e as mensagens são idênticas.\n");
    } else {
        printf("\nErro: A mensagem decifrada difere da original.\n");
        imprimirHexa(mensagem,32);
    }

    return 0;
}
