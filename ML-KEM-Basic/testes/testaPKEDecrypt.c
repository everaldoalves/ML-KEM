#include <stdio.h>
#include <stdlib.h>
#include "auxiliares.h" 
#include "ntt.h"        
#include "parametros.h" 
#include "pkeEncrypt.h" 
#include "pkeDecrypt.h"
#include "pkeKeyGen.h"

// Suponha que você tenha uma função pkeEncrypt e pkeDecrypt definidas em pke.h
// void pkeEncrypt(const uint8_t *ekPKE, const uint8_t *mensagem, uint8_t *ciphertext);
// void pkeDecrypt(const uint8_t *dkPKE, const uint8_t *ciphertext, uint8_t *mensagemDecifrada);

void imprimirHexa(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main() {
    
    chavesPKE chaves;
    uint8_t r[32];
    
    chaves = pkeKeyGen();
    
    // Mensagem de exemplo para ser encriptada
    uint8_t mensagem[32]; // Ajuste conforme o tamanho da mensagem
    generateRandomBytes(mensagem,32);
    generateRandomBytes(r,32);

    // Buffer para o texto cifrado
    uint8_t ciphertext[32 * (KYBER_DU * KYBER_K + KYBER_DV)]; // Ajuste conforme necessário

    // Buffer para a mensagem decifrada
    uint8_t mensagemDecifrada[32];

    printf("\nMensagem original: ");
    imprimirHexa(mensagem, 32);

    // Encripta a mensagem
    pkeEncrypt(chaves.ek, mensagem, r, ciphertext);

    printf("\nTexto cifrado: ");
    imprimirHexa(ciphertext, sizeof(ciphertext));

    // Decripta o texto cifrado
    pkeDecrypt(chaves.dk, ciphertext, mensagemDecifrada);

    printf("\nMensagem decifrada: ");
    imprimirHexa(mensagemDecifrada, 32);

    // Comparar a mensagem original com a decifrada
    if (memcmp(mensagem, mensagemDecifrada, 32) == 0) {
        printf("\nA decriptação foi bem-sucedida e as mensagens são idênticas.\n");
    } else {
        printf("\nErro: A mensagem decifrada difere da original.\n");
    }

    return 0;
}
