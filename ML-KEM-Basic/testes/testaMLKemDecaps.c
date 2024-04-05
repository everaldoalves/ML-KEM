#include <stdio.h>
#include <string.h>
#include "mlKemKeyGen.h"
#include "mlKemEncaps.h"
#include "auxiliares.h" 
#include "mlKemDecaps.h"

/*******************************************************************************
Testa o Algorithm 17 ML-KEM.Decaps(c,dk)
Uses the decapsulation key to produce a shared key from a ciphertext.
Validated input: ciphertext c ∈ B32(du*k + dv)
Validated input: decapsulation key dk ∈ B768k+96   
Output: shared key K ∈ B32 
********************************************************************************/

void printHex(const char* label, const uint8_t* data, size_t size) {
    printf("%s", label);
    for (size_t i = 0; i < size; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

int main() {
    printf("\nGerando as chaves...\n");
    // Gerar as chaves de encapsulamento e desencapsulamento
    // Substitua os tipos de dados e nomes de variáveis conforme necessário
    chavesKEM keys = mlKemKeyGen();
    
    printf("\nEncapsulando a chave secreta...\n");
    // Encapsular para obter a chave compartilhada K e o texto cifrado c
    encaps encapsulated = mlKemEncaps(keys.ek);
    
    printHex("\nChave K (encapsulamento): ", encapsulated.K, 32);
    
    printf("\nDesencapsulando a chave secreta...\n");
    // Desencapsular para obter a chave compartilhada K'
    uint8_t K_prime[32];
    mlKemDecaps(encapsulated.c, keys.dk, K_prime);
    
    printHex("\nChave K (desencapsulamento): ", K_prime, 32);
    
    // Verificando se as duas chaves são iguais
    printf("Verificando se a chave secreta gerada no encapsulamento coincide com a chave secreta desencapsulada...\n");
    if (memcmp(encapsulated.K, K_prime, 32) == 0) {
        printf("As chaves coincidem. Teste bem-sucedido.\n");
    } else {
        printf("As chaves não coincidem. Teste falhou.\n");
    }

    return 0;
}
