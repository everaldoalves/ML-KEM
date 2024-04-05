#include <stdio.h>
#include <string.h>
#include "mlKemEncaps.h"
#include "auxiliares.h"
#include "parametros.h"
#include "mlKemKeyGen.h"

/******************************************************************************
Testa a implementação do Algoritmo 16 - ML-KEM.Encaps() -  ML-KEM FIPS 203 ipd
Generates an encapsulation key and a corresponding decapsulation key.
Output: Encapsulation key ek ∈ B^384k+32.
Output: Decapsulation key dk ∈ B^768k+96
******************************************************************************/

int main() {

    uint16_t tamanhoTextoCifrado = 32 *(KYBER_DU * KYBER_K + KYBER_DV);
    uint8_t tamanhoChaveK = 32;

    printf("Chave de encapsulamento ek :\n");
    
    chavesKEM chavesCriptograficas = {0};
    chavesCriptograficas = mlKemKeyGen();

    // Chama a função mlKemEncaps com a chave de encapsulamento de teste
    printf("Executando mlKemEncaps...\n");
    encaps result = mlKemEncaps(chavesCriptograficas.ek);

    printf("\nResultado do encapsulamento da chave \n");
    // Mostra os resultados
    printf("\n\nChave compartilhada K:\n");
    for(int i = 0; i < 32; i++) {
        printf("%02X ", result.K[i]);
    }
     printf("\nTamanho da chave compartilhada K = %d bytes",tamanhoChaveK);

    printf("\n\n Texto Cifrado c: \n");      
    for(int i = 0; i < tamanhoTextoCifrado; i++) {
        printf("%02X ", result.c[i]);
    }
    printf("\nTamanho do texto cifrado = %d bytes",tamanhoTextoCifrado);
    
    printf("\n");

    return 0;
}
