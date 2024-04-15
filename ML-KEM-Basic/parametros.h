#ifndef PARAMETROS_H
#define PARAMETROS_H

#define KYBER_K 2
#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_Z 17
#define ENCAPS_SIZE (384 * KYBER_K + 32)  // Tamanho da chave de Encapsulamento


// Variáveis globais dependendo do valor de KYBER_K
#if KYBER_K == 2
    #define KYBER_ETA1 3
    #define KYBER_ETA2 2
    #define KYBER_DU 10
    #define KYBER_DV 4
#elif KYBER_K == 3
    #define KYBER_ETA1 2
    #define KYBER_ETA2 2
    #define KYBER_DU 10
    #define KYBER_DV 4
#elif KYBER_K == 4
    #define KYBER_ETA1 2
    #define KYBER_ETA2 2
    #define KYBER_DU 11
    #define KYBER_DV 5
#else
    #error "KYBER_K deve ser 2, 3 ou 4"
#endif


#endif