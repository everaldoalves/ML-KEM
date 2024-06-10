#include "pkeKeyGen.h"
#include "pkeEncrypt.h"
#include "pkeDecrypt.h"
#include "mlKemKeyGen.h"
#include "mlKemEncaps.h"
#include "mlKemDecaps.h"
#include "ntt.h"
#include "amostragem.h"


chavesPKE pkeKeyGen();
chavesKEM mlKemKeyGen();

void pkeEncrypt(const uint8_t *ekPKE, const uint8_t *m, const uint8_t *r, uint8_t *c);
encaps mlKemEncaps(uint8_t encapsKey[384*KYBER_K+32], size_t size);

void pkeDecrypt(const uint8_t *dkPKE, const uint8_t *c, uint8_t *m);
void mlKemDecaps(const uint8_t *c, const uint8_t *dk, uint8_t *K_linha);


// transformada NTT
void ntt(uint16_t vetor[KYBER_N]);

// Calcula os elementos em Rq a partir de um vetor em Tq
void invntt(uint16_t vetor[KYBER_N]);

void samplePolyCBD(unsigned char B[], uint16_t f[], uint8_t eta);
void samplePolyCBD_neon(unsigned char B[], uint16_t f[], uint8_t eta);

void sampleNTT(const unsigned char B[], uint16_t a_hat[]);
void sampleNTT_neon(const unsigned char B[], uint16_t a_hat[]);
