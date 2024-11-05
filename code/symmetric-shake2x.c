#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "symmetricx2.h"
#include "fips202x2.h"


/*************************************************
* Name:        kyber_shake128x2_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context,
*              optimized to handle two sets of inputs in parallel.
*
* Arguments:   - keccakx2_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
*              - uint8_t x1: additional byte of input for first instance
*              - uint8_t y1: additional byte of input for first instance
*              - uint8_t x2: additional byte of input for second instance
*              - uint8_t y2: additional byte of input for second instance
**************************************************/
void kyber_shake128x2_absorb(keccakx2_state *state,
                             const uint8_t seed[KYBER_SYMBYTES],
                             uint8_t x1, uint8_t y1,
                             uint8_t x2, uint8_t y2)
{
    uint8_t extseed1[KYBER_SYMBYTES + 2];
    uint8_t extseed2[KYBER_SYMBYTES + 2];

    // Concatenação dos valores extras nos dois arrays de sementes
    memcpy(extseed1, seed, KYBER_SYMBYTES);
    extseed1[KYBER_SYMBYTES + 0] = x1;
    extseed1[KYBER_SYMBYTES + 1] = y1;

    memcpy(extseed2, seed, KYBER_SYMBYTES);
    extseed2[KYBER_SYMBYTES + 0] = x2;
    extseed2[KYBER_SYMBYTES + 1] = y2;

    // Absorver ambas as entradas em paralelo
    shake128x2_absorb(state, extseed1, extseed2, sizeof(extseed1));
}

/*************************************************
* Name:        kyber_shake256x2_prf
*
* Description: Usage of SHAKE256 as a PRF, optimized for parallel input processing.
*
* Arguments:   - uint8_t *out1: pointer to the first output
*              - uint8_t *out2: pointer to the second output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce1: nonce (public PRF input) for first instance
*              - uint8_t nonce2: nonce (public PRF input) for second instance
**************************************************/
void kyber_shake256x2_prf(uint8_t *out1, uint8_t *out2, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce1, uint8_t nonce2)
{
    uint8_t extkey1[KYBER_SYMBYTES + 1];
    uint8_t extkey2[KYBER_SYMBYTES + 1];

    // Concatenação das chaves com os respectivos nonces
    memcpy(extkey1, key, KYBER_SYMBYTES);
    extkey1[KYBER_SYMBYTES] = nonce1;

    memcpy(extkey2, key, KYBER_SYMBYTES);
    extkey2[KYBER_SYMBYTES] = nonce2;

    // Gerar a saída em paralelo usando SHAKE256
    shake256x2(out1, out2, outlen, extkey1, extkey2, sizeof(extkey1));
}

/*************************************************
* Name:        kyber_shake256x2_rkprf
*
* Description: Parallel version of the randomized keyed PRF (RKPRF) using SHAKE256.
*
* Arguments:   - uint8_t out1[KYBER_SSBYTES]: pointer to the first output
*              - uint8_t out2[KYBER_SSBYTES]: pointer to the second output
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - const uint8_t *input1: first public input
*              - const uint8_t *input2: second public input
**************************************************/
void kyber_shake256x2_rkprf(uint8_t out1[KYBER_SSBYTES], uint8_t out2[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES],
                            const uint8_t input1[KYBER_CIPHERTEXTBYTES], const uint8_t input2[KYBER_CIPHERTEXTBYTES])
{
    keccakx2_state state;

    // Inicializa o estado do SHAKE256 em paralelo
    shake256x2_init(&state);

    // Absorver chave e entrada em paralelo
    shake256x2_absorb(&state, key, key, KYBER_SYMBYTES);
    shake256x2_absorb(&state, input1, input2, KYBER_CIPHERTEXTBYTES);

    // Finalizar e gerar a saída
    shake256x2_finalize(&state);  // Passa o estado e a posição atual
    shake256x2_squeezeblocks(out1, out2, 1, &state);
}
