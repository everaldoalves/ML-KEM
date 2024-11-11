#include <stdint.h>
#include <emscripten.h>
#include "../api.h"

// Função para gerar chave
EMSCRIPTEN_KEEPALIVE
int gerar_chaves(uint8_t *pk, uint8_t *sk) {
    return everaldo_kyber512_keypair(pk, sk);
}

// Função para encapsular
EMSCRIPTEN_KEEPALIVE
int encapsular(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return everaldo_kyber512_enc(ct, ss, pk);
}

// Função para desencapsular
EMSCRIPTEN_KEEPALIVE
int desencapsular(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return everaldo_kyber512_dec(ss, ct, sk);
}

