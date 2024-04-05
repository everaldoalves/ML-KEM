#include <stdint.h>
#include "parametros.h"

#ifndef AUXILIARES_H
#define AUXILIARES_H

// Função para converter um array de bits em um array de bytes
void bitsToBytes(const uint8_t bits[], uint8_t* bytes, int num_bits);

// Função para converter um array de bytes em um array de bits
void bytesToBits(const uint8_t bytes[], uint8_t bits[], size_t num_bits);

// Função para codificar um array de d-bit inteiros em um array de bytes
void byteEncode(const uint16_t F[], uint8_t B[], int d);

// Função para decodificar um array de bytes em um array de d-bit inteiros
void byteDecode(const uint8_t B[], uint16_t F[], int d);

// Função G - SHA-3 512 utilizando openssl  G : B∗ → B32 × B32  G(c) := SHA3-512(c)
void G(const unsigned char *input, size_t input_len, unsigned char *a, unsigned char *b);

// Função H - SHA-3 256 utilizando openssl  H : B∗ → B32   H(s) := SHA3-256(s)
void H(const unsigned char *input, size_t input_len, unsigned char output[32]); 

// Função J - SHAKE256 utilizando openssl   J : B∗ → B32   J(s) := SHAKE256(s,32)
void J(const unsigned char *input, size_t input_len, unsigned char output[32]); 

// Função XOF - Shake128 utilizando openssl  
void XOF(unsigned char *rho, unsigned char i, unsigned char j, unsigned char *md);
    
// Função PRF - Shake256 utilizando openssl
void PRF(uint8_t eta, const uint8_t s[32], uint8_t b, uint8_t *output);

// Gera bytes aleatórios
void generateRandomBytes(unsigned char *buffer, int length);

// Faz o arredondamento para mais a partir 0.5 ou para menos quando inferior a 0.5
int rounding(int numerator, int denominator);

// Comprime Compress_d: Zq -> Z_2^d
uint16_t compress_d(uint16_t x, uint16_t d);
    
// Descomprime Decompress_d: Z_2^d -> Zq
uint16_t decompress_d(uint16_t y, uint16_t d);

#endif