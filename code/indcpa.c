#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arm_neon.h>
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "fips202x2.h"
#include "randombytes.h"


/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  polyvec_tobytes(r, pk);
  memcpy(r+KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  polyvec_frombytes(pk, packedpk);
  memcpy(seed, packedpk+KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v)
{
  polyvec_compress(r, b);
  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  polyvec_decompress(b, c);
  poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r, unsigned int len, const uint8_t *buf, unsigned int buflen) {
  unsigned int ctr = 0, pos = 0;
  uint16_t val0, val1, val2, val3;

  // Processo unrolled: 2 pares (val0-val1 e val2-val3) a cada iteração
  while (ctr + 4 <= len && pos + 6 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    val2 = ((buf[pos+3] >> 0) | ((uint16_t)buf[pos+4] << 8)) & 0xFFF;
    val3 = ((buf[pos+4] >> 4) | ((uint16_t)buf[pos+5] << 4)) & 0xFFF;
    pos += 6;

    if (val0 < KYBER_Q) r[ctr++] = val0;
    if (val1 < KYBER_Q && ctr < len) r[ctr++] = val1;
    if (val2 < KYBER_Q && ctr < len) r[ctr++] = val2;
    if (val3 < KYBER_Q && ctr < len) r[ctr++] = val3;
  }

  // Processo restante (caso haja valores que não completaram um bloco de 6 bytes)
  while (ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if (val0 < KYBER_Q) r[ctr++] = val0;
    if (val1 < KYBER_Q && ctr < len) r[ctr++] = val1;
  }

  return ctr;
}


#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#if(XOF_BLOCKBYTES % 3)
#error "Implementation of gen_matrix assumes that XOF_BLOCKBYTES is a multiple of 3"
#endif

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

static void xof_absorb2x(keccakx2_state *state,
                  const uint8_t seed[KYBER_SYMBYTES],
                  uint8_t x0, uint8_t y0, uint8_t x1, uint8_t y1) {
    uint8_t extseed0[KYBER_SYMBYTES + 2];
    uint8_t extseed1[KYBER_SYMBYTES + 2];

    memcpy(extseed0, seed, KYBER_SYMBYTES);
    memcpy(extseed1, seed, KYBER_SYMBYTES);

    extseed0[KYBER_SYMBYTES] = x0;
    extseed0[KYBER_SYMBYTES + 1] = y0;
    
    extseed1[KYBER_SYMBYTES] = x1;
    extseed1[KYBER_SYMBYTES + 1] = y1; 

    shake128x2_absorb_once(state, extseed0, extseed1, sizeof(extseed0));
}

static void xof_squeezeblocks2x(uint8_t *out0, uint8_t *out1, size_t nblocks, keccakx2_state *state)
{    
    shake128x2_squeezeblocks(out0, out1, nblocks, state);
}


// Geração da Matriz A
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed) {
    unsigned int ctr0, ctr1, i, j;
    unsigned int buflen;
    uint8_t buf0[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    uint8_t buf1[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
  
    keccakx2_state state;
    keccak_state state1x;

    if (KYBER_K!=3) {

        for (i = 0; i < KYBER_K; i++) {
            // Percorre pares de polinômios
            for (j = 0; j + 1 < KYBER_K; j += 2) {
                // Absorver o estado para dois polinômios simultaneamente
                if (transposed) {
                    xof_absorb2x(&state, seed, i, j, i, j + 1);
                } else {
                    xof_absorb2x(&state, seed, j, i, j + 1, i);
                }
                

                // Extrair blocos de dados em paralelo
                xof_squeezeblocks2x(buf0, buf1, GEN_MATRIX_NBLOCKS, &state);
                buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;

                // Aplicar rejeição uniforme para os dois polinômios
                ctr0 = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf0, buflen);
                ctr1 = rej_uniform(a[i].vec[j + 1].coeffs, KYBER_N, buf1, buflen);

                // Continuar extraindo dados até preencher KYBER_N elementos para ambos
                while (ctr0 < KYBER_N || ctr1 < KYBER_N) {
                    xof_squeezeblocks2x(buf0, buf1, 1, &state);
                    buflen = XOF_BLOCKBYTES;

                    if (ctr0 < KYBER_N) {
                        ctr0 += rej_uniform(a[i].vec[j].coeffs + ctr0, KYBER_N - ctr0, buf0, buflen);
                    }
                    if (ctr1 < KYBER_N) {
                        ctr1 += rej_uniform(a[i].vec[j + 1].coeffs + ctr1, KYBER_N - ctr1, buf1, buflen);
                    }
                }
            }
            
        }
    }
    else {
        ctr0 = 0; i=0; j=0;
        uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES];
  

        for(i=0;i<KYBER_K;i++) {
          for(j=0;j<KYBER_K;j++) {
            if(transposed)
              xof_absorb(&state1x, seed, i, j);
            else
              xof_absorb(&state1x, seed, j, i);

            xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state1x);
            buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
            ctr0 = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

            while(ctr0 < KYBER_N) {
              xof_squeezeblocks(buf, 1, &state1x);
              buflen = XOF_BLOCKBYTES;
              ctr0 += rej_uniform(a[i].vec[j].coeffs + ctr0, KYBER_N - ctr0, buf, buflen);
            }
          }
        }
      }

    }

/*************************************************
* Name:        indcpa_keypair_derand
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                             (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                             (of length KYBER_SYMBYTES bytes)
**************************************************/
void indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t buf[2*KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf+KYBER_SYMBYTES;
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv;

  memcpy(buf, coins, KYBER_SYMBYTES);
  buf[KYBER_SYMBYTES] = KYBER_K;
  hash_g(buf, buf, KYBER_SYMBYTES+1);
  
  gen_a(a, publicseed);
  
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
  
  polyvec_ntt(&skpv);
  polyvec_ntt(&e);
  
  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
  
    poly_tomont(&pkpv.vec[i]);
  
  }

  polyvec_add(&pkpv, &pkpv, &e);
  
  polyvec_reduce(&pkpv);
  
  pack_sk(sk, &skpv);
  
  pack_pk(pk, &pkpv, publicseed);
   
}


/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{  
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[KYBER_K], b;
  poly v, k, epp;
 
  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);
  gen_at(at, seed);
 
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  poly_getnoise_eta2(&epp, coins, nonce++);
 
  polyvec_ntt(&sp);
 
  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
 
  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);
 
  polyvec_invntt_tomont(&b);
  poly_invntt_tomont(&v);
 
  polyvec_add(&b, &b, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&b);
  poly_reduce(&v);

  pack_ciphertext(c, &b, &v);
 
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec b, skpv;
  poly v, mp;

  unpack_ciphertext(&b, &v, c);
  unpack_sk(&skpv, sk);

  polyvec_ntt(&b);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
}