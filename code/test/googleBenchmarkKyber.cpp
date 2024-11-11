// Comando para compilar a partir da pasta ref:
//g++ -O2 -std=c++11 -I /opt/homebrew/include test/googleBenchmarkKyber.cpp kem.c indcpa.c poly.c polyvec.c randombytes.c ntt.c reduce.c cbd.c verify.c fips202.c fips202x2.c symmetric-shake.c feat.S -L /opt/homebrew/lib -lbenchmark -lpthread -o test/googleBenchmarkKyber

#include <benchmark/benchmark.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../randombytes.h"
#include "../kem.h"
#include "../params.h"
#include "../indcpa.h"
#include "../polyvec.h"
#include "../poly.h"
#include "cpucycles.h"
#include "speed_print.h"
#include "../feat_dit.h"

#define NTESTS 1000

uint64_t t[NTESTS];
uint8_t seed[KYBER_SYMBYTES] = {0};

  unsigned int i;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key[CRYPTO_BYTES];
  uint8_t coins32[KYBER_SYMBYTES];
  uint8_t coins64[2*KYBER_SYMBYTES];
  polyvec matrix[KYBER_K];
  poly ap;

// Classe de fixture para o benchmark
class KyberBenchmark : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State& state) {
        // Inicialização das variáveis
        randombytes(coins32, KYBER_SYMBYTES);
        randombytes(coins64, 2 * KYBER_SYMBYTES);
        set_dit_bit();
        // Inicialize outras variáveis necessárias aqui
    }

    void TearDown(const ::benchmark::State& state) {
        // Limpeza, se necessário
    }
   
    // Variáveis que podem ser usadas em todos os benchmarks dentro desta fixture    
};


  // Função para medir o tempo de "gen_matrix"
static void BM_gen_matrix(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'matrix' e 'seed' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        gen_matrix(matrix, seed, 0);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_gen_matrix);

// Função para medir o tempo de "poly_getnoise_eta1"
static void BM_poly_getnoise_eta1(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
        
    for (auto _ : state) {
        start_cycles = cpucycles();
        poly_getnoise_eta1(&ap, seed, 0);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_poly_getnoise_eta1);

// Função para medir o tempo de "poly_getnoise_eta2"
static void BM_poly_getnoise_eta2(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ap' e 'seed' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        poly_getnoise_eta2(&ap, seed, 0);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_poly_getnoise_eta2);

// Função para medir o tempo de "poly_ntt"
static void BM_poly_ntt(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ap' está declarado e inicializado adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        poly_ntt(&ap);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_poly_ntt);

// Função para medir o tempo de "poly_invntt_tomont"
static void BM_poly_invntt_tomont(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ap' está declarado e inicializado adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        poly_invntt_tomont(&ap);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_poly_invntt_tomont);

// Função para medir o tempo de "polyvec_basemul_acc_montgomery"
static void BM_polyvec_basemul_acc_montgomery(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ap' e 'matrix' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        polyvec_basemul_acc_montgomery(&ap, &matrix[0], &matrix[1]);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_polyvec_basemul_acc_montgomery);

// Função para medir o tempo de "poly_tomsg"
static void BM_poly_tomsg(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ct' e 'ap' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        poly_tomsg(ct, &ap);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_poly_tomsg);

// Função para medir o tempo de "poly_frommsg"
static void BM_poly_frommsg(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    // Supondo que 'ap' e 'ct' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        poly_frommsg(&ap, ct);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_poly_frommsg);

// Função para medir o tempo de "poly_compress"
static void BM_poly_compress(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ct' e 'ap' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        poly_compress(ct, &ap);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_poly_compress);

// Função para medir o tempo de "poly_decompress"
static void BM_poly_decompress(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ap' e 'ct' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        poly_decompress(&ap, ct);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_poly_decompress);

// Função para medir o tempo de "polyvec_compress"
static void BM_polyvec_compress(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ct' e 'matrix' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        polyvec_compress(ct, &matrix[0]);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_polyvec_compress);

// Função para medir o tempo de "polyvec_decompress"
static void BM_polyvec_decompress(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'matrix' e 'ct' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        polyvec_decompress(&matrix[0], ct);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_polyvec_decompress);

// Função para medir o tempo de "indcpa_keypair_derand"
static void BM_indcpa_keypair_derand(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'pk', 'sk' e 'coins32' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        indcpa_keypair_derand(pk, sk, coins32);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_indcpa_keypair_derand);


// Função para medir o tempo de "indcpa_enc"
static void BM_indcpa_enc(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ct', 'key', 'pk' e 'seed' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        indcpa_enc(ct, key, pk, seed);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_indcpa_enc);

// Função para medir o tempo de "indcpa_dec"
static void BM_indcpa_dec(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'key', 'ct' e 'sk' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        indcpa_dec(key, ct, sk);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_indcpa_dec);

// Função para medir o tempo de "crypto_kem_keypair_derand"
static void BM_crypto_kem_keypair_derand(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'pk', 'sk' e 'coins64' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        crypto_kem_keypair_derand(pk, sk, coins64);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_crypto_kem_keypair_derand);

// Função para medir o tempo de "crypto_kem_keypair"
static void BM_crypto_kem_keypair(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'pk' e 'sk' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        crypto_kem_keypair(pk, sk);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_crypto_kem_keypair);

// Função para medir o tempo de "crypto_kem_enc_derand"
static void BM_crypto_kem_enc_derand(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ct', 'key', 'pk' e 'coins32' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        crypto_kem_enc_derand(ct, key, pk, coins32);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_crypto_kem_enc_derand);


// Função para medir o tempo de "crypto_kem_enc"
static void BM_crypto_kem_enc(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'ct', 'key' e 'pk' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        crypto_kem_enc(ct, key, pk);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_crypto_kem_enc);

// Função para medir o tempo de "crypto_kem_dec"
static void BM_crypto_kem_dec(benchmark::State &state) {
    uint64_t start_cycles, end_cycles, total_cycles = 0;
    
    // Supondo que 'key', 'ct' e 'sk' estão declarados e inicializados adequadamente
    for (auto _ : state) {
        start_cycles = cpucycles();
        crypto_kem_dec(key, ct, sk);
        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);
    }
    state.counters["Ciclos"] = total_cycles / state.iterations();
}
BENCHMARK(BM_crypto_kem_dec);

// Função principal para executar os benchmarks

BENCHMARK_MAIN();
