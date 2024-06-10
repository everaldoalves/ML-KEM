#include <benchmark/benchmark.h>
#include "mlKemKeyGen.h"
#include "mlKemEncaps.h"
#include "mlKemDecaps.h"
#include "pkeKeyGen.h"
#include "pkeDecrypt.h"
#include "pkeEncrypt.h"
#include "auxiliares.h"
#include "amostragem.h"
#include "ntt.h"
#include <cstdint>
#include <random>
#include "randombytes.h"



chavesPKE PKEKeys;
chavesKEM KEMKeys;
unsigned char mensagem[32];
unsigned char r[32];
unsigned char d[32];
unsigned char sigma[32];            // saídas de G
unsigned char output[64 * KYBER_ETA1] = {0};    // Bytes aleatórios para SamplePolyCBD
unsigned char md[1024];
uint8_t textoCifrado[KYBER_DU*KYBER_K+KYBER_DV];
encaps resultadoEncaps;
uint8_t i,j=1;
uint16_t f[256],g[256],h[256];
uint8_t eta = 2;
uint8_t outputPRF[64*KYBER_ETA1];
uint16_t A[KYBER_K][KYBER_K][KYBER_N] = {{{0}}};
uint16_t s[KYBER_K][KYBER_N] = {{0}};
uint16_t e[KYBER_K][KYBER_N] = {{0}};    
uint16_t t_hat[KYBER_K][KYBER_N] = {{0}}; 
uint16_t a_hat[KYBER_N] = {0}; 
uint16_t r_vector[KYBER_K][KYBER_N] = {{0}};
uint16_t e1[KYBER_K][KYBER_N] = {{0}};
uint16_t e2[KYBER_N] = {0}; 
uint16_t u[KYBER_N][KYBER_N] = {{0}};; uint16_t v[KYBER_N] = {0}; uint16_t mu[KYBER_N] = {0}; 
uint8_t  c[384*KYBER_K+32], c1[KYBER_K * KYBER_N * KYBER_DU / 8], c2[KYBER_N * KYBER_DV / 8]; 
//Decaps
uint8_t m_linha[32]; uint8_t dkPKE[384*KYBER_K]; uint8_t ekPKE[384*KYBER_K + 32];  uint8_t r_linha[32]; uint8_t m_linha_h[64];
uint16_t tamanhoTextoCifrado = 32 * (KYBER_DU * KYBER_K + KYBER_DV);
uint8_t K_bar[32]; uint8_t z[32];
uint8_t z_c[700]; uint8_t c_linha[800]; 
    


// Função que lê o contador de ciclos de CPU no ARM
inline uint64_t read_cycle_count() {
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r" (val));
    return val;
}

// Função generateRandomBytes
static void BM_GenerateRandomBytes(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        generateRandomBytes(mensagem,32);       
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_GenerateRandomBytes);

// Função RandomBytes Otimizada Decio
static void BM_RandomBytes(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        randombytes(mensagem,32);       
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_RandomBytes);

// Função ByteEncode
static void BM_ByteEncode(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        byteEncode(f,mensagem, 12);      
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
BENCHMARK(BM_ByteEncode);

// Função ByteDecode
static void BM_ByteDecode(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        byteDecode(mensagem, f, 12);
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
BENCHMARK(BM_ByteDecode);



//************************************************************ GERAÇÃO DAS CHAVES PKE *******************************************************************

// Função de Geração de Chaves PKE
static void BM_pkeKeyGen(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();        
        PKEKeys = pkeKeyGen(); 
        auto end = read_cycle_count();     
        // O contador de ciclos é armazenado como uma métrica customizada
        state.counters["Cycles"] = end - start;
    }
}
BENCHMARK(BM_pkeKeyGen);

// Custo da geração de bytes aleatórios e função G (SHA-3)
static void BM_pkeKeyGenRandomBytesPlusFuncionG(benchmark::State& state) {
    unsigned char md[KYBER_K * 3 * KYBER_N]; // Buffer grande o suficiente para a linha inteira
    for (auto _ : state) {
        auto start = read_cycle_count();      
        
        // Gera bytes aleatórios para semente
        generateRandomBytes(d, sizeof(d));                  

        // Aplica a função G em d para obter rho e sigma
        G(d, sizeof(d), r, mensagem);

        auto end = read_cycle_count();     
        // O contador de ciclos é armazenado como uma métrica customizada
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_pkeKeyGenRandomBytesPlusFuncionG);


// Função de Geração da matriz A para KeyGen
static void BM_pkeKeyGenMatrizAOtimizada(benchmark::State& state) {
    unsigned char md[KYBER_K * 3 * KYBER_N]; // Buffer grande o suficiente para a linha inteira
    for (auto _ : state) {
        auto start = read_cycle_count();      
        
        geraMatrizAOtimizada(r,A);

        auto end = read_cycle_count();     
        // O contador de ciclos é armazenado como uma métrica customizada
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_pkeKeyGenMatrizAOtimizada);

// Função de Geração da matriz A para KeyGen SEM OTIMITZAÇÃO PARA COMPARAÇÃO COM A GERAÇÃO DA MATRIZ OTIMIZADA
static void BM_pkeKeyGenMatrizA(benchmark::State& state) {
    unsigned char md[KYBER_K * 3 * KYBER_N]; // Buffer grande o suficiente para a linha inteira
    for (auto _ : state) {
        auto start = read_cycle_count();      
        
        for (uint8_t i=0; i < KYBER_K; i++) {                     
            for (uint8_t j=0; j < KYBER_K; j++) {                         
                XOF(r, j, i, md);                         
                sampleNTT(md, A[i][j]);                               
            }    
        }

        auto end = read_cycle_count();     
        // O contador de ciclos é armazenado como uma métrica customizada
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_pkeKeyGenMatrizA);


// Função de Geração dos vetores S e E para KeyGen
static void BM_pkeKeyGenSeE(benchmark::State& state) {
    uint8_t N=0;
    for (auto _ : state) {
        auto start = read_cycle_count();        
           // Gera os elementos do vetor s
        for (int i=0; i < KYBER_K; i++)    {                      // generate s ∈ (Zq256)^k              
                PRF(KYBER_ETA1,mensagem,N,outputPRF);                      
                samplePolyCBD_neon(outputPRF, f, KYBER_ETA1);                                                                       
                memcpy(s[i], f, KYBER_N * sizeof(uint16_t));
                N = N + 1;
        }  

        // Gera os elementos do vetor e
        for (int i=0; i < KYBER_K; i++)    {                      // generate e ∈ (Zq256)^k                                                                 
            PRF(KYBER_ETA1,mensagem,N,outputPRF);
            samplePolyCBD_neon(outputPRF, f, KYBER_ETA1);
            memcpy(e[i], f, KYBER_N * sizeof(uint16_t));
            N = N + 1;  
        }
        auto end = read_cycle_count();     
        // O contador de ciclos é armazenado como uma métrica customizada
        state.counters["Cycles"] = end - start;
    }
}
BENCHMARK(BM_pkeKeyGenSeE);

// Função de Geração dos vetores S e E
static void BM_pkeKeyGenNTTSeE(benchmark::State& state) {
    uint8_t N=0;   

    for (auto _ : state) {
        auto start = read_cycle_count();        

        // Gera os elementos do vetor s
        for (int i=0; i < KYBER_K; i++)    {                      // generate s ∈ (Zq256)^k              
            PRF(KYBER_ETA1,sigma,N,output);                        
            samplePolyCBD(output, s[i], KYBER_ETA1);                                                                                 
            N = N + 1;
            ntt(s[i]);                         // NTT is run k times (once for each coordinate of s)
            
        }  
    
        // Gera os elementos do vetor e
        for (int i=0; i < KYBER_K; i++)    {                      // generate e ∈ (Zq256)^k                                                                 
            PRF(KYBER_ETA1,sigma,N,output);
            samplePolyCBD(output, e[i], KYBER_ETA1);        
            N = N + 1;                 
            ntt(e[i]);                         // NTT is run k times    
        }    

        auto end = read_cycle_count();     
        // O contador de ciclos é armazenado como uma métrica customizada
        state.counters["Cycles"] = end - start;
    }
    
}
BENCHMARK(BM_pkeKeyGenNTTSeE);
  
// Função de Cálculo de t_hat durante a geração das chaves t_hat=As+e
static void BM_tHat(benchmark::State& state) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dist(0, 3328);
    // Inicialização dos vetores com valores aleatórios
    for (int i = 0; i < KYBER_K; ++i) {
        for (int j = 0; j < KYBER_K; ++j) {
            for (int k = 0; k < KYBER_N; ++k) {
                A[i][j][k] = dist(gen);
            }
        }
        for (int j = 0; j < KYBER_N; ++j) {
            s[i][j] = dist(gen);
            e[i][j] = dist(gen);
        }
    }

    for (auto _ : state) {
        auto start = read_cycle_count();        
        calculaT_hat(A, s, e, t_hat); 
        auto end = read_cycle_count();     
        // O contador de ciclos é armazenado como uma métrica customizada
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_tHat);

// Função de ByteEncode durante a geração das chaves 
static void BM_PKEKeyGenByteEncode(benchmark::State& state) {   

    for (auto _ : state) {
        auto start = read_cycle_count();   

        // Geração das CHAVES
        for (int i=0; i < KYBER_K; i++) {         
            // Codifica t[i]                        // ▷ ByteEncode12 is run k times; include seed for Aˆ        
            byteEncode(t_hat[i], PKEKeys.ek + (i * 384), 12);                                              

            // Codifica s[i] para dk              chaves.dk[i] = byteEncode(s[i]);            // ▷ ByteEncode12 is run k times     
            byteEncode(s[i], PKEKeys.dk + (i * 384), 12);
        } 

        auto end = read_cycle_count();     
        // O contador de ciclos é armazenado como uma métrica customizada
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_PKEKeyGenByteEncode);

// ************************************ Funções PKE Encrypt *********************************************************************************

// Função PKE Encrypt
static void BM_pkeEncrypt(benchmark::State& state) {
    generateRandomBytes(mensagem,32);
    generateRandomBytes(r,32);
    for (auto _ : state) {                
        auto start = read_cycle_count();  
        pkeEncrypt(PKEKeys.ek, mensagem, r, textoCifrado);
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_pkeEncrypt);

// Função PKE Encrypt - Generate Random Vectors
static void BM_pkeEncryptGenRandomVectors(benchmark::State& state) {    
    generateRandomBytes(r,32);
    for (auto _ : state) {                
        auto start = read_cycle_count();  
        generateRandomVectors(r,r_vector,e1,e2,0); 
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_pkeEncryptGenRandomVectors);


// Função PKE Encrypt - Calcula vetor u
static void BM_pkeEncryptCalculaU(benchmark::State& state) {    
    generateRandomBytes(r,32);
    for (auto _ : state) {                
        auto start = read_cycle_count();  
        calculaU(A, r_vector, e1,  u);
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
BENCHMARK(BM_pkeEncryptCalculaU);

// Função PKE Encrypt - Calcula vetor v
static void BM_pkeEncryptCalculaV(benchmark::State& state) {    
    generateRandomBytes(r,32);
    for (auto _ : state) {                
        auto start = read_cycle_count();  
        calculaV(t_hat, r_vector, e2, mu, v);
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
BENCHMARK(BM_pkeEncryptCalculaV);

// Função PKE Encrypt - CompressEEncode
static void BM_pkeEncryptCompressEncode(benchmark::State& state) {    
    generateRandomBytes(r,32);
    for (auto _ : state) {                
        auto start = read_cycle_count();  
        compressAndEncode(u, v, c1, c2);
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
BENCHMARK(BM_pkeEncryptCompressEncode);

// Função PKE Encrypt - DecompressMu
static void BM_pkeEncryptDecompressMu(benchmark::State& state) {    
    generateRandomBytes(r,32);
    for (auto _ : state) {                
        auto start = read_cycle_count();  
        decompressMu(mensagem, mu);
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
BENCHMARK(BM_pkeEncryptDecompressMu);

// Função PKE Encrypt - GenMatrizA
static void BM_pkeEncryptGenMatrizA(benchmark::State& state) {    
    generateRandomBytes(r,32);
    for (auto _ : state) {                
        auto start = read_cycle_count();  
        geraMatrizA(r,A);
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
BENCHMARK(BM_pkeEncryptGenMatrizA);

// Função PKE Encrypt - Passos 2 e 3
static void BM_pkeEncryptPassos2e3(benchmark::State& state) {    
    
    for (auto _ : state) {                
        auto start = read_cycle_count();  
        
        // Passo 2: ByteDecode do ekPKE para t_hat       
        int subarraySize = 384 * KYBER_K;       
        uint8_t ekPKE_Subarray[subarraySize];
        memcpy(ekPKE_Subarray, PKEKeys.ek, subarraySize);   
        uint8_t auxiliar[384];

        for (int i = 0; i < KYBER_K; i++) {
            if (i==0)  {
                memcpy(auxiliar,ekPKE_Subarray, 384);              
            }
            else {
                memcpy(auxiliar,ekPKE_Subarray + i* 384, 384);  
            }
                    
            byteDecode(auxiliar, t_hat[i], 12);
        }      
        // Passo 3: Extração de rho
        memcpy(r, PKEKeys.ek + 384 * KYBER_K, 32);

        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
BENCHMARK(BM_pkeEncryptPassos2e3);

// Função PKE Encrypt - Passo 24 - Última parte da Encryptação
static void BM_pkeEncryptPasso18(benchmark::State& state) {    
    generateRandomBytes(r,32);
    for (auto _ : state) {                
        auto start = read_cycle_count();  
        // Passo 18: Aplicação de NTT a r    
        for (int i = 0; i < KYBER_K; i++) {
            ntt(r_vector[i]);
        } 
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_pkeEncryptPasso18);


// Função PKE Encrypt - Passo 24 - Última parte da Encryptação
static void BM_pkeEncryptPasso24(benchmark::State& state) {    
    generateRandomBytes(r,32);
    for (auto _ : state) {                
        auto start = read_cycle_count();  
         // Passo 4-8: Geração da matriz A
        // 24: return c ← (c1∥c2)
        memcpy(c, c1, sizeof(c1)); // Copia 'c1' para 'c'
        memcpy(c + sizeof(c1), c2, sizeof(c2)); // Concatena 'c2' após 'c1' em 'c'
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_pkeEncryptPasso24);

   
 

// ******************************* Funções PKE Decrypt ***************************************************************

// Função PKE Decrypt
static void BM_pkeDecrypt(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count(); 
        pkeDecrypt(PKEKeys.dk,textoCifrado,mensagem);
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_pkeDecrypt);

//****************************** Funções ML-KEM ******************************************************************

// Função de Geração de Chaves KEM
static void BM_mlKemKeyGen(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        KEMKeys = mlKemKeyGen();
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemKeyGen);

// Função ML-KEM Encaps
static void BM_mlKemEncaps(benchmark::State& state) {
    size_t size = sizeof(KEMKeys.ek);
    for (auto _ : state) {
        auto start = read_cycle_count();           
        mlKemEncaps(KEMKeys.ek,size);       
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemEncaps);

// Função ML-KEM Decaps
static void BM_mlKemDecaps(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        mlKemDecaps(resultadoEncaps.c,KEMKeys.dk,resultadoEncaps.K);       
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemDecaps);

// Função ML-KEM Decaps - Passo 1
static void BM_mlKemDecapsPasso1(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        // 1: Extrai dkPKE        
        memcpy(dkPKE, KEMKeys.dk, 384*KYBER_K);    
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemDecapsPasso1);

// Função ML-KEM Decaps - Passo 2
static void BM_mlKemDecapsPasso2(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        // 2: Extrai ekPKE         
        memcpy(ekPKE, KEMKeys.dk + 384*KYBER_K, 384*KYBER_K + 32);       
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemDecapsPasso2);

// Função ML-KEM Decaps - Passo 3
static void BM_mlKemDecapsPasso3(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        // 3: Extrai h
        uint8_t h[32];
        memcpy(h, KEMKeys.dk + 768*KYBER_K + 32, 32);       
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemDecapsPasso3);    

// Função ML-KEM Decaps - Passo 4
static void BM_mlKemDecapsPasso4(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        // 4: Extrai z        
        memcpy(z, KEMKeys.dk + 768*KYBER_K + 64, 32);      
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemDecapsPasso4); 

// Função ML-KEM Decaps - Passo 5
static void BM_mlKemDecapsPasso5(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        // 5: Decriptar c para obter m'        
        pkeDecrypt(dkPKE, resultadoEncaps.c, m_linha);     
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemDecapsPasso5); 
    
// Função ML-KEM Decaps - Passo 6
static void BM_mlKemDecapsPasso6(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
         // 6: Deriva K' e r' de G(m'||h)   
        memcpy(m_linha_h, m_linha, 32);
        memcpy(m_linha_h + 32, h, 32);
        G(m_linha_h, 64, resultadoEncaps.K, r_linha);   
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemDecapsPasso6); 
  
// Função ML-KEM Decaps - Passo 7
static void BM_mlKemDecapsPasso7(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        // 7: Calcula K̄ usando J(z||c, 32)       
        memcpy(z_c, z, 32);
        memcpy(z_c + 32, c, tamanhoTextoCifrado); 
        J(z_c, tamanhoTextoCifrado+32, K_bar);  
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemDecapsPasso7); 
    
// Função ML-KEM Decaps - Passo 8
static void BM_mlKemDecapsPasso8(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        // 8: Re-criptografa m' usando r' para obter c'        
        pkeEncrypt(ekPKE, m_linha, r_linha, c_linha);  
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemDecapsPasso8); 
  
// Função ML-KEM Decaps - Passo 9
static void BM_mlKemDecapsPasso9(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        // 9: Verifica se c é igual a c'. Se não, usa K̄
        if (memcmp(resultadoEncaps.c, c_linha, tamanhoTextoCifrado) != 0) {
            memcpy(resultadoEncaps.K, K_bar, 32); // Usa K̄ se os textos cifrados não coincidirem
        }  
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start; 
    }
}
// Registra o benchmark
BENCHMARK(BM_mlKemDecapsPasso9); 


    

//****************************** Funções Auxiliares ******************************************************************

// Função G
static void BM_G(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        G(mensagem,32,mensagem,r);        
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_G);

// Função H
static void BM_H(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        H(mensagem,32,r);      
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;  
    }
}
// Registra o benchmark
BENCHMARK(BM_H);

// Função J
static void BM_J(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        J(mensagem,32,r);        
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_J);

// Função XOF
static void BM_XOF_PER_ROW(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        XOF_per_row(mensagem,i,md,sizeof(md));            
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;    
    }
}
// Registra o benchmark
BENCHMARK(BM_XOF_PER_ROW);

// Função XOF
static void BM_XOF(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        XOF(mensagem,i,j,md);    
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;    
    }
}
// Registra o benchmark
BENCHMARK(BM_XOF);

// Função PRF
static void BM_PRF(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        PRF(3,mensagem,i,md);        
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_PRF);

//****************************** Funções de Amostragem ******************************************************************

// Função samplePolyCBD
static void BM_SamplePolyCBD(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        samplePolyCBD(outputPRF,f,eta);   
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;     
    }
}
// Registra o benchmark
BENCHMARK(BM_SamplePolyCBD);

// Função samplePolyCBD
static void BM_SamplePolyCBD_NEON(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();  
        samplePolyCBD_neon(outputPRF,f,eta);   
        auto end = read_cycle_count();  
        state.counters["Cycles"] = end - start;     
    }
}
// Registra o benchmark
BENCHMARK(BM_SamplePolyCBD_NEON);

// Função sampleNTT
static void BM_SampleNTT(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();        
        sampleNTT(md, f);
        auto end = read_cycle_count();       
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_SampleNTT);

// Função sampleNTT_neon
static void BM_SampleNTT_neon(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();        
        sampleNTT_neon(md, f);
        auto end = read_cycle_count();       
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_SampleNTT_neon);

//****************************** Funções NTT ******************************************************************

// Função NTT
static void BM_NTT(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();        
        ntt(f);
        auto end = read_cycle_count();        
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_NTT);

// Função INVNTT
static void BM_INVNTT(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();        
        invntt(f);
        auto end = read_cycle_count();        
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_INVNTT);

// Função MultiplicaNTT
static void BM_MultiplicaNTT(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();        
        multiplicaNTT(f, g, h);
        auto end = read_cycle_count();        
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_MultiplicaNTT);

// Função MultiplicaNTT NEON
static void BM_MultiplicaNTT_NEON(benchmark::State& state) {
    for (auto _ : state) {
        auto start = read_cycle_count();        
        multiplicaNTT_neon(f, g, h);
        auto end = read_cycle_count();        
        state.counters["Cycles"] = end - start;
    }
}
// Registra o benchmark
BENCHMARK(BM_MultiplicaNTT_NEON);


// A função main é necessária para executar os benchmarks
BENCHMARK_MAIN();
