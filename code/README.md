<img src="https://github.com/everaldoalves/ML-KEM/raw/master/ML-KEM-Basic/chaveCompartilhadaKyberGitHub.jpeg" alt="Imagem de Fundo" width="200" height="auto">

# ML-KEM

Implementação do mecanismo de encapsulamento de chaves pós-quântico Module-Lattice-Key Encapsulation Mechanism - ML-KEM (FIPS 203) para plataforma ARMv8-A.

## Instruções de compilação
A implementação contêm programas de teste e benchmarking e um Makefile para facilitar a compilação.

### Pré-requisitos

Alguns dos programas de teste requerem o OpenSSL. Se os arquivos de cabeçalho e/ou bibliotecas compartilhadas do OpenSSL não estiverem em um dos locais padrão em seu sistema, é necessário especificar seu local através de flags do compilador e linker nas variáveis de ambiente CFLAGS, NISTFLAGS e LDFLAGS.

Por exemplo, no macOS você pode instalar o OpenSSL via Homebrew executando

```sh 
brew install openssl
```

Em seguida, execute:

```sh
export CFLAGS="-I/opt/homebrew/opt/openssl@1.1/include

export NISTFLAGS="-I/opt/homebrew/opt/openssl@1.1/include

export LDFLAGS="-L/opt/homebrew/opt/openssl@1.1/lib
```

antes da compilação para adicionar os locais dos cabeçalhos e bibliotecas OpenSSL aos respectivos caminhos de busca.

## Programas de Teste
Para compilar os programas de teste no Linux ou macOS, vá para o diretório code/ e execute:

```sh
make
```

Isso produz o executável:

```sh
test/test_kyber$ALG
```

onde $ALG varia sobre os conjuntos de parâmetros 512, 768 e 1024.

test/test_kyber$ALG testa 1000 vezes o processo de gerar chaves, encapsular uma chave aleatória e desencapsulá-la corretamente novamente. Além disso, o programa testa se as chaves não podem ser desencapsuladas corretamente usando uma chave secreta aleatória ou um texto cifrado onde um único byte aleatório foi distorcido aleatoriamente para testar falhas triviais da segurança CCA. O programa abortará com uma mensagem de erro e retornará 1 se houver um erro. Caso contrário, ele emitirá os tamanhos da chave e do texto cifrado e retornará 0.

Também é possível verificar a assertividade da implementação com o script testaDilithium.sh. Este script realizará testes de geração de chaves, assinatura e verificação exibindo os resultados para cada uma das versões do esquema.

## Programas de Benchmarking
Para realizar o benchmarking da implementação, estão disponíveis os programas de teste de velocidade para CPUs x86 que usam o Time Step Counter (TSC) ou o contador de ciclos real fornecido pelos Performance Measurement Counters (PMC) para medir o desempenho. Para compilar os programas, execute:

```sh
make speed
```

Isso produz os executáveis:

```sh
test/test_speed$ALG
```

para todos os conjuntos de parâmetros $ALG mencionados anteriormente. Os programas relatam as contagens de ciclos medianas e médias de 10.000 execuções de várias funções internas e das funções da API para geração de chaves, assinatura e verificação. Por padrão, o Time Step Counter é usado. Se você quiser obter as contagens de ciclos reais dos Performance Measurement Counters, exporte CFLAGS="-DUSE_RDPMC" antes da compilação.

Também é possível realizar o benchmark de maneira mais simples com o emprego do script googleBenchmark.sh. Para utilizá-lo, primeiro você precisa instalar o Google Benchmark. O script instalaGoogleBenchmark.sh pode ser usado para auxiliá-lo nessa tarefa. Com a instalação realizada, basta acessar a pasta test e executar o comando:

```sh
./googleBenchmark.sh
```
## Resultados
A tabela a seguir apresenta os resultados alcançados comparando os ciclos da implementação de referência [1] e deste trabalho para os três níveis de segurança do ML-KEM. Os experimentos para avaliação do desempenho foram realizados no  MacBook Air com o chip Apple M1 (8GB RAM), que possui uma arquitetura ARMv8 com suporte a instruções NEON. O compilador utilizado foi o Clang 18.1.8 e o sistema operacional o iOS Sonoma 14.6.1.

| **Versão**    | **Métrica** | **Impl. Ref.** | **Este Trabalho** | **Aceleração** |
|---------------|-------------|----------------|-------------------|----------------|
| **ML-KEM-512** | KeyGen      | 1282           | 613               | 2.09           |
|               | Encaps        | 5937           | 2518              | 2.38           |
|               | Decaps      | 1418           | 659               | 2.15           |
| **ML-KEM-768** | KeyGen      | 2553           | 997               | 2.56           |
|               | Encaps        | 10964          | 4110              | 2.67           |
|               | Decaps      | 2472           | 1081              | 2.29           |
| **ML-KEM-1024** | KeyGen      | 3515           | 1646              | 2.14           |
|               | Encaps        | 12290          | 4739              | 2.59           |
|               | Decaps      | 3708           | 1666              | 2.23           |

[1] Ducas, L. et al. (2021). CRYSTALS-Kyber (round 3)
</div>
