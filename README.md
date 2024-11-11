<img src="https://github.com/everaldoalves/ML-KEM/raw/master/ML-KEM-Basic/chaveCompartilhadaKyberGitHub.jpeg" alt="Imagem de Fundo" width="200" height="auto">

# ML-KEM

Implementação do mecanismo de encapsulamento de chaves pós-quântico Module-Lattice-Key Encapsulation Mechanism - ML-KEM (FIPS 203) para plataforma ARMv8-A.

## Instruções de compilação
A implementação contém programas de teste e benchmarking, bem como um Makefile para facilitar a compilação.

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


## Programas de Benchmarking

Para realizar o benchmark de maneira simples, utilize o script googleBenchmark.sh, sendo necessário instalar o Google Benchmark previamente. O script instalaGoogleBenchmark.sh pode ser usado para auxiliá-lo nessa tarefa. Com a instalação realizada, basta acessar a pasta test e executar o comando:

```sh
./googleBenchmark.sh
```

Também estão disponíveis os programas de teste de velocidade para CPUs que usam o contador de ciclos real fornecido pelos Performance Measurement Counters (PMC) para medir o desempenho. Para compilar os programas, execute:

```sh
make speed
```

Isso produz os executáveis:

```sh
test/test_speed$ALG
```

para todos os conjuntos de parâmetros $ALG mencionados anteriormente. Os programas relatam as contagens de ciclos medianas e médias de 10.000 execuções de várias funções internas e das funções da API para geração de chaves, assinatura e verificação. Por padrão, o Time Step Counter é usado. Se você quiser obter as contagens de ciclos reais dos Performance Measurement Counters, exporte CFLAGS="-DUSE_RDPMC" antes da compilação.

## Resultados
As tabelas a seguir apresentam os resultados alcançados comparando os ciclos da implementação de referência [1] e deste trabalho para os três níveis de segurança do ML-KEM. Os experimentos para avaliação do desempenho foram realizados em dois dispositivos Apple. O MacBook Air com o chip M1 (8GB RAM) e o MacBook Air com o chip M2 (8GB RAM), que possuem uma arquitetura ARMv8 com suporte a instruções NEON. O compilador utilizado foi o Clang 18.1.8 e o sistema operacional o MacOS Sonoma 14.4 no M1 e 14.6 no M2.

## Apple M1

| Variante       | Algoritmo | Impl. Ref. | Este Trabalho | Aceleração (x) |
|--------------|-----------|------------|---------------|----------------|
| ML-KEM-512   | KeyGen    | 430        | 166           | 2.59           |
|              | Encaps    | 510        | 204           | 2.50           |
|              | Decaps    | 660        | 275           | 2.40           |
| ML-KEM-768   | KeyGen    | 743        | 336           | 2.21           |
|              | Encaps    | 812        | 350           | 2.32           |
|              | Decaps    | 1018       | 489           | 2.08           |
| ML-KEM-1024  | KeyGen    | 1171       | 415           | 2.82           |
|              | Encaps    | 1194       | 466           | 2.56           |
|              | Decaps    | 1473       | 618           | 2.38           |

*Tabela: Contagens de ciclos no Apple M1 para os três níveis de segurança do ML-KEM em comparação com [1]*

## Apple M2

| Variante       | Algoritmo | Impl. Ref. | Este Trabalho | Aceleração (x) |
|--------------|-----------|------------|---------------|----------------|
| ML-KEM-512   | KeyGen    | 413        | 163           | 2.53           |
|              | Encaps    | 479        | 192           | 2.49           |
|              | Decaps    | 612        | 263           | 2.33           |
| ML-KEM-768   | KeyGen    | 701        | 305           | 2.29           |
|              | Encaps    | 759        | 342           | 2.21           |
|              | Decaps    | 948        | 459           | 2.07           |
| ML-KEM-1024  | KeyGen    | 1094       | 395           | 2.77           |
|              | Encaps    | 1134       | 441           | 2.57           |
|              | Decaps    | 1388       | 587           | 2.36           |

*Tabela: Contagens de ciclos no Apple M2 para os três níveis de segurança do ML-KEM em comparação com [1]*

[1] Ducas, L. et al. (2021). CRYSTALS-Kyber (round 3)
</div>
