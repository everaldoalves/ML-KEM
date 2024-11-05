Esta pasta contém os códigos para benchmarks das funções otimizadas.
Para compilar é necessário primeiramente instalar o Google benchmarks. O script instalaGoogleBenchmark.sh pode ser utilizado para realizar a instalação.
O compilador deve ser utilizado o g++
 g++ -O3 -march=armv8-a+simd -lbenchmark -lpthread -o <nome do executável> <nome do arquivo.cpp> -march=armv8-a+simd
 g++ -O3 -march=armv8-a+simd -I /opt/homebrew/include -L /opt/homebrew/lib -o benchmark_rej_uniform benchmark_rej_uniform.cpp -march=armv8-a+simd
 Se você não exportou as variáveis de ambiente com os caminhos para a biblioteca do google benchmark, precisará informar o caminho completo:
g++ -O3 -std=c++11 -I /opt/homebrew/include benchmark_rej_uniform.cpp  -L /opt/homebrew/lib -lbenchmark -lpthread -o benchmark_rej_uniform -march=armv8-a+simd