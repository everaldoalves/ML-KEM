# Nome da biblioteca a ser criada
LIBNAME = libMLKEM-Basic.a

# Compiladores
CC = gcc
CXX = g++

# Opções de compilação
CFLAGS = -Wall -Wextra -mcpu=apple-m1 -mfpu=neon -O3 -ffast-math -funroll-loops -I/opt/homebrew/opt/openssl@3/include
CXXFLAGS = $(CFLAGS) -I/opt/homebrew/opt/google-benchmark/include -std=c++11

# Flags do vinculador para o OpenSSL e Google Benchmark
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -L/opt/homebrew/opt/google-benchmark/lib -lbenchmark -lbenchmark_main -pthread


# Encontrar todos os arquivos fonte no diretório
SRC = $(wildcard *.c)
CPPSRC = $(wildcard *.cpp)

# Substituir a extensão .c por .o para todos os arquivos fonte
OBJ = $(SRC:.c=.o)
CPPOBJ = $(CPPSRC:.cpp=.o)

# A regra padrão
all: $(LIBNAME) run_benchmarks

# Como construir a biblioteca final
$(LIBNAME): $(OBJ)
	ar rcs $@ $(OBJ)
	ranlib $@

# Como construir os objetos
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compilar e linkar benchmarks
run_benchmarks: $(CPPOBJ)
	$(CXX) $^ $(LDFLAGS) -o $@
run_benchmarks: benchmark.o $(LIBNAME)
	g++ benchmark.o -L. -lMLKEM-Basic -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -L/opt/homebrew/opt/google-benchmark/lib -lbenchmark -lbenchmark_main -pthread -o run_benchmarks


# Limpar arquivos intermediários
clean:
	rm -f $(OBJ) $(CPPOBJ) $(LIBNAME) run_benchmarks

# Instalar a biblioteca (opcional)
install:
	cp $(LIBNAME) /usr/local/lib
	cp *.h /usr/local/include
