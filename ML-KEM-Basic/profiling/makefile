# Nome da biblioteca a ser criada
LIBNAME = libMLKEM-Basic.a

# Compilador
CC = gcc

# Opções de compilação
CFLAGS = -Wall -Wextra -O2 -I/usr/include/openssl

# Flags do vinculador para o OpenSSL
LDFLAGS = -lssl -lcrypto

# Encontrar todos os arquivos fonte no diretório
SRC = $(wildcard *.c)

# Substituir a extensão .c por .o para todos os arquivos fonte
OBJ = $(SRC:.c=.o)

# A regra padrão
all: $(LIBNAME)

# Como construir a biblioteca final
$(LIBNAME): $(OBJ)
	ar rcs $@ $(OBJ)
	ranlib $@

# Como construir os objetos
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Limpar arquivos intermediários
clean:
	rm -f $(OBJ) $(LIBNAME)

# Instalar a biblioteca (opcional)
install:
	cp $(LIBNAME) /usr/local/lib
	cp *.h /usr/local/include
