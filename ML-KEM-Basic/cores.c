#include <stdio.h>
#include "cores.h"

//Função para impressão de mensagens em cores distintas na tela

void printColor(const char *string, const char *color) {
    printf("%s%s%s", color, string, RESET);
}