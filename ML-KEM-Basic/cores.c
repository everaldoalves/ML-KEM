#include <stdio.h>
#include "cores.h"

// Definindo constantes para códigos de cores ANSI
#define RESET   "\x1b[0m"
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"

void printColor(const char *string, const char *color) {
    printf("%s%s%s", color, string, RESET);
}