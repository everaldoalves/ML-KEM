
#ifndef CORES_H
#define CORES_H

// Definindo constantes para códigos de cores ANSI
#define RESET   "\x1b[0m"
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define CYANBOLD "\x1b[1m\x1b[36m\x1b[5m"
#define WHITEBOLD "\x1b[1m\x1b[37m\x1b[5m"

// Função para imprimir uma string com uma cor específica
void printColor(const char *string, const char *color);

#endif