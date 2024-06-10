
#include <stdio.h>
#include <math.h>
/*
int extended_gcd(int a, int b, int& x, int& y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    int x1, y1;
    int gcd = extended_gcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return gcd;
}

int mod_inverse(int a, int m) {
    int x, y;
    int g = extended_gcd(a, m, x, y);
    if (g != 1)
        return -1;  // Inverso não existe
    else
        return (x % m + m) % m;  // Assegurar resultado positivo
}

// Calcular R^-1 mod q e -q^-1 mod R
const int q = 3329;
const int R = 65536;
int R_inv = mod_inverse(R, q);
int q_inv = mod_inverse(q, R);
int q_prime = (R - q_inv) % R;

void compute_twiddle_factors(int twiddle[], int n, int w, int q, int R) {
    int w_current = 1;
    for (int i = 0; i < n/2; ++i) {
        twiddle[i] = (w_current * R) % q;  // w^i * R mod q
        w_current = (w_current * w) % q;  // w^(i+1)
    }
}
*/
#define KYBER_Q 3329  // Exemplo de valor, precisa ser ajustado conforme necessário
#define KYBER_Z 17    // Exemplo de valor, ajuste conforme a especificação
#define KYBER_N 256   // Deve ser uma potência de 2, usualmente 256

int power(int x, int y, int p) {
    int res = 1;
    x = x % p;
    while (y > 0) {
        if (y & 1)
            res = (res * x) % p;
        y = y >> 1;
        x = (x * x) % p;
    }
    return res;
}

int BitRev7(int i) {
    int reverse = 0;
    int bits = log2(KYBER_N/2);  // Log base 2 de 128, que é 7
    for (int j = 0; j < bits; j++) {
        reverse = (reverse << 1) | (i & 1);
        i >>= 1;
    }
    return reverse;
}

int zeta_ntt[KYBER_N/2], zeta_invntt[KYBER_N/2];


void precompute_twiddles() {
    int root = KYBER_Z;  // Raiz primitiva
    int n = KYBER_N;

    // KYBER_Z deve ser a raiz n-ésima de 1 módulo KYBER_Q
    for (int i = 0; i < n/2; i++) {
        int rev_i = BitRev7(i) * (n/2);  // Revisar se BitRev7 está correto para i em [0, n/2)
        zeta_ntt[i] = power(root, rev_i % (n-1), KYBER_Q);  // Módulo n-1 porque estamos ciclando os valores de raiz
    }
    printf("\nVetor zetas NTT : ");
    for (int i = 0; i < KYBER_N / 2; i++) {
        printf(" %d,",zeta_ntt[i]);        
    }  
}




int main() {
    /*
    printf("Gerando a tabela com a primneira função \n:");
    u_int16_t t[128] = {0};
    compute_twiddle_factors(t,256,17,q,R);

    for (int i=0, i<128; i++) {
        printf("%d,", t[i]);        
    }
    */
    printf("Gerando a tabela com a segunda função: \n");
    precompute_twiddles();
}