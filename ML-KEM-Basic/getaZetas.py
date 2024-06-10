def bit_reverse(n, bits):
    reversed_n = 0
    for i in range(bits):
        if n & (1 << i):
            reversed_n |= 1 << (bits - 1 - i)
    return reversed_n

def precompute_zetas(base, modulus, n):
    zetas = []
    length = n // 2
    for k in range(0, length):
        index = bit_reverse(k, bits=7)  # Ajustar para 7 bits conforme BitRev7 sugere
        zeta = pow(base, index, modulus)
        zetas.append(zeta)
    return zetas

KYBER_Z = 17
KYBER_Q = 3329
KYBER_N = 256

# ζ^(BitRev7(i))
zetas = precompute_zetas(KYBER_Z, KYBER_Q, KYBER_N)
print(zetas)  # Exibe os zetas calculados

#-----------------------------------------------------
def bit_reverse_7(n):
    result = 0
    for i in range(7):
        if n & (1 << i):
            result |= 1 << (6 - i)
    return result

def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp = exp // 2
    return result


# ζ^(2*BitRev7(i)+1)
zeta = 17  # Um valor arbitrário para zeta
q = 3329   # Valor típico para KYBER_Q
num_elements = 128  # Tamanho da tabela

# Gerar a tabela de zetas
zetas_table = [mod_exp(zeta, (2 * bit_reverse_7(i) + 1), q) for i in range(num_elements)]

# Imprimir a tabela para inserção no código C
print("{", ", ".join(map(str, zetas_table)), "};")

