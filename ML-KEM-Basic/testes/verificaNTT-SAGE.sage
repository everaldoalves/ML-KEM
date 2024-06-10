# Este código viabiliza checar os resultados esperados para implementação da ntt
# Pode ser usado como referência para testar se a implementação em C está correta

# Definir os parâmetros
q = 3329
R = Integers(q)
zeta = R(17)  # Valor de zeta
n = 256  # Tamanho do vetor

# Função para inverter os bits
def brv(x, log2n=7):
    result = 0
    for i in range(log2n):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result

# Função para calcular a NTT em um vetor v
def NTT(v):
    log2n = log(len(v), 2)
    result = [0] * len(v)
    for i in range(len(v)):
        for j in range(len(v)):
            if i == j % 2:
                result[i] += zeta^((2 * brv(i >> 1, log2n) + 1) * (j >> 1)) * v[j]
    return result


# Função para calcular a multiplicação de dois vetores a e b
def multiply(a, b):
    result = [0] * len(a)
    for i in range(len(a)):
        if i % 2 == 0:
            result[i] = (a[i] * b[i] + zeta^((2 * brv(i >> 1, log(len(a), 2)) + 1)) * a[i + 1] * b[i + 1]) % q
        else:
            result[i] = (a[i - 1] * b[i] + a[i] * b[i - 1]) % q
    return result


# Função para calcular a inversa da NTT em um vetor v
def InvNTT(v):
    log2n = log(len(v), 2)
    result = [0] * len(v)
    for i in range(len(v)):
        for j in range(len(v)):
            if i == j % 2:
                result[i] += zeta^(256 - (2 * brv(j >> 1, log2n) + 1) * (i >> 1)) * v[j]
    return result

x = vector([R(1),R(1)] + [R(0)]*254)
y = vector([R(i) for i in range(256)])
print("X:",x)
print("Y:",y)

# Calcular a NTT para os vetores v e u
ntt_x = NTT(x)
ntt_y = NTT(y)

# Exibir a matriz NTT
print("\nNTT X: ",ntt_x)
print("NTT Y: ",ntt_y)

# Calcular a multiplicação de u e v
result = multiply(ntt_x, ntt_y)

# Calcular a inversa da NTT para o resultado
inv_ntt_result = InvNTT(result)
print("\nINVERSA NTT X*Y: ",inv_ntt_result)

