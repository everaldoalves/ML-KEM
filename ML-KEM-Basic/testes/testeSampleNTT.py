def generate_test_input(size=34):
    """Gera 3 conjuntos de teste, cada um com um padrão específico."""
    tests = []
    
    # Teste 1: Bytes sequenciais começando de 0x01 até o tamanho.
    tests.append(bytes(range(1, size + 1)))
    
    # Teste 2: Todos os bytes são 0x80 para testar o cálculo com um valor médio.
    tests.append(bytes([0x80] * size))
    
    # Teste 3: Bytes alternando entre 0x01 e 0xFF para testar os limites de cálculo.
    tests.append(bytes([0x01 if i % 2 == 0 else 0xFF for i in range(size)]))
    
    return tests

# Gerar e imprimir os testes de entrada
test_inputs = generate_test_input()
for i, test in enumerate(test_inputs):
    print(f"Test {i+1}: {test.hex()}\n")

