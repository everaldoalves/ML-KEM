from Crypto.Hash import SHAKE256

input_data = "Teste para J".encode()
shake = SHAKE256.new()
shake.update(input_data)
output_j = shake.read(32)
print(output_j.hex())

