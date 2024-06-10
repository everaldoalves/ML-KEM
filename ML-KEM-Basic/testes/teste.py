# Converte string de bytes para o formato adequado a um vetor de bytes em C
hex_string = "268efe02bfb81e4903edd324b4cbb97aaaa9400f1b92042b5ed802faeccfcee4b6e47d3f0edd993ea4853f6ffad6bafc6af6c2cb1a281496a7bfcfb3dcf0c5a73a325ac05d294deaa88f0dd3f9dd463f1528548e4d4c6c6cb333449da14c4008c7503b7e02b42119e6eb119ca389b9e8705553eb8f0e4ce2289654ffa76725a81d9cf42a5b3aaf73f0fca88732a695e9048bfb9e91b3faf374f697965f9404e11cb9e3d690275530342cb0ccf2358055291b78b3407882dea6c8313cd8d88a9fad25e19a7195e1d273e299f1a7c9e84f91df19fbd15c620b1fcd83ba766c0be8d8781ba43fe5781a30a2fd06333ca10adea97bf8ca7dd1667640dda833cac4cb9fbd1cb16f854977454a844766418089587f29c669101c7e70c3db8de0cb0534860493ceef8718dea8becfd18a63505a6a369c65c179f273fdcf91ece49974dd4bbef4ad6300b0c63e6bd6938f2346e47b78148b0b576b388dd6869a7c5a42e89389758aff458b1dc1d33ed8d096a682d150c25028582a4da366f1e9e099cb43cd9579ad294a958fc34a837c51b824d390cc0b4436ca2bbe74628003e6c4d4739a90aa1592d6815ff0d8d0ee92d4e035f47193af38a127ac27bef5e8e4a985a42d8bc158d4099e9a62ae401b814f7a2d8979ebc0cbdb409e6c587b003c3362a70c6498a2235127a056b7ff75c4e275e4225b26ce23345e40206f8caf2f77b1ddfe155fb487c756b3723204ad73b9203487cb870a5ba23d34eeb8f5ee6c899958992aba34ed4c597d2389dd66eb841ca5e0850c31722c19586a3451bfb3ef2ecf97c353f95abbf85711dfd15268c5f53e1a7b5e02b7e7a1ffa3c47487b015512e9ae13ac50926a020339791fa88be552b79e6fede508c33b02e7b99b85c2f20fd2534a61655c65ed9a2e6b2af1e030971ea65aee4a60c4941e8f7d833b46cae5e5031be5404aa8bdc8be8ab0f2ef6a1d412f648ec7b779c0e4a813da6a233a24afb4cdc85c2b4f3960a587e391df4b4459366a5f536a985e3585a7866a69f86ae076a8518adbd92b2024a42ac907ecb7b375fc59a859e64712112a79b66044cbc"

# Formatando a string para inserir vírgulas após cada dois caracteres
formatted_hex = ', '.join('0x' + hex_string[i:i+2] for i in range(0, len(hex_string), 2))

print(formatted_hex)
