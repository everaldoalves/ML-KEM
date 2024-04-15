# Converte string de bytes para o formato adequado a um vetor de bytes em C
hex_string = "b89265f7996b78169ba27338b8fcca48e857da8085a108a7416669c2625c65a14a48792d7ec03eee050abfc8c45128ce13c570364a355c567c29170870eb35d5b88e45e6145260c5b2556ef8840aaed1599c74b7f8249a58401746fa99fac41354127e1e6458227944115aaeec60b43102a94fd549d8700edf54b71618010fe403d3191ba1e3ce612a45e1ea4096a41318142b84b6749c8554e73a9d54e2c2aa55ca40f542cfb37f07d43e3df109faf402fb098439d75956b71417423dc1615910184004d423264b34acc503853b3c2c3086a1c7b168e7c4f9dca54a7a81ab35c552fc556194abeb39c27601340f1a19fac14665b62b80910263552b73a563bc0400a6065899f331bca635941c3812394ae4681d2dd7cdbca65fada67d63d0102ebb96a511165c455e5261841408a848766c43bac4c257906090211bf7439d036526357ca285a0eed53467a660ee569014782a2568a43a77ab95373cd56ac3f9a02d507070d18a693f4a009375b7c930c735ebc8d4020eee9ace11e083faf10655d193d5d915079cb1efb3c810001790d52a38e2a29ba93a401c8fa647921d59936e2aa2dc61243f960d4dec3cba1c3ce405659660cc9f74ca76b1960414c97e6849d7cc8b45797a37c980b8d665dbd4b7f9075fe50853bba1b6f3e37c1fc57a7d8a94106222a750b49102c919c2bf01eac179d81c894873dcb0653c53a3cf441e200c1e1820983f3944d15118bec9c7048379ca8ac6a2d332a4a255879a66706b6ff2330fa4f703fb702dfe7a8d727787ef818fc68621446125fe83613de692587c0cf8b053e4124ba1541be88590ef162d10450af0392e28019cb1a28f7cb3bafbec48534062dc2842f909be91ac20e71534672566d4a91d19b08a1ea4998d6795ecb4acf4e7897f8c047298b59ff087aad69de1643558547156fbcf5882b1466236dccb2e233a9f6856bf34c94d61d59d0df147b45c4611790e215b393e494586ba586e58491e940d2f936cd9489a9df26f82928ba3e577e4092f83431bdc4b17d0ea8403cc529f30c0549b99ff09a4a2f01338566cbe11206370b9afbb5d0fc7cc960bbbb05885770467e76eaeac20909c622c8eb2e46571b4dd2baae597"

# Formatando a string para inserir vírgulas após cada dois caracteres
formatted_hex = ', '.join('0x' + hex_string[i:i+2] for i in range(0, len(hex_string), 2))

print(formatted_hex)

