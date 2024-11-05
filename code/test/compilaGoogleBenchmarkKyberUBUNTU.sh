#!/bin/bash

# Array com as versões do KYBER
KYBER_VERSIONS=(2 3 4)

echo -e "====================================================="
g++ --version
echo -e "======================================================\n"

# Loop para compilar e executar para cada versão
for VERSION in "${KYBER_VERSIONS[@]}"
do
    # Quebra de linha antes da mensagem
    echo -e "\n\nCompilando e executando benchmark para KYBER versão $VERSION\n"

     # Definir o DILITHIUM_MODE, compilar e suprimir warnings com a flag -w
    g++ -O3 -w -std=c++11 -DKYBER_K=$VERSION -I /usr/local/include googleBenchmarkKyber.cpp kem.c indcpa.c poly.c polyvec.c cbd.c reduce.c verify.c randombytes.c ntt.c fips202.c fips202x2.c symmetric-shake.c feat.S -L /usr/local/lib -lbenchmark -lpthread -o googleBenchmarkKyber_UBUNTU_mode$VERSION

    # Executar o benchmark
    ./googleBenchmarkKyber_UBUNTU_mode$VERSION

    # Quebra de linha após a execução
    echo -e "\n"
done

# Criar um arquivo de resumo dos resultados
echo "Benchmark Summary for KYBER Optimized" > benchmark_kyber_opt_UBUNTU.txt
printf "%-35s %-25s %-25s %-25s %-25s %-25s %-25s\n" "Function" "Time (512)" "Ciclos (512)" "Time (768)" "Ciclos (768)" "Time (1024)" "Ciclos (1024)" >> benchmark_kyber_opt_UBUNTU.txt

# Extrair os resultados para cada benchmark
for benchmark in BM_gen_matrix BM_poly_getnoise_eta1 BM_poly_getnoise_eta2 BM_poly_ntt BM_poly_invntt_tomont \
                 BM_polyvec_basemul_acc_montgomery BM_poly_tomsg BM_poly_frommsg BM_poly_compress \
                 BM_poly_decompress BM_polyvec_compress BM_polyvec_decompress BM_indcpa_keypair_derand \
                 BM_indcpa_enc BM_indcpa_dec BM_crypto_kem_keypair_derand BM_crypto_kem_keypair \
                 BM_crypto_kem_enc_derand BM_crypto_kem_enc BM_crypto_kem_dec; do

    # Extraindo dados para cada versão
    time_512=$(grep -m 1 "$benchmark" benchmark_kyber_2_opt_UBUNTU.txt | awk '{print $2}')
    ciclos_512=$(grep -m 1 "$benchmark" benchmark_kyber_2_opt_UBUNTU.txt | sed -n 's/.*Ciclos=\([0-9.]*\).*/\1/p')

    time_768=$(grep -m 1 "$benchmark" benchmark_kyber_3_opt_UBUNTU.txt | awk '{print $2}')
    ciclos_768=$(grep -m 1 "$benchmark" benchmark_kyber_3_opt_UBUNTU.txt | sed -n 's/.*Ciclos=\([0-9.]*\).*/\1/p')

    time_1024=$(grep -m 1 "$benchmark" benchmark_kyber_4_opt_UBUNTU.txt | awk '{print $2}')
    ciclos_1024=$(grep -m 1 "$benchmark" benchmark_kyber_4_opt_UBUNTU.txt | sed -n 's/.*Ciclos=\([0-9.]*\).*/\1/p')

    # Preenchendo valores vazios com "N/A"
    if [[ -z $time_512 ]]; then time_512="N/A"; fi
    if [[ -z $ciclos_512 ]]; then ciclos_512="N/A"; fi
    if [[ -z $time_768 ]]; then time_768="N/A"; fi
    if [[ -z $ciclos_768 ]]; then ciclos_768="N/A"; fi
    if [[ -z $time_1024 ]]; then time_1024="N/A"; fi
    if [[ -z $ciclos_1024 ]]; then ciclos_1024="N/A"; fi

    # Adicionando ao arquivo resumo com formatação alinhada
    printf "%-35s %-25s %-25s %-25s %-25s %-25s %-25s\n" "$benchmark" "$time_512" "$ciclos_512" "$time_768" "$ciclos_768" "$time_1024" "$ciclos_1024" >> benchmark_kyber_opt_UBUNTU.txt
done


# Exibir os dados do benchmark de referência
echo -e "\n=================== Dados do Benchmark de Referência ==================="
cat benchmark_kyber_ref_UBUNTU.txt

# Exibir os dados do benchmark otimizado
echo -e "\n=================== Dados do Benchmark Otimizado ==================="
cat benchmark_kyber_opt_UBUNTU.txt

# Função para converter o valor de ciclos que pode conter 'k' em um número inteiro ou decimal
convert_to_number() {
    local value=$1
    if [[ $value == *k ]]; then
        value=$(echo "$value" | sed 's/k//')
        echo $(awk "BEGIN {print $value * 1000}")
    elif [[ $value == *.* ]]; then
        # Lidar com valores que contêm ponto decimal, mantendo o valor como número
        echo $(awk "BEGIN {print $value * 1000}")
    else
        echo "$value"
    fi
}

echo -e "\n\n=================== Aceleração alcançada ==================="

# Criar um arquivo de resumo dos resultados de aceleração
echo "Speed-Up Summary for KYBER" > speed-up_UBUNTU.txt
printf "%-35s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s\n" "Function" "512-Ref" "512-Opt" "Aceleração" "768-Ref" "768-Opt" "Aceleração" "1024-Ref" "1024-Opt" "Aceleração" >> speed-up_UBUNTU.txt

# Iterar sobre cada linha dos benchmarks de referência e otimizado

# Iterar sobre cada linha dos benchmarks de referência e otimizado
while IFS= read -r line_ref && IFS= read -r line_opt <&3; do
    if [[ "$line_ref" == BM_* ]]; then
        function_name=$(echo "$line_ref" | awk '{print $1}')
        
        # Extrair os valores de cada coluna do benchmark de referência
        ciclos_512_ref=$(convert_to_number $(echo "$line_ref" | awk '{print $3}'))
        ciclos_768_ref=$(convert_to_number $(echo "$line_ref" | awk '{print $5}'))
        ciclos_1024_ref=$(convert_to_number $(echo "$line_ref" | awk '{print $7}'))

        # Extrair os valores de cada coluna do benchmark otimizado
        ciclos_512_opt=$(convert_to_number $(echo "$line_opt" | awk '{print $3}'))
        ciclos_768_opt=$(convert_to_number $(echo "$line_opt" | awk '{print $5}'))
        ciclos_1024_opt=$(convert_to_number $(echo "$line_opt" | awk '{print $7}'))

        # Verificar se os valores estão ausentes e substituí-los por "N/A"
        [[ -z $ciclos_512_ref ]] && ciclos_512_ref="N/A"
        [[ -z $ciclos_768_ref ]] && ciclos_768_ref="N/A"
        [[ -z $ciclos_1024_ref ]] && ciclos_1024_ref="N/A"
        [[ -z $ciclos_512_opt ]] && ciclos_512_opt="N/A"
        [[ -z $ciclos_768_opt ]] && ciclos_768_opt="N/A"
        [[ -z $ciclos_1024_opt ]] && ciclos_1024_opt="N/A"

        # Calcular a aceleração, caso os valores estejam disponíveis e sejam válidos
        if [[ $ciclos_512_ref != "N/A" && $ciclos_512_opt != "N/A" && $ciclos_512_opt > 0 ]]; then
            aceleracao_512=$(awk "BEGIN {printf \"%.2f\", $ciclos_512_ref / $ciclos_512_opt}")
        else
            aceleracao_512="N/A"
        fi

        if [[ $ciclos_768_ref != "N/A" && $ciclos_768_opt != "N/A" && $ciclos_768_opt > 0 ]]; then
            aceleracao_768=$(awk "BEGIN {printf \"%.2f\", $ciclos_768_ref / $ciclos_768_opt}")
        else
            aceleracao_768="N/A"
        fi

        if [[ $ciclos_1024_ref != "N/A" && $ciclos_1024_opt != "N/A" && $ciclos_1024_opt > 0 ]]; then
            aceleracao_1024=$(awk "BEGIN {printf \"%.2f\", $ciclos_1024_ref / $ciclos_1024_opt}")
        else
            aceleracao_1024="N/A"
        fi

        # Adicionar ao arquivo de resumo com formatação alinhada
        printf "%-35s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s\n" "$function_name" "$ciclos_512_ref" "$ciclos_512_opt" "$aceleracao_512" "$ciclos_768_ref" "$ciclos_768_opt" "$aceleracao_768" "$ciclos_1024_ref" "$ciclos_1024_opt" "$aceleracao_1024" >> speed-up_UBUNTU.txt
    fi
done < benchmark_kyber_ref_UBUNTU.txt 3< benchmark_kyber_opt_UBUNTU.txt

# Exibir o conteúdo do arquivo "speed-up_UBUNTU.txt"
cat speed-up_UBUNTU.txt

# Quebra de linha após a execução
echo -e "\n"