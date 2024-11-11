#!/bin/bash

# Define o arquivo de saída
output_file="plataformaAlvo.txt"

# Limpa o conteúdo anterior do arquivo (se existir)
> "$output_file"

# Extrai informações gerais do hardware (sem dados sensíveis)
echo "=== Informações do Sistema ===" >> "$output_file"
system_profiler SPHardwareDataType | grep -E "Model Name:|Model Identifier:|Model Number:|Chip:|Total Number of Cores:|Memory:|System Firmware Version:|OS Loader Version:|Provisioning UDID:|Activation Lock Status:" >> "$output_file"

# Adiciona uma linha em branco para separação
echo "" >> "$output_file"

# Extrai informações sobre o cache L1 e L2
echo "=== Informações de Cache ===" >> "$output_file"
cache_info=$(sysctl -a | grep -E "hw\.l1(icache|dcache)_size|hw\.l2cachesize")
if [ -n "$cache_info" ]; then
    echo "$cache_info" | while read -r line; do
        # Formata a saída para ser mais legível
        key=$(echo "$line" | cut -d' ' -f1)
        value=$(echo "$line" | cut -d' ' -f2)
        case "$key" in
            hw.l1icache_size) echo "L1 Instruction Cache: $((value / 1024)) KB" >> "$output_file" ;;
            hw.l1dcache_size) echo "L1 Data Cache: $((value / 1024)) KB" >> "$output_file" ;;
            hw.l2cachesize)   echo "L2 Cache: $((value / 1024)) KB" >> "$output_file" ;;
        esac
    done
else
    echo "Informações de cache não disponíveis." >> "$output_file"
fi

# Adiciona uma linha em branco para separação
echo "" >> "$output_file"

# Extrai as extensões da CPU para ajudar a determinar a versão da arquitetura ARM
echo "=== Extensões da CPU ===" >> "$output_file"
cpu_features=$(sysctl -a | grep "machdep.cpu.features")
if [ -n "$cpu_features" ]; then
    echo "$cpu_features" >> "$output_file"
else
    echo "Extensões da CPU não disponíveis." >> "$output_file"
fi

# Adiciona uma linha em branco para separação
echo "" >> "$output_file"

# Adiciona detalhes sobre a arquitetura ARM
echo "=== Arquitetura ARM ===" >> "$output_file"
uname -m >> "$output_file"

# Mensagem de conclusão
echo "As informações foram coletadas e salvas em $output_file"
