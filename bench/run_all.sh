#!/usr/bin/env bash
# roda os experimentos inteiros e gera os relatórios, cerca de 25 minutos com
# os padrões. compile antes como usuário comum, make && make tests, e depois
# sudo bash bench/run_all.sh
#
# atenção, a fase de kill roda o detector com --kill no sistema todo. feche
# programas que gravam muito arquivo comprimido durante o teste, tipo
# navegador baixando coisa ou backup, porque eles entram no critério também

set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C.UTF-8

[[ $EUID -ne 0 ]] && { echo "ERRO: execute com sudo"; exit 1; }
DONO="${SUDO_USER:-root}"

falta=()
for t in fio ffmpeg zip gzip tar git openssl python3 bpftool; do
    command -v "$t" > /dev/null || falta+=("$t")
done
if (( ${#falta[@]} )); then
    echo "ERRO: faltam ${falta[*]}, apt install ${falta[*]}"
    exit 1
fi
[[ -x ./ransomware_detect && -x tests/sim_encrypt ]] || \
    { echo "ERRO: rode make && make tests como usuário comum antes"; exit 1; }

# o verificador só roda com privilégio, então é aqui que ele aceita ou não o
# programa. com --verbose o libbpf despeja o log do verificador se recusar
echo "[*] testando o carregamento do programa eBPF"
if ! timeout 3 ./ransomware_detect --verbose > /tmp/verificador.log 2>&1; then
    # timeout devolve 124 quando o detector estava rodando normal
    if ! grep -q "detector ativo" /tmp/verificador.log; then
        echo "ERRO: o verificador recusou o programa, últimas linhas do log"
        tail -60 /tmp/verificador.log
        exit 1
    fi
fi
echo "[*] programa carregado e anexado"

bash bench/run_bench.sh
bash bench/falsos_positivos.sh

chown -R "$DONO": bench/results bench/plots

sudo -u "$DONO" python3 scripts/plot_results.py
sudo -u "$DONO" python3 scripts/calibrar_limiar.py bench/results/fp

echo ""
echo "[*] pronto, relatórios em bench/results/bench.md e bench/results/fp/calibracao.md"
