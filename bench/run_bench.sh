#!/usr/bin/env bash
# fase 1, overhead de E/S e de CPU com fio em várias cargas, sem e com detector
# fase 2, tempo até o bloqueio e arquivos perdidos com sim_encrypt e --kill
# roda como root a partir da raiz do projeto, sudo bash bench/run_bench.sh
# REPS e FIO_RUNTIME no ambiente mudam repetições e segundos por execução

set -euo pipefail
cd "$(dirname "$0")/.."

RESULTS="bench/results"
DETECTOR="./ransomware_detect"
REPS="${REPS:-5}"
FIO_RUNTIME="${FIO_RUNTIME:-20}"
ALVO_FIO="/tmp/bench_fio"
ALVO_CIFRA="/tmp/bench_cifra"

[[ $EUID -ne 0 ]] && { echo "ERRO: execute como root (sudo)"; exit 1; }
command -v fio > /dev/null || { echo "ERRO: fio ausente, apt install fio"; exit 1; }
[[ -x "$DETECTOR" && -x tests/sim_encrypt && -x tests/sim_benign ]] || \
    { echo "ERRO: rode make && make tests antes"; exit 1; }

mkdir -p "$RESULTS/fio" "$RESULTS/kill"

# custo por execução do kprobe, o kernel só contabiliza com isso ligado
sysctl -qw kernel.bpf_stats_enabled=1
trap 'sysctl -qw kernel.bpf_stats_enabled=0' EXIT

# sobe o detector e só volta quando ele anexou, sleep fixo errava nas duas
# direções, às vezes curto demais e o começo da carga passava sem monitor
iniciar_detector() {
    local log="$1"; shift
    "$DETECTOR" "$@" > "$log" 2>&1 &
    DET_PID=$!
    for _ in $(seq 1 100); do
        grep -q "detector ativo" "$log" 2>/dev/null && return 0
        kill -0 "$DET_PID" 2>/dev/null || break
        sleep 0.05
    done
    echo "ERRO: detector não subiu, log em $log"
    cat "$log"
    exit 1
}

parar_detector() {
    kill -INT "$DET_PID" 2>/dev/null || true
    wait "$DET_PID" 2>/dev/null || true
}

# tempo de CPU do processo em segundos, utime mais stime do /proc
cpu_processo() {
    awk -v hz="$(getconf CLK_TCK)" '{print ($14 + $15) / hz}' "/proc/$1/stat"
}

# run_cnt e run_time_ns do kprobe, o nome aparece truncado em 15 caracteres
stats_kprobe() {
    bpftool prog show -j | python3 -c '
import json, sys
for p in json.load(sys.stdin):
    if p.get("name", "").startswith("kprobe_vfs_wri"):
        print(p.get("run_cnt", 0), p.get("run_time_ns", 0))
        break
else:
    print(0, 0)'
}

# fase 1

# psync e não libaio, porque io_submit não passa por vfs_write e o detector
# nunca enxergaria a carga, o overhead sairia zero por engano
CARGAS=(
    "seq_64k|--rw=write --bs=64k --size=1g"
    "seq_4k|--rw=write --bs=4k --size=1g"
    "rand_4k|--rw=randwrite --bs=4k --size=1g"
    "muitos_arquivos|--rw=write --bs=16k --nrfiles=200 --filesize=64k --size=12800k"
)

CSV_OVERHEAD="$RESULTS/overhead.csv"
echo "carga,modo,rep,bw_kib,iops,lat_p99_us,usr_cpu,sys_cpu,agente_cpu_s,kprobe_execucoes,kprobe_ns_total" \
    > "$CSV_OVERHEAD"

rodar_fio() {
    local carga="$1" args="$2" saida="$3"
    rm -rf "$ALVO_FIO"; mkdir -p "$ALVO_FIO"
    # shellcheck disable=SC2086
    fio --name="$carga" --ioengine=psync --numjobs=2 --group_reporting \
        --runtime="$FIO_RUNTIME" --time_based --end_fsync=1 \
        --directory="$ALVO_FIO" --output-format=json --output="$saida" $args \
        > /dev/null
}

extrair_fio() {
    python3 - "$1" <<'EOF'
import json, sys
j = json.load(open(sys.argv[1]))["jobs"][0]
w = j["write"]
p99 = w["clat_ns"]["percentile"].get("99.000000", 0) / 1000
print(f'{w["bw"]},{w["iops"]:.1f},{p99:.1f},{j["usr_cpu"]:.3f},{j["sys_cpu"]:.3f}')
EOF
}

echo "=== Fase 1: overhead, $REPS repetições de ${FIO_RUNTIME}s por carga e modo ==="
for entrada in "${CARGAS[@]}"; do
    carga="${entrada%%|*}"
    args="${entrada#*|}"
    for rep in $(seq 1 "$REPS"); do
        # alterna a ordem a cada repetição pra deriva térmica e de cache não
        # cair sempre no mesmo modo
        if (( rep % 2 )); then modos="sem com"; else modos="com sem"; fi
        for modo in $modos; do
            json="$RESULTS/fio/${carga}_${modo}_${rep}.json"
            echo "[*] $carga $modo rep $rep"
            if [[ $modo == com ]]; then
                iniciar_detector "$RESULTS/fio/detector_${carga}_${rep}.log" \
                    --csv "$RESULTS/fio/eventos_${carga}_${rep}.csv"
                cpu0=$(cpu_processo "$DET_PID")
                rodar_fio "$carga" "$args" "$json"
                cpu1=$(cpu_processo "$DET_PID")
                read -r execs ns < <(stats_kprobe)
                parar_detector
                agente=$(python3 -c "print(f'{$cpu1 - $cpu0:.3f}')")
            else
                rodar_fio "$carga" "$args" "$json"
                agente=0; execs=0; ns=0
            fi
            echo "$carga,$modo,$rep,$(extrair_fio "$json"),$agente,$execs,$ns" >> "$CSV_OVERHEAD"
        done
    done
done
rm -rf "$ALVO_FIO"

# fase 2

CSV_KILL="$RESULTS/latencia_kill.csv"
echo "cenario,tamanho_kb,atraso_ms,rep,arquivos_total,arquivos_perdidos,morto,inicio_ns,ts_evento_ns,ts_user_ns,ts_kill_ns,t_ate_kill_ms,t_kernel_user_us" \
    > "$CSV_KILL"

# arquivo perdido é o que não começa mais com o texto do sim_benign, inclusive
# o que foi truncado e ficou pela metade no instante do kill
contar_perdidos() {
    python3 - "$1" <<'EOF'
import os, sys
d = sys.argv[1]
perdidos = 0
for nome in os.listdir(d):
    with open(os.path.join(d, nome), "rb") as f:
        if f.read(5) != b"Lorem":
            perdidos += 1
print(perdidos)
EOF
}

rodar_kill() {
    local cenario="$1" tam="$2" atraso="$3" rep="$4" total="$5"
    local base="$RESULTS/kill/${cenario}_${tam}k_${atraso}ms_${rep}"

    rm -rf "$ALVO_CIFRA"; mkdir -p "$ALVO_CIFRA"
    ./tests/sim_benign "$ALVO_CIFRA" --files "$total" --size-kb "$tam" 2>/dev/null
    sync

    iniciar_detector "$base.log" --kill --csv "$base.csv"
    # stdout descartado, num arquivo regular as linhas CIFRADO entrariam no
    # histograma do simulador e o estrago já é contado direto no disco
    ./tests/sim_encrypt "$ALVO_CIFRA" --max-files "$total" --delay-ms "$atraso" \
        > /dev/null 2> "$base.sim.err" || true
    # dá tempo do callback gravar a linha do csv depois do kill
    sleep 0.3
    parar_detector

    local inicio perdidos
    inicio=$(sed -n 's/.*inicio_ns=\([0-9]*\).*/\1/p' "$base.sim.err")
    perdidos=$(contar_perdidos "$ALVO_CIFRA")

    python3 - "$base.csv" "$cenario" "$tam" "$atraso" "$rep" "$total" "$perdidos" "$inicio" \
        >> "$CSV_KILL" <<'EOF'
import csv, sys
arq, cen, tam, atr, rep, total, perdidos, inicio = sys.argv[1:]
inicio = int(inicio)
kill = None
for linha in csv.DictReader(open(arq)):
    if linha["proc"].startswith("sim_encrypt") and int(linha["ts_kill_ns"]) > 0:
        kill = linha
        break
if kill:
    ev, us, tk = int(kill["ts_evento_ns"]), int(kill["ts_user_ns"]), int(kill["ts_kill_ns"])
    print(f"{cen},{tam},{atr},{rep},{total},{perdidos},1,{inicio},{ev},{us},{tk},"
          f"{(tk - inicio) / 1e6:.3f},{(us - ev) / 1e3:.1f}")
else:
    print(f"{cen},{tam},{atr},{rep},{total},{perdidos},0,{inicio},0,0,0,,")
EOF
    echo "[*] $cenario ${tam}KiB atraso ${atraso}ms rep $rep: $perdidos de $total perdidos"
}

echo ""
echo "=== Fase 2: tempo até o bloqueio ==="
for tam in 16 64 256; do
    for rep in $(seq 1 "$REPS"); do
        rodar_kill rapido "$tam" 0 "$rep" 300
    done
done

# ransomware lento, com a janela padrão de 10 s. 500 ms por arquivo junta 10
# arquivos em 5 s e deve ser pego, 1500 ms leva 15 s e mostra a evasão
for atraso in 500 1500; do
    for rep in 1 2 3; do
        rodar_kill lento 64 "$atraso" "$rep" 40
    done
done
rm -rf "$ALVO_CIFRA"

echo ""
echo "[*] Resultados em $CSV_OVERHEAD e $CSV_KILL"
