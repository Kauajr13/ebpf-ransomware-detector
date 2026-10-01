#!/usr/bin/env bash
# mede throughput e latencia p99 com e sem o detector ativo, precisa de fio
# roda como root, sudo bash bench/run_bench.sh

set -euo pipefail

RESULTS_DIR="bench/results"
DETECTOR="./ransomware_detect"
FIO_SIZE="512m"
FIO_BS="64k"
FIO_RUNTIME=30   # segundos por job
TARGET_DIR="/tmp/bench_target"
CSV_FILE="$RESULTS_DIR/overhead_fio.csv"

mkdir -p "$RESULTS_DIR" "$TARGET_DIR"

if [[ $EUID -ne 0 ]]; then
    echo "ERRO: execute como root (sudo)"
    exit 1
fi

echo "[*] Benchmark, $(date)"
echo "pid,comm,entropy,total_bytes,elapsed_ms" > "$CSV_FILE"

# função pra rodar fio e capturar métricas

run_fio() {
    local label="$1"
    local output="$RESULTS_DIR/fio_${label}.json"

    echo "[*] fio: $label (${FIO_RUNTIME}s, ${FIO_BS} bs, ${FIO_SIZE})"

    fio --name=bench \
        --ioengine=libaio \
        --iodepth=8 \
        --rw=write \
        --bs="$FIO_BS" \
        --size="$FIO_SIZE" \
        --numjobs=2 \
        --runtime="$FIO_RUNTIME" \
        --time_based \
        --directory="$TARGET_DIR" \
        --output-format=json \
        --output="$output" \
        --group_reporting \
        2>/dev/null

    # extrai throughput e latencia p99 do json
    python3 -c "
import json, sys
with open('$output') as f:
    d = json.load(f)
j = d['jobs'][0]
bw  = j['write']['bw']           # KB/s
lat = j['write']['lat_ns']['percentile']['99.000000'] / 1e6  # ms
iops = j['write']['iops']
print(f'  Throughput: {bw/1024:.1f} MB/s  IOPS: {iops:.0f}  Latência p99: {lat:.2f} ms')
print(f'  {\"$label\"},{bw/1024:.2f},{iops:.0f},{lat:.3f}')
" | tee -a "$RESULTS_DIR/summary.txt"
}

# fase 1, sem detector

echo ""
echo "=== Fase 1: sem detector ==="
run_fio "sem_detector"

# fase 2, com detector em modo monitor, sem kill

echo ""
echo "=== Fase 2: com detector (monitor) ==="
"$DETECTOR" --threshold 7.8 --floor 65536 --csv "$RESULTS_DIR/events_monitor.csv" &
DETECTOR_PID=$!
sleep 1  # aguardar o detector estabilizar

run_fio "com_detector_monitor"

kill $DETECTOR_PID 2>/dev/null
wait $DETECTOR_PID 2>/dev/null || true

# fase 3, latência de detecção

echo ""
echo "=== Fase 3: latência de detecção ==="

# cria diretorio com arquivos de texto para o simulador
ENCRYPT_TARGET="/tmp/bench_encrypt"
mkdir -p "$ENCRYPT_TARGET"
./tests/sim_benign "$ENCRYPT_TARGET" --files 200 --size-kb 32 2>/dev/null

# TODO fase 3 ta pela metade, so conta arquivos perdidos.
# falta cronometrar o tempo ate o kill pra ter latencia de verdade

# 3a, detector eBPF
"$DETECTOR" --threshold 7.8 --floor 65536 --kill \
    --csv "$RESULTS_DIR/events_kill.csv" &
DETECTOR_PID=$!
sleep 1

./tests/sim_encrypt "$ENCRYPT_TARGET" --max-files 200 2>&1 | \
    grep -c "CIFRADO" > "$RESULTS_DIR/files_lost_ebpf.txt" || true

kill $DETECTOR_PID 2>/dev/null
wait $DETECTOR_PID 2>/dev/null || true

echo "[*] Resultados em $RESULTS_DIR/"
ls -la "$RESULTS_DIR/"
