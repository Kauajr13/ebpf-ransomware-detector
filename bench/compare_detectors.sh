#!/usr/bin/env bash
# compara latencia de deteccao entre eBPF, auditd e inotify, tempo ate o
# bloqueio e quantos arquivos foram cifrados antes disso
# roda como root, sudo bash bench/compare_detectors.sh

set -euo pipefail

RESULTS="bench/results"
ENCRYPT_BIN="./tests/sim_encrypt"
BENIGN_BIN="./tests/sim_benign"
DETECTOR="./ransomware_detect"
TARGET="/tmp/compare_target"
N_FILES=300

mkdir -p "$RESULTS"

[[ $EUID -ne 0 ]] && { echo "ERRO: execute como root"; exit 1; }

echo "abordagem,arquivos_perdidos,latencia_ms" > "$RESULTS/comparison.csv"

setup_target() {
    rm -rf "$TARGET"
    mkdir -p "$TARGET"
    "$BENIGN_BIN" "$TARGET" --files "$N_FILES" --size-kb 16 2>/dev/null
    echo "[*] $N_FILES arquivos criados em $TARGET"
}

# ebpf

echo ""
echo "=== eBPF ==="
setup_target

"$DETECTOR" --threshold 7.8 --floor 32768 --files 5 --kill \
    --csv "$RESULTS/ebpf_events.csv" &
DET_PID=$!
sleep 1

T0=$(date +%s%3N)
"$ENCRYPT_BIN" "$TARGET" --max-files "$N_FILES" 2>&1 | \
    tee "$RESULTS/ebpf_encrypt.log" &
ENC_PID=$!

wait $ENC_PID || true
T1=$(date +%s%3N)

FILES_LOST=$(grep -c "CIFRADO" "$RESULTS/ebpf_encrypt.log" 2>/dev/null || echo 0)
LATENCY=$((T1 - T0))

echo "eBPF: $FILES_LOST arquivos cifrados em ${LATENCY}ms"
echo "ebpf,$FILES_LOST,$LATENCY" >> "$RESULTS/comparison.csv"

kill $DET_PID 2>/dev/null; wait $DET_PID 2>/dev/null || true

# auditd

echo ""
echo "=== auditd ==="
setup_target

# configura regra de auditoria
auditctl -w "$TARGET" -p w -k ransom_test 2>/dev/null || true

T0=$(date +%s%3N)
"$ENCRYPT_BIN" "$TARGET" --max-files "$N_FILES" 2>&1 | \
    tee "$RESULTS/auditd_encrypt.log"
T1=$(date +%s%3N)

FILES_LOST=$(grep -c "CIFRADO" "$RESULTS/auditd_encrypt.log" 2>/dev/null || echo "$N_FILES")
LATENCY=$((T1 - T0))

# auditd não bloqueia por padrão, todos os arquivos são perdidos
echo "auditd: $FILES_LOST arquivos cifrados (sem bloqueio) em ${LATENCY}ms"
echo "auditd,$FILES_LOST,$LATENCY" >> "$RESULTS/comparison.csv"

auditctl -D 2>/dev/null || true

# inotify

echo ""
echo "=== inotify (monitor userspace) ==="
setup_target

# detector inotify simples, so loga o fechamento do arquivo
# sem kill nativo, limitacao da abordagem
inotifywait -r -m -e close_write "$TARGET" --format '%w%f' 2>/dev/null | \
while IFS= read -r filepath; do
    # nao calcula entropia real aqui, so registra o evento, limitacao do inotify puro
    echo "[inotify] $filepath"
done > "$RESULTS/inotify_events.log" &
INOTIFY_PID=$!

T0=$(date +%s%3N)
"$ENCRYPT_BIN" "$TARGET" --max-files "$N_FILES" 2>&1 | \
    tee "$RESULTS/inotify_encrypt.log"
T1=$(date +%s%3N)

FILES_LOST=$N_FILES  # inotify não bloqueia
LATENCY=$((T1 - T0))

echo "inotify: $FILES_LOST arquivos (sem bloqueio) em ${LATENCY}ms"
echo "inotify,$FILES_LOST,$LATENCY" >> "$RESULTS/comparison.csv"

kill $INOTIFY_PID 2>/dev/null || true

# resultado final

echo ""
echo "=== Resultado ==="
column -t -s, "$RESULTS/comparison.csv"
echo ""
echo "[*] CSV: $RESULTS/comparison.csv"
