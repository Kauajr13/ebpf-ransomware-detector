#!/usr/bin/env bash
# roda cargas benignas de entropia alta e controles positivos com o detector
# em modo monitor, gravando todo evento, acima ou abaixo do limiar. é daqui
# que scripts/calibrar_limiar.py tira a taxa de acerto e o limiar
# roda como root a partir da raiz do projeto, sudo bash bench/falsos_positivos.sh
# DRY=1 roda só as cargas, sem detector e sem root, pra conferir que funcionam
# EMULAR=1 roda sem root, cada carga sob strace e scripts/emular_detector.py
# reproduzindo a lógica do kprobe, gera o mesmo csv do detector real
# REPO_REF aponta um repositório git local pra carga git_clone

set -euo pipefail
cd "$(dirname "$0")/.."
# ponto decimal em qualquer número que passe do shell pro python
export LC_ALL=C.UTF-8
RAIZ="$(pwd)"

RESULTS="${RESULTS:-bench/results/fp}"
DETECTOR="./ransomware_detect"
TRAB="${TRAB:-/tmp/bench_fp}"
REPS="${REPS:-3}"
DRY="${DRY:-0}"
EMULAR="${EMULAR:-0}"
if [[ $EMULAR == 1 ]]; then
    DRY=1
fi
# parte do .git comum e não da raiz, que dentro de uma worktree fica em outro
# lugar. safe.directory porque como root o git recusa repositório de outro dono
GIT_COMUM="$(git -c safe.directory='*' -C "$RAIZ" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
REPO_REF="${REPO_REF:-$(dirname "$GIT_COMUM")/../libbpf-bootstrap}"

if [[ $DRY != 1 && $EUID -ne 0 ]]; then
    echo "ERRO: execute como root (sudo)"; exit 1
fi
for t in ffmpeg zip gzip tar git openssl python3; do
    command -v "$t" > /dev/null || { echo "ERRO: $t ausente"; exit 1; }
done

mkdir -p "$RESULTS"
echo "carga,classe,rep,inicio_ns,fim_ns" > "$RESULTS/cargas.csv"

iniciar_detector() {
    [[ $DRY == 1 ]] && return 0
    local log="$1"; shift
    # --all-events porque com o corte de qui2 no kernel o evento benigno nem
    # chega ao agente, e é dele que sai a taxa de falso positivo
    "$DETECTOR" --all-events "$@" > "$log" 2>&1 &
    DET_PID=$!
    for _ in $(seq 1 100); do
        grep -q "detector ativo" "$log" 2>/dev/null && return 0
        kill -0 "$DET_PID" 2>/dev/null || break
        sleep 0.05
    done
    echo "ERRO: detector não subiu"; cat "$log"; exit 1
}

parar_detector() {
    [[ $DRY == 1 ]] && return 0
    kill -INT "$DET_PID" 2>/dev/null || true
    wait "$DET_PID" 2>/dev/null || true
}

agora_ns() { python3 -c 'import time; print(time.monotonic_ns())'; }

RUIDO="nullsrc=s=1280x720,geq=random(1)*255:128:128"

# material de entrada preparado uma vez, fora da medição
preparar() {
    rm -rf "$TRAB"; mkdir -p "$TRAB/texto" "$TRAB/fotos_ruido"
    # 200 arquivos de texto real, cabeçalho C tem entropia típica de código
    # substituição de processo e não pipe com head, que mata o find com
    # SIGPIPE e o pipefail derruba o script inteiro
    local textos
    mapfile -t textos < <(find /usr/include -name '*.h' -size +8k -size -200k | sort)
    for f in "${textos[@]:0:200}"; do
        cp "$f" "$TRAB/texto/$(echo "${f#/}" | tr / _)"
    done
    # foto com ruído é o pior caso de jpg, quase não comprime
    ffmpeg -loglevel error -f lavfi -i "$RUIDO" -frames:v 60 -q:v 3 "$TRAB/fotos_ruido/img_%03d.jpg"
    tar cf "$TRAB/fotos.tar" -C "$TRAB" fotos_ruido
}

# cada carga escreve a partir de um processo só, que é o que o detector
# agrupa por tgid. as negativas são uso legítimo com entropia alta

carga_gzip_muitos() {
    # logrotate e backup incremental fazem isso, muitos .gz num processo
    cp -r "$TRAB/texto" "$TRAB/saida" && gzip -r "$TRAB/saida"
}
carga_tar_gz() { mkdir -p "$TRAB/saida" && tar czf "$TRAB/saida/s.tgz" -C /usr include; }
carga_zip_r() { mkdir -p "$TRAB/saida" && zip -qr "$TRAB/saida/s.zip" /usr/include; }
carga_extrair_fotos() { mkdir -p "$TRAB/saida" && tar xf "$TRAB/fotos.tar" -C "$TRAB/saida"; }
carga_ffmpeg_jpg_ruido() {
    mkdir -p "$TRAB/saida"
    ffmpeg -loglevel error -f lavfi -i "$RUIDO" -frames:v 60 -q:v 3 "$TRAB/saida/i_%03d.jpg"
}
carga_ffmpeg_hls() {
    # transcodificação em segmentos, um arquivo de vídeo novo a cada 2 s
    mkdir -p "$TRAB/saida"
    ffmpeg -loglevel error -f lavfi -i "testsrc2=size=1280x720:rate=30" -t 40 \
        -c:v mpeg4 -q:v 2 -f hls -hls_time 2 -hls_list_size 0 "$TRAB/saida/v.m3u8"
}
carga_git_clone() { git -c safe.directory='*' clone -q --no-local "$REPO_REF" "$TRAB/saida"; }
carga_sim_benign() { mkdir -p "$TRAB/saida" && ./tests/sim_benign "$TRAB/saida" --files 100 --size-kb 64; }
carga_nao_regular() {
    # 12 sockets com dado aleatório, antes do filtro S_ISREG isso batia os
    # três critérios igual tráfego tls de um navegador
    python3 -c '
import os, socket
pares = [socket.socketpair() for _ in range(12)]
for a, b in pares:
    for _ in range(2):
        a.send(os.urandom(8192))
        b.recv(8192)'
}
carga_cifragem_legitima() {
    # ferramenta legítima de backup cifrado, um processo cifrando 40 arquivos.
    # o comportamento é idêntico ao de ransomware, então entra como positiva
    mkdir -p "$TRAB/saida"
    python3 - "$TRAB/texto" "$TRAB/saida" <<'EOF'
import os, subprocess, sys
orig, dest = sys.argv[1:]
for nome in sorted(os.listdir(orig))[:40]:
    dados = open(os.path.join(orig, nome), "rb").read()
    cifrado = subprocess.run(["openssl", "enc", "-aes-256-ctr", "-pbkdf2", "-pass", "pass:x"],
                             input=dados, capture_output=True, check=True).stdout
    open(os.path.join(dest, nome + ".enc"), "wb").write(cifrado)
EOF
}
sim_encrypt_tam() {
    mkdir -p "$TRAB/saida"
    ./tests/sim_benign "$TRAB/saida" --files 60 --size-kb "$1" 2>/dev/null
    ./tests/sim_encrypt "$TRAB/saida" --max-files 60
}
carga_sim_encrypt_16k() { sim_encrypt_tam 16; }
carga_sim_encrypt_64k() { sim_encrypt_tam 64; }
carga_sim_encrypt_256k() { sim_encrypt_tam 256; }

classe() {
    case "$1" in
        sim_encrypt_*|cifragem_legitima) echo positivo ;;
        *) echo negativo ;;
    esac
}

# exportadas porque a carga roda num bash -c, que é o que dá pra pôr sob strace
export TRAB RUIDO REPO_REF
export -f carga_gzip_muitos carga_tar_gz carga_zip_r carga_extrair_fotos \
    carga_ffmpeg_jpg_ruido carga_ffmpeg_hls carga_git_clone carga_sim_benign \
    carga_nao_regular carga_cifragem_legitima sim_encrypt_tam carga_sim_encrypt_16k \
    carga_sim_encrypt_64k carga_sim_encrypt_256k

CARGAS=(gzip_muitos tar_gz zip_r extrair_fotos ffmpeg_jpg_ruido ffmpeg_hls git_clone
        sim_benign nao_regular cifragem_legitima sim_encrypt_16k sim_encrypt_64k sim_encrypt_256k)
if [[ -n "${SO_CARGAS:-}" ]]; then
    read -r -a CARGAS <<< "$SO_CARGAS"
fi

echo "[*] preparando material em $TRAB"
preparar

if [[ $DRY != 1 ]]; then
    echo "=== ocioso, 60 s sem carga, só o que o sistema já faz ==="
    iniciar_detector "$RESULTS/ocioso_1.log" --csv "$RESULTS/ocioso_1.csv"
    t0=$(agora_ns); sleep 60; t1=$(agora_ns)
    parar_detector
    echo "ocioso,negativo,1,$t0,$t1" >> "$RESULTS/cargas.csv"
fi

for carga in "${CARGAS[@]}"; do
    if [[ $carga == git_clone && ! -d "$REPO_REF/.git" ]]; then
        echo "[aviso] $REPO_REF não é repositório git, pulando git_clone"
        continue
    fi
    for rep in $(seq 1 "$REPS"); do
        rm -rf "$TRAB/saida"
        sync
        iniciar_detector "$RESULTS/${carga}_${rep}.log" --csv "$RESULTS/${carga}_${rep}.csv"
        t0=$(agora_ns)
        if [[ $EMULAR == 1 ]]; then
            rodar=(strace -f -qq -Y -y -xx -s 512 -ttt --seccomp-bpf
                   -e trace=write,pwrite64,writev,pwritev,pwritev2,clone,clone3
                   -e signal=none -o "$RESULTS/${carga}_${rep}.strace"
                   bash -c "carga_$carga")
        else
            rodar=(bash -c "carga_$carga")
        fi
        # stdout vai pro lixo porque um log em arquivo regular entra no histograma
        # do próprio processo e dilui a entropia, foi o que derrubou o sim_encrypt
        # de 8,0 pra 7,94 na primeira rodada
        if ! "${rodar[@]}" > /dev/null 2> "$RESULTS/${carga}_${rep}.carga.log"; then
            echo "[aviso] $carga terminou com erro, veja $RESULTS/${carga}_${rep}.carga.log"
        fi
        t1=$(agora_ns)
        if [[ $EMULAR == 1 ]]; then
            python3 scripts/emular_detector.py "$RESULTS/${carga}_${rep}.strace" \
                > "$RESULTS/${carga}_${rep}.csv" 2> "$RESULTS/${carga}_${rep}.emul.log"
            rm -f "$RESULTS/${carga}_${rep}.strace"
        fi
        sleep 0.3
        parar_detector
        echo "[*] $carga rep $rep, $(( (t1 - t0) / 1000000 )) ms, $(du -sh "$TRAB/saida" 2>/dev/null | cut -f1) escritos"
        echo "$carga,$(classe "$carga"),$rep,$t0,$t1" >> "$RESULTS/cargas.csv"
    done
done

rm -rf "$TRAB"
echo "[*] Resultados em $RESULTS/"
