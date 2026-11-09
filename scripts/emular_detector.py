#!/usr/bin/env python3
"""Reproduz a lógica do kprobe sobre um trace do strace, sem root.

O strace com -xx -s 512 -y mostra os primeiros 512 bytes de cada write e o
caminho do descritor, que é exatamente o que o programa eBPF enxerga. Isso
permite calibrar o limiar numa máquina sem sudo e conferir depois que o
detector real dá o mesmo resultado.

uso
    strace -f -qq -Y -y -xx -s 512 -ttt --seccomp-bpf \
        -e trace=write,pwrite64,writev,pwritev,pwritev2,clone,clone3 \
        -e signal=none -o trace.txt COMANDO
    emular_detector.py trace.txt > eventos.csv

A saída tem as mesmas colunas do --csv do detector. ts_* vêm do relógio de
parede do strace e servem só pra ordem e pra janela.
"""

import argparse
import math
import re
import sys

TAM_AMOSTRA = 512
AMOSTRA_MINIMA = 64
MAX_INODES = 32

LINHA = re.compile(r"^(\d+)<([^>]*)> (\d+\.\d+) (.*)$")
CHAMADA = re.compile(r"^(\w+)\((.*)\) += (-?\d+)")
RETOMADA = re.compile(r"^<\.\.\. (\w+) resumed>(.*)\) += (-?\d+)")
# fd<caminho>, "buffer" possivelmente com ... de truncado, count
ARGS_WRITE = re.compile(r'^(\d+)<([^>]*)>, "((?:\\x[0-9a-f]{2})*)"(?:\.\.\.)?, (\d+)')
ARGS_FD = re.compile(r"^(\d+)<([^>]*)>")


def decodificar(hexesc):
    return bytes.fromhex(hexesc.replace("\\x", ""))


def entropias(hist):
    total = sum(hist)
    if total == 0:
        return 0.0, 0.0, 0
    h = 0.0
    presentes = 0
    for c in hist:
        if c:
            presentes += 1
            p = c / total
            h -= p * math.log2(p)
    mm = h + (presentes - 1) / (2 * total * math.log(2))
    return h, mm, total


def qui_quadrado(hist):
    # distância do histograma até a uniforme. dado cifrado fica perto de 255,
    # que são os graus de liberdade, e comprimido costuma passar bem disso
    total = sum(hist)
    if total == 0:
        return 0.0
    esperado = total / 256
    return sum((c - esperado) ** 2 for c in hist) / esperado


def regular(caminho):
    # o kernel testa S_ISREG no inode. pelo strace o que não é arquivo
    # regular aparece como pipe:[n], socket:[n] ou caminho em /dev, /proc
    if not caminho.startswith("/"):
        return False
    return not caminho.startswith(("/dev/", "/proc/", "/sys/", "/run/user/"))


class Estado:
    def __init__(self, ts):
        self.zerar(ts)

    def zerar(self, ts):
        self.hist = [0] * 256
        self.total = 0
        self.inodes = []
        self.ts_inicio = ts


def emular(linhas, piso, arquivos, janela_s, limiar, max_qui2):
    tgid_de = {}
    estados = {}
    pendentes = {}
    eventos = []
    ponto_cego = {"writev": 0}

    for bruta in linhas:
        m = LINHA.match(bruta.rstrip("\n"))
        if not m:
            continue
        tid, comm, ts, resto = int(m[1]), decodificar(m[2]).decode(errors="replace"), float(m[3]), m[4]

        # chamada interrompida por outra thread chega em duas linhas
        if resto.endswith("<unfinished ...>"):
            pendentes[tid] = resto[: -len(" <unfinished ...>")]
            continue
        r = RETOMADA.match(resto)
        if r:
            if tid not in pendentes:
                continue
            resto = f"{pendentes.pop(tid)}{r[2]}) = {r[3]}"

        c = CHAMADA.match(resto)
        if not c:
            continue
        nome, args, ret = c[1], c[2], int(c[3])
        tgid = tgid_de.setdefault(tid, tid)

        if nome in ("clone", "clone3"):
            if ret > 0:
                tgid_de[ret] = tgid if "CLONE_THREAD" in args else ret
            continue

        if nome in ("writev", "pwritev", "pwritev2"):
            # vfs_writev não passa pelo kprobe de vfs_write, fica contado à
            # parte como ponto cego do detector
            a = ARGS_FD.match(args)
            if a and regular(decodificar(a[2]).decode(errors="replace")) and ret > 0:
                ponto_cego["writev"] += ret
            continue

        a = ARGS_WRITE.match(args)
        if not a:
            continue
        caminho = decodificar(a[2]).decode(errors="replace")
        buf = decodificar(a[3])
        count = int(a[4])

        if count < AMOSTRA_MINIMA or not regular(caminho):
            continue

        st = estados.get(tgid)
        if st is None:
            st = estados[tgid] = Estado(ts)
        if janela_s and ts - st.ts_inicio > janela_s:
            st.zerar(ts)

        amostra = buf[:TAM_AMOSTRA] if count >= TAM_AMOSTRA else buf[:AMOSTRA_MINIMA]
        for b in amostra:
            st.hist[b] += 1
        st.total += count

        if caminho not in st.inodes and len(st.inodes) < MAX_INODES:
            st.inodes.append(caminho)

        if st.total < piso or len(st.inodes) < arquivos:
            continue

        h, mm, amostras = entropias(st.hist)
        q2 = qui_quadrado(st.hist)
        eventos.append({
            "pid": tgid, "proc": comm[:15], "entropia": h, "entropia_mm": mm, "qui2": q2,
            "acima_limiar": int(mm >= limiar and (max_qui2 <= 0 or q2 <= max_qui2)), "total_bytes": st.total,
            "amostras": amostras, "n_arquivos": len(st.inodes),
            "ts_inicio_ns": int(st.ts_inicio * 1e9), "ts_evento_ns": int(ts * 1e9),
            "ts_user_ns": int(ts * 1e9), "ts_kill_ns": 0, "tempo_ms": 0,
        })
        st.zerar(ts)

    return eventos, ponto_cego


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("trace")
    ap.add_argument("--floor", type=int, default=65536)
    ap.add_argument("--files", type=int, default=10)
    ap.add_argument("--window", type=float, default=10.0)
    ap.add_argument("--threshold", type=float, default=7.8)
    ap.add_argument("--chi2", type=float, default=325.0)
    args = ap.parse_args()

    with open(args.trace, errors="replace") as f:
        eventos, cego = emular(f, args.floor, args.files, args.window, args.threshold, args.chi2)

    cols = ["pid", "proc", "entropia", "entropia_mm", "qui2", "acima_limiar", "total_bytes",
            "amostras", "n_arquivos", "ts_inicio_ns", "ts_evento_ns", "ts_user_ns",
            "ts_kill_ns", "tempo_ms"]
    print(",".join(cols))
    for e in eventos:
        print(",".join(f"{e[c]:.6f}" if isinstance(e[c], float) else str(e[c]) for c in cols))
    if cego["writev"]:
        print(f"[ponto cego] {cego['writev']} bytes escritos via writev, invisíveis ao kprobe",
              file=sys.stderr)


if __name__ == "__main__":
    main()
