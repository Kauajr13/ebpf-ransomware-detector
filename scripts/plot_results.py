#!/usr/bin/env python3
"""Resume bench/results/overhead.csv e latencia_kill.csv, gerados por run_bench.sh.

Grava bench/results/bench.md com as tabelas e os gráficos em bench/plots.
uso, a partir da raiz do projeto, python3 scripts/plot_results.py
"""

import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

RESULTS_DIR = sys.argv[1] if len(sys.argv) > 1 else "bench/results"
OUT_DIR = "bench/plots"
os.makedirs(OUT_DIR, exist_ok=True)


def tabela_md(df):
    cab = "| " + " | ".join(df.columns) + " |"
    sep = "| " + " | ".join("---" for _ in df.columns) + " |"
    corpo = ["| " + " | ".join(str(v) for v in linha) + " |" for linha in df.itertuples(index=False)]
    return "\n".join([cab, sep] + corpo)


def media_dp(s, fmt="{:.1f}"):
    if len(s) < 2:
        return fmt.format(s.mean())
    return f"{fmt.format(s.mean())} ± {fmt.format(s.std())}"


def overhead(md):
    arq = os.path.join(RESULTS_DIR, "overhead.csv")
    if not os.path.exists(arq):
        print("[aviso] overhead.csv não encontrado", file=sys.stderr)
        return
    df = pd.read_csv(arq)
    linhas = []
    for carga, g in df.groupby("carga", sort=False):
        sem, com = g[g.modo == "sem"], g[g.modo == "com"]
        bw_s, bw_c = sem.bw_kib.mean(), com.bw_kib.mean()
        sys_s, sys_c = sem.sys_cpu.mean(), com.sys_cpu.mean()
        ns_chamada = (com.kprobe_ns_total / com.kprobe_execucoes.where(com.kprobe_execucoes > 0)).mean()
        linhas.append({
            "carga": carga,
            "MB/s sem": media_dp(sem.bw_kib / 1024),
            "MB/s com": media_dp(com.bw_kib / 1024),
            "perda de vazão": f"{(bw_s - bw_c) / bw_s:+.1%}" if bw_s else "-",
            "p99 µs sem": media_dp(sem.lat_p99_us),
            "p99 µs com": media_dp(com.lat_p99_us),
            "CPU sys % sem": f"{sys_s:.1f}",
            "CPU sys % com": f"{sys_c:.1f}",
            "ns por kprobe": f"{ns_chamada:.0f}" if pd.notna(ns_chamada) else "-",
            "CPU do agente s": f"{com.agente_cpu_s.mean():.3f}",
            "reps": len(com),
        })
    res = pd.DataFrame(linhas)
    md += ["## Overhead", "",
           "Média ± desvio padrão entre repetições. CPU sys é do fio, que é onde o tempo "
           "do kprobe aparece, porque o programa eBPF roda no contexto de quem escreve. "
           "CPU do agente é o processo em espaço de usuário.", "",
           tabela_md(res), ""]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
    cargas = list(res.carga)
    x = range(len(cargas))
    for desloc, modo, cor, rot in ((-0.2, "sem", "#4c78a8", "sem detector"), (0.2, "com", "#e45756", "com detector")):
        g = df[df.modo == modo].groupby("carga", sort=False)
        bw = g.bw_kib.agg(["mean", "std"]).reindex(cargas) / 1024
        p99 = g.lat_p99_us.agg(["mean", "std"]).reindex(cargas)
        ax1.bar([i + desloc for i in x], bw["mean"], 0.4, yerr=bw["std"], color=cor, label=rot, capsize=3)
        ax2.bar([i + desloc for i in x], p99["mean"], 0.4, yerr=p99["std"], color=cor, label=rot, capsize=3)
    for ax, titulo in ((ax1, "vazão de escrita, MB/s"), (ax2, "latência p99, µs")):
        ax.set_xticks(list(x), cargas, rotation=15)
        ax.set_title(titulo)
        ax.grid(axis="y", alpha=0.3)
    ax1.legend(fontsize=8)
    fig.tight_layout()
    out = os.path.join(OUT_DIR, "overhead.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    md += [f"![overhead](../plots/{os.path.basename(out)})", ""]


def latencia(md):
    arq = os.path.join(RESULTS_DIR, "latencia_kill.csv")
    if not os.path.exists(arq):
        print("[aviso] latencia_kill.csv não encontrado", file=sys.stderr)
        return
    df = pd.read_csv(arq)
    linhas = []
    for (cen, tam, atr), g in df.groupby(["cenario", "tamanho_kb", "atraso_ms"], sort=False):
        mortos = g[g.morto == 1]
        linhas.append({
            "cenário": cen, "arquivo KiB": tam, "atraso ms": atr,
            "bloqueado": f"{len(mortos)}/{len(g)}",
            "arquivos perdidos": media_dp(g.arquivos_perdidos),
            "de": int(g.arquivos_total.iloc[0]),
            "ms até o kill": media_dp(mortos.t_ate_kill_ms) if len(mortos) else "-",
            "kernel até agente µs": media_dp(mortos.t_kernel_user_us, "{:.0f}") if len(mortos) else "-",
        })
    md += ["## Tempo até o bloqueio", "",
           "ms até o kill vai do primeiro instante do simulador até o SIGKILL, no mesmo "
           "CLOCK_MONOTONIC. Arquivos perdidos são contados no disco depois do kill, "
           "inclusive o que ficou truncado pela metade.", "",
           tabela_md(pd.DataFrame(linhas)), ""]

    rapido = df[(df.cenario == "rapido") & (df.morto == 1)]
    if not rapido.empty:
        fig, ax = plt.subplots(figsize=(6, 4))
        tams = sorted(rapido.tamanho_kb.unique())
        ax.boxplot([rapido[rapido.tamanho_kb == t].arquivos_perdidos for t in tams],
                   labels=[f"{t} KiB" for t in tams])
        ax.set_ylabel("arquivos perdidos antes do SIGKILL")
        ax.set_xlabel("tamanho de cada arquivo cifrado")
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        out = os.path.join(OUT_DIR, "arquivos_perdidos.png")
        fig.savefig(out, dpi=150)
        plt.close(fig)
        md += [f"![arquivos perdidos](../plots/{os.path.basename(out)})", ""]


if __name__ == "__main__":
    md = ["# Resultados do benchmark", ""]
    overhead(md)
    latencia(md)
    saida = os.path.join(RESULTS_DIR, "bench.md")
    with open(saida, "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))
    print(f"\n[*] relatório em {saida}", file=sys.stderr)
