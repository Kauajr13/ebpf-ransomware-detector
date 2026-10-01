#!/usr/bin/env python3
"""Gera os graficos de overhead e comparacao a partir dos csv/json do benchmark."""

import json
import os

import matplotlib.pyplot as plt
import pandas as pd

RESULTS_DIR = "bench/results"
OUT_DIR = "bench/plots"
os.makedirs(OUT_DIR, exist_ok=True)

plt.rcParams.update({
    "figure.dpi": 150,
    "font.family": "monospace",
    "axes.grid": True,
    "grid.alpha": 0.3,
})

# gráfico 1, overhead de throughput usando fio

def plot_overhead():
    sem_file = os.path.join(RESULTS_DIR, "fio_sem_detector.json")
    com_file = os.path.join(RESULTS_DIR, "fio_com_detector_monitor.json")

    if not os.path.exists(sem_file) or not os.path.exists(com_file):
        print("[aviso] Arquivos fio não encontrados, pulando gráfico de overhead")
        return

    def parse_fio(path):
        with open(path) as f:
            d = json.load(f)
        j = d["jobs"][0]
        return {
            "throughput_mbs": j["write"]["bw"] / 1024,
            "iops":           j["write"]["iops"],
            "lat_p99_ms":     j["write"]["lat_ns"]["percentile"]["99.000000"] / 1e6,
        }

    sem = parse_fio(sem_file)
    com = parse_fio(com_file)

    labels = ["Sem detector", "Com detector\n(eBPF monitor)"]
    throughputs = [sem["throughput_mbs"], com["throughput_mbs"]]
    latencies   = [sem["lat_p99_ms"],     com["lat_p99_ms"]]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    fig.suptitle("Overhead do detector eBPF, fio (escrita sequencial)", fontsize=11)

    ax1.bar(labels, throughputs, color=["#4c9be8", "#e8704c"], width=0.5)
    ax1.set_ylabel("Throughput (MB/s)")
    ax1.set_title("Throughput de escrita")
    overhead_pct = (sem["throughput_mbs"] - com["throughput_mbs"]) / sem["throughput_mbs"] * 100
    ax1.text(1, com["throughput_mbs"] * 0.5,
             f"overhead\n{overhead_pct:.1f}%",
             ha="center", va="center", fontsize=9, color="white", fontweight="bold")

    ax2.bar(labels, latencies, color=["#4c9be8", "#e8704c"], width=0.5)
    ax2.set_ylabel("Latência p99 (ms)")
    ax2.set_title("Latência de escrita (p99)")

    plt.tight_layout()
    out = os.path.join(OUT_DIR, "overhead_throughput.png")
    plt.savefig(out)
    print(f"[*] Salvo: {out}")
    plt.close()

# gráfico 2, comparação de detectores

def plot_comparison():
    csv_file = os.path.join(RESULTS_DIR, "comparison.csv")
    if not os.path.exists(csv_file):
        print("[aviso] comparison.csv não encontrado, pulando gráfico de comparação")
        return

    df = pd.read_csv(csv_file)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    fig.suptitle("Comparação de abordagens de detecção", fontsize=11)

    colors = {"ebpf": "#27ae60", "auditd": "#e74c3c", "inotify": "#e67e22"}
    bar_colors = [colors.get(a, "#95a5a6") for a in df["abordagem"]]

    ax1.bar(df["abordagem"], df["arquivos_perdidos"], color=bar_colors, width=0.5)
    ax1.set_ylabel("Arquivos cifrados antes do bloqueio")
    ax1.set_title("Arquivos perdidos")
    ax1.set_xlabel("Abordagem")

    ax2.bar(df["abordagem"], df["latencia_ms"], color=bar_colors, width=0.5)
    ax2.set_ylabel("Tempo total de cifragem (ms)")
    ax2.set_title("Latência de detecção / cifragem")
    ax2.set_xlabel("Abordagem")

    plt.tight_layout()
    out = os.path.join(OUT_DIR, "detection_comparison.png")
    plt.savefig(out)
    print(f"[*] Salvo: {out}")
    plt.close()

# gráfico 3, distribuição de entropia dos eventos

def plot_entropy_dist():
    csv_file = os.path.join(RESULTS_DIR, "ebpf_events.csv")
    if not os.path.exists(csv_file):
        print("[aviso] ebpf_events.csv não encontrado, pulando histograma de entropia")
        return

    df = pd.read_csv(csv_file)
    if df.empty or "entropia" not in df.columns:
        return

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(df["entropia"], bins=20, color="#4c9be8", edgecolor="white", linewidth=0.5)
    ax.axvline(7.8, color="#e74c3c", linestyle="--", label="Threshold (7.8)")
    ax.set_xlabel("Entropia (bits/byte)")
    ax.set_ylabel("Frequência de eventos")
    ax.set_title("Distribuição de entropia dos alertas eBPF")
    ax.legend()
    plt.tight_layout()

    out = os.path.join(OUT_DIR, "entropy_distribution.png")
    plt.savefig(out)
    print(f"[*] Salvo: {out}")
    plt.close()

if __name__ == "__main__":
    print(f"[*] Gerando gráficos a partir de {RESULTS_DIR}/")
    plot_overhead()
    plot_comparison()
    plot_entropy_dist()
    print(f"[*] Gráficos em {OUT_DIR}/")
