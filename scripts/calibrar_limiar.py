#!/usr/bin/env python3
"""Calibra o limiar de entropia a partir dos eventos de bench/falsos_positivos.sh.

uso
    calibrar_limiar.py bench/results/fp            # detector real
    calibrar_limiar.py bench/results/fp_emulado    # emulação por strace

Lê cargas.csv e os csv de eventos de cada execução, avalia três regras de
decisão e grava calibracao.md no mesmo diretório, mais os gráficos em
bench/plots com o nome do diretório como sufixo.

Evento positivo é só o que vem do processo que cifrou. O sim_benign que
prepara os arquivos dentro de uma carga positiva conta como negativo, porque
é escrita legítima que o detector não deveria acusar.
"""

import argparse
import math
import os
import sys

import pandas as pd

ATACANTES = {"sim_encrypt": {"sim_encrypt"}, "cifragem_legitima": {"python3"}}
LIMIAR_PADRAO = 7.8
# quantil 0,999 da qui-quadrado com 255 graus de liberdade, aproximação normal
# de média 255 e desvio raiz de 510. acima disso o histograma é incompatível
# com a uniforme. fica no relatório como referência teórica
QUI2_UNIFORME = 255 + 3.09 * math.sqrt(2 * 255)
# corte usado na decisão. o teórico deixou 3 de 66 eventos de cifragem do
# openssl acima, entre 330 e 361, porque o cabeçalho fixo Salted__ cai bem no
# começo do arquivo, que é o que a amostra pega. o menor benigno ficou em 731,
# e 500 fica perto do meio dos dois em escala log, com folga pros dois lados
QUI2_CORTE = 500.0


def atacante(carga, proc):
    for prefixo, procs in ATACANTES.items():
        if carga.startswith(prefixo):
            return proc in procs
    return False


def carregar(diretorio):
    cargas = pd.read_csv(os.path.join(diretorio, "cargas.csv"))
    linhas = []
    for c in cargas.itertuples():
        arq = os.path.join(diretorio, f"{c.carga}_{c.rep}.csv")
        if not os.path.exists(arq):
            continue
        ev = pd.read_csv(arq)
        if ev.empty:
            continue
        ev["carga"] = c.carga
        ev["rep"] = c.rep
        linhas.append(ev)
    eventos = pd.concat(linhas, ignore_index=True) if linhas else pd.DataFrame()
    if not eventos.empty:
        eventos["positivo"] = [atacante(c, p) for c, p in zip(eventos.carga, eventos.proc)]
        if "qui2" not in eventos:
            eventos["qui2"] = float("nan")
    return cargas, eventos


REGRAS = {
    "entropia comum": lambda ev, t: ev.entropia >= t,
    "miller-madow": lambda ev, t: ev.entropia_mm >= t,
    "miller-madow + qui2": lambda ev, t: (ev.entropia_mm >= t) & (ev.qui2 <= QUI2_CORTE),
}


def avaliar(cargas, eventos, regra, t):
    """Taxas por execução, que é o que importa pro usuário. Um alarme falso
    numa execução já mata o processo errado, não importa quantos eventos."""
    dispara = REGRAS[regra](eventos, t)
    pos_runs = cargas[cargas.classe == "positivo"]
    detectadas = 0
    for r in pos_runs.itertuples():
        sel = (eventos.carga == r.carga) & (eventos.rep == r.rep) & eventos.positivo
        detectadas += bool(dispara[sel].any())
    falsas = set()
    for (carga, rep), grupo in eventos[~eventos.positivo & dispara].groupby(["carga", "rep"]):
        falsas.add((carga, rep))
    neg_ev = (~eventos.positivo).sum()
    return {
        "tpr": detectadas / max(len(pos_runs), 1),
        "execucoes_com_falso": len(falsas),
        "execucoes": len(cargas),
        "fpr_eventos": (dispara & ~eventos.positivo).sum() / max(neg_ev, 1),
    }


def recomendar(cargas, eventos, regra):
    # maior tpr menos taxa de execuções com alarme falso. no empate fica o
    # limiar da faixa vencedora mais perto do original, a menor mudança que os
    # dados justificam. com amostra pequena dado aleatório corrigido chega a
    # 7,80, então subir o limiar sem necessidade custa detecção fora do teste
    grade = [round(7.0 + i * 0.005, 3) for i in range(201)]
    notas = []
    for t in grade:
        a = avaliar(cargas, eventos, regra, t)
        notas.append((a["tpr"] - a["execucoes_com_falso"] / a["execucoes"], t, a))
    melhor = max(n[0] for n in notas)
    faixa = [n for n in notas if n[0] == melhor]
    escolhido = min(faixa, key=lambda n: abs(n[1] - LIMIAR_PADRAO))
    return escolhido[1], escolhido[2], (faixa[0][1], faixa[-1][1])


def tabela_md(df):
    cab = "| " + " | ".join(df.columns) + " |"
    sep = "| " + " | ".join("---" for _ in df.columns) + " |"
    corpo = ["| " + " | ".join(str(v) for v in linha) + " |" for linha in df.itertuples(index=False)]
    return "\n".join([cab, sep] + corpo)


def resumo_cargas(cargas, eventos, regra, t):
    linhas = []
    dispara = REGRAS[regra](eventos, t)
    padrao = REGRAS["entropia comum"](eventos, LIMIAR_PADRAO)
    for carga in cargas.carga.unique():
        reps = cargas[cargas.carga == carga]
        classe = reps.classe.iloc[0]
        ev = eventos[eventos.carga == carga] if not eventos.empty else eventos
        if classe == "positivo":
            ev_rel = ev[ev.positivo]
        else:
            ev_rel = ev
        def alarmes(serie):
            if ev_rel.empty:
                return f"0/{len(reps)}"
            n = sum(bool(serie[ev_rel.index][ev_rel.rep == r].any()) for r in reps.rep)
            return f"{n}/{len(reps)}"
        fmt = lambda s, f: "-" if ev_rel.empty else f.format(s)
        linhas.append({
            "carga": carga, "classe": classe, "eventos": len(ev_rel),
            "H_mm min": fmt(ev_rel.entropia_mm.min() if not ev_rel.empty else 0, "{:.3f}"),
            "H_mm max": fmt(ev_rel.entropia_mm.max() if not ev_rel.empty else 0, "{:.3f}"),
            "qui2 min": fmt(ev_rel.qui2.min() if not ev_rel.empty else 0, "{:.0f}"),
            "qui2 max": fmt(ev_rel.qui2.max() if not ev_rel.empty else 0, "{:.0f}"),
            f"alarme H>={LIMIAR_PADRAO}": alarmes(padrao),
            "alarme recomendado": alarmes(dispara),
        })
    return pd.DataFrame(linhas)


def graficos(eventos, sufixo, t_mm):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[aviso] matplotlib ausente, sem gráficos", file=sys.stderr)
        return []
    os.makedirs("bench/plots", exist_ok=True)
    saidas = []

    ordem = (eventos.groupby("carga").entropia_mm.median().sort_values().index.tolist())
    fig, ax = plt.subplots(figsize=(9, 4.5))
    for i, carga in enumerate(ordem):
        ev = eventos[eventos.carga == carga]
        for positivo, cor in ((False, "#4c78a8"), (True, "#e45756")):
            s = ev[ev.positivo == positivo]
            ax.scatter(s.entropia_mm, [i] * len(s), color=cor, s=18, alpha=0.7,
                       label=("cifragem" if positivo else "benigno") if i == 0 else None)
    ax.axvline(LIMIAR_PADRAO, color="#888", ls="--", lw=1, label=f"limiar original {LIMIAR_PADRAO}")
    ax.axvline(t_mm, color="#222", ls="-", lw=1, label=f"só entropia precisaria de {t_mm}")
    ax.set_yticks(range(len(ordem)), ordem)
    ax.set_xlabel("entropia com correção de Miller-Madow, bits por byte")
    ax.set_xlim(left=max(0, eventos.entropia_mm.min() - 0.2), right=8.02)
    ax.legend(loc="lower left", fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    out = f"bench/plots/calibracao_entropia_{sufixo}.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    saidas.append(out)

    alta = eventos[eventos.entropia_mm >= 7.5]
    if not alta.empty and alta.qui2.notna().any():
        fig, ax = plt.subplots(figsize=(7, 4.5))
        for positivo, cor, rot in ((False, "#4c78a8", "benigno"), (True, "#e45756", "cifragem")):
            s = alta[alta.positivo == positivo]
            ax.scatter(s.entropia_mm, s.qui2, color=cor, s=18, alpha=0.7, label=rot)
        ax.axhline(QUI2_CORTE, color="#222", lw=1, label=f"corte usado, {QUI2_CORTE:.0f}")
        ax.axhline(QUI2_UNIFORME, color="#888", ls="--", lw=1,
                   label=f"quantil 0,999 teórico, {QUI2_UNIFORME:.0f}")
        ax.set_yscale("log")
        ax.set_xlabel("entropia com correção de Miller-Madow, bits por byte")
        ax.set_ylabel("qui-quadrado contra a uniforme, escala log")
        ax.legend(fontsize=8)
        ax.grid(alpha=0.3)
        fig.tight_layout()
        out = f"bench/plots/calibracao_qui2_{sufixo}.png"
        fig.savefig(out, dpi=150)
        plt.close(fig)
        saidas.append(out)
    return saidas


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("diretorio")
    args = ap.parse_args()

    cargas, eventos = carregar(args.diretorio)
    if eventos.empty:
        sys.exit("nenhum evento encontrado")
    sufixo = os.path.basename(os.path.normpath(args.diretorio))

    md = [f"# Calibração do limiar, {sufixo}", ""]
    md.append(f"{len(cargas)} execuções, {len(eventos)} eventos, "
              f"{int(eventos.positivo.sum())} vindos do processo que cifrou.")
    md.append("")
    md.append("Taxas por execução. Uma execução benigna conta como alarme falso se qualquer "
              "evento dela passa na regra, porque com --kill isso já derruba o processo.")
    md.append("")

    recs = {}
    linhas = []
    for regra in REGRAS:
        if regra.endswith("qui2") and eventos.qui2.isna().all():
            continue
        t, a, faixa = recomendar(cargas, eventos, regra)
        recs[regra] = t
        padrao = avaliar(cargas, eventos, regra, LIMIAR_PADRAO)
        linhas.append({
            "regra": regra,
            f"detecção em {LIMIAR_PADRAO}": f"{padrao['tpr']:.0%}",
            f"execuções com falso em {LIMIAR_PADRAO}": f"{padrao['execucoes_com_falso']}/{padrao['execucoes']}",
            "limiar recomendado": t,
            "faixa empatada": f"{faixa[0]} a {faixa[1]}",
            "detecção": f"{a['tpr']:.0%}",
            "execuções com falso": f"{a['execucoes_com_falso']}/{a['execucoes']}",
        })
    md += ["## Regras", "", tabela_md(pd.DataFrame(linhas)), ""]
    pos_ev = eventos[eventos.positivo]
    neg_alta = eventos[~eventos.positivo & (eventos.entropia_mm >= LIMIAR_PADRAO)]
    md.append(f"Corte de qui2 = {QUI2_CORTE:.0f}. O quantil 0,999 teórico da qui-quadrado com "
              f"255 graus de liberdade é {QUI2_UNIFORME:.0f} e deixaria "
              f"{int((pos_ev.qui2 > QUI2_UNIFORME).sum())} de {len(pos_ev)} eventos de cifragem "
              f"acima, contra {int((pos_ev.qui2 > QUI2_CORTE).sum())} com o corte usado. "
              f"Maior qui2 de cifragem {pos_ev.qui2.max():.0f}, menor qui2 benigno com entropia "
              f"corrigida a partir de {LIMIAR_PADRAO}, "
              f"{neg_alta.qui2.min():.0f}." if not neg_alta.empty else "")
    md.append("")

    regra_final = "miller-madow + qui2" if "miller-madow + qui2" in recs else "miller-madow"
    md += [f"## Por carga, regra {regra_final} em {recs[regra_final]}", "",
           tabela_md(resumo_cargas(cargas, eventos, regra_final, recs[regra_final])), ""]

    pos = eventos[eventos.positivo]
    neg = eventos[~eventos.positivo]
    folga = pos.groupby(["carga", "rep"]).entropia_mm.max().min() - neg.entropia_mm.max()
    md.append(f"Margem pela entropia sozinha, menor máximo de execução positiva menos maior "
              f"evento negativo, {folga:+.3f} bits por byte.")
    md.append("")

    for g in graficos(eventos, sufixo, recs.get("miller-madow", LIMIAR_PADRAO)):
        md.append(f"![{os.path.basename(g)}](../../plots/{os.path.basename(g)})")

    saida = os.path.join(args.diretorio, "calibracao.md")
    with open(saida, "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))
    print(f"\n[*] relatório em {saida}", file=sys.stderr)


if __name__ == "__main__":
    main()
