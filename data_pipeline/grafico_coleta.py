#!/usr/bin/env python3
"""Grafico de sessoes por dia e honeypot a partir do JSON de relatorio_coleta.py.

O periodo fechado em 10/09/2026 (de onde saiu a amostra de avaliacao) aparece
sombreado, para que o leitor nao confunda a amostra com a coleta inteira.

Uso:
    python data_pipeline/relatorio_coleta.py --db data/beeia.db --json relatorio.json
    python data_pipeline/grafico_coleta.py --relatorio relatorio.json \\
        --saida md-usotcc/img/sessoes-por-dia.png
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

CORES = {"cowrie": "#2a78d6", "dionaea": "#eb6834"}
TINTA, TINTA_2, GRADE, FUNDO = "#0b0b0b", "#52514e", "#e6e5e1", "#fcfcfb"
FIM_PERIODO_FECHADO = dt.date(2026, 9, 10)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--relatorio", type=Path, required=True)
    ap.add_argument("--saida", type=Path, required=True)
    args = ap.parse_args()
    r = json.loads(args.relatorio.read_text(encoding="utf-8"))

    series: dict[str, dict[dt.date, int]] = {}
    for linha in r["por_dia"]:
        dia = dt.date.fromisoformat(linha["dia"])
        series.setdefault(linha["honeypot"], {})[dia] = linha["sessoes"]
    dias = sorted({d for s in series.values() for d in s})
    # O ultimo dia esta incompleto (coleta em andamento): fica de fora.
    ultimo_completo = dt.date.fromisoformat(r["gerado_em"][:10]) - dt.timedelta(days=1)
    dias = [d for d in dias if d <= ultimo_completo]

    fig, ax = plt.subplots(figsize=(9, 4.2), dpi=150)
    fig.patch.set_facecolor(FUNDO)
    ax.set_facecolor(FUNDO)
    ax.axvspan(mdates.date2num(dias[0]) - 0.5, mdates.date2num(FIM_PERIODO_FECHADO) + 0.5,
               color=GRADE, zorder=0, linewidth=0)
    ax.text(mdates.date2num(dias[0]) - 0.3, 0.97, "período fechado\n(origem da amostra)",
            transform=ax.get_xaxis_transform(), va="top", fontsize=8, color=TINTA_2)

    topo = 0
    for honeypot in ("cowrie", "dionaea"):
        valores = [series.get(honeypot, {}).get(d, 0) for d in dias]
        topo = max(topo, *valores)
        ax.plot(dias, valores, color=CORES[honeypot], linewidth=2, marker="o",
                markersize=4, markeredgecolor=FUNDO, markeredgewidth=1, label=honeypot.capitalize(),
                zorder=3)
        ax.annotate(f"{honeypot.capitalize()}  {valores[-1]}", (dias[-1], valores[-1]),
                    xytext=(6, 0), textcoords="offset points", va="center", fontsize=8.5, color=TINTA)

    ax.set_ylim(0, topo * 1.12)
    ax.set_xlim(mdates.date2num(dias[0]) - 0.6, mdates.date2num(dias[-1]) + 3.2)
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=3))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m"))
    ax.grid(axis="y", color=GRADE, linewidth=0.8)
    ax.set_axisbelow(True)
    for lado in ("top", "right", "left"):
        ax.spines[lado].set_visible(False)
    ax.spines["bottom"].set_color(TINTA_2)
    ax.tick_params(colors=TINTA_2, labelsize=8.5, length=0)
    ax.set_ylabel("sessões por dia (UTC)", color=TINTA_2, fontsize=9)
    ax.legend(loc="upper right", frameon=False, fontsize=8.5, labelcolor=TINTA, ncols=2)
    ax.set_title(f"Sessões classificadas por dia — {dias[0]:%d/%m} a {dias[-1]:%d/%m/%Y}",
                 loc="left", fontsize=11, color=TINTA, pad=12)
    fig.tight_layout()
    args.saida.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.saida, facecolor=FUNDO)
    print(f"{len(dias)} dias completos -> {args.saida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
