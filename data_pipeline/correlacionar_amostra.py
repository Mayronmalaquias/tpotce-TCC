#!/usr/bin/env python3
"""Confere se cada sessao do banco tem lastro no log bruto do honeypot.

Por que isto existe
-------------------
O banco e o produto de uma cadeia: honeypot escreve o log, o LogWatcher agrupa,
o classificador rotula, o backend grava. Um erro em qualquer elo produz numeros
que parecem bons e nao correspondem a nada — foi exatamente o que aconteceu
quando o watcher descartava em silencio todo o trafego do Dionaea.

Contar linhas no banco nao detecta isso. Este script pega uma amostra aleatoria
de sessoes gravadas e volta ao log original para confirmar que o evento existiu.

O identificador difere entre os dois honeypots:

  cowrie    o log traz o campo `session`, que vai direto para o banco.
  dionaea   o log real NAO tem campo de sessao. O identificador e sintetizado
            como `<ip>-<timestamp>`, entao a conferencia e por IP de origem.

Limite conhecido: os logs rotacionam e sao apagados. Uma sessao antiga sem
lastro pode significar que o log sumiu, e nao que o dado foi inventado — por
isso o resultado separa "sem lastro" de "fora da janela dos logs".

Uso:
    python data_pipeline/correlacionar_amostra.py --db data/beeia.db --n 40
"""
from __future__ import annotations

import argparse
import contextlib
import glob
import gzip
import json
from pathlib import Path
import random
import sqlite3
import sys


def carrega_eventos(dir_dados: Path) -> dict:
    """Le os logs em disco uma vez so, guardando o que permite correlacionar."""
    indice = {
        "cowrie": {"sessoes": set(), "min": None, "max": None},
        "dionaea": {"ips": set(), "min": None, "max": None},
    }
    padroes = {"cowrie": "cowrie/log/cowrie.json*", "dionaea": "dionaea/log/dionaea.json*"}

    for honeypot, padrao in padroes.items():
        for caminho in sorted(glob.glob(str(dir_dados / padrao))):
            p = Path(caminho)
            if not p.is_file() or p.suffix == ".tgz":
                continue
            abrir = gzip.open if p.suffix == ".gz" else open
            try:
                with abrir(p, "rt", encoding="utf-8", errors="replace") as fluxo:
                    for linha in fluxo:
                        linha = linha.strip()
                        if not linha:
                            continue
                        try:
                            evento = json.loads(linha)
                        except ValueError:
                            continue
                        marca = evento.get("timestamp")
                        if marca:
                            atual = indice[honeypot]
                            atual["min"] = marca if atual["min"] is None or marca < atual["min"] else atual["min"]
                            atual["max"] = marca if atual["max"] is None or marca > atual["max"] else atual["max"]
                        if honeypot == "cowrie":
                            if evento.get("session"):
                                indice["cowrie"]["sessoes"].add(evento["session"])
                        elif evento.get("src_ip"):
                            indice["dionaea"]["ips"].add(evento["src_ip"])
            except OSError:
                continue
    return indice


def _normaliza(marca: str | None) -> str:
    return (marca or "").replace("Z", "")


def correlaciona(caminho_db: Path, dir_dados: Path, n: int, semente: int) -> dict:
    uri = "file:" + str(caminho_db) + "?mode=ro"
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        linhas = [dict(r) for r in conn.execute(
            "SELECT session_id, src_ip, honeypot, timestamp, attack_type FROM attacks"
        ).fetchall()]

    if not linhas:
        return {"erro": "banco sem sessoes"}

    indice = carrega_eventos(dir_dados)
    rng = random.Random(semente)
    amostra = rng.sample(linhas, min(n, len(linhas)))

    confirmadas, sem_lastro, fora_da_janela = [], [], []
    for linha in amostra:
        honeypot = linha["honeypot"] or "cowrie"
        dados = indice.get(honeypot)
        marca = _normaliza(linha["timestamp"])
        if not dados or dados["min"] is None:
            fora_da_janela.append(linha)
            continue
        dentro = _normaliza(dados["min"]) <= marca <= _normaliza(dados["max"])
        achou = (linha["session_id"] in dados["sessoes"]) if honeypot == "cowrie" \
            else (linha["src_ip"] in dados["ips"])
        if achou:
            confirmadas.append(linha)
        elif not dentro:
            fora_da_janela.append(linha)
        else:
            sem_lastro.append(linha)

    verificaveis = len(confirmadas) + len(sem_lastro)
    return {
        "amostra": len(amostra),
        "semente": semente,
        "confirmadas": len(confirmadas),
        "sem_lastro": len(sem_lastro),
        "fora_da_janela_dos_logs": len(fora_da_janela),
        "taxa_de_confirmacao": round(len(confirmadas) / verificaveis, 4) if verificaveis else None,
        "janela_dos_logs": {h: {"de": d["min"], "ate": d["max"]} for h, d in indice.items()},
        "exemplos_sem_lastro": sem_lastro[:10],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", type=Path, default=Path("data/beeia.db"))
    ap.add_argument("--dados", type=Path, default=Path("data"))
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--semente", type=int, default=42)
    args = ap.parse_args()

    if not args.db.is_file():
        print(f"Banco nao encontrado: {args.db}", file=sys.stderr)
        return 2

    r = correlaciona(args.db, args.dados, args.n, args.semente)
    if "erro" in r:
        print(r["erro"], file=sys.stderr)
        return 2

    print("=" * 66)
    print("  CORRELACAO BANCO <-> LOG BRUTO")
    print("=" * 66)
    print(f"  amostra              : {r['amostra']} sessoes (semente {r['semente']})")
    print(f"  confirmadas no log   : {r['confirmadas']}")
    print(f"  sem lastro           : {r['sem_lastro']}")
    print(f"  fora da janela       : {r['fora_da_janela_dos_logs']}  (log rotacionado/apagado)")
    if r["taxa_de_confirmacao"] is not None:
        print(f"  taxa de confirmacao  : {r['taxa_de_confirmacao']:.2%} das verificaveis")
    print("\n  Janela coberta pelos logs em disco")
    for honeypot, janela in r["janela_dos_logs"].items():
        print(f"    {honeypot:<9} {janela['de']}  ->  {janela['ate']}")
    if r["exemplos_sem_lastro"]:
        print("\n  ATENCAO: sessoes dentro da janela e sem evento correspondente")
        for x in r["exemplos_sem_lastro"]:
            print(f"    {x['timestamp']}  {x['honeypot']:<9} {x['session_id']}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
