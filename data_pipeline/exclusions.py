#!/usr/bin/env python3
"""Sessoes que sao trafego nosso, nao de atacante, e precisam sair da avaliacao.

O banco operacional nao e alterado: as sessoes continuam la, com o log original.
Quem monta amostra de avaliacao aplica este filtro; quem estuda a coleta bruta
nao aplica. As duas leituras precisam ser distinguiveis, e a diferenca entre elas
precisa ser reproduzivel por outra pessoa.

Uso:
    python data_pipeline/exclusions.py --db data/beeia.db
"""
from __future__ import annotations

import argparse
import contextlib
import json
from pathlib import Path
import sqlite3
import sys

# Conexoes TCP feitas por nos para verificar alcance de entrada dos honeypots.
# Nao houve tentativa de login; as quatro foram classificadas como brute_force,
# o que e um erro de classificacao observavel e util na discussao de limitacoes.
EXCLUDED_SESSION_IDS: dict[str, str] = {
    "eb997411a1e3": "2026-09-10T15:58:13Z teste de alcance apos implantacao do dashboard",
    "a4ec7910d346": "2026-09-10T16:49:03Z teste de alcance apos aplicar a contencao",
    "ee407fc4aab6": "2026-09-10T17:16:19Z teste de alcance apos o reboot",
    "435e8004bb3a": "2026-09-10T17:16:42Z teste de alcance apos o reboot",
}

# O IP administrativo nao entra no repositorio, que e publico. Coloque um IP por
# linha neste arquivo, fora do Git, para excluir tambem testes futuros.
LOCAL_IP_FILE = Path(__file__).parent / "excluded_ips.local.txt"


def load_excluded_ips(path: Path = LOCAL_IP_FILE) -> list[str]:
    """Le IPs a excluir. Ausencia do arquivo nao e erro: filtra so por session_id."""
    if not path.is_file():
        return []
    ips = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            ips.append(line)
    return sorted(set(ips))


def where_clause(ips: list[str] | None = None) -> tuple[str, list[str]]:
    """Devolve (SQL, parametros) que mantem apenas trafego externo genuino."""
    ips = load_excluded_ips() if ips is None else ips
    parts, params = [], []
    if EXCLUDED_SESSION_IDS:
        marks = ",".join("?" * len(EXCLUDED_SESSION_IDS))
        parts.append(f"session_id NOT IN ({marks})")
        params.extend(sorted(EXCLUDED_SESSION_IDS))
    if ips:
        marks = ",".join("?" * len(ips))
        parts.append(f"src_ip NOT IN ({marks})")
        params.extend(ips)
    return (" AND ".join(parts) if parts else "1=1"), params


def report(db_path: Path) -> dict:
    """Conta o que sai e o que fica, sem escrever no banco."""
    uri = "file:" + str(db_path) + "?mode=ro"
    # closing() e necessario: `with sqlite3.connect(...)` so encerra a transacao,
    # nao a conexao, e o arquivo fica preso ate o garbage collector passar.
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as db:
        total = db.execute("SELECT count(*) FROM attacks").fetchone()[0]
        clause, params = where_clause()
        kept = db.execute(f"SELECT count(*) FROM attacks WHERE {clause}", params).fetchone()[0]
        known = {
            sid: db.execute(
                "SELECT count(*) FROM attacks WHERE session_id = ?", (sid,)
            ).fetchone()[0]
            for sid in sorted(EXCLUDED_SESSION_IDS)
        }
    return {
        "total_no_banco": total,
        "excluidas": total - kept,
        "para_avaliacao": kept,
        "ips_locais_carregados": len(load_excluded_ips()),
        "session_ids_encontrados": known,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("data/beeia.db"))
    args = parser.parse_args()
    if not args.db.is_file():
        print(f"Banco nao encontrado: {args.db}", file=sys.stderr)
        return 2
    result = report(args.db)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    faltando = [s for s, n in result["session_ids_encontrados"].items() if n == 0]
    if faltando:
        # Nao e erro: o banco pode ser outro snapshot, anterior a esses testes.
        print(f"aviso: session_id sem correspondencia neste banco: {faltando}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
