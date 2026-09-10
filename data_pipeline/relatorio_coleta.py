#!/usr/bin/env python3
"""Fecha um periodo de coleta com numeros verificaveis.

O que este relatorio existe para evitar
---------------------------------------
Afirmar "coletamos N ataques em X dias" a partir do que aparece na tela. O
dashboard lista no maximo 100 registros por requisicao; esse numero nao e o
total do experimento. E o total do banco tambem nao e "ataques": e o numero de
sessoes que o classificador registrou, o que e outra coisa.

Tres contagens diferentes, que este relatorio mantem separadas:

  eventos   linhas nos logs brutos dos honeypots (uma conexao, um login, um
            comando). Rotacionam e sao comprimidos, entao os logs em disco
            cobrem menos tempo do que o banco.
  sessoes   registros classificados no banco. Uma sessao agrega varios eventos.
  proprias  sessoes geradas pelos nossos testes de alcance, que nao sao
            trafego de atacante e saem da avaliacao (ver exclusions.py).

Uso:
    python data_pipeline/relatorio_coleta.py --db data/beeia.db
    python data_pipeline/relatorio_coleta.py --db data/beeia.db --json relatorio.json
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import glob
import gzip
import json
import os
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exclusions import where_clause  # noqa: E402

# Uma lacuna so vira "interrupcao" acima disto. Abaixo, e so o intervalo normal
# entre ataques — a internet nao bate na porta em cadencia fixa.
LACUNA_MINIMA_H = 3.0


def _iso(valor: str | None) -> str | None:
    return valor


def _para_datetime(valor: str | None) -> dt.datetime | None:
    if not valor:
        return None
    texto = valor.strip().replace("Z", "+00:00")
    try:
        marca = dt.datetime.fromisoformat(texto)
    except ValueError:
        return None
    return marca if marca.tzinfo else marca.replace(tzinfo=dt.timezone.utc)


def _linhas_do_log(caminho: Path) -> tuple[int, str | None, str | None]:
    """Conta eventos e devolve o primeiro e o ultimo timestamp do arquivo."""
    abrir = gzip.open if caminho.suffix == ".gz" else open
    total, primeiro, ultimo = 0, None, None
    try:
        with abrir(caminho, "rt", encoding="utf-8", errors="replace") as fluxo:
            for linha in fluxo:
                linha = linha.strip()
                if not linha:
                    continue
                total += 1
                try:
                    marca = json.loads(linha).get("timestamp")
                except (ValueError, AttributeError):
                    continue
                if marca:
                    primeiro = marca if primeiro is None or marca < primeiro else primeiro
                    ultimo = marca if ultimo is None or marca > ultimo else ultimo
    except OSError:
        return 0, None, None
    return total, primeiro, ultimo


def eventos_brutos(dir_dados: Path) -> dict:
    """Inventaria os logs em disco. Rotacao faz isto cobrir menos que o banco."""
    resultado = {}
    for honeypot, padrao in (("cowrie", "cowrie/log/cowrie.json*"),
                             ("dionaea", "dionaea/log/dionaea.json*")):
        arquivos, total, primeiro, ultimo = [], 0, None, None
        for caminho in sorted(glob.glob(str(dir_dados / padrao))):
            p = Path(caminho)
            if p.suffix in (".tgz",) or not p.is_file():
                continue
            n, ini, fim = _linhas_do_log(p)
            if not n:
                continue
            arquivos.append({"arquivo": p.name, "eventos": n, "de": ini, "ate": fim})
            total += n
            primeiro = ini if primeiro is None or (ini and ini < primeiro) else primeiro
            ultimo = fim if ultimo is None or (fim and fim > ultimo) else ultimo
        resultado[honeypot] = {
            "eventos": total, "primeiro": primeiro, "ultimo": ultimo, "arquivos": arquivos,
        }
    return resultado


def _consulta(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def relatorio(caminho_db: Path, dir_dados: Path | None) -> dict:
    uri = "file:" + str(caminho_db) + "?mode=ro"
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as conn:
        conn.row_factory = sqlite3.Row

        integridade = conn.execute("PRAGMA quick_check").fetchone()[0]
        clausula, params = where_clause()

        total_bruto = conn.execute("SELECT count(*) FROM attacks").fetchone()[0]
        total_avaliavel = conn.execute(
            f"SELECT count(*) FROM attacks WHERE {clausula}", params).fetchone()[0]

        periodo = conn.execute(
            f"SELECT min(timestamp) ini, max(timestamp) fim, count(DISTINCT src_ip) ips "
            f"FROM attacks WHERE {clausula}", params).fetchone()

        por_honeypot = _consulta(conn, f"""
            SELECT honeypot, count(*) sessoes, count(DISTINCT src_ip) ips
            FROM attacks WHERE {clausula} GROUP BY honeypot ORDER BY sessoes DESC""", params)

        por_classe = _consulta(conn, f"""
            SELECT honeypot, attack_type, count(*) sessoes,
                   round(avg(confidence), 4) conf_media
            FROM attacks WHERE {clausula}
            GROUP BY honeypot, attack_type ORDER BY honeypot, sessoes DESC""", params)

        por_dia = _consulta(conn, f"""
            SELECT substr(timestamp, 1, 10) dia, honeypot, count(*) sessoes
            FROM attacks WHERE {clausula}
            GROUP BY dia, honeypot ORDER BY dia, honeypot""", params)

        top_ips = _consulta(conn, f"""
            SELECT src_ip, count(*) sessoes, max(country) pais
            FROM attacks WHERE {clausula}
            GROUP BY src_ip ORDER BY sessoes DESC LIMIT 10""", params)

        duplicados = _consulta(conn, """
            SELECT session_id, count(*) n FROM attacks
            GROUP BY session_id HAVING n > 1 ORDER BY n DESC LIMIT 10""")

        sem_timestamp = conn.execute(
            "SELECT count(*) FROM attacks WHERE timestamp IS NULL OR timestamp = ''"
        ).fetchone()[0]

        marcas = [_para_datetime(r["timestamp"]) for r in _consulta(
            conn, f"SELECT timestamp FROM attacks WHERE {clausula} ORDER BY timestamp", params)]
        proprias = _consulta(conn, f"""
            SELECT session_id, honeypot, attack_type, timestamp FROM attacks
            WHERE NOT ({clausula}) ORDER BY timestamp""", params)

    marcas = [m for m in marcas if m]
    lacunas = []
    for anterior, seguinte in zip(marcas, marcas[1:]):
        horas = (seguinte - anterior).total_seconds() / 3600
        if horas >= LACUNA_MINIMA_H:
            lacunas.append({"de": anterior.isoformat(), "ate": seguinte.isoformat(),
                            "horas": round(horas, 2)})

    inicio, fim = _para_datetime(periodo["ini"]), _para_datetime(periodo["fim"])
    dias = round((fim - inicio).total_seconds() / 86400, 2) if inicio and fim else None

    return {
        "gerado_em": dt.datetime.now(dt.timezone.utc).isoformat(),
        "banco": str(caminho_db),
        "integridade_sqlite": integridade,
        "periodo": {
            "inicio_utc": _iso(periodo["ini"]), "fim_utc": _iso(periodo["fim"]),
            "duracao_dias": dias,
        },
        "sessoes": {
            "no_banco": total_bruto,
            "proprias_excluidas": total_bruto - total_avaliavel,
            "elegiveis_para_avaliacao": total_avaliavel,
            "ips_distintos": periodo["ips"],
            "sem_timestamp": sem_timestamp,
        },
        "por_honeypot": por_honeypot,
        "por_classe_prevista": por_classe,
        "por_dia": por_dia,
        "top_ips": top_ips,
        "lacunas_acima_de_3h": lacunas,
        "session_ids_duplicados": duplicados,
        "sessoes_proprias": proprias,
        "eventos_brutos": eventos_brutos(dir_dados) if dir_dados else None,
    }


def imprime(r: dict) -> None:
    p, s = r["periodo"], r["sessoes"]
    print("=" * 66)
    print("  PERIODO DE COLETA")
    print("=" * 66)
    print(f"  inicio (UTC)        : {p['inicio_utc']}")
    print(f"  fim    (UTC)        : {p['fim_utc']}")
    print(f"  duracao             : {p['duracao_dias']} dias")
    print(f"  integridade SQLite  : {r['integridade_sqlite']}")
    print()
    print(f"  sessoes no banco    : {s['no_banco']}")
    print(f"  proprias (excluidas): {s['proprias_excluidas']}")
    print(f"  elegiveis           : {s['elegiveis_para_avaliacao']}")
    print(f"  IPs distintos       : {s['ips_distintos']}")

    print("\n  Por honeypot")
    for h in r["por_honeypot"]:
        print(f"    {h['honeypot']:<10} {h['sessoes']:>6} sessoes  {h['ips']:>5} IPs")

    print("\n  Por classe prevista (NAO e acuracia — e o que o modelo disse)")
    for c in r["por_classe_prevista"]:
        print(f"    {c['honeypot']:<9} {c['attack_type']:<24} {c['sessoes']:>6}"
              f"  conf.media {c['conf_media']}")

    print("\n  Por dia")
    dias = {}
    for d in r["por_dia"]:
        dias.setdefault(d["dia"], {})[d["honeypot"]] = d["sessoes"]
    for dia, contagem in sorted(dias.items()):
        detalhe = "  ".join(f"{k}={v}" for k, v in sorted(contagem.items()))
        print(f"    {dia}   total={sum(contagem.values()):>5}   {detalhe}")

    if r["lacunas_acima_de_3h"]:
        print(f"\n  Lacunas acima de {LACUNA_MINIMA_H}h sem nenhuma sessao")
        for l in r["lacunas_acima_de_3h"]:
            print(f"    {l['de']}  ->  {l['ate']}   ({l['horas']}h)")
    else:
        print("\n  Nenhuma lacuna acima de 3h.")

    if r["session_ids_duplicados"]:
        print("\n  ATENCAO: session_id duplicados")
        for d in r["session_ids_duplicados"]:
            print(f"    {d['session_id']}  x{d['n']}")

    if r["sessoes_proprias"]:
        print("\n  Sessoes proprias excluidas da avaliacao")
        for x in r["sessoes_proprias"]:
            print(f"    {x['timestamp']}  {x['honeypot']:<9} {x['attack_type']:<22} {x['session_id']}")

    ev = r.get("eventos_brutos")
    if ev:
        print("\n  Eventos nos logs brutos em disco")
        print("  (rotacionam: cobrem MENOS tempo que o banco — nao sao o periodo)")
        for honeypot, dados in ev.items():
            print(f"    {honeypot:<9} {dados['eventos']:>8} eventos   "
                  f"{dados['primeiro']} -> {dados['ultimo']}")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", type=Path, default=Path("data/beeia.db"))
    ap.add_argument("--dados", type=Path, default=Path("data"),
                    help="diretorio com cowrie/log e dionaea/log")
    ap.add_argument("--json", type=Path, help="grava o relatorio completo em JSON")
    args = ap.parse_args()

    if not args.db.is_file():
        print(f"Banco nao encontrado: {args.db}", file=sys.stderr)
        return 2

    r = relatorio(args.db, args.dados if args.dados.is_dir() else None)
    imprime(r)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  relatorio completo em {args.json}\n")
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    sys.exit(main())
