#!/usr/bin/env python3
"""Sorteia a amostra de avaliacao e gera a planilha de revisao CEGA.

O problema que isto resolve
---------------------------
Nao existe verdade-terreno para o trafego capturado. O que o banco guarda e o
que o MODELO disse, e comparar o modelo com ele mesmo nao mede nada. Para ter
desempenho de verdade alguem precisa olhar as sessoes e rotular a mao.

Tres cuidados que mudam o resultado:

  revisao cega      a planilha NAO traz a previsao do modelo. Ver o palpite
                    antes de decidir contamina o julgamento, e o numero que sai
                    disso mede concordancia com o modelo, nao acerto.
  sem vazamento     sessoes usadas para treinar ficam de fora. O script confere
                    isso pelo session_id e ainda marca, por sessao, se o IP ja
                    aparecia no treino — permite reportar as metricas com e sem
                    esses casos.
  amostragem dita   com `--min-por-classe`, classes raras sao super-amostradas
                    para que precisao/recall delas sejam calculaveis. Isso torna
                    a amostra NAO proporcional a populacao, e o arquivo de
                    metadados registra exatamente o desenho usado, porque a
                    interpretacao das metricas depende disso.

Saidas (em --saida):
    amostra.json      desenho, semente e IDs sorteados — reproduz o sorteio
    revisao_cega.csv  planilha para os revisores, sem a previsao
    previsoes.csv     as previsoes, guardadas em separado para a apuracao

Uso:
    python data_pipeline/amostra_avaliacao.py --db data/beeia.db --n 200
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import datetime as dt
import json
from pathlib import Path
import random
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exclusions import where_clause  # noqa: E402

# Evidencia que o revisor precisa para decidir sem ver a previsao.
COLUNAS_EVIDENCIA = [
    "session_id", "honeypot", "timestamp", "src_ip", "country", "protocol",
    "login_attempts", "login_success", "command_count", "session_duration_s",
    "connection_count", "unique_ports",
    "has_wget_curl", "has_reverse_shell", "has_recon_commands",
    "has_file_download", "has_shellcode",
]

# Preenchidas a mao. Dois revisores independentes; `inconclusivo` existe para
# nao forcar rotulo em sessao ambigua — forcar inventa acerto ou erro.
COLUNAS_REVISAO = ["rotulo_revisor1", "rotulo_revisor2", "inconclusivo", "observacao"]


def ids_de_treino(caminhos: list[Path]) -> tuple[set, set]:
    sessoes, ips = set(), set()
    for caminho in caminhos:
        if not caminho.is_file():
            continue
        with caminho.open(newline="", encoding="utf-8") as fluxo:
            for linha in csv.DictReader(fluxo):
                if linha.get("session_id"):
                    sessoes.add(linha["session_id"])
                if linha.get("src_ip"):
                    ips.add(linha["src_ip"])
    return sessoes, ips


def carrega_elegiveis(caminho_db: Path, sessoes_treino: set) -> list[dict]:
    clausula, params = where_clause()
    uri = "file:" + str(caminho_db) + "?mode=ro"
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        linhas = [dict(r) for r in conn.execute(
            f"SELECT * FROM attacks WHERE {clausula}", params).fetchall()]
    return [l for l in linhas if l["session_id"] not in sessoes_treino]


def sorteia(linhas: list[dict], n: int, min_por_classe: int, semente: int) -> tuple[list, dict]:
    rng = random.Random(semente)
    estratos: dict[tuple, list] = {}
    for linha in linhas:
        chave = (linha["honeypot"] or "cowrie", linha["attack_type"] or "?")
        estratos.setdefault(chave, []).append(linha)
    for grupo in estratos.values():
        grupo.sort(key=lambda l: (l["timestamp"] or "", l["session_id"] or ""))

    escolhidas, desenho = [], {}

    # 1) piso por classe, para que classe rara tenha metrica calculavel
    for chave, grupo in sorted(estratos.items()):
        piso = min(min_por_classe, len(grupo))
        selecionadas = rng.sample(grupo, piso) if piso else []
        escolhidas.extend(selecionadas)
        desenho[f"{chave[0]}/{chave[1]}"] = {
            "na_populacao": len(grupo), "piso_aplicado": piso, "proporcional": 0,
        }

    # 2) o restante proporcional a populacao, sem repetir
    ja = {l["session_id"] for l in escolhidas}
    restantes = [l for l in linhas if l["session_id"] not in ja]
    vagas = max(0, n - len(escolhidas))
    if vagas and restantes:
        peso = {}
        for linha in restantes:
            chave = (linha["honeypot"] or "cowrie", linha["attack_type"] or "?")
            peso.setdefault(chave, []).append(linha)
        total = len(restantes)
        for chave, grupo in sorted(peso.items()):
            cota = min(len(grupo), round(vagas * len(grupo) / total))
            if cota:
                selecionadas = rng.sample(grupo, cota)
                escolhidas.extend(selecionadas)
                desenho[f"{chave[0]}/{chave[1]}"]["proporcional"] = cota

    escolhidas.sort(key=lambda l: (l["honeypot"] or "", l["timestamp"] or ""))
    return escolhidas, desenho


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", type=Path, default=Path("data/beeia.db"))
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--min-por-classe", type=int, default=10)
    ap.add_argument("--semente", type=int, default=42)
    ap.add_argument("--treino", type=Path, nargs="*",
                    default=[Path("data/captura_real/dionaea_real_labeled.csv")])
    ap.add_argument("--saida", type=Path, default=Path("data/avaliacao"))
    args = ap.parse_args()

    if not args.db.is_file():
        print(f"Banco nao encontrado: {args.db}", file=sys.stderr)
        return 2

    sessoes_treino, ips_treino = ids_de_treino(args.treino)
    elegiveis = carrega_elegiveis(args.db, sessoes_treino)
    if not elegiveis:
        print("Nenhuma sessao elegivel.", file=sys.stderr)
        return 2

    escolhidas, desenho = sorteia(elegiveis, args.n, args.min_por_classe, args.semente)
    args.saida.mkdir(parents=True, exist_ok=True)

    with (args.saida / "revisao_cega.csv").open("w", newline="", encoding="utf-8") as fluxo:
        escritor = csv.DictWriter(fluxo, fieldnames=COLUNAS_EVIDENCIA + COLUNAS_REVISAO)
        escritor.writeheader()
        for linha in escolhidas:
            escritor.writerow({**{c: linha.get(c) for c in COLUNAS_EVIDENCIA},
                               **{c: "" for c in COLUNAS_REVISAO}})

    with (args.saida / "previsoes.csv").open("w", newline="", encoding="utf-8") as fluxo:
        escritor = csv.DictWriter(
            fluxo, fieldnames=["session_id", "honeypot", "previsto", "confianca",
                               "ip_visto_no_treino"])
        escritor.writeheader()
        for linha in escolhidas:
            escritor.writerow({
                "session_id": linha["session_id"], "honeypot": linha["honeypot"],
                "previsto": linha["attack_type"], "confianca": linha["confidence"],
                "ip_visto_no_treino": int(linha["src_ip"] in ips_treino),
            })

    contaminados = sum(1 for l in escolhidas if l["src_ip"] in ips_treino)
    meta = {
        "gerado_em": dt.datetime.now(dt.timezone.utc).isoformat(),
        "banco": str(args.db),
        "semente": args.semente,
        "alvo_n": args.n,
        "min_por_classe": args.min_por_classe,
        "amostrada": len(escolhidas),
        "populacao_elegivel": len(elegiveis),
        "sessoes_de_treino_excluidas": len(sessoes_treino),
        "sessoes_com_ip_visto_no_treino": contaminados,
        "amostra_e_proporcional": args.min_por_classe == 0,
        "desenho_por_estrato": desenho,
        "session_ids": [l["session_id"] for l in escolhidas],
    }
    (args.saida / "amostra.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=" * 66)
    print("  AMOSTRA DE AVALIACAO")
    print("=" * 66)
    print(f"  populacao elegivel        : {len(elegiveis)}")
    print(f"  sorteadas                 : {len(escolhidas)}  (semente {args.semente})")
    print(f"  IDs de treino excluidos   : {len(sessoes_treino)}")
    print(f"  com IP visto no treino    : {contaminados}  (marcado em previsoes.csv)")
    print(f"  proporcional a populacao  : {'sim' if meta['amostra_e_proporcional'] else 'NAO — piso por classe aplicado'}")
    print("\n  Por estrato (honeypot/classe prevista)")
    for chave, d in sorted(desenho.items()):
        total = d["piso_aplicado"] + d["proporcional"]
        if total:
            print(f"    {chave:<34} {total:>4}  de {d['na_populacao']:>5} na populacao")
    print(f"\n  planilha de revisao : {args.saida / 'revisao_cega.csv'}")
    print(f"  previsoes separadas : {args.saida / 'previsoes.csv'}")
    print(f"  desenho e IDs       : {args.saida / 'amostra.json'}")
    print("\n  Proximo passo: dois revisores preenchem rotulo_revisor1 e")
    print("  rotulo_revisor2 SEM abrir previsoes.csv. Depois:")
    print("    python data_pipeline/avaliar_amostra.py --amostra", args.saida)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
