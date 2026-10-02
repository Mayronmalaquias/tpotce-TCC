#!/usr/bin/env python3
"""Apura o desempenho do classificador contra a rotulagem manual.

So roda depois que a planilha `revisao_cega.csv` estiver preenchida. Sem
rotulo humano nao existe metrica: comparar a previsao com ela mesma nao mede
acerto nenhum, e este script recusa produzir numero nessa situacao em vez de
devolver algo que parece resultado.

O que reporta, e por que
------------------------
  matriz de confusao   mostra ONDE erra, nao so quanto. Num conjunto muito
                       desbalanceado a acuracia global engana: prever sempre a
                       classe majoritaria ja da acuracia alta.
  precisao/recall/F1   por classe, com o suporte ao lado. Classe com poucos
                       exemplos tem metrica instavel, e isso fica marcado.
  macro-F1             media sem peso entre classes — nao deixa a classe
                       majoritaria esconder o desempenho nas raras.
  concordancia         entre os dois revisores. F1 alto sobre rotulagem em que
                       os proprios humanos discordam nao significa muito.

Cowrie e Dionaea sao DOIS modelos com taxonomias diferentes: apure cada um
com --honeypot. Uma matriz unica mistura os dois e o macro-F1 resultante nao
descreve nenhum deles.

Rotulos especiais da revisao:
  inconclusivo        de qualquer revisor tira a sessao do calculo.
  fora_da_taxonomia   o revisor viu que nenhuma classe do modelo descreve a
                      sessao (ex.: conexao aberta e fechada, sem login). Com
                      --fora-da-taxonomia excluir (padrao) ela sai do calculo
                      e e contada; com `classe` vira classe real que o modelo
                      nunca preve, e conta como erro. Reporte os dois.

Uso:
    python data_pipeline/avaliar_amostra.py --amostra data/avaliacao --honeypot cowrie
    python data_pipeline/avaliar_amostra.py --amostra data/avaliacao --honeypot cowrie \\
        --fora-da-taxonomia classe
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
from pathlib import Path
import sys

# Abaixo disto a metrica por classe e ruido; o relatorio marca a classe.
SUPORTE_MINIMO = 10
INCONCLUSIVO = "inconclusivo"
FORA_DA_TAXONOMIA = "fora_da_taxonomia"


def carrega(caminho: Path) -> list[dict]:
    with caminho.open(newline="", encoding="utf-8") as fluxo:
        return list(csv.DictReader(fluxo))


def _limpo(valor) -> str:
    return (valor or "").strip()


def consolida_rotulos(revisao: list[dict]) -> dict:
    """Une os dois revisores. Discordancia e inconclusivo NAO viram rotulo."""
    verdade, discordancias, inconclusivas, sem_rotulo = {}, [], [], []
    concordaram = 0
    for linha in revisao:
        sid = _limpo(linha.get("session_id"))
        r1, r2 = _limpo(linha.get("rotulo_revisor1")), _limpo(linha.get("rotulo_revisor2"))
        if (_limpo(linha.get("inconclusivo")).lower() in ("1", "sim", "true", "x")
                or INCONCLUSIVO in (r1, r2)):
            inconclusivas.append(sid)
            continue
        if not r1 and not r2:
            sem_rotulo.append(sid)
            continue
        if r1 and r2:
            if r1 == r2:
                verdade[sid] = r1
                concordaram += 1
            else:
                discordancias.append({"session_id": sid, "revisor1": r1, "revisor2": r2})
            continue
        # Um revisor so: aproveita, mas o relatorio conta separado.
        verdade[sid] = r1 or r2
    return {
        "verdade": verdade, "discordancias": discordancias,
        "inconclusivas": inconclusivas, "sem_rotulo": sem_rotulo,
        "duplamente_revisadas": concordaram + len(discordancias),
        "concordaram": concordaram,
    }


def _conjunto(valor) -> set:
    return {c for c in _limpo(valor).split(";") if c}


def multicomportamento(revisao: list[dict], previsoes: dict) -> dict | None:
    """Sessoes reais juntam varios comportamentos; o modelo devolve um so.

    Por sessao, os comportamentos considerados sao os que os DOIS revisores
    marcaram (ou os de quem marcou, se so um marcou). Mede quantas sessoes tem
    mais de um, e se a previsao do modelo esta entre eles.
    """
    if not revisao or "comportamentos_revisor1" not in revisao[0]:
        return None
    n = multiplos = acertos = 0
    for linha in revisao:
        c1 = _conjunto(linha.get("comportamentos_revisor1"))
        c2 = _conjunto(linha.get("comportamentos_revisor2"))
        observados = (c1 & c2) if (c1 and c2) else (c1 or c2)
        previsao = previsoes.get(_limpo(linha.get("session_id")))
        if not observados or not previsao:
            continue
        n += 1
        multiplos += len(observados) > 1
        acertos += _limpo(previsao.get("previsto")) in observados
    if not n:
        return None
    return {"sessoes": n, "com_mais_de_um": multiplos,
            "previsao_entre_os_observados": acertos,
            "taxa_previsao_entre_os_observados": round(acertos / n, 4)}


def metricas(pares: list[tuple[str, str]]) -> dict:
    classes = sorted({c for par in pares for c in par})
    matriz = {real: {previsto: 0 for previsto in classes} for real in classes}
    for real, previsto in pares:
        matriz[real][previsto] += 1

    por_classe, soma_f1 = {}, 0.0
    for classe in classes:
        vp = matriz[classe][classe]
        fp = sum(matriz[outra][classe] for outra in classes if outra != classe)
        fn = sum(matriz[classe][outra] for outra in classes if outra != classe)
        precisao = vp / (vp + fp) if (vp + fp) else 0.0
        recall = vp / (vp + fn) if (vp + fn) else 0.0
        f1 = 2 * precisao * recall / (precisao + recall) if (precisao + recall) else 0.0
        suporte = vp + fn
        por_classe[classe] = {
            "precisao": round(precisao, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "suporte": suporte,
            "suporte_insuficiente": suporte < SUPORTE_MINIMO,
        }
        soma_f1 += f1

    acertos = sum(matriz[c][c] for c in classes)
    return {
        "n": len(pares),
        "acuracia": round(acertos / len(pares), 4) if pares else None,
        "macro_f1": round(soma_f1 / len(classes), 4) if classes else None,
        "classes": classes,
        "matriz_confusao": matriz,
        "por_classe": por_classe,
    }


def imprime_matriz(m: dict) -> None:
    classes = m["classes"]
    largura = max([len(c) for c in classes] + [12]) + 2
    print(" " * largura + "".join(f"{c[:largura-1]:>{largura}}" for c in classes))
    for real in classes:
        linha = f"{real:<{largura}}"
        for previsto in classes:
            linha += f"{m['matriz_confusao'][real][previsto]:>{largura}}"
        print("  " + linha)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--amostra", type=Path, default=Path("data/avaliacao"))
    ap.add_argument("--json", type=Path)
    ap.add_argument("--somente-ip-novo", action="store_true",
                    help="ignora sessoes cujo IP ja aparecia no treino")
    ap.add_argument("--honeypot", choices=["cowrie", "dionaea"],
                    help="apura so um modelo (recomendado: rode uma vez para cada)")
    ap.add_argument("--fora-da-taxonomia", choices=["excluir", "classe"], default="excluir",
                    help="excluir: tira do calculo; classe: conta como classe que o modelo erra")
    args = ap.parse_args()

    revisao_csv = args.amostra / "revisao_cega.csv"
    previsoes_csv = args.amostra / "previsoes.csv"
    for caminho in (revisao_csv, previsoes_csv):
        if not caminho.is_file():
            print(f"Arquivo nao encontrado: {caminho}", file=sys.stderr)
            return 2

    revisao = carrega(revisao_csv)
    if args.honeypot:
        revisao = [l for l in revisao if _limpo(l.get("honeypot")) == args.honeypot]
    previsoes = {l["session_id"]: l for l in carrega(previsoes_csv)}
    consolidado = consolida_rotulos(revisao)
    verdade = consolidado["verdade"]

    if not verdade:
        print("=" * 66)
        print("  SEM METRICA: a planilha ainda nao foi rotulada")
        print("=" * 66)
        print(f"  sessoes na amostra    : {len(revisao)}")
        print(f"  sem rotulo            : {len(consolidado['sem_rotulo'])}")
        print("\n  Preencha rotulo_revisor1 e rotulo_revisor2 em")
        print(f"  {revisao_csv}")
        print("  SEM consultar previsoes.csv, e rode este script de novo.")
        print("\n  Nenhum numero de desempenho pode ser reportado ate la.\n")
        return 1

    pares, ignoradas_ip, fora = [], 0, 0
    for sid, real in verdade.items():
        previsao = previsoes.get(sid)
        if not previsao:
            continue
        if real == FORA_DA_TAXONOMIA:
            fora += 1
            if args.fora_da_taxonomia == "excluir":
                continue
        if args.somente_ip_novo and previsao.get("ip_visto_no_treino") == "1":
            ignoradas_ip += 1
            continue
        pares.append((real, _limpo(previsao["previsto"])))

    if not pares:
        print("Nenhuma sessao rotulada casou com as previsoes.", file=sys.stderr)
        return 2

    m = metricas(pares)
    dupla = consolidado["duplamente_revisadas"]
    concordancia = round(consolidado["concordaram"] / dupla, 4) if dupla else None

    print("=" * 66)
    print("  DESEMPENHO EM SESSOES REAIS" + (f" — {args.honeypot}" if args.honeypot else ""))
    print("=" * 66)
    if not args.honeypot:
        print("  ATENCAO: Cowrie e Dionaea misturados; use --honeypot para cada modelo")
    print(f"  sessoes avaliadas       : {m['n']}")
    print(f"  inconclusivas (fora)    : {len(consolidado['inconclusivas'])}")
    print(f"  discordancias (fora)    : {len(consolidado['discordancias'])}")
    trata = "excluidas" if args.fora_da_taxonomia == "excluir" else "contadas como classe"
    print(f"  fora da taxonomia       : {fora} ({trata})")
    if concordancia is not None:
        print(f"  concordancia entre revisores: {concordancia:.2%} de {dupla} sessoes")
    if args.somente_ip_novo:
        print(f"  ignoradas por IP de treino : {ignoradas_ip}")
    print(f"\n  acuracia  : {m['acuracia']:.2%}")
    print(f"  macro-F1  : {m['macro_f1']:.4f}")

    print("\n  Matriz de confusao  (linha = rotulo humano | coluna = previsto)")
    imprime_matriz(m)

    print("\n  Por classe")
    for classe, v in sorted(m["por_classe"].items()):
        aviso = "  <- suporte baixo, metrica instavel" if v["suporte_insuficiente"] else ""
        print(f"    {classe:<24} P={v['precisao']:.3f}  R={v['recall']:.3f}  "
              f"F1={v['f1']:.3f}  n={v['suporte']}{aviso}")

    multi = multicomportamento(revisao, previsoes)
    if multi:
        print("\n  Multicomportamento (todas as classes observadas, nao so a principal)")
        print(f"    sessoes com comportamentos marcados : {multi['sessoes']}")
        print(f"    com mais de um comportamento        : {multi['com_mais_de_um']}")
        print(f"    previsao entre os observados        : {multi['previsao_entre_os_observados']}"
              f" ({multi['taxa_previsao_entre_os_observados']:.2%})")

    if consolidado["discordancias"]:
        print("\n  Sessoes em que os revisores discordaram (revisar juntos)")
        for d in consolidado["discordancias"][:10]:
            print(f"    {d['session_id']}  r1={d['revisor1']}  r2={d['revisor2']}")

    print("\n  Leia junto com o desenho da amostra em amostra.json: se um piso")
    print("  por classe foi aplicado, a amostra NAO e proporcional a populacao")
    print("  e estas metricas nao se transferem direto para o total coletado.\n")

    if args.json:
        saida = {"gerado_em": dt.datetime.now(dt.timezone.utc).isoformat(),
                 "honeypot": args.honeypot, "multicomportamento": multi, "fora_da_taxonomia": {
                     "tratamento": args.fora_da_taxonomia, "sessoes": fora},
                 "concordancia_entre_revisores": concordancia,
                 "inconclusivas": consolidado["inconclusivas"],
                 "discordancias": consolidado["discordancias"], **m}
        args.json.write_text(json.dumps(saida, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  resultado em {args.json}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
