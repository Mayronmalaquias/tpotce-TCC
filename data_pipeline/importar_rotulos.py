#!/usr/bin/env python3
"""Preenche `revisao_cega.csv` com os rotulos gravados pela pagina de revisao.

A pagina guarda um documento por revisor:
    {"revisor": "1" | "2", "rotulos": {session_id: {"rotulo": ..., "observacao": ...}}}

Este script recebe esses documentos (um JSON com a lista deles) e escreve
`rotulo_revisor1`, `rotulo_revisor2`, `inconclusivo` e `observacao`.

Recusa em vez de adivinhar:
  * dois documentos dizendo ser o mesmo revisor;
  * rotulo que nao pertence a taxonomia do honeypot da sessao;
  * session_id que nao esta na planilha;
  * planilha que ja tem rotulo diferente (use --substituir de proposito).

Uso (na VM, com os rotulos gravados pelo dashboard):
    python3 data_pipeline/importar_rotulos.py --dir-rotulos data/avaliacao/rotulos
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

CLASSES = {
    "cowrie": {"brute_force", "recon", "command_injection", "malware_download"},
    "dionaea": {"service_probe", "credential_bruteforce", "connection_flood",
                "port_scan", "exploit_attempt", "malware_download"},
}
ESPECIAIS = {"inconclusivo", "fora_da_taxonomia"}


class ErroImportacao(ValueError):
    pass


def importa(linhas: list[dict], documentos: list[dict], substituir: bool = False) -> dict:
    por_id = {l["session_id"]: l for l in linhas}
    vistos, resumo = set(), {"1": 0, "2": 0}
    for doc in documentos:
        revisor = str(doc.get("revisor", "")).strip()
        if revisor not in ("1", "2"):
            raise ErroImportacao(f"documento sem revisor 1 ou 2: {revisor!r}")
        if revisor in vistos:
            raise ErroImportacao(f"dois documentos para o revisor {revisor}")
        vistos.add(revisor)
        coluna = "rotulo_revisor" + revisor
        for sid, entrada in (doc.get("rotulos") or {}).items():
            linha = por_id.get(sid)
            if linha is None:
                raise ErroImportacao(f"sessao fora da planilha: {sid}")
            rotulo = str((entrada or {}).get("rotulo", "")).strip()
            if not rotulo:
                continue
            if rotulo not in CLASSES[linha["honeypot"]] | ESPECIAIS:
                raise ErroImportacao(f"{sid}: rotulo {rotulo!r} nao existe para {linha['honeypot']}")
            atual = (linha.get(coluna) or "").strip()
            if atual and atual != rotulo and not substituir:
                raise ErroImportacao(f"{sid}: {coluna} ja tem {atual!r}; use --substituir")
            linha[coluna] = rotulo
            resumo[revisor] += 1
            obs = str((entrada or {}).get("observacao", "")).strip().replace("\n", " ")
            if obs:
                partes = [p for p in (linha.get("observacao") or "").split(" | ")
                          if p and not p.startswith(f"R{revisor}: ")]
                linha["observacao"] = " | ".join(sorted(partes + [f"R{revisor}: {obs}"]))
    for linha in linhas:
        if "inconclusivo" in (linha.get("rotulo_revisor1"), linha.get("rotulo_revisor2")):
            linha["inconclusivo"] = "1"
    return resumo


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    origem = ap.add_mutually_exclusive_group(required=True)
    origem.add_argument("--rotulos", type=Path, help="JSON com a lista de documentos")
    origem.add_argument("--dir-rotulos", type=Path,
                        help="pasta com um JSON por revisor (data/avaliacao/rotulos, gravada pelo dashboard)")
    ap.add_argument("--revisao", type=Path, default=Path("data/avaliacao/revisao_cega.csv"))
    ap.add_argument("--substituir", action="store_true")
    args = ap.parse_args()
    with args.revisao.open(newline="", encoding="utf-8") as fluxo:
        leitor = csv.DictReader(fluxo)
        campos, linhas = leitor.fieldnames, list(leitor)
    if args.dir_rotulos:
        documentos = [json.loads(p.read_text(encoding="utf-8"))
                      for p in sorted(args.dir_rotulos.glob("*.json"))]
    else:
        documentos = json.loads(args.rotulos.read_text(encoding="utf-8"))
    try:
        resumo = importa(linhas, documentos, args.substituir)
    except ErroImportacao as exc:
        print(f"Nada foi gravado: {exc}", file=sys.stderr)
        return 2
    with args.revisao.open("w", newline="", encoding="utf-8") as fluxo:
        escritor = csv.DictWriter(fluxo, fieldnames=campos, lineterminator="\n")
        escritor.writeheader()
        escritor.writerows(linhas)
    print(f"revisor 1: {resumo['1']} rotulos  |  revisor 2: {resumo['2']} rotulos")
    return 0


if __name__ == "__main__":
    sys.exit(main())
