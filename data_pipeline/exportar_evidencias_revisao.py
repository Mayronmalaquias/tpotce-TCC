#!/usr/bin/env python3
"""Extrai do log bruto os eventos de cada sessao da revisao cega.

Por que isto existe
-------------------
`revisao_cega.csv` traz so contagens (tentativas de login, comandos, portas).
Para rotular com seguranca o revisor precisa ver o que aconteceu: quais
usuarios e senhas, quais comandos, quais servicos. Os logs rotacionam e somem,
entao este export tambem preserva a evidencia que sustentou cada rotulo.

O arquivo gerado NAO contem a previsao do modelo nem a confianca. Ele le apenas
`revisao_cega.csv` e os logs; `previsoes.csv` nao e aberto.

Como cada sessao e reencontrada no log:

  cowrie    pelo campo `session`, identico ao `session_id` do banco.
  dionaea   o log real nao tem sessao. O backend agrupa por IP e fecha por
            inatividade; aqui se usa o mesmo IP na janela
            [inicio, inicio + duracao] gravada na sessao, com folga de 1 s.

Uso (na VM, onde estao os logs):
    python3 data_pipeline/exportar_evidencias_revisao.py \\
        --revisao data/avaliacao/revisao_cega.csv --dados data \\
        --saida data/avaliacao/evidencias_revisao.json
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import glob
import gzip
import hashlib
import json
from pathlib import Path
import sys

MAX_EVENTOS = 400
FOLGA_S = 1.0

# Campos do Cowrie que ajudam a decidir a classe. O resto (kex, uuid, sensor)
# e ruido para o revisor e so incha o arquivo.
CAMPOS_COWRIE = ("username", "password", "input", "url", "outfile", "shasum",
                 "version", "dst_port", "duration", "arch", "size", "destfile")


def instante(marca: str) -> float:
    """ISO com ou sem Z/offset -> epoch UTC. O Dionaea grava sem fuso, em UTC."""
    marca = marca.strip().replace("Z", "+00:00")
    valor = dt.datetime.fromisoformat(marca)
    if valor.tzinfo is None:
        valor = valor.replace(tzinfo=dt.timezone.utc)
    return valor.timestamp()


def arquivos(dir_dados: Path, padrao: str) -> list[Path]:
    return [Path(p) for p in sorted(glob.glob(str(dir_dados / padrao)))
            if Path(p).is_file() and not p.endswith((".tgz", ".sqlite"))
            and ".sqlite" not in Path(p).name]


def le_eventos(caminho: Path):
    abrir = gzip.open if caminho.suffix == ".gz" else open
    with abrir(caminho, "rt", encoding="utf-8", errors="replace") as fluxo:
        for linha in fluxo:
            linha = linha.strip()
            if not linha:
                continue
            try:
                evento = json.loads(linha)
            except ValueError:
                continue
            if isinstance(evento, dict):
                yield evento


def resume_cowrie(evento: dict) -> dict:
    item = {"t": evento.get("timestamp"),
            "ev": str(evento.get("eventid", "")).removeprefix("cowrie.")}
    for campo in CAMPOS_COWRIE:
        if evento.get(campo) not in (None, ""):
            item[campo] = evento[campo]
    return item


def resume_dionaea(evento: dict) -> dict:
    conexao = evento.get("connection") or {}
    item = {"t": evento.get("timestamp"), "protocolo": conexao.get("protocol"),
            "transporte": conexao.get("transport"), "porta": evento.get("dst_port")}
    for chave, valor in evento.items():
        if chave not in ("connection", "timestamp", "dst_ip", "dst_port", "src_ip",
                         "src_port", "src_hostname"):
            item[chave] = valor
    return item


def anexa(destino: dict, item: dict) -> None:
    destino["total"] += 1
    if len(destino["eventos"]) < MAX_EVENTOS:
        destino["eventos"].append(item)


def exporta(revisao: list[dict], dir_dados: Path) -> dict:
    vazio = lambda: {"eventos": [], "total": 0}
    cowrie = {l["session_id"]: vazio() for l in revisao if l["honeypot"] == "cowrie"}
    janelas: dict[str, list[tuple[float, float, str]]] = {}
    dionaea = {}
    for linha in revisao:
        if linha["honeypot"] != "dionaea":
            continue
        inicio = instante(linha["timestamp"])
        fim = inicio + float(linha.get("session_duration_s") or 0)
        janelas.setdefault(linha["src_ip"], []).append(
            (inicio - FOLGA_S, fim + FOLGA_S, linha["session_id"]))
        dionaea[linha["session_id"]] = vazio()

    fontes = []
    for caminho in arquivos(dir_dados, "cowrie/log/cowrie.json*"):
        fontes.append(caminho)
        for evento in le_eventos(caminho):
            alvo = cowrie.get(evento.get("session"))
            if alvo is not None:
                anexa(alvo, resume_cowrie(evento))
    for caminho in arquivos(dir_dados, "dionaea/log/dionaea.json*"):
        fontes.append(caminho)
        for evento in le_eventos(caminho):
            candidatas = janelas.get(evento.get("src_ip"))
            if not candidatas or not evento.get("timestamp"):
                continue
            try:
                momento = instante(evento["timestamp"])
            except ValueError:
                continue
            for inicio, fim, sid in candidatas:
                if inicio <= momento <= fim:
                    anexa(dionaea[sid], resume_dionaea(evento))

    sessoes = {}
    for sid, dados in {**cowrie, **dionaea}.items():
        dados["eventos"].sort(key=lambda e: e.get("t") or "")
        dados["truncado"] = dados["total"] > len(dados["eventos"])
        sessoes[sid] = dados
    return {
        "gerado_em": dt.datetime.now(dt.timezone.utc).isoformat(),
        "max_eventos_por_sessao": MAX_EVENTOS,
        "criterio_dionaea": f"mesmo src_ip em [inicio, inicio + duracao] +/- {FOLGA_S} s",
        "fontes": [{"arquivo": p.relative_to(dir_dados).as_posix(),
                    "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in fontes],
        "sem_evento": sorted(sid for sid, d in sessoes.items() if d["total"] == 0),
        "sessoes": sessoes,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--revisao", type=Path, default=Path("data/avaliacao/revisao_cega.csv"))
    ap.add_argument("--dados", type=Path, default=Path("data"))
    ap.add_argument("--saida", type=Path, default=Path("data/avaliacao/evidencias_revisao.json"))
    args = ap.parse_args()
    if not args.revisao.is_file():
        print(f"Arquivo nao encontrado: {args.revisao}", file=sys.stderr)
        return 2
    with args.revisao.open(newline="", encoding="utf-8") as fluxo:
        revisao = list(csv.DictReader(fluxo))
    resultado = exporta(revisao, args.dados)
    args.saida.write_text(json.dumps(resultado, ensure_ascii=False, separators=(",", ":")),
                          encoding="utf-8")
    com = len(resultado["sessoes"]) - len(resultado["sem_evento"])
    print(f"sessoes: {len(resultado['sessoes'])}  com evento: {com}  "
          f"sem evento: {len(resultado['sem_evento'])}")
    print(f"truncadas em {MAX_EVENTOS}: "
          f"{sum(1 for d in resultado['sessoes'].values() if d['truncado'])}")
    print(f"saida: {args.saida}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
