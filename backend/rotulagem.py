"""
Rotulagem cega das sessoes da amostra de avaliacao (data/avaliacao).

O que a tela recebe: as colunas cegas de `revisao_cega.csv` e os eventos
brutos de `evidencias_revisao.json`. O que NUNCA recebe: `previsoes.csv` — este
modulo nao abre esse arquivo. Quem ve o palpite do modelo antes de decidir mede
concordancia com o modelo, nao acerto.

Cada revisor tem um arquivo proprio, `rotulos/<revisor>.json`, no formato que
`data_pipeline/importar_rotulos.py --dir-rotulos` le:
    {"revisor": "1", "nome": "mayron",
     "rotulos": {session_id: {"rotulo", "comportamentos", "observacao", "em"}}}

`rotulo` e a classe PRINCIPAL (uma so, pela precedencia em PRECEDENCIA), que e
o que se compara com a previsao do modelo. `comportamentos` lista TODAS as
classes observadas na sessao: sessoes reais juntam varias (entra, enumera,
baixa e executa), e o modelo so devolve uma.

Os rotulos de um revisor nunca sao devolvidos ao outro; o progresso agregado
so traz contagens.
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import os
import tempfile
import threading
from pathlib import Path

DIR_AVALIACAO = Path(os.getenv(
    "BEEIA_AVALIACAO_DIR", Path(__file__).resolve().parent.parent / "data" / "avaliacao"))

# Nome no login da tela -> coluna da planilha (rotulo_revisor1 / rotulo_revisor2).
REVISORES = {"mayron": "1", "caio": "2"}

# Mesma taxonomia de data_pipeline/importar_rotulos.py.
CLASSES = {
    "cowrie": {"brute_force", "recon", "command_injection", "malware_download"},
    "dionaea": {"service_probe", "credential_bruteforce", "connection_flood",
                "port_scan", "exploit_attempt", "malware_download"},
}
ESPECIAIS = {"inconclusivo", "fora_da_taxonomia"}
# Quando a sessao mostra varios comportamentos, a classe principal e o mais grave.
PRECEDENCIA = {
    "cowrie": ["malware_download", "command_injection", "recon", "brute_force"],
    "dionaea": ["malware_download", "exploit_attempt", "credential_bruteforce",
                "port_scan", "connection_flood", "service_probe"],
}

COLUNAS_CEGAS = ("honeypot", "timestamp", "src_ip", "country", "protocol")
FEATURES = ("login_attempts", "login_success", "command_count", "session_duration_s",
            "connection_count", "unique_ports", "has_wget_curl", "has_reverse_shell",
            "has_recon_commands", "has_file_download", "has_shellcode")
MAX_OBSERVACAO = 2000

_trava = threading.Lock()
_cache: dict = {}


class RotulagemIndisponivel(RuntimeError):
    pass


class RotuloInvalido(ValueError):
    pass


def _amostra() -> tuple[list[dict], dict[str, str]]:
    """Sessoes cegas + mapa session_id -> honeypot. Recarrega se o arquivo mudar."""
    planilha = DIR_AVALIACAO / "revisao_cega.csv"
    evidencias = DIR_AVALIACAO / "evidencias_revisao.json"
    for caminho in (planilha, evidencias):
        if not caminho.is_file():
            raise RotulagemIndisponivel(f"{caminho.name} nao encontrado no servidor.")
    marca = (planilha.stat().st_mtime_ns, evidencias.stat().st_mtime_ns)
    if _cache.get("marca") != marca:
        with planilha.open(newline="", encoding="utf-8") as fluxo:
            linhas = list(csv.DictReader(fluxo))
        eventos = json.loads(evidencias.read_text(encoding="utf-8"))["sessoes"]
        sessoes = []
        for linha in linhas:
            e = eventos.get(linha["session_id"], {"eventos": [], "total": 0, "truncado": False})
            sessoes.append({
                "id": linha["session_id"],
                **{k: linha.get(k, "") for k in COLUNAS_CEGAS},
                "f": {k: linha.get(k, "") for k in FEATURES},
                "eventos": e["eventos"], "total": e["total"], "truncado": e["truncado"],
            })
        _cache.update(marca=marca, sessoes=sessoes,
                      honeypots={s["id"]: s["honeypot"] for s in sessoes})
    return _cache["sessoes"], _cache["honeypots"]


def sessoes() -> list[dict]:
    return _amostra()[0]


def _arquivo(nome: str) -> Path:
    return DIR_AVALIACAO / "rotulos" / f"{nome}.json"


def _le(nome: str) -> dict:
    caminho = _arquivo(nome)
    if not caminho.is_file():
        return {"revisor": REVISORES[nome], "nome": nome, "rotulos": {}}
    return json.loads(caminho.read_text(encoding="utf-8"))


def _grava(nome: str, dados: dict) -> None:
    caminho = _arquivo(nome)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    fd, temporario = tempfile.mkstemp(dir=caminho.parent, prefix=".rotulos-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fluxo:
            json.dump(dados, fluxo, ensure_ascii=False, indent=1, sort_keys=True)
        os.replace(temporario, caminho)
    finally:
        if os.path.exists(temporario):
            os.unlink(temporario)


def revisor_valido(nome: str) -> str:
    nome = (nome or "").strip().lower()
    if nome not in REVISORES:
        raise RotuloInvalido("Revisor desconhecido.")
    return nome


def rotulos_de(nome: str) -> dict:
    nome = revisor_valido(nome)
    with _trava:
        return _le(nome)


def marca(nome: str, session_id: str, rotulo: str | None, observacao: str | None,
          comportamentos: list[str] | None = None) -> dict:
    """Grava rotulo, comportamentos e/ou observacao de uma sessao. `None` mantem
    o valor atual; rotulo vazio ou lista vazia limpa."""
    nome = revisor_valido(nome)
    _, honeypots = _amostra()
    honeypot = honeypots.get(session_id)
    if honeypot is None:
        raise RotuloInvalido("Sessao fora da amostra.")
    if rotulo is not None:
        rotulo = rotulo.strip()
        if rotulo and rotulo not in CLASSES[honeypot] | ESPECIAIS:
            raise RotuloInvalido(f"'{rotulo}' nao e classe do {honeypot}.")
    if comportamentos is not None:
        invalidos = set(comportamentos) - CLASSES[honeypot]
        if invalidos:
            raise RotuloInvalido(f"Comportamento fora da taxonomia do {honeypot}: {sorted(invalidos)}")
        comportamentos = [c for c in PRECEDENCIA[honeypot] if c in set(comportamentos)]
    if observacao is not None and len(observacao) > MAX_OBSERVACAO:
        raise RotuloInvalido("Observacao longa demais.")
    with _trava:
        dados = _le(nome)
        entrada = dict(dados["rotulos"].get(session_id, {}))
        if rotulo is not None:
            entrada["rotulo"] = rotulo
        if comportamentos is not None:
            entrada["comportamentos"] = comportamentos
        if observacao is not None:
            entrada["observacao"] = observacao
        entrada["em"] = dt.datetime.now(dt.timezone.utc).isoformat()
        dados["rotulos"][session_id] = entrada
        _grava(nome, dados)
        return entrada


def progresso() -> dict:
    total = len(sessoes())
    with _trava:
        feitos = {nome: sum(1 for r in _le(nome)["rotulos"].values() if r.get("rotulo"))
                  for nome in REVISORES}
    return {"total": total, "revisores": feitos}
