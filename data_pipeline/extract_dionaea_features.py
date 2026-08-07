"""
Extrator de features por sessão a partir de logs Dionaea (JSONL, formato normalizado).

Lê os eventos brutos, agrupa por session_id e calcula 10 features numéricas
que capturam o comportamento de cada sessão. Se um arquivo de labels for
fornecido, adiciona a coluna 'label' ao CSV de saída.

Funciona com os logs sintéticos gerados por generate_dionaea_logs.py. Ao
integrar o Dionaea real, ajustar o agrupamento por sessão e os nomes dos
campos conforme o dionaea.json real (ver nota em generate_dionaea_logs.py).

Features extraídas:
  connection_count            — total de conexões na sessão (varredura de portas)
  unique_ports                — quantidade de portas de destino distintas
  unique_protocols            — quantidade de protocolos/serviços distintos
  session_duration_s          — duração total da sessão em segundos
  avg_connection_interval_ms  — intervalo médio entre conexões (ms)
  min_connection_interval_ms  — intervalo mínimo entre conexões (detecta scan automatizado)
  has_shellcode               — 1 se algum payload com assinatura de shellcode/exploit
  has_download                — 1 se evento dionaea.download.complete presente
  payload_size_avg            — tamanho médio dos payloads recebidos (bytes)
  login_attempt_count         — tentativas de login em serviços com autenticação
"""

import csv
import json
import statistics
from datetime import datetime
from pathlib import Path

_CONNECT_EVENTS = {"dionaea.connection.tcp.accept", "dionaea.connection.udp.accept"}

# ── parser de timestamp ISO ──────────────────────────────────────────────────

def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")

# ── extração por sessão ───────────────────────────────────────────────────────

def _extract(events: list) -> dict:
    connects  = [e for e in events if e["eventid"] in _CONNECT_EVENTS]
    data_evs  = [e for e in events if e["eventid"] == "dionaea.data.in"]
    logins    = [e for e in events if e["eventid"] == "dionaea.login.attempt"]
    downloads = [e for e in events if e["eventid"] == "dionaea.download.complete"]
    free_ev   = next((e for e in events if e["eventid"] == "dionaea.connection.free"), None)

    # duração da sessão
    if free_ev and "duration" in free_ev:
        duration_s = float(free_ev["duration"])
    elif events:
        ts_sorted = sorted(_parse_ts(e["timestamp"]) for e in events)
        duration_s = (ts_sorted[-1] - ts_sorted[0]).total_seconds()
    else:
        duration_s = 0.0

    # intervalos entre conexões (detecta scan automatizado)
    conn_ts = sorted(_parse_ts(e["timestamp"]) for e in connects)
    if len(conn_ts) >= 2:
        intervals = [(conn_ts[i+1] - conn_ts[i]).total_seconds() * 1000
                     for i in range(len(conn_ts) - 1)]
        avg_interval = sum(intervals) / len(intervals)
        min_interval = min(intervals)
    else:
        avg_interval = 0.0
        min_interval = 0.0

    sizes = [e.get("data_length", 0) for e in data_evs]

    return {
        "session_id":                  (connects[0] if connects else events[0])["session"],
        "src_ip":                      (connects[0] if connects else events[0]).get("src_ip", ""),
        "connection_count":            len(connects),
        "unique_ports":                len({e.get("dst_port") for e in connects}),
        "unique_protocols":            len({e.get("protocol") for e in connects}),
        "session_duration_s":          round(duration_s, 3),
        "avg_connection_interval_ms":  round(avg_interval, 1),
        "min_connection_interval_ms":  round(min_interval, 1),
        "has_shellcode":               int(any(e.get("has_shellcode") for e in data_evs)),
        "has_download":                int(bool(downloads)),
        "payload_size_avg":            round(statistics.mean(sizes), 1) if sizes else 0.0,
        "login_attempt_count":         len(logins),
    }

# ── pipeline ──────────────────────────────────────────────────────────────────

def extract_features(
    logs_path: str,
    output_path: str,
    labels_path: str | None = None,
) -> None:
    # agrupa eventos por sessão
    sessions: dict[str, list] = {}
    with open(logs_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            sessions.setdefault(ev["session"], []).append(ev)

    print(f"  Sessões encontradas: {len(sessions)}")

    # carrega labels opcionais
    labels: dict[str, str] = {}
    if labels_path and Path(labels_path).exists():
        with open(labels_path, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                labels[row["session_id"]] = row["label"]

    # extrai features
    rows = [_extract(evs) for evs in sessions.values()]

    if not rows:
        print("  Nenhuma sessão encontrada.")
        return

    if labels:
        for row in rows:
            row["label"] = labels.get(row["session_id"], "unknown")

    # salva CSV
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    cols = len(rows[0])
    print(f"  -> {output_path}")
    print(f"     {len(rows)} sessoes  |  {cols} colunas")


if __name__ == "__main__":
    extract_features(
        logs_path="../data/dataset/dionaea_logs.jsonl",
        labels_path="../data/dataset/dionaea_session_labels.csv",
        output_path="../data/dataset/dionaea_training_features.csv",
    )
