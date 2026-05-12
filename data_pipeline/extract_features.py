"""
Extrator de features por sessão a partir de logs Cowrie (JSONL).

Lê os eventos brutos, agrupa por session_id e calcula 13 features numéricas
que capturam o comportamento de cada sessão. Se um arquivo de labels for
fornecido, adiciona a coluna 'label' ao CSV de saída.

Funciona com logs reais do Cowrie e com os logs sintéticos gerados por
generate_logs.py — não depende de campos extras.

Features extraídas:
  login_attempt_count    — total de tentativas de login (falhas)
  login_success          — 1 se houve login bem-sucedido, 0 caso contrário
  unique_usernames       — quantidade de usernames distintos tentados
  unique_passwords       — quantidade de senhas distintas tentadas
  session_duration_s     — duração total da sessão em segundos
  command_count          — número de comandos executados no shell
  avg_login_interval_ms  — intervalo médio entre tentativas (ms)
  min_login_interval_ms  — intervalo mínimo entre tentativas (ms)
  has_wget_curl          — 1 se algum comando contém wget ou curl
  has_reverse_shell      — 1 se padrão de reverse shell detectado
  has_recon_commands     — 1 se comandos de enumeração detectados
  has_file_download      — 1 se evento cowrie.session.file_download presente
  command_rate_per_min   — taxa de comandos por minuto na sessão
"""

import csv
import json
import re
from datetime import datetime
from pathlib import Path

# ── padrões de detecção ───────────────────────────────────────────────────────

_RECON = re.compile(
    r"\b(uname|whoami|hostname|id\b|"
    r"cat\s+/etc/(passwd|shadow|os-release|crontab)|"
    r"ls\s+-?l?a?\s*/|ps\s+(aux|ef)|netstat|ifconfig|ip\s+a\b|"
    r"df\s+-h|free\s+-m|printenv|env\b|last\b|who\b|crontab\s+-l)\b"
)

_REVERSE_SHELL = re.compile(
    r"/dev/tcp/|nc\s+-e|bash\s+-i\s+>&|ncat\s+.+/bin|"
    r"python\S*\s+.+socket.+connect|perl.+socket|mkfifo.+nc\b"
)

_WGET_CURL = re.compile(r"\b(wget|curl)\b")

# ── parser de timestamp ISO ──────────────────────────────────────────────────

def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")

# ── extração por sessão ───────────────────────────────────────────────────────

def _extract(events: list) -> dict:
    connect = next((e for e in events if e["eventid"] == "cowrie.session.connect"), None)
    closed  = next((e for e in events if e["eventid"] == "cowrie.session.closed"), None)
    failures = [e for e in events if e["eventid"] == "cowrie.login.failed"]
    successes = [e for e in events if e["eventid"] == "cowrie.login.success"]
    commands  = [e for e in events if e["eventid"] == "cowrie.command.input"]
    downloads = [e for e in events if e["eventid"] == "cowrie.session.file_download"]

    # duração da sessão
    if connect and closed:
        duration_s = (_parse_ts(closed["timestamp"]) - _parse_ts(connect["timestamp"])).total_seconds()
    elif closed:
        duration_s = float(closed.get("duration", 0))
    else:
        duration_s = 0.0

    # intervalos entre tentativas de login
    fail_ts = sorted(_parse_ts(e["timestamp"]) for e in failures)
    if len(fail_ts) >= 2:
        intervals = [(fail_ts[i+1] - fail_ts[i]).total_seconds() * 1000
                     for i in range(len(fail_ts) - 1)]
        avg_interval = sum(intervals) / len(intervals)
        min_interval = min(intervals)
    else:
        avg_interval = 0.0
        min_interval = 0.0

    # análise de comandos
    cmd_text = " ".join(e.get("input", "") for e in commands).lower()
    cmd_rate = (len(commands) / duration_s * 60) if duration_s > 0 else 0.0

    return {
        "session_id":            (connect or events[0])["session"],
        "src_ip":                (connect or events[0]).get("src_ip", ""),
        "login_attempt_count":   len(failures),
        "login_success":         int(bool(successes)),
        "unique_usernames":      len({e.get("username", "") for e in failures}),
        "unique_passwords":      len({e.get("password", "") for e in failures}),
        "session_duration_s":    round(duration_s, 3),
        "command_count":         len(commands),
        "avg_login_interval_ms": round(avg_interval, 1),
        "min_login_interval_ms": round(min_interval, 1),
        "has_wget_curl":         int(bool(_WGET_CURL.search(cmd_text))),
        "has_reverse_shell":     int(bool(_REVERSE_SHELL.search(cmd_text))),
        "has_recon_commands":    int(bool(_RECON.search(cmd_text))),
        "has_file_download":     int(bool(downloads)),
        "command_rate_per_min":  round(cmd_rate, 3),
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
        logs_path="../data/dataset/cowrie_logs.jsonl",
        labels_path="../data/dataset/session_labels.csv",
        output_path="../data/dataset/training_features.csv",
    )
