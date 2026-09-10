"""
Extrator de features a partir de capturas REAIS do Dionaea.

Por que este modulo existe separado de `extract_dionaea_features.py`:
o schema que o Dionaea realmente escreve nao tem nada a ver com o que o
gerador sintetico produz. Verificado contra uma captura de 14 dias:

    sintetico : {"eventid": "dionaea.connection.tcp.accept", "session": "abc", ...}
    real      : {"connection": {"type": "accept", "protocol": "smbd", ...},
                 "src_ip": "...", "dst_port": 445, "timestamp": "..."}

Duas diferencas sao fatais para o pipeline atual:

  1. Nao existe campo `session`. O `backend/log_watcher.py` agrupa por
     `ev.get("session")` e descarta o evento se ele faltar — ou seja, 100%
     dos eventos reais eram silenciosamente ignorados.
  2. Nao existe `eventid`. O tipo fica em `connection.type`.

Sessao sintetizada: o Dionaea nao tem conceito nativo de sessao neste log
(a coluna `connection_root` do SQLite e 1:1 com a conexao — verificado, nao
agrupa nada). Agrupamos por IP de origem, quebrando a sessao quando o
intervalo entre conexoes consecutivas passa de SESSION_GAP_S.

Duas das dez features do modelo NAO existem em captura real:

  has_shellcode     — depende da tabela `emu_profiles` do Dionaea, vazia em
                      14 dias de captura (nenhum shellcode emulado)
  payload_size_avg  — o Dionaea nao registra tamanho de payload em lugar nenhum

Ambas ficam em 0.0 e estao listadas em UNAVAILABLE_FEATURES. Isso importa:
o modelo treinado no sintetico usa essas features como sinal discriminativo,
entao a ausencia delas em producao e parte do gap sim->real que o TCC mede.

Uso:
    python extract_dionaea_real.py --sqlite ../data/captura_real/dionaea.sqlite.1
    python extract_dionaea_real.py --json   ../data/captura_real/dionaea.json.1
"""

import argparse
import csv
import json
import sqlite3
from datetime import datetime
from pathlib import Path

# Intervalo maximo entre conexoes do mesmo IP para continuarem na mesma sessao.
SESSION_GAP_S = 300.0

# Features que o Dionaea real nao fornece — mantidas em zero para preservar a
# compatibilidade de colunas com o modelo treinado no dataset sintetico.
UNAVAILABLE_FEATURES = ("has_shellcode", "payload_size_avg")

FEATURE_COLS = [
    "connection_count", "unique_ports", "unique_protocols", "session_duration_s",
    "avg_connection_interval_ms", "min_connection_interval_ms", "has_shellcode",
    "has_download", "payload_size_avg", "login_attempt_count",
]


def _parse_ts(ts):
    """Aceita os formatos com e sem sufixo Z / microssegundos."""
    ts = ts.replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError("timestamp irreconhecivel: " + ts)


# ── leitura das duas fontes possiveis ────────────────────────────────────────

def load_from_sqlite(path):
    """Le o dionaea.sqlite — inclui logins e downloads, ausentes do JSON."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row

    downloads = {r[0] for r in conn.execute("SELECT connection FROM downloads")}
    logins = {}
    for cid, in conn.execute("SELECT connection FROM logins"):
        logins[cid] = logins.get(cid, 0) + 1
    try:
        shellcode = {r[0] for r in conn.execute("SELECT connection FROM emu_profiles")}
    except sqlite3.Error:
        shellcode = set()

    rows = []
    q = """SELECT connection, connection_protocol, connection_transport,
                  connection_timestamp, remote_host, local_port
           FROM connections WHERE connection_type = 'accept'
           ORDER BY remote_host, connection_timestamp"""
    for r in conn.execute(q):
        rows.append({
            "src_ip":    r["remote_host"],
            "dst_port":  r["local_port"],
            "protocol":  r["connection_protocol"],
            "transport": r["connection_transport"],
            "ts":        datetime.fromtimestamp(r["connection_timestamp"]),
            "logins":    logins.get(r["connection"], 0),
            "download":  r["connection"] in downloads,
            "shellcode": r["connection"] in shellcode,
        })
    conn.close()
    return rows


def load_from_json(path):
    """Le o dionaea.json — e o que o backend acompanha em tempo real."""
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            c = ev.get("connection") or {}
            if c.get("type") != "accept":
                continue
            creds = ev.get("credentials") or {}
            rows.append({
                "src_ip":    ev.get("src_ip", ""),
                "dst_port":  ev.get("dst_port"),
                "protocol":  c.get("protocol"),
                "transport": c.get("transport"),
                "ts":        _parse_ts(ev["timestamp"]),
                "logins":    len(creds.get("username", []) or []) if creds else 0,
                "download":  False,   # o JSON nao registra download
                "shellcode": False,
            })
    rows.sort(key=lambda r: (r["src_ip"], r["ts"]))
    return rows


# ── sessionizacao e features ─────────────────────────────────────────────────

def sessionize(rows, gap_s=SESSION_GAP_S):
    """Agrupa conexoes do mesmo IP separadas por menos de `gap_s` segundos."""
    sessions, current, last_ip, last_ts = [], [], None, None
    for r in rows:
        new = (r["src_ip"] != last_ip or last_ts is None
               or (r["ts"] - last_ts).total_seconds() > gap_s)
        if new and current:
            sessions.append(current)
            current = []
        current.append(r)
        last_ip, last_ts = r["src_ip"], r["ts"]
    if current:
        sessions.append(current)
    return sessions


def features(session, idx):
    ts = [r["ts"] for r in session]
    duration = (ts[-1] - ts[0]).total_seconds()

    if len(ts) >= 2:
        gaps = [(ts[i + 1] - ts[i]).total_seconds() * 1000 for i in range(len(ts) - 1)]
        avg_gap, min_gap = sum(gaps) / len(gaps), min(gaps)
    else:
        avg_gap = min_gap = 0.0

    return {
        "session_id":                 "real-{:06d}".format(idx),
        "src_ip":                     session[0]["src_ip"],
        "first_seen":                 ts[0].isoformat(timespec="seconds"),
        "connection_count":           len(session),
        "unique_ports":               len({r["dst_port"] for r in session}),
        "unique_protocols":           len({r["protocol"] for r in session}),
        "session_duration_s":         round(duration, 3),
        "avg_connection_interval_ms": round(avg_gap, 1),
        "min_connection_interval_ms": round(min_gap, 1),
        "has_shellcode":              int(any(r["shellcode"] for r in session)),
        "has_download":               int(any(r["download"] for r in session)),
        "payload_size_avg":           0.0,   # indisponivel — ver docstring
        "login_attempt_count":        sum(r["logins"] for r in session),
        "protocols":                  "|".join(sorted({r["protocol"] or "?" for r in session})),
    }


def extract(rows, output_path, gap_s=SESSION_GAP_S):
    sessions = sessionize(rows, gap_s)
    out = [features(s, i) for i, s in enumerate(sessions)]

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)

    print("  conexoes            : {}".format(len(rows)))
    print("  sessoes sintetizadas: {}".format(len(out)))
    print("  IPs distintos       : {}".format(len({r['src_ip'] for r in rows})))
    print("  -> {}".format(output_path))
    return out


def main():
    ap = argparse.ArgumentParser(description="Extrai features de capturas reais do Dionaea")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--sqlite", help="dionaea.sqlite (inclui logins e downloads)")
    src.add_argument("--json", dest="json_path", help="dionaea.json (formato acompanhado em producao)")
    ap.add_argument("--output", default="../data/captura_real/dionaea_real_features.csv")
    ap.add_argument("--gap", type=float, default=SESSION_GAP_S,
                    help="Intervalo (s) que separa duas sessoes do mesmo IP")
    args = ap.parse_args()

    if args.sqlite:
        print("Lendo SQLite: {}".format(args.sqlite))
        rows = load_from_sqlite(args.sqlite)
    else:
        print("Lendo JSON: {}".format(args.json_path))
        rows = load_from_json(args.json_path)

    extract(rows, args.output, args.gap)


if __name__ == "__main__":
    main()
