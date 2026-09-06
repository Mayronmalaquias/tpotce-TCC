"""
Rotulagem heuristica de sessoes reais do Dionaea.

Trafego real nao vem rotulado. Este modulo aplica regras derivadas das
DISTRIBUICOES OBSERVADAS na captura (nao de limiares arbitrarios) e separa uma
amostra estratificada para validacao manual — o gabarito de ouro que mede a
qualidade da propria heuristica.

Por que a taxonomia difere das 4 classes do gerador sintetico
-------------------------------------------------------------
A captura de 14 dias mostrou que duas premissas do dataset sintetico nao se
sustentam em producao:

  * `port_scan` foi modelado como varredura vertical (um IP tocando muitas
    portas). A internet faz varredura horizontal: p99 de `unique_ports` = 1,
    maximo 6. A classe praticamente nao existe no formato modelado.
  * Nao havia classe para forca bruta de credenciais, que na pratica responde
    por 24.924 tentativas de login — o segundo comportamento mais comum.

O trafego tambem e nitidamente bimodal (`connection_count` p50=1 / p90=114;
`login_attempt_count` p90=2 / p95=123): ruido de fundo de um lado, ataque
sustentado do outro. Os limiares abaixo ficam nesse vale.

Precedencia (mais severo vence, uma sessao pode satisfazer varias regras):
    malware_download > exploit_attempt > credential_bruteforce
                     > port_scan > connection_flood > service_probe

Uso:
    python label_dionaea_real.py \
        --features ../data/captura_real/dionaea_real_features.csv \
        --sqlite   ../data/captura_real/dionaea.sqlite.1
"""

import argparse
import csv
import sqlite3
from collections import Counter
from pathlib import Path

# ── limiares, todos justificados pelas distribuicoes observadas ──────────────

MIN_LOGINS_BRUTEFORCE = 5     # p90=2, p95=123 -> 5 cai no vale entre os modos
MIN_PORTS_SCAN        = 2     # p99=1: tocar 2+ portas ja e excecao (0,6%)
MIN_CONNS_FLOOD       = 100   # p75=4, p90=114 -> 100 separa ruido de martelada

LABEL_PRECEDENCE = [
    "malware_download",
    "exploit_attempt",
    "credential_bruteforce",
    "port_scan",
    "connection_flood",
    "service_probe",
]


def load_enrichment(sqlite_path):
    """IPs com indicadores que o CSV de features nao carrega."""
    conn = sqlite3.connect(sqlite_path)
    dcerpc = {r[0] for r in conn.execute(
        "SELECT DISTINCT co.remote_host FROM dcerpcrequests d "
        "JOIN connections co ON co.connection = d.connection")}
    downloads = {r[0] for r in conn.execute(
        "SELECT DISTINCT co.remote_host FROM downloads d "
        "JOIN connections co ON co.connection = d.connection")}
    conn.close()
    return dcerpc, downloads


def label_session(row, dcerpc_ips, download_ips):
    """Retorna (label, justificativa) — a justificativa vai para revisao manual."""
    ip     = row["src_ip"]
    conns  = int(float(row["connection_count"]))
    ports  = int(float(row["unique_ports"]))
    logins = int(float(row["login_attempt_count"]))
    dl     = int(float(row["has_download"]))

    if dl or ip in download_ips:
        return "malware_download", "binario baixado pelo atacante"
    if ip in dcerpc_ips:
        return "exploit_attempt", "requisicao DCERPC (exploracao de SMB/RPC)"
    if logins >= MIN_LOGINS_BRUTEFORCE:
        return "credential_bruteforce", "{} tentativas de login".format(logins)
    if ports >= MIN_PORTS_SCAN:
        return "port_scan", "{} portas distintas".format(ports)
    if conns >= MIN_CONNS_FLOOD:
        return "connection_flood", "{} conexoes na sessao".format(conns)
    return "service_probe", "{} conexao(oes), sem login".format(conns)


def main():
    ap = argparse.ArgumentParser(description="Rotula sessoes reais do Dionaea por heuristica")
    ap.add_argument("--features", default="../data/captura_real/dionaea_real_features.csv")
    ap.add_argument("--sqlite",   default="../data/captura_real/dionaea.sqlite.1")
    ap.add_argument("--output",   default="../data/captura_real/dionaea_real_labeled.csv")
    ap.add_argument("--gold-out", default="../data/captura_real/gabarito_para_revisar.csv")
    ap.add_argument("--gold-size", type=int, default=200,
                    help="Sessoes por amostra de validacao manual (padrao: 200)")
    args = ap.parse_args()

    dcerpc_ips, download_ips = load_enrichment(args.sqlite)
    print("Enriquecimento: {} IPs com DCERPC | {} IPs com download".format(
        len(dcerpc_ips), len(download_ips)))

    with open(args.features, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    counts = Counter()
    for r in rows:
        label, why = label_session(r, dcerpc_ips, download_ips)
        r["label"], r["justificativa"] = label, why
        counts[label] += 1

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print("\nDistribuicao dos rotulos ({} sessoes):".format(len(rows)))
    for label in LABEL_PRECEDENCE:
        n = counts.get(label, 0)
        if n:
            bar = "#" * int(n / len(rows) * 50)
            print("  {:<24} {:>5}  ({:5.1f}%)  {}".format(label, n, n / len(rows) * 100, bar))

    # ── amostra estratificada para revisao manual ────────────────────────────
    # Classes raras entram inteiras: sao justamente as que importam e as que a
    # heuristica tem mais chance de errar.
    by_label = {}
    for r in rows:
        by_label.setdefault(r["label"], []).append(r)

    per_class = max(1, args.gold_size // max(1, len(by_label)))
    gold = []
    for label, group in by_label.items():
        step = max(1, len(group) // per_class)
        gold.extend(group[::step][:per_class])

    for r in gold:
        r["label_revisado"] = ""      # preenchido manualmente
        r["revisor_concorda"] = ""    # s/n

    cols = ["session_id", "src_ip", "first_seen", "protocols", "connection_count",
            "unique_ports", "login_attempt_count", "has_download",
            "session_duration_s", "label", "justificativa",
            "label_revisado", "revisor_concorda"]
    with open(args.gold_out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(gold)

    print("\n  -> {}".format(args.output))
    print("  -> {}  ({} sessoes para revisar)".format(args.gold_out, len(gold)))
    print("\n  Para validar: abra o gabarito, confira cada linha e preencha")
    print("  'revisor_concorda' com s/n. Onde discordar, escreva a classe")
    print("  correta em 'label_revisado'.")


if __name__ == "__main__":
    main()
