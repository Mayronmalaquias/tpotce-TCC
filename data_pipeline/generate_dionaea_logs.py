"""
Gerador de logs sintéticos no formato normalizado do Dionaea.

O Dionaea real trata cada conexão TCP/UDP como um objeto isolado (não existe um
conceito nativo de "sessão do atacante" como no Cowrie). O BeeIA normaliza isso
agrupando, sob um único `session`, todas as conexões que um mesmo IP faz contra
o Dionaea dentro de uma janela curta — o suficiente para caracterizar o padrão
de comportamento (scan, sondagem, exploit, download de malware). Esse mesmo
agrupamento deverá ser replicado por `backend/dionaea_watcher.py` ao consumir
o `dionaea.json` real.

Produz dois arquivos:
  - dionaea_logs.jsonl     : eventos brutos (formato normalizado do Dionaea)
  - dionaea_session_labels.csv : session_id → classe do ataque

Classes geradas:
  port_scan          — varredura rápida de múltiplas portas/serviços, sem payload
  service_probe      — poucas conexões, payload pequeno/benigno, sem exploit
  exploit_attempt     — payload com assinatura de shellcode/exploit conhecido
  malware_download    — download de binário capturado (dionaea.download.complete)
"""

import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# ── protocolos/portas emulados pelo Dionaea ────────────────────────────────────

SERVICES = [
    ("ftpd",   21),
    ("smbd",   445),
    ("mssqld", 1433),
    ("mqttd",  1883),
    ("httpd",  443),
    ("mysqld", 3306),
    ("sipd",   5060),
    ("upnpd",  1900),
    ("tftpd",  69),
]

MALWARE_URLS = [
    "http://45.33.32.156/bot.elf",
    "http://192.241.205.159/payload.bin",
    "http://178.128.23.9/miner.exe",
    "http://134.209.82.17/drop.sh",
]

FTP_USERNAMES = ["anonymous", "admin", "ftp", "root", "user"]
FTP_PASSWORDS = ["anonymous", "admin", "123456", "ftp", "guest"]

# ── helpers ──────────────────────────────────────────────────────────────────

def _ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _ts(base: datetime, offset_ms: float) -> str:
    return (base + timedelta(milliseconds=offset_ms)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _ev(eventid: str, session: str, ts: str, src_ip: str, **kw) -> dict:
    return {"eventid": eventid, "session": session, "timestamp": ts,
            "src_ip": src_ip, "sensor": "dionaea", **kw}

# ── geradores por classe ──────────────────────────────────────────────────────

def gen_port_scan(base: datetime) -> list:
    """Varre várias portas/serviços rapidamente, sem enviar payload."""
    sid = uuid.uuid4().hex[:12]
    ip = _ip()
    t = 0.0
    ev = []

    targets = random.sample(SERVICES, random.randint(5, len(SERVICES)))
    for protocol, port in targets:
        t += random.uniform(20, 150)  # scan automatizado: intervalos muito curtos
        ev.append(_ev("dionaea.connection.tcp.accept", sid, _ts(base, t), ip,
                      src_port=random.randint(1024, 65535), dst_port=port, protocol=protocol))

    t += random.uniform(50, 200)
    ev.append(_ev("dionaea.connection.free", sid, _ts(base, t), ip,
                  duration=round(t / 1000, 3)))
    return ev


def gen_service_probe(base: datetime) -> list:
    """Poucas conexões, payload pequeno/benigno, sem assinatura de exploit."""
    sid = uuid.uuid4().hex[:12]
    ip = _ip()
    t = 0.0
    ev = []

    protocol, port = random.choice(SERVICES)
    for _ in range(random.randint(1, 3)):
        t += random.uniform(500, 3000)
        ev.append(_ev("dionaea.connection.tcp.accept", sid, _ts(base, t), ip,
                      src_port=random.randint(1024, 65535), dst_port=port, protocol=protocol))
        t += random.uniform(100, 800)
        ev.append(_ev("dionaea.data.in", sid, _ts(base, t), ip,
                      data_length=random.randint(4, 64), has_shellcode=False))

    if protocol in ("ftpd", "mssqld", "mqttd"):
        t += random.uniform(200, 900)
        ev.append(_ev("dionaea.login.attempt", sid, _ts(base, t), ip,
                      username=random.choice(FTP_USERNAMES),
                      password=random.choice(FTP_PASSWORDS)))

    t += random.uniform(300, 1500)
    ev.append(_ev("dionaea.connection.free", sid, _ts(base, t), ip,
                  duration=round(t / 1000, 3)))
    return ev


def gen_exploit_attempt(base: datetime) -> list:
    """Conexão a serviço vulnerável (SMB/MSSQL) com payload de shellcode."""
    sid = uuid.uuid4().hex[:12]
    ip = _ip()
    t = 0.0
    ev = []

    protocol, port = random.choice([("smbd", 445), ("mssqld", 1433)])
    for _ in range(random.randint(1, 3)):
        t += random.uniform(300, 1500)
        ev.append(_ev("dionaea.connection.tcp.accept", sid, _ts(base, t), ip,
                      src_port=random.randint(1024, 65535), dst_port=port, protocol=protocol))

    t += random.uniform(200, 900)
    ev.append(_ev("dionaea.data.in", sid, _ts(base, t), ip,
                  data_length=random.randint(300, 1400), has_shellcode=True))

    t += random.uniform(100, 500)
    ev.append(_ev("dionaea.data.in", sid, _ts(base, t), ip,
                  data_length=random.randint(200, 900), has_shellcode=True))

    t += random.uniform(500, 3000)
    ev.append(_ev("dionaea.connection.free", sid, _ts(base, t), ip,
                  duration=round(t / 1000, 3)))
    return ev


def gen_malware_download(base: datetime) -> list:
    """Exploração seguida de download do payload capturado pelo honeypot."""
    sid = uuid.uuid4().hex[:12]
    ip = _ip()
    t = 0.0
    ev = []

    protocol, port = random.choice([("smbd", 445), ("httpd", 443), ("ftpd", 21), ("tftpd", 69)])
    ev.append(_ev("dionaea.connection.tcp.accept", sid, _ts(base, t), ip,
                  src_port=random.randint(1024, 65535), dst_port=port, protocol=protocol))

    t += random.uniform(100, 600)
    ev.append(_ev("dionaea.data.in", sid, _ts(base, t), ip,
                  data_length=random.randint(200, 1200), has_shellcode=random.random() < 0.6))

    t += random.uniform(500, 4000)
    url = random.choice(MALWARE_URLS)
    ev.append(_ev("dionaea.download.complete", sid, _ts(base, t), ip,
                  url=url, md5_hash=uuid.uuid4().hex, file_size=random.randint(4_000, 500_000)))

    t += random.uniform(300, 2000)
    ev.append(_ev("dionaea.connection.free", sid, _ts(base, t), ip,
                  duration=round(t / 1000, 3)))
    return ev


# ── orquestrador ─────────────────────────────────────────────────────────────

ATTACK_GENERATORS = {
    "port_scan":         gen_port_scan,
    "service_probe":     gen_service_probe,
    "exploit_attempt":   gen_exploit_attempt,
    "malware_download":  gen_malware_download,
}


def generate_dataset(
    logs_path: str,
    labels_path: str,
    sessions_per_class: int = 500,
    seed: int = 42,
) -> None:
    random.seed(seed)
    Path(logs_path).parent.mkdir(parents=True, exist_ok=True)

    base = datetime(2025, 1, 1)
    all_sessions = []  # [(session_id, label, events)]

    for label, gen_fn in ATTACK_GENERATORS.items():
        print(f"  {label:<22} {sessions_per_class} sessões")
        for i in range(sessions_per_class):
            offset = timedelta(hours=i * 0.5 + random.uniform(0, 0.4))
            events = gen_fn(base + offset)
            all_sessions.append((events[0]["session"], label, events))

    random.shuffle(all_sessions)  # intercala como log real faria

    total_events = 0
    with (
        open(logs_path, "w", encoding="utf-8") as f_logs,
        open(labels_path, "w", encoding="utf-8") as f_labels,
    ):
        f_labels.write("session_id,label\n")
        for sid, label, events in all_sessions:
            f_labels.write(f"{sid},{label}\n")
            for ev in events:
                f_logs.write(json.dumps(ev) + "\n")
                total_events += 1

    print(f"\n  -> {logs_path}")
    print(f"     {total_events} eventos  |  {len(all_sessions)} sessoes  |  {len(ATTACK_GENERATORS)} classes")


if __name__ == "__main__":
    print("Gerando logs sintéticos do Dionaea...\n")
    generate_dataset(
        logs_path="../data/dataset/dionaea_logs.jsonl",
        labels_path="../data/dataset/dionaea_session_labels.csv",
        sessions_per_class=500,
    )
    print("\nConcluído.")
