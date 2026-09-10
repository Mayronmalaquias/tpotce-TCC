"""
Teste do agrupamento de sessoes sintetizadas (caminho do Dionaea real).

O Cowrie marca cada evento com um campo `session` e encerra a sessao com um
evento explicito. O Dionaea real nao faz nem uma coisa nem outra: seus eventos
sao conexoes soltas, sem identificador de sessao e sem marco de encerramento.

    {"connection": {"protocol": "smbd", "type": "accept"},
     "src_ip": "1.2.3.4", "dst_port": 445, "timestamp": "..."}

Como o LogWatcher agrupava por `ev.get("session")` e descartava o evento se o
campo faltasse, 100% do trafego do Dionaea era silenciosamente ignorado em
producao — o honeypot capturava, o log enchia, e nada chegava ao dashboard.

Este teste cobre o mecanismo que resolve isso: chave de agrupamento
configuravel (aqui, o IP de origem) e fechamento da sessao por inatividade,
ja que nao existe evento de fim.

    python backend/tests/test_sessao_sintetizada.py
"""

import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from log_watcher import LogWatcher

TIMEOUT_SESSAO_S = 2.0     # curto, para o teste nao demorar
entregues = []


def evento_dionaea(src_ip, porta, protocolo="smbd"):
    """Reproduz o formato exato que o Dionaea real escreve."""
    return {
        "connection": {"protocol": protocolo, "transport": "tcp", "type": "accept"},
        "dst_ip": "172.19.0.2",
        "dst_port": porta,
        "src_hostname": "",
        "src_ip": src_ip,
        "src_port": 40000,
        "timestamp": "2026-09-06T02:00:00.000000",
    }


def escrever(path, eventos):
    with open(path, "a", encoding="utf-8") as f:
        for ev in eventos:
            f.write(json.dumps(ev) + "\n")
        f.flush()


def esperar(total, timeout=10.0):
    fim = time.time() + timeout
    while time.time() < fim:
        if len(entregues) >= total:
            return True
        time.sleep(0.2)
    return False


def main():
    tmp = Path(tempfile.mkdtemp())
    log = tmp / "dionaea.json"
    log.write_text("", encoding="utf-8")

    watcher = LogWatcher(
        on_session=lambda sid, evs: entregues.append((sid, len(evs))),
        log_path=str(log),
        label="TesteDionaea",
        session_key=lambda ev: ev.get("src_ip"),      # sem campo `session`
        session_timeout_s=TIMEOUT_SESSAO_S,           # sem evento de fim
    )
    watcher.start()
    time.sleep(0.6)

    falhas = []

    # 1. varias conexoes do mesmo IP viram UMA sessao
    escrever(log, [evento_dionaea("203.0.113.10", 445) for _ in range(5)])
    if esperar(1, timeout=TIMEOUT_SESSAO_S + 6):
        sid, n = entregues[0]
        if sid == "203.0.113.10" and n == 5:
            print("ok    5 conexoes do mesmo IP agrupadas numa sessao")
        else:
            falhas.append(f"agrupamento errado: sid={sid} eventos={n}")
            print(f"FALHA agrupamento errado: sid={sid} eventos={n}")
    else:
        falhas.append("sessao nao foi entregue por inatividade")
        print("FALHA sessao nao foi entregue por inatividade")

    # 2. IPs diferentes geram sessoes separadas
    entregues.clear()
    escrever(log, [evento_dionaea("198.51.100.7", 3306, "mysqld"),
                   evento_dionaea("198.51.100.8", 1433, "mssqld")])
    if esperar(2, timeout=TIMEOUT_SESSAO_S + 6):
        ips = sorted(sid for sid, _ in entregues)
        if ips == ["198.51.100.7", "198.51.100.8"]:
            print("ok    IPs distintos geraram sessoes separadas")
        else:
            falhas.append(f"separacao por IP falhou: {ips}")
            print(f"FALHA separacao por IP falhou: {ips}")
    else:
        falhas.append("nao entregou as duas sessoes de IPs distintos")
        print("FALHA nao entregou as duas sessoes de IPs distintos")

    # 3. evento sem a chave de agrupamento nao derruba o watcher
    entregues.clear()
    escrever(log, [{"connection": {"type": "listen"}, "timestamp": "..."}])
    time.sleep(1.0)
    escrever(log, [evento_dionaea("192.0.2.55", 21, "ftpd")])
    if esperar(1, timeout=TIMEOUT_SESSAO_S + 6):
        print("ok    evento sem IP ignorado sem afetar os seguintes")
    else:
        falhas.append("watcher parou apos evento sem chave")
        print("FALHA watcher parou apos evento sem chave")

    watcher.stop()

    if falhas:
        print("\nFALHOU: " + "; ".join(falhas))
        return 1
    print("\nPASSOU: sessoes sintetizadas agrupam por IP e fecham por inatividade")
    return 0


if __name__ == "__main__":
    sys.exit(main())
