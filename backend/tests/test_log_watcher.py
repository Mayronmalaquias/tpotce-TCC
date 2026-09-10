"""
Teste de regressao do LogWatcher: rotacao e truncamento de log.

Por que este teste existe
-------------------------
Em producao o `tpotinit` rotaciona os logs dos honeypots a cada restart do
stack (`cowrie.json` vira `cowrie.json.1.gz` e um arquivo novo nasce no lugar).
O watcher mantinha aberto o descritor do arquivo antigo e, a partir dali,
parava de ver eventos — sem erro, sem log, sem nenhum sinal. O backend
continuava "rodando" e capturando nada.

Foi assim que a captura do BeeIA ficou parada por duas semanas sem ninguem
perceber. O teste cobre as duas formas de rotacao:

  * rename  — o arquivo e renomeado e outro e criado no mesmo caminho
  * truncate — o arquivo e zerado no lugar, mantendo o mesmo inode

Nao usa framework: o projeto nao tem um, e o teste precisa de threads e tempo
real de polling. Rode direto e confira o codigo de saida.

    python backend/tests/test_log_watcher.py

Observacao: o passo de rename nao roda no Windows, que impede renomear um
arquivo aberto por outro processo. Em Linux — o ambiente de producao — os tres
passos rodam.
"""

import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from log_watcher import LogWatcher

TIMEOUT_S = 8.0
capturadas = []


def escrever_sessao(path, sid):
    """Escreve uma sessao completa: connect -> login -> closed."""
    with open(path, "a", encoding="utf-8") as f:
        for ev in (
            {"eventid": "cowrie.session.connect", "session": sid, "src_ip": "1.2.3.4"},
            {"eventid": "cowrie.login.failed", "session": sid, "username": "root"},
            {"eventid": "cowrie.session.closed", "session": sid, "duration": 1.0},
        ):
            f.write(json.dumps(ev) + "\n")
        f.flush()


def esperar(total, timeout=TIMEOUT_S):
    fim = time.time() + timeout
    while time.time() < fim:
        if len(capturadas) >= total:
            return True
        time.sleep(0.2)
    return False


def main():
    tmp = Path(tempfile.mkdtemp())
    log = tmp / "cowrie.json"
    log.write_text("", encoding="utf-8")

    watcher = LogWatcher(on_session=lambda sid, evs: capturadas.append(sid),
                         log_path=str(log), label="TesteRotacao")
    watcher.start()
    time.sleep(0.6)

    falhas = []

    # 1. captura normal, antes de qualquer rotacao
    escrever_sessao(log, "antes-da-rotacao")
    if esperar(1):
        print("ok    sessao capturada antes da rotacao")
    else:
        falhas.append("nao capturou a sessao inicial")
        print("FALHA nao capturou a sessao inicial")

    # 2. rotacao por rename, como o tpotinit faz
    if sys.platform == "win32":
        print("pulo  rename nao e possivel no Windows com o arquivo aberto")
    else:
        log.rename(tmp / "cowrie.json.1")
        log.write_text("", encoding="utf-8")
        time.sleep(1.5)
        escrever_sessao(log, "depois-da-rotacao")
        if esperar(2):
            print("ok    sessao capturada depois do rename")
        else:
            falhas.append("perdeu eventos apos rename")
            print("FALHA perdeu eventos apos rename")

    # 3. rotacao por truncamento no lugar
    alvo = len(capturadas) + 1
    with open(log, "w", encoding="utf-8"):
        pass
    time.sleep(1.5)
    escrever_sessao(log, "depois-do-truncamento")
    if esperar(alvo):
        print("ok    sessao capturada depois do truncamento")
    else:
        falhas.append("perdeu eventos apos truncamento")
        print("FALHA perdeu eventos apos truncamento")

    watcher.stop()

    if falhas:
        print("\nFALHOU: " + "; ".join(falhas))
        return 1
    print("\nPASSOU: o watcher sobrevive a rotacao e ao truncamento")
    return 0


if __name__ == "__main__":
    sys.exit(main())
