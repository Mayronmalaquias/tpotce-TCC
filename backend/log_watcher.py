"""
Monitora o arquivo de log de um honeypot (JSONL) em tempo real.
Agrupa eventos por session_id e dispara callback quando a sessão é encerrada.

Genérico o suficiente para Cowrie e Dionaea: cada instância recebe o caminho
do log e o conjunto de eventos que marcam o fim de uma sessão.
"""

import json
import os
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

DEFAULT_LOG = Path(__file__).parent.parent / "data" / "cowrie" / "log" / "cowrie.json"

_SESSION_END = {"cowrie.session.closed", "cowrie.session.timeout"}


class LogWatcher:
    def __init__(
        self,
        on_session: Callable[[str, list], None],
        log_path: Optional[str] = None,
        default_log: Optional[Path] = None,
        session_end_events: Optional[set] = None,
        label: str = "LogWatcher",
        thread_name: str = "log-watcher",
        session_key: Optional[Callable[[dict], Optional[str]]] = None,
        session_timeout_s: Optional[float] = None,
    ):
        base = Path(log_path) if log_path else (default_log or DEFAULT_LOG)
        # Caminho relativo e resolvido a partir da raiz do repositorio, nao do
        # diretorio de trabalho: em producao o servico systemd roda com
        # WorkingDirectory em backend/, onde `data/` nao existe.
        self._path        = base if base.is_absolute() else (Path(__file__).parent.parent / base)
        self._callback     = on_session
        self._sessions: dict[str, list] = defaultdict(list)
        self._running      = False
        self._thread: Optional[threading.Thread] = None
        self._session_end  = session_end_events or _SESSION_END
        self._label        = label
        self._thread_name  = thread_name

        # Como identificar a que sessao um evento pertence. O Cowrie traz um
        # campo `session` pronto; o Dionaea real nao tem nenhum, e o
        # agrupamento precisa ser sintetizado (na pratica, por IP de origem).
        self._session_key = session_key or (lambda ev: ev.get("session"))

        # Sessoes sintetizadas nao tem evento de encerramento: fecham por
        # inatividade. Quando definido, uma sessao e entregue ao classificador
        # apos este intervalo sem eventos novos.
        self._session_timeout_s = session_timeout_s
        self._last_seen: dict[str, float] = {}

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True, name=self._thread_name)
        self._thread.start()
        print(f"[{self._label}] Monitorando: {self._path}")
        if not self._path.exists():
            print(
                f"[{self._label}] AVISO: {self._path} nao existe. O watcher fica "
                "aguardando o arquivo aparecer — se o honeypot ja estiver rodando, "
                "confira o caminho configurado."
            )

    def stop(self):
        self._running = False

    # ── thread principal ─────────────────────────────────────────────────────

    def _rotated(self, f) -> bool:
        """Diz se o arquivo aberto em `f` deixou de ser o arquivo do caminho.

        O tpotinit rotaciona os logs dos honeypots a cada restart do stack
        (cowrie.json vira cowrie.json.1.gz e um arquivo novo nasce no lugar).
        Sem esta checagem o watcher seguiria lendo o descritor antigo e pararia
        de ver eventos em silencio — sem erro, sem log — ate alguem reiniciar o
        backend por outro motivo.
        """
        try:
            on_disk = self._path.stat()
        except OSError:
            return True                       # sumiu: rotacao em andamento

        here = os.fstat(f.fileno())
        if (on_disk.st_ino, on_disk.st_dev) != (here.st_ino, here.st_dev):
            return True                       # outro arquivo ocupa o caminho

        return on_disk.st_size < f.tell()     # truncado atras da nossa posicao

    def _run(self):
        # Começa no final do arquivo (ignora histórico ao iniciar)
        pos = self._path.stat().st_size if self._path.exists() else 0

        while self._running:
            if not self._path.exists():
                time.sleep(2)
                continue

            try:
                with open(self._path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    while self._running:
                        line = f.readline()
                        if line:
                            pos = f.tell()
                            self._process(line.strip())
                            continue

                        # Sem linha nova: momento de fechar sessoes vencidas e
                        # de checar rotacao, antes de dormir.
                        self._flush_stale()

                        # O arquivo novo comeca do zero, entao a posicao
                        # tambem volta para o inicio.
                        if self._rotated(f):
                            print(f"[{self._label}] Log rotacionado — reabrindo {self._path}")
                            pos = 0
                            break

                        time.sleep(0.3)
            except OSError:
                time.sleep(2)

    def _process(self, line: str):
        if not line:
            return
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return

        sid = self._session_key(ev)
        if not sid:
            return

        self._sessions[sid].append(ev)
        self._last_seen[sid] = time.monotonic()

        if ev.get("eventid") in self._session_end:
            self._flush(sid)

    def _flush(self, sid: str):
        """Entrega a sessao ao classificador e esquece o estado dela."""
        events = self._sessions.pop(sid, [])
        self._last_seen.pop(sid, None)
        if not events:
            return
        try:
            self._callback(sid, events)
        except Exception as exc:
            print(f"[{self._label}] Erro no callback da sessao {sid}: {exc}")

    def _flush_stale(self):
        """Fecha sessoes paradas ha mais tempo que `session_timeout_s`.

        Necessario para honeypots cujo log nao marca fim de sessao — sem isso
        os eventos ficariam acumulados em memoria para sempre, sem nunca serem
        classificados.
        """
        if not self._session_timeout_s:
            return
        agora = time.monotonic()
        vencidas = [sid for sid, visto in self._last_seen.items()
                    if agora - visto >= self._session_timeout_s]
        for sid in vencidas:
            self._flush(sid)
