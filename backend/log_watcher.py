"""
Monitora o arquivo de log de um honeypot (JSONL) em tempo real.
Agrupa eventos por session_id e dispara callback quando a sessão é encerrada.

Genérico o suficiente para Cowrie e Dionaea: cada instância recebe o caminho
do log e o conjunto de eventos que marcam o fim de uma sessão.
"""

import json
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
    ):
        self._path        = Path(log_path) if log_path else (default_log or DEFAULT_LOG)
        self._callback     = on_session
        self._sessions: dict[str, list] = defaultdict(list)
        self._running      = False
        self._thread: Optional[threading.Thread] = None
        self._session_end  = session_end_events or _SESSION_END
        self._label        = label
        self._thread_name  = thread_name

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True, name=self._thread_name)
        self._thread.start()
        print(f"[{self._label}] Monitorando: {self._path}")

    def stop(self):
        self._running = False

    # ── thread principal ─────────────────────────────────────────────────────

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
                        if not line:
                            time.sleep(0.3)
                            continue
                        pos = f.tell()
                        self._process(line.strip())
            except OSError:
                time.sleep(2)

    def _process(self, line: str):
        if not line:
            return
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return

        sid = ev.get("session")
        if not sid:
            return

        self._sessions[sid].append(ev)

        if ev.get("eventid") in self._session_end:
            events = self._sessions.pop(sid, [])
            if events:
                try:
                    self._callback(sid, events)
                except Exception as exc:
                    print(f"[{self._label}] Erro no callback da sessao {sid}: {exc}")
