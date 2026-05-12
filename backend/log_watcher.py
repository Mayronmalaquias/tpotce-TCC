"""
Monitora o arquivo de log do Cowrie (JSONL) em tempo real.
Agrupa eventos por session_id e dispara callback quando a sessão é encerrada.
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
    ):
        self._path     = Path(log_path) if log_path else DEFAULT_LOG
        self._callback = on_session
        self._sessions: dict[str, list] = defaultdict(list)
        self._running  = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True, name="log-watcher")
        self._thread.start()
        print(f"[LogWatcher] Monitorando: {self._path}")

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

        if ev.get("eventid") in _SESSION_END:
            events = self._sessions.pop(sid, [])
            if events:
                try:
                    self._callback(sid, events)
                except Exception as exc:
                    print(f"[LogWatcher] Erro no callback da sessao {sid}: {exc}")
