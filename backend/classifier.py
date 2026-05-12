"""
Carrega o modelo treinado do Cowrie e classifica sessões em tempo real.
Replica a extração de features de data_pipeline/extract_features.py
para funcionar de forma autônoma no backend.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

MODEL_PATH = Path(__file__).parent.parent / "ml" / "cowrie" / "models" / "cowrie_rf.joblib"

FEATURE_COLS = [
    "login_attempt_count", "login_success", "unique_usernames", "unique_passwords",
    "session_duration_s", "command_count", "avg_login_interval_ms", "min_login_interval_ms",
    "has_wget_curl", "has_reverse_shell", "has_recon_commands", "has_file_download",
    "command_rate_per_min",
]

_RECON = re.compile(
    r"\b(uname|whoami|hostname|id\b|cat\s+/etc/(passwd|shadow|os-release|crontab)|"
    r"ls\s+-?l?a?\s*/|ps\s+(aux|ef)|netstat|ifconfig|ip\s+a\b|df\s+-h|free\s+-m|"
    r"printenv|env\b|last\b|who\b|crontab\s+-l)\b"
)
_REVERSE_SHELL = re.compile(
    r"/dev/tcp/|nc\s+-e|bash\s+-i\s+>&|python\S*\s+.+socket.+connect|perl.+socket"
)
_WGET_CURL = re.compile(r"\b(wget|curl)\b")


def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")


def _extract(events: list) -> dict:
    connect   = next((e for e in events if e["eventid"] == "cowrie.session.connect"), None)
    closed    = next((e for e in events if e["eventid"] == "cowrie.session.closed"), None)
    failures  = [e for e in events if e["eventid"] == "cowrie.login.failed"]
    successes = [e for e in events if e["eventid"] == "cowrie.login.success"]
    commands  = [e for e in events if e["eventid"] == "cowrie.command.input"]
    downloads = [e for e in events if e["eventid"] == "cowrie.session.file_download"]

    if connect and closed:
        duration_s = (_parse_ts(closed["timestamp"]) - _parse_ts(connect["timestamp"])).total_seconds()
    elif closed:
        duration_s = float(closed.get("duration", 0))
    else:
        duration_s = 0.0

    fail_ts = sorted(_parse_ts(e["timestamp"]) for e in failures)
    if len(fail_ts) >= 2:
        intervals  = [(fail_ts[i+1] - fail_ts[i]).total_seconds() * 1000 for i in range(len(fail_ts) - 1)]
        avg_int    = sum(intervals) / len(intervals)
        min_int    = min(intervals)
    else:
        avg_int = min_int = 0.0

    cmd_text  = " ".join(e.get("input", "") for e in commands).lower()
    cmd_rate  = (len(commands) / duration_s * 60) if duration_s > 0 else 0.0

    return {
        "login_attempt_count":   len(failures),
        "login_success":         int(bool(successes)),
        "unique_usernames":      len({e.get("username", "") for e in failures}),
        "unique_passwords":      len({e.get("password", "") for e in failures}),
        "session_duration_s":    round(duration_s, 3),
        "command_count":         len(commands),
        "avg_login_interval_ms": round(avg_int, 1),
        "min_login_interval_ms": round(min_int, 1),
        "has_wget_curl":         int(bool(_WGET_CURL.search(cmd_text))),
        "has_reverse_shell":     int(bool(_REVERSE_SHELL.search(cmd_text))),
        "has_recon_commands":    int(bool(_RECON.search(cmd_text))),
        "has_file_download":     int(bool(downloads)),
        "command_rate_per_min":  round(cmd_rate, 3),
    }


class CowrieClassifier:
    def __init__(self):
        self._model = None
        self._le    = None

    def load(self):
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Modelo nao encontrado: {MODEL_PATH}\n"
                "Execute: cd ml/cowrie && python train.py"
            )
        artifact    = joblib.load(MODEL_PATH)
        self._model = artifact["model"]
        self._le    = artifact["label_encoder"]
        print(f"[Classifier] Modelo carregado: {MODEL_PATH.name}")

    def predict(self, events: list) -> Optional[dict]:
        if self._model is None:
            return None
        features = _extract(events)
        X        = np.array([[features[c] for c in FEATURE_COLS]], dtype=float)
        proba    = self._model.predict_proba(X)[0]
        idx      = int(np.argmax(proba))
        return {
            "attack_type": str(self._le.classes_[idx]),
            "confidence":  round(float(proba[idx]), 4),
            "features":    features,
        }


classifier = CowrieClassifier()
