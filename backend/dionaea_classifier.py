"""
Carrega o modelo treinado do Dionaea e classifica sessões em tempo real.
Replica a extração de features de data_pipeline/extract_dionaea_features.py
para funcionar de forma autônoma no backend (mesmo padrão de classifier.py,
usado para o Cowrie).
"""

import statistics
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

MODEL_PATH = Path(__file__).parent.parent / "ml" / "dionaea" / "models" / "dionaea_rf.joblib"

FEATURE_COLS = [
    "connection_count", "unique_ports", "unique_protocols", "session_duration_s",
    "avg_connection_interval_ms", "min_connection_interval_ms",
    "has_shellcode", "has_download", "payload_size_avg", "login_attempt_count",
]

_CONNECT_EVENTS = {"dionaea.connection.tcp.accept", "dionaea.connection.udp.accept"}


def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")


def _extract(events: list) -> dict:
    connects  = [e for e in events if e["eventid"] in _CONNECT_EVENTS]
    data_evs  = [e for e in events if e["eventid"] == "dionaea.data.in"]
    logins    = [e for e in events if e["eventid"] == "dionaea.login.attempt"]
    downloads = [e for e in events if e["eventid"] == "dionaea.download.complete"]
    free_ev   = next((e for e in events if e["eventid"] == "dionaea.connection.free"), None)

    if free_ev and "duration" in free_ev:
        duration_s = float(free_ev["duration"])
    elif events:
        ts_sorted  = sorted(_parse_ts(e["timestamp"]) for e in events)
        duration_s = (ts_sorted[-1] - ts_sorted[0]).total_seconds()
    else:
        duration_s = 0.0

    conn_ts = sorted(_parse_ts(e["timestamp"]) for e in connects)
    if len(conn_ts) >= 2:
        intervals = [(conn_ts[i+1] - conn_ts[i]).total_seconds() * 1000 for i in range(len(conn_ts) - 1)]
        avg_int   = sum(intervals) / len(intervals)
        min_int   = min(intervals)
    else:
        avg_int = min_int = 0.0

    sizes = [e.get("data_length", 0) for e in data_evs]

    return {
        "connection_count":           len(connects),
        "unique_ports":               len({e.get("dst_port") for e in connects}),
        "unique_protocols":           len({e.get("protocol") for e in connects}),
        "session_duration_s":         round(duration_s, 3),
        "avg_connection_interval_ms": round(avg_int, 1),
        "min_connection_interval_ms": round(min_int, 1),
        "has_shellcode":              int(any(e.get("has_shellcode") for e in data_evs)),
        "has_download":               int(bool(downloads)),
        "payload_size_avg":           round(statistics.mean(sizes), 1) if sizes else 0.0,
        "login_attempt_count":        len(logins),
    }


class DionaeaClassifier:
    def __init__(self):
        self._model = None
        self._le    = None

    def load(self):
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Modelo nao encontrado: {MODEL_PATH}\n"
                "Execute: cd ml/dionaea && python train.py"
            )
        artifact    = joblib.load(MODEL_PATH)
        self._model = artifact["model"]
        self._le    = artifact["label_encoder"]
        print(f"[DionaeaClassifier] Modelo carregado: {MODEL_PATH.name}")

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


classifier = DionaeaClassifier()
