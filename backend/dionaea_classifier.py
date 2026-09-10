"""
Carrega o modelo do Dionaea e classifica sessoes em tempo real.

Le o formato que o Dionaea REALMENTE escreve, verificado contra uma captura de
14 dias em producao:

    {"connection": {"protocol": "smbd", "transport": "tcp", "type": "accept"},
     "dst_ip": "172.19.0.2", "dst_port": 445, "src_ip": "1.2.3.4",
     "src_port": 40000, "timestamp": "2026-09-06T02:24:27.045448",
     "credentials": {"username": ["sa"], "password": [""]}}

A versao anterior deste modulo esperava o formato do gerador sintetico
(`{"eventid": "dionaea.connection.tcp.accept", "session": "..."}`), que nao
existe fora dos dados que nos mesmos geramos. Como o log real nao tem campo
`session`, o agrupamento e sintetizado pelo `LogWatcher` (por IP de origem,
com fechamento por inatividade).

Sete features, e nao dez: `has_download` so aparece no dionaea.sqlite,
`payload_size_avg` nao e registrado em lugar nenhum e `has_shellcode` depende
da tabela `emu_profiles`, vazia em 14 dias de captura. Treinar com features
indisponiveis em producao criaria distorcao entre treino e execucao — ver
`ml/dionaea/train_real.py`.

Mesmo padrao de `classifier.py` (Cowrie): a extracao e reimplementada aqui,
em vez de importada de `data_pipeline/`, para o backend em producao nao
depender do modulo de pipeline offline. Mudancas em uma precisam ser
espelhadas na outra (`data_pipeline/extract_dionaea_real.py`).
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

_MODELS_DIR = Path(__file__).parent.parent / "ml" / "dionaea" / "models"

# Modelo treinado com trafego real. O sintetico (`dionaea_rf.joblib`) fica
# disponivel como alternativa, mas preve uma unica classe em trafego real —
# ver Docs/artigo-tcc2-consolidado.md, secao 5.5.
MODEL_PATH = _MODELS_DIR / "dionaea_real_rf.joblib"

FEATURE_COLS = [
    "connection_count",
    "unique_ports",
    "unique_protocols",
    "session_duration_s",
    "avg_connection_interval_ms",
    "min_connection_interval_ms",
    "login_attempt_count",
]


def _parse_ts(ts: str) -> Optional[datetime]:
    """O Dionaea escreve sem sufixo Z; aceita com e sem microssegundos."""
    if not ts:
        return None
    ts = ts.replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _conexoes(events: list) -> list:
    return [e for e in events
            if (e.get("connection") or {}).get("type") == "accept"]


def _tentativas_de_login(ev: dict) -> int:
    creds = ev.get("credentials") or {}
    return len(creds.get("username") or [])


def _extract(events: list) -> dict:
    conexoes = _conexoes(events) or events

    marcas = sorted(t for t in (_parse_ts(e.get("timestamp")) for e in conexoes) if t)
    duracao = (marcas[-1] - marcas[0]).total_seconds() if len(marcas) >= 2 else 0.0

    if len(marcas) >= 2:
        intervalos = [(marcas[i + 1] - marcas[i]).total_seconds() * 1000
                      for i in range(len(marcas) - 1)]
        intervalo_medio = sum(intervalos) / len(intervalos)
        intervalo_minimo = min(intervalos)
    else:
        intervalo_medio = intervalo_minimo = 0.0

    return {
        "connection_count":           len(conexoes),
        "unique_ports":               len({e.get("dst_port") for e in conexoes}),
        "unique_protocols":           len({(e.get("connection") or {}).get("protocol")
                                           for e in conexoes}),
        "session_duration_s":         round(duracao, 3),
        "avg_connection_interval_ms": round(intervalo_medio, 1),
        "min_connection_interval_ms": round(intervalo_minimo, 1),
        "login_attempt_count":        sum(_tentativas_de_login(e) for e in events),
        # Guardado para o registro do ataque, nao usado como feature.
        "protocol":                   (conexoes[0].get("connection") or {}).get("protocol")
                                      if conexoes else None,
    }


class DionaeaClassifier:
    def __init__(self, model_path: Path = MODEL_PATH):
        self._model = None
        self._le = None
        self._path = model_path

    def load(self):
        if not self._path.exists():
            raise FileNotFoundError(
                "Modelo do Dionaea nao encontrado: {}. "
                "Treine com: cd ml/dionaea && python train_real.py".format(self._path))
        bundle = joblib.load(self._path)
        self._model = bundle["model"]
        self._le = bundle["label_encoder"]
        print("[DionaeaClassifier] Modelo carregado: {}".format(self._path.name))

    def predict(self, events: list) -> Optional[dict]:
        if self._model is None:
            return None
        features = _extract(events)
        X = np.array([[features[c] for c in FEATURE_COLS]], dtype=float)
        proba = self._model.predict_proba(X)[0]
        idx = int(np.argmax(proba))
        return {
            "attack_type": str(self._le.classes_[idx]),
            "confidence":  round(float(proba[idx]), 4),
            "features":    features,
        }


classifier = DionaeaClassifier()
