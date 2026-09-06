"""
BeeIA — Backend principal (FastAPI).

Endpoints REST:
  GET  /api/stats
  GET  /api/attacks          ?limit &offset &attack_type &honeypot
  GET  /api/attacks/chart    ?hours
  GET  /api/attacks/top-ips  ?limit
  GET  /api/geo
  GET  /api/blocked
  GET  /api/report          ?hours (relatório em linguagem natural via LLM)
  POST /api/block/{ip}
  DEL  /api/block/{ip}

WebSocket:
  WS /ws  → emite { type: "new_attack"|"stats", data: {...} }

Segurança (ver backend/auth.py, backend/ratelimit.py e
md-usotcc/proteger-dashboard.md antes de expor publicamente):
  - Todas as rotas acima e o /ws exigem o header `X-API-Key` (ou ?api_key=
    no WS) quando BEEIA_API_KEY está definida no .env. Sem a variável, a API
    fica sem autenticação (modo dev local).
  - CORS restrito às origens em CORS_ORIGINS (.env), não mais "*".
  - Rate limit por IP: global + limite mais estrito em /api/report (custa
    chamada de API paga).
  - Este backend não deve ser exposto diretamente à internet — coloque atrás
    de um proxy reverso autenticado (ver docker/nginx/dist/conf/beeia.conf).

Iniciar:
  uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

import database
import firewall
import geo
import llm
from auth import auth_enabled, require_api_key, ws_key_is_valid
from classifier import classifier as cowrie_classifier
from dionaea_classifier import classifier as dionaea_classifier
from log_watcher import LogWatcher
from ratelimit import RateLimiter

# ── WebSocket manager ─────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._clients.append(ws)

    def disconnect(self, ws: WebSocket):
        self._clients.discard(ws) if hasattr(self._clients, "discard") else None
        try:
            self._clients.remove(ws)
        except ValueError:
            pass

    async def broadcast(self, payload: dict):
        dead = []
        for ws in list(self._clients):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = ConnectionManager()
_event_loop: Optional[asyncio.AbstractEventLoop] = None

# ── callback do LogWatcher (thread de background) ─────────────────────────────

AUTO_BLOCK_THRESHOLD = float(os.getenv("AUTO_BLOCK_THRESHOLD", "0.95"))


def _finalize_attack(attack: dict, confidence: float):
    """Persiste, transmite via WebSocket e aciona auto-bloqueio — comum a
    qualquer honeypot (Cowrie ou Dionaea) após a classificação de uma sessão."""
    database.insert_attack(attack)
    src_ip = attack["src_ip"]
    print(f"[Attack] {src_ip:<18} {attack['attack_type']:<22} "
          f"conf={confidence:.0%}  [{attack['honeypot']}]")

    if _event_loop and not _event_loop.is_closed():
        asyncio.run_coroutine_threadsafe(
            ws_manager.broadcast({"type": "new_attack", "data": attack}),
            _event_loop,
        )

    if confidence >= AUTO_BLOCK_THRESHOLD and src_ip not in ("unknown", "127.0.0.1"):
        ok, msg = firewall.block_ip(src_ip)
        if ok:
            database.block_ip(src_ip, reason=f"Auto ({attack['honeypot']}): {attack['attack_type']}")
            print(f"[Firewall] Bloqueado {src_ip} — {msg}")
            if _event_loop and not _event_loop.is_closed():
                asyncio.run_coroutine_threadsafe(
                    ws_manager.broadcast({"type": "ip_blocked", "data": {"ip": src_ip}}),
                    _event_loop,
                )


def _on_session(session_id: str, events: list):
    """Callback do LogWatcher do Cowrie — sessão SSH/Telnet encerrada."""
    connect_ev = next((e for e in events if e["eventid"] == "cowrie.session.connect"), None)
    src_ip     = connect_ev.get("src_ip", "unknown") if connect_ev else "unknown"
    timestamp  = connect_ev.get("timestamp", "")    if connect_ev else ""

    result = cowrie_classifier.predict(events)
    if not result:
        return

    feat     = result["features"]
    location = geo.get_location(src_ip) or {}

    attack = {
        "session_id":          session_id,
        "honeypot":            "cowrie",
        "src_ip":              src_ip,
        "attack_type":         result["attack_type"],
        "confidence":          result["confidence"],
        "timestamp":           timestamp,
        "login_attempts":      feat["login_attempt_count"],
        "login_success":       feat["login_success"],
        "command_count":       feat["command_count"],
        "session_duration_s":  feat["session_duration_s"],
        "has_reverse_shell":   feat["has_reverse_shell"],
        "has_wget_curl":       feat["has_wget_curl"],
        "has_recon_commands":  feat["has_recon_commands"],
        "has_file_download":   feat["has_file_download"],
        "country":             location.get("country"),
        "city":                location.get("city"),
        "latitude":            location.get("latitude"),
        "longitude":           location.get("longitude"),
        "blocked":             0,
    }

    _finalize_attack(attack, result["confidence"])


def _on_dionaea_session(session_id: str, events: list):
    """Callback do LogWatcher do Dionaea — janela de conexoes de um IP encerrada.

    `session_id` aqui e o IP de origem: o log real do Dionaea nao tem campo
    `session`, entao o agrupamento e sintetizado pelo watcher e fechado por
    inatividade. Como o mesmo IP volta a atacar depois, o identificador
    persistido combina IP e horario para nao colidir entre janelas.
    """
    first     = events[0]
    src_ip    = first.get("src_ip", session_id)
    timestamp = first.get("timestamp", "")

    result = dionaea_classifier.predict(events)
    if not result:
        return

    feat     = result["features"]
    location = geo.get_location(src_ip) or {}

    attack = {
        "session_id":          f"{src_ip}-{timestamp}" if timestamp else session_id,
        "honeypot":            "dionaea",
        "src_ip":              src_ip,
        "attack_type":         result["attack_type"],
        "confidence":          result["confidence"],
        "timestamp":           timestamp,
        "protocol":            feat.get("protocol"),
        "connection_count":    feat["connection_count"],
        "unique_ports":        feat["unique_ports"],
        "has_shellcode":       0,   # emu_profiles vazia em captura real
        "has_file_download":   0,   # registrado so no dionaea.sqlite
        "session_duration_s":  feat["session_duration_s"],
        "login_attempts":      feat["login_attempt_count"],
        "country":             location.get("country"),
        "city":                location.get("city"),
        "latitude":            location.get("latitude"),
        "longitude":           location.get("longitude"),
        "blocked":             0,
    }

    _finalize_attack(attack, result["confidence"])


# ── lifecycle ─────────────────────────────────────────────────────────────────

cowrie_watcher = LogWatcher(
    on_session=_on_session,
    log_path=os.getenv("COWRIE_LOG_PATH"),
)
# O log real do Dionaea nao tem campo `session` nem evento de encerramento:
# sao conexoes soltas. A sessao e sintetizada por IP de origem e fechada apos
# DIONAEA_SESSION_TIMEOUT_S sem novos eventos daquele IP — mesmo criterio usado
# na analise offline (data_pipeline/extract_dionaea_real.py).
DIONAEA_SESSION_TIMEOUT_S = float(os.getenv("DIONAEA_SESSION_TIMEOUT_S", "300"))

dionaea_watcher = LogWatcher(
    on_session=_on_dionaea_session,
    log_path=os.getenv("DIONAEA_LOG_PATH"),
    default_log=Path(__file__).parent.parent / "data" / "dionaea" / "log" / "dionaea.json",
    label="DionaeaWatcher",
    thread_name="dionaea-watcher",
    session_key=lambda ev: ev.get("src_ip"),
    session_timeout_s=DIONAEA_SESSION_TIMEOUT_S,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _event_loop
    _event_loop = asyncio.get_event_loop()

    database.init()
    cowrie_classifier.load()
    try:
        dionaea_classifier.load()
        dionaea_watcher.start()
    except FileNotFoundError as e:
        print(f"[BeeIA] Dionaea desabilitado: {e}")
    cowrie_watcher.start()
    print("[BeeIA] Backend pronto.")

    yield

    cowrie_watcher.stop()
    dionaea_watcher.stop()
    print("[BeeIA] Backend encerrado.")


# ── app ───────────────────────────────────────────────────────────────────────

# Com BEEIA_API_KEY configurada, desliga a documentação automática (/docs,
# /redoc, /openapi.json) para não expor o formato da API sem necessidade.
_docs_kwargs = {"docs_url": None, "redoc_url": None, "openapi_url": None} if auth_enabled() else {}

app = FastAPI(
    title="BeeIA API",
    version="1.0.0",
    lifespan=lifespan,
    **_docs_kwargs,
)

CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

if not auth_enabled():
    print("[BeeIA] AVISO: BEEIA_API_KEY nao configurada — API rodando sem autenticacao (modo dev local).")

# `require_api_key`/`_global_rate_limit` só fazem sentido para requisições
# HTTP normais — um APIRouter dedicado evita que sejam avaliadas também para
# a rota WebSocket (que usa checagem própria, ver ws_key_is_valid).
_global_rate_limit = RateLimiter(max_calls=60, period_s=60)   # 60 req/min por IP em qualquer rota
# Limite adicional (mais estrito) só para /api/report, que dispara uma
# chamada paga à API da Anthropic — soma-se ao _global_rate_limit acima.
_report_rate_limit = RateLimiter(max_calls=5, period_s=600)   # 5 a cada 10 min por IP

api_router = APIRouter(dependencies=[Depends(require_api_key), Depends(_global_rate_limit)])

# ── rotas ─────────────────────────────────────────────────────────────────────

@api_router.get("/api/stats")
def stats():
    return database.get_stats()


@api_router.get("/api/attacks")
def attacks(
    limit:       int            = Query(50,   ge=1, le=200),
    offset:      int            = Query(0,    ge=0),
    attack_type: Optional[str]  = Query(None),
    honeypot:    Optional[str]  = Query(None, description="cowrie | dionaea"),
):
    return database.get_attacks(limit=limit, offset=offset, attack_type=attack_type, honeypot=honeypot)


@api_router.get("/api/attacks/chart")
def chart(hours: int = Query(24, ge=1, le=168)):
    return database.get_chart_data(hours=hours)


@api_router.get("/api/attacks/top-ips")
def top_ips(limit: int = Query(10, ge=1, le=50)):
    return database.get_top_ips(limit=limit)


@api_router.get("/api/geo")
def geo_data():
    return database.get_geo_data()


@api_router.get("/api/blocked")
def blocked():
    return database.get_blocked_ips()


@api_router.get("/api/report", dependencies=[Depends(_report_rate_limit)])
def report(hours: int = Query(24, ge=1, le=168)):
    data = database.get_report_data(hours=hours)
    try:
        text = llm.generate_report(data)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao gerar relatório: {e}")
    return {"report": text, "data": data}


@api_router.post("/api/block/{ip}")
def block(ip: str):
    ok, msg = firewall.block_ip(ip)
    if ok:
        database.block_ip(ip, reason="Manual")
    return {"success": ok, "message": msg}


@api_router.delete("/api/block/{ip}")
def unblock(ip: str):
    ok, msg = firewall.unblock_ip(ip)
    if ok:
        database.unblock_ip(ip)
    return {"success": ok, "message": msg}


app.include_router(api_router)

# ── WebSocket (fora do api_router — usa checagem própria, ver ws_key_is_valid) ─

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    if not ws_key_is_valid(ws):
        await ws.close(code=1008)  # policy violation
        return

    await ws_manager.connect(ws)
    # Envia snapshot de stats ao conectar
    await ws.send_json({"type": "stats", "data": database.get_stats()})
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
