"""
BeeIA — Backend principal (FastAPI).

Endpoints REST:
  GET  /api/stats
  GET  /api/attacks          ?limit &offset &attack_type
  GET  /api/attacks/chart    ?hours
  GET  /api/attacks/top-ips  ?limit
  GET  /api/geo
  GET  /api/blocked
  POST /api/block/{ip}
  DEL  /api/block/{ip}

WebSocket:
  WS /ws  → emite { type: "new_attack"|"stats", data: {...} }

Iniciar:
  uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import asyncio
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

import database
import firewall
import geo
from classifier import classifier
from log_watcher import LogWatcher

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


def _on_session(session_id: str, events: list):
    connect_ev = next((e for e in events if e["eventid"] == "cowrie.session.connect"), None)
    src_ip     = connect_ev.get("src_ip", "unknown") if connect_ev else "unknown"
    timestamp  = connect_ev.get("timestamp", "")    if connect_ev else ""

    result = classifier.predict(events)
    if not result:
        return

    feat     = result["features"]
    location = geo.get_location(src_ip) or {}

    attack = {
        "session_id":          session_id,
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

    database.insert_attack(attack)
    print(f"[Attack] {src_ip:<18} {result['attack_type']:<22} conf={result['confidence']:.0%}")

    # Broadcast via WebSocket
    if _event_loop and not _event_loop.is_closed():
        asyncio.run_coroutine_threadsafe(
            ws_manager.broadcast({"type": "new_attack", "data": attack}),
            _event_loop,
        )

    # Auto-bloqueio por confiança alta
    if result["confidence"] >= AUTO_BLOCK_THRESHOLD and src_ip not in ("unknown", "127.0.0.1"):
        ok, msg = firewall.block_ip(src_ip)
        if ok:
            database.block_ip(src_ip, reason=f"Auto: {result['attack_type']}")
            print(f"[Firewall] Bloqueado {src_ip} — {msg}")
            if _event_loop and not _event_loop.is_closed():
                asyncio.run_coroutine_threadsafe(
                    ws_manager.broadcast({"type": "ip_blocked", "data": {"ip": src_ip}}),
                    _event_loop,
                )


# ── lifecycle ─────────────────────────────────────────────────────────────────

log_path = os.getenv("COWRIE_LOG_PATH")
watcher  = LogWatcher(on_session=_on_session, log_path=log_path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _event_loop
    _event_loop = asyncio.get_event_loop()

    database.init()
    classifier.load()
    watcher.start()
    print("[BeeIA] Backend pronto.")

    yield

    watcher.stop()
    print("[BeeIA] Backend encerrado.")


# ── app ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="BeeIA API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── rotas ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def stats():
    return database.get_stats()


@app.get("/api/attacks")
def attacks(
    limit:       int            = Query(50,   ge=1, le=200),
    offset:      int            = Query(0,    ge=0),
    attack_type: Optional[str]  = Query(None),
):
    return database.get_attacks(limit=limit, offset=offset, attack_type=attack_type)


@app.get("/api/attacks/chart")
def chart(hours: int = Query(24, ge=1, le=168)):
    return database.get_chart_data(hours=hours)


@app.get("/api/attacks/top-ips")
def top_ips(limit: int = Query(10, ge=1, le=50)):
    return database.get_top_ips(limit=limit)


@app.get("/api/geo")
def geo_data():
    return database.get_geo_data()


@app.get("/api/blocked")
def blocked():
    return database.get_blocked_ips()


@app.post("/api/block/{ip}")
def block(ip: str):
    ok, msg = firewall.block_ip(ip)
    if ok:
        database.block_ip(ip, reason="Manual")
    return {"success": ok, "message": msg}


@app.delete("/api/block/{ip}")
def unblock(ip: str):
    ok, msg = firewall.unblock_ip(ip)
    if ok:
        database.unblock_ip(ip)
    return {"success": ok, "message": msg}


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    # Envia snapshot de stats ao conectar
    await ws.send_json({"type": "stats", "data": database.get_stats()})
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
