import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent.parent / "data" / "beeia.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attacks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT    UNIQUE NOT NULL,
    src_ip           TEXT    NOT NULL,
    attack_type      TEXT    NOT NULL,
    confidence       REAL    NOT NULL,
    timestamp        TEXT    NOT NULL,
    login_attempts   INTEGER DEFAULT 0,
    login_success    INTEGER DEFAULT 0,
    command_count    INTEGER DEFAULT 0,
    session_duration_s REAL  DEFAULT 0,
    has_reverse_shell  INTEGER DEFAULT 0,
    has_wget_curl      INTEGER DEFAULT 0,
    has_recon_commands INTEGER DEFAULT 0,
    has_file_download  INTEGER DEFAULT 0,
    country          TEXT,
    city             TEXT,
    latitude         REAL,
    longitude        REAL,
    blocked          INTEGER DEFAULT 0,
    created_at       TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip           TEXT PRIMARY KEY,
    blocked_at   TEXT DEFAULT (datetime('now')),
    attack_count INTEGER DEFAULT 0,
    reason       TEXT
);
"""


@contextmanager
def _db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with _db() as conn:
        conn.executescript(_SCHEMA)


def insert_attack(attack: dict) -> bool:
    with _db() as conn:
        cur = conn.execute("""
            INSERT OR IGNORE INTO attacks (
                session_id, src_ip, attack_type, confidence, timestamp,
                login_attempts, login_success, command_count, session_duration_s,
                has_reverse_shell, has_wget_curl, has_recon_commands, has_file_download,
                country, city, latitude, longitude, blocked
            ) VALUES (
                :session_id, :src_ip, :attack_type, :confidence, :timestamp,
                :login_attempts, :login_success, :command_count, :session_duration_s,
                :has_reverse_shell, :has_wget_curl, :has_recon_commands, :has_file_download,
                :country, :city, :latitude, :longitude, :blocked
            )
        """, attack)
        return cur.lastrowid is not None


def get_stats() -> dict:
    with _db() as conn:
        total    = conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        uniq_ips = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM attacks").fetchone()[0]
        blocked  = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
        last24h  = conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE created_at >= datetime('now','-1 day')"
        ).fetchone()[0]
        type_rows = conn.execute(
            "SELECT attack_type, COUNT(*) FROM attacks GROUP BY attack_type"
        ).fetchall()
        type_counts = {r[0]: r[1] for r in type_rows}
        return {
            "total_attacks":      total,
            "unique_ips":         uniq_ips,
            "blocked_count":      blocked,
            "attacks_last_24h":   last24h,
            "attack_type_counts": type_counts,
            "top_attack_type":    max(type_counts, key=type_counts.get) if type_counts else "none",
        }


def get_attacks(limit: int = 50, offset: int = 0, attack_type: Optional[str] = None) -> list:
    with _db() as conn:
        if attack_type:
            rows = conn.execute(
                "SELECT * FROM attacks WHERE attack_type=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (attack_type, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM attacks ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]


def get_chart_data(hours: int = 24) -> list:
    with _db() as conn:
        rows = conn.execute("""
            SELECT strftime('%Y-%m-%dT%H:00:00', created_at) AS hour,
                   attack_type, COUNT(*) AS count
            FROM   attacks
            WHERE  created_at >= datetime('now', :delta)
            GROUP  BY hour, attack_type
            ORDER  BY hour
        """, {"delta": f"-{hours} hours"}).fetchall()
        return [dict(r) for r in rows]


def get_geo_data() -> list:
    with _db() as conn:
        rows = conn.execute("""
            SELECT src_ip, attack_type, country, city, latitude, longitude,
                   COUNT(*) AS count, MAX(blocked) AS blocked
            FROM   attacks
            WHERE  latitude IS NOT NULL
            GROUP  BY src_ip
        """).fetchall()
        return [dict(r) for r in rows]


def get_top_ips(limit: int = 10) -> list:
    with _db() as conn:
        rows = conn.execute("""
            SELECT src_ip, COUNT(*) AS count, country,
                   GROUP_CONCAT(DISTINCT attack_type) AS attack_types,
                   MAX(blocked) AS blocked
            FROM   attacks
            GROUP  BY src_ip
            ORDER  BY count DESC
            LIMIT  ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def block_ip(ip: str, reason: str = "ML detection") -> None:
    with _db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE src_ip=?", (ip,)
        ).fetchone()[0]
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, attack_count, reason) VALUES (?,?,?)",
            (ip, count, reason),
        )
        conn.execute("UPDATE attacks SET blocked=1 WHERE src_ip=?", (ip,))


def unblock_ip(ip: str) -> None:
    with _db() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
        conn.execute("UPDATE attacks SET blocked=0 WHERE src_ip=?", (ip,))


def get_blocked_ips() -> list:
    with _db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
        ).fetchall()]


def is_blocked(ip: str) -> bool:
    with _db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM blocked_ips WHERE ip=?", (ip,)
        ).fetchone()[0] > 0
