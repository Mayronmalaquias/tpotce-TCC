import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent.parent / "data" / "beeia.db"

# Colunas comportamentais são um superconjunto: cada honeypot preenche apenas
# o subconjunto relevante (Cowrie: login/comandos/shell; Dionaea: conexões/
# portas/payload). "honeypot" e "protocol" identificam a origem do evento.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS attacks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT    UNIQUE NOT NULL,
    honeypot         TEXT    NOT NULL DEFAULT 'cowrie',
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
    protocol           TEXT,
    connection_count   INTEGER DEFAULT 0,
    unique_ports        INTEGER DEFAULT 0,
    has_shellcode        INTEGER DEFAULT 0,
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

# Colunas adicionadas após o schema original — aplicadas via ALTER TABLE em
# bancos já existentes (SQLite não suporta "ADD COLUMN IF NOT EXISTS").
_MIGRATIONS = {
    "honeypot":         "TEXT NOT NULL DEFAULT 'cowrie'",
    "protocol":         "TEXT",
    "connection_count": "INTEGER DEFAULT 0",
    "unique_ports":     "INTEGER DEFAULT 0",
    "has_shellcode":    "INTEGER DEFAULT 0",
}

_ATTACK_COLUMNS = [
    "session_id", "honeypot", "src_ip", "attack_type", "confidence", "timestamp",
    "login_attempts", "login_success", "command_count", "session_duration_s",
    "has_reverse_shell", "has_wget_curl", "has_recon_commands", "has_file_download",
    "protocol", "connection_count", "unique_ports", "has_shellcode",
    "country", "city", "latitude", "longitude", "blocked",
]

_ATTACK_DEFAULTS = {
    "honeypot": "cowrie",
    "login_attempts": 0, "login_success": 0, "command_count": 0, "session_duration_s": 0.0,
    "has_reverse_shell": 0, "has_wget_curl": 0, "has_recon_commands": 0, "has_file_download": 0,
    "protocol": None, "connection_count": 0, "unique_ports": 0, "has_shellcode": 0,
    "country": None, "city": None, "latitude": None, "longitude": None, "blocked": 0,
}


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
        existing = {row[1] for row in conn.execute("PRAGMA table_info(attacks)").fetchall()}
        for col, ddl in _MIGRATIONS.items():
            if col not in existing:
                conn.execute(f"ALTER TABLE attacks ADD COLUMN {col} {ddl}")


def insert_attack(attack: dict) -> bool:
    row = {**_ATTACK_DEFAULTS, **attack}
    with _db() as conn:
        cur = conn.execute(f"""
            INSERT OR IGNORE INTO attacks ({", ".join(_ATTACK_COLUMNS)})
            VALUES ({", ".join(":" + c for c in _ATTACK_COLUMNS)})
        """, row)
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
        honeypot_rows = conn.execute(
            "SELECT honeypot, COUNT(*) FROM attacks GROUP BY honeypot"
        ).fetchall()
        honeypot_counts = {r[0]: r[1] for r in honeypot_rows}
        return {
            "total_attacks":      total,
            "unique_ips":         uniq_ips,
            "blocked_count":      blocked,
            "attacks_last_24h":   last24h,
            "attack_type_counts": type_counts,
            "honeypot_counts":    honeypot_counts,
            "top_attack_type":    max(type_counts, key=type_counts.get) if type_counts else "none",
        }


def get_attacks(
    limit: int = 50,
    offset: int = 0,
    attack_type: Optional[str] = None,
    honeypot: Optional[str] = None,
) -> list:
    with _db() as conn:
        where, params = [], []
        if attack_type:
            where.append("attack_type=?")
            params.append(attack_type)
        if honeypot:
            where.append("honeypot=?")
            params.append(honeypot)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = conn.execute(
            f"SELECT * FROM attacks {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
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
            SELECT src_ip, attack_type, honeypot, country, city, latitude, longitude,
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


def get_report_data(hours: int = 24) -> dict:
    """Agrega estatísticas do banco para alimentar o módulo LLM (backend/llm.py)."""
    with _db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        uniq_ips = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM attacks").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
        attacks_period = conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE created_at >= datetime('now', :delta)",
            {"delta": f"-{hours} hours"},
        ).fetchone()[0]

        type_rows = conn.execute(
            "SELECT attack_type, COUNT(*) FROM attacks GROUP BY attack_type ORDER BY COUNT(*) DESC"
        ).fetchall()
        type_counts = {r[0]: r[1] for r in type_rows}

        honeypot_rows = conn.execute(
            "SELECT honeypot, COUNT(*) FROM attacks GROUP BY honeypot ORDER BY COUNT(*) DESC"
        ).fetchall()
        honeypot_counts = {r[0]: r[1] for r in honeypot_rows}

        country_rows = conn.execute("""
            SELECT country, COUNT(*) AS c FROM attacks
            WHERE country IS NOT NULL AND country != ''
            GROUP BY country ORDER BY c DESC LIMIT 10
        """).fetchall()
        countries = {r[0]: r[1] for r in country_rows}

        avg_row = conn.execute("""
            SELECT AVG(login_attempts), AVG(command_count), AVG(session_duration_s),
                   AVG(has_reverse_shell) * 100, AVG(has_wget_curl) * 100,
                   AVG(has_recon_commands) * 100, AVG(has_file_download) * 100
            FROM attacks
        """).fetchone()

    return {
        "period_hours":             hours,
        "total_attacks":            total,
        "attacks_period":           attacks_period,
        "unique_ips":               uniq_ips,
        "blocked_count":            blocked,
        "attack_type_distribution": type_counts,
        "honeypot_counts":          honeypot_counts,
        "top_ips":                  get_top_ips(limit=5),
        "countries":                countries,
        "avg_features": {
            "avg_login_attempts":     avg_row[0] or 0,
            "avg_command_count":      avg_row[1] or 0,
            "avg_session_duration_s": avg_row[2] or 0,
            "reverse_shell_pct":      avg_row[3] or 0,
            "wget_curl_pct":          avg_row[4] or 0,
            "recon_pct":              avg_row[5] or 0,
            "file_download_pct":      avg_row[6] or 0,
        },
    }
