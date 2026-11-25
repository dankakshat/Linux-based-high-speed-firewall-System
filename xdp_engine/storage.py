"""SQLite WAL persistence layer shared by the engine and Flask dashboard."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterator

from .models import Alert, BlockedIP, EngineStats, OperatingMode


class Storage:
    """Thread-safe SQLite store with WAL concurrency."""

    def __init__(self, db_path: str | Path = "engine.db") -> None:
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS engine_status (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    status TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    interface TEXT NOT NULL,
                    backend TEXT NOT NULL,
                    dropped INTEGER NOT NULL DEFAULT 0,
                    passed INTEGER NOT NULL DEFAULT 0,
                    tcp INTEGER NOT NULL DEFAULT 0,
                    udp INTEGER NOT NULL DEFAULT 0,
                    icmp INTEGER NOT NULL DEFAULT 0,
                    drop_rate_pps REAL NOT NULL DEFAULT 0.0,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mitre TEXT NOT NULL,
                    action TEXT NOT NULL,
                    block_seconds INTEGER NOT NULL,
                    enforced INTEGER NOT NULL,
                    details TEXT NOT NULL,
                    timestamp REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    blocked_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    hits INTEGER NOT NULL DEFAULT 0,
                    enforced INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS events_feed (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    level TEXT NOT NULL,
                    category TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp REAL NOT NULL
                );
                """
            )

    def update_status(
        self,
        status: str,
        mode: OperatingMode,
        interface: str,
        backend: str,
        stats: EngineStats,
    ) -> None:
        """Upsert live engine telemetry counters and status."""
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO engine_status (
                    id, status, mode, interface, backend,
                    dropped, passed, tcp, udp, icmp, drop_rate_pps, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    mode = excluded.mode,
                    interface = excluded.interface,
                    backend = excluded.backend,
                    dropped = excluded.dropped,
                    passed = excluded.passed,
                    tcp = excluded.tcp,
                    udp = excluded.udp,
                    icmp = excluded.icmp,
                    drop_rate_pps = excluded.drop_rate_pps,
                    updated_at = excluded.updated_at
                """,
                (
                    status,
                    mode.value,
                    interface,
                    backend,
                    stats.dropped,
                    stats.passed,
                    stats.tcp,
                    stats.udp,
                    stats.icmp,
                    stats.drop_rate_pps,
                    now,
                ),
            )

    def mark_offline(self) -> None:
        """Mark the engine offline in the status table."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE engine_status SET status = 'OFFLINE', updated_at = ? WHERE id = 1",
                (time.time(),),
            )

    def record_alert(self, alert: Alert) -> None:
        """Persist an alert record."""
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alerts (
                    rule_name, src_ip, severity, mitre, action,
                    block_seconds, enforced, details, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.rule_name,
                    alert.src_ip,
                    alert.severity,
                    ",".join(alert.mitre),
                    alert.action,
                    alert.block_seconds,
                    1 if alert.enforced else 0,
                    alert.details,
                    alert.timestamp,
                ),
            )

    def sync_blocked_ips(self, entries: list[BlockedIP]) -> None:
        """Replace active blocked IP snapshot with current backend state."""
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM blocked_ips")
            conn.executemany(
                """
                INSERT INTO blocked_ips (ip, reason, blocked_at, expires_at, hits, enforced)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        e.ip,
                        e.reason,
                        e.blocked_at,
                        e.expires_at,
                        e.hits,
                        1 if e.enforced else 0,
                    )
                    for e in entries
                ],
            )

    def add_feed_event(self, level: str, category: str, message: str) -> None:
        """Append a human-readable line to the live dashboard feed."""
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO events_feed (level, category, message, timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (level, category, message, time.time()),
            )
            # Keep feed bounded to last 500 entries.
            conn.execute(
                """
                DELETE FROM events_feed
                WHERE id NOT IN (
                    SELECT id FROM events_feed ORDER BY id DESC LIMIT 500
                )
                """
            )

    def get_status(self) -> dict[str, Any]:
        """Return latest status row (or offline default)."""
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM engine_status WHERE id = 1").fetchone()
        if row is None:
            return {
                "status": "OFFLINE",
                "mode": "detect",
                "interface": "-",
                "backend": "-",
                "dropped": 0,
                "passed": 0,
                "tcp": 0,
                "udp": 0,
                "icmp": 0,
                "drop_rate_pps": 0.0,
                "updated_at": 0.0,
            }
        data = dict(row)
        # Consider engine offline if heartbeat is older than 5 seconds.
        if data["status"] == "ONLINE" and (time.time() - data["updated_at"]) > 5.0:
            data["status"] = "OFFLINE"
        return data

    def get_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent alerts newest-first."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_blocked_ips(self) -> list[dict[str, Any]]:
        """Return active blocked IPs with computed remaining_seconds."""
        now = time.time()
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
            ).fetchall()
        result: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            exp = item["expires_at"]
            if exp > 0 and now >= exp:
                continue
            item["remaining_seconds"] = -1 if exp <= 0 else max(0, int(exp - now))
            result.append(item)
        return result

    def get_feed(self, limit: int = 60) -> list[dict[str, Any]]:
        """Return recent feed events newest-first."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events_feed ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
