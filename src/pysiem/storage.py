from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from pysiem.logging_config import get_logger
from pysiem.models import Alert, AlertStatus, DetectionResult, RawEvent, Severity

logger = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT,
    event_type TEXT,
    username TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    port INTEGER,
    status TEXT,
    message TEXT,
    severity TEXT,
    raw_log TEXT,
    hostname TEXT,
    protocol TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    detection_id TEXT,
    rule_id TEXT,
    rule_name TEXT,
    severity TEXT,
    status TEXT DEFAULT 'NEW',
    source_ip TEXT,
    timestamp TEXT,
    description TEXT,
    mitre_technique TEXT,
    related_events TEXT,
    details TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    severity TEXT,
    threshold INTEGER,
    time_window INTEGER,
    mitre_technique TEXT,
    rule_type TEXT,
    enabled INTEGER,
    pattern TEXT,
    fields TEXT
);

CREATE TABLE IF NOT EXISTS detection_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT,
    rule_name TEXT,
    severity TEXT,
    source_ip TEXT,
    timestamp TEXT,
    description TEXT,
    mitre_technique TEXT,
    related_events TEXT,
    details TEXT,
    created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
"""


class DatabaseManager:
    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._connect()

    def _connect(self) -> None:
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        logger.debug("Veritabanina baglandi: %s", self.db_path)

    def initialize(self) -> None:
        if self._conn is None:
            self._connect()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.info("Veritabanisi tablolari baslatildi.")

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def insert_event(self, event: RawEvent) -> str:
        d = event.to_dict()
        self._conn.execute(
            """INSERT INTO events
               (id, timestamp, source, event_type, username, source_ip,
                destination_ip, port, status, message, severity, raw_log,
                hostname, protocol)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                d["id"], d["timestamp"], d["source"], d["event_type"],
                d["username"], d["source_ip"], d["destination_ip"],
                d["port"], d["status"], d["message"], d["severity"],
                d["raw_log"], d["hostname"], d["protocol"],
            ),
        )
        self._conn.commit()
        return d["id"]

    def insert_events(self, events: list[RawEvent]) -> list[str]:
        ids: list[str] = []
        for ev in events:
            ids.append(self.insert_event(ev))
        return ids

    def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        event_type: str | None = None,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_events(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return row[0] if row else 0

    def get_events_by_ip(self, ip: str, since: datetime | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM events WHERE source_ip = ?"
        params: list[Any] = [ip]
        if since:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())
        query += " ORDER BY timestamp ASC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_failed_logins(self, ip: str, window_seconds: int = 300) -> list[dict[str, Any]]:
        query = """
            SELECT * FROM events
            WHERE source_ip = ?
              AND event_type = 'auth_failure'
              AND timestamp >= datetime('now', ?)
            ORDER BY timestamp ASC
        """
        rows = self._conn.execute(query, (ip, f"-{window_seconds} seconds")).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def insert_alert(self, alert: Alert) -> str:
        self._conn.execute(
            """INSERT INTO alerts
               (id, detection_id, rule_id, rule_name, severity, status,
                source_ip, timestamp, description, mitre_technique,
                related_events, details, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.id, alert.detection_id, alert.rule_id, alert.rule_name,
                alert.severity.value, alert.status.value, alert.source_ip,
                alert.timestamp.isoformat(), alert.description,
                alert.mitre_technique, json.dumps(alert.related_events),
                json.dumps(alert.details), alert.created_at.isoformat(),
            ),
        )
        self._conn.commit()
        logger.info("Alert olusturuldu: %s [%s]", alert.rule_name, alert.severity.value)
        return alert.id

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        status: str | None = None,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            d = self._row_to_dict(r)
            d["related_events"] = json.loads(d.get("related_events", "[]") or "[]")
            d["details"] = json.loads(d.get("details", "{}") or "{}")
            results.append(d)
        return results

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        cur = self._conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id)
        )
        self._conn.commit()
        return cur.rowcount > 0

    def count_alerts(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
        return row[0] if row else 0

    def get_alerts_by_severity(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        ).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    def alert_exists(self, rule_id: str, source_ip: str, window_seconds: int = 60) -> bool:
        row = self._conn.execute(
            """SELECT COUNT(*) as cnt FROM alerts
               WHERE rule_id = ? AND source_ip = ?
               AND created_at >= datetime('now', ?)""",
            (rule_id, source_ip, f"-{window_seconds} seconds"),
        ).fetchone()
        return (row["cnt"] if row else 0) > 0

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def insert_rule(self, rule_dict: dict[str, Any]) -> str:
        self._conn.execute(
            """INSERT OR REPLACE INTO rules
               (id, name, description, severity, threshold, time_window,
                mitre_technique, rule_type, enabled, pattern, fields)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rule_dict["id"], rule_dict["name"], rule_dict["description"],
                rule_dict["severity"], rule_dict.get("threshold", 5),
                rule_dict.get("time_window", 300),
                rule_dict.get("mitre_technique", ""),
                rule_dict.get("rule_type", ""),
                1 if rule_dict.get("enabled", True) else 0,
                rule_dict.get("pattern", ""),
                json.dumps(rule_dict.get("fields", {})),
            ),
        )
        self._conn.commit()
        return rule_dict["id"]

    def get_rules(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM rules WHERE enabled = 1").fetchall()
        results = []
        for r in rows:
            d = self._row_to_dict(r)
            d["fields"] = json.loads(d.get("fields", "{}") or "{}")
            d["enabled"] = bool(d["enabled"])
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # Detection log
    # ------------------------------------------------------------------

    def log_detection(self, detection: DetectionResult) -> None:
        self._conn.execute(
            """INSERT INTO detection_log
               (rule_id, rule_name, severity, source_ip, timestamp,
                description, mitre_technique, related_events, details, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                detection.rule_id, detection.rule_name, detection.severity.value,
                detection.source_ip, detection.timestamp.isoformat(),
                detection.description, detection.mitre_technique,
                json.dumps(detection.related_events),
                json.dumps(detection.details),
                datetime.now(datetime.UTC).isoformat(),
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_event_stats(self) -> dict[str, Any]:
        stats: dict[str, Any] = {}
        stats["total_events"] = self.count_events()
        stats["total_alerts"] = self.count_alerts()

        rows = self._conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        ).fetchall()
        stats["alerts_by_severity"] = {r["severity"]: r["cnt"] for r in rows}

        rows = self._conn.execute(
            "SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        stats["events_by_type"] = {r["event_type"]: r["cnt"] for r in rows}

        rows = self._conn.execute(
            "SELECT source_ip, COUNT(*) as cnt FROM events WHERE source_ip != '' GROUP BY source_ip ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        stats["top_source_ips"] = {r["source_ip"]: r["cnt"] for r in rows}

        rows = self._conn.execute(
            "SELECT source_ip, COUNT(*) as cnt FROM alerts GROUP BY source_ip ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        stats["top_alert_ips"] = {r["source_ip"]: r["cnt"] for r in rows}

        rows = self._conn.execute(
            "SELECT rule_name, COUNT(*) as cnt FROM detection_log GROUP BY rule_name ORDER BY cnt DESC"
        ).fetchall()
        stats["detections_by_rule"] = {r["rule_name"]: r["cnt"] for r in rows}

        rows = self._conn.execute(
            "SELECT mitre_technique, COUNT(*) as cnt FROM detection_log WHERE mitre_technique != '' GROUP BY mitre_technique ORDER BY cnt DESC"
        ).fetchall()
        stats["mitre_distribution"] = {r["mitre_technique"]: r["cnt"] for r in rows}

        rows = self._conn.execute(
            """SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as cnt
               FROM events GROUP BY hour ORDER BY hour DESC LIMIT 24"""
        ).fetchall()
        stats["hourly_events"] = {r["hour"]: r["cnt"] for r in rows}

        return stats
