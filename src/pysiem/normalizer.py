from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

from pysiem.logging_config import get_logger
from pysiem.models import EventType, RawEvent, Severity

logger = get_logger(__name__)

# Patterns that indicate malicious activity
SQLI_PATTERNS = [
    re.compile(r"(?i)(union\s+select|select\s+\*\s+from|drop\s+table|insert\s+into|delete\s+from)"),
    re.compile(r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*')"),
    re.compile(r"(?i)(--\s*$|/\*.*\*/|char\s*\(|0x[0-9a-f]+)"),
]

CMDI_PATTERNS = [
    re.compile(r"(;|\|{1,2}|`|\$)\s*(ls|cat|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|ruby)"),
    re.compile(r"(?i)(\|\s*(bash|sh|python|perl))"),
    re.compile(r"(?i)(cmd=|exec=|command=|run=|eval=)\s*(ls|cat|id|whoami|uname|wget|curl|nc|bash|sh|python|perl)"),
    re.compile(r"(?i)(/bin/(ba)?sh|/usr/bin/(python|perl|ruby))"),
]

SUSPICIOUS_PATHS = [
    re.compile(r"(?i)(/etc/passwd|/etc/shadow|/proc/self)"),
    re.compile(r"(?i)(\.\./\.\./|\.git/|\.env|\.htaccess)"),
]


def _is_valid_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


class EventNormalizer:
    def normalize(self, events: list[RawEvent]) -> list[RawEvent]:
        normalized: list[RawEvent] = []
        for ev in events:
            nev = self._normalize_single(ev)
            if nev is not None:
                normalized.append(nev)
        logger.info("%d olay normalize edildi.", len(normalized))
        return normalized

    def _normalize_single(self, event: RawEvent) -> RawEvent | None:
        if not event:
            return None

        if not _is_valid_ip(event.source_ip):
            event.source_ip = ""

        if not event.timestamp:
            event.timestamp = datetime.now()

        event.message = event.message.strip()
        event.raw_log = event.raw_log.strip()

        event = self._enrich_severity(event)
        event = self._detect_web_attack_patterns(event)
        event = self._normalize_event_type(event)

        return event

    def _enrich_severity(self, event: RawEvent) -> RawEvent:
        severity_order = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}

        if event.event_type == EventType.WEB_REQUEST:
            if any(p.search(event.message) for p in SQLI_PATTERNS):
                event.severity = Severity.HIGH
                event.extra["attack_detected"] = "sql_injection"
                logger.debug("SQL injection patterni tespit edildi: %s", event.source_ip)
            if any(p.search(event.message) for p in CMDI_PATTERNS):
                event.severity = Severity.HIGH
                event.extra["attack_detected"] = "command_injection"
                logger.debug("Command injection patterni tespit edildi: %s", event.source_ip)
            if event.status.startswith("4"):
                try:
                    code = int(event.status)
                    if code == 404:
                        if severity_order[event.severity] <= severity_order[Severity.MEDIUM]:
                            event.severity = Severity.LOW
                except ValueError:
                    pass
            if event.status.startswith("5"):
                event.severity = Severity.HIGH

        if event.event_type in (EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS):
            msg_lower = event.message.lower()
            if "root" in msg_lower:
                if severity_order[event.severity] < severity_order[Severity.HIGH]:
                    event.severity = Severity.HIGH

        return event

    def _detect_web_attack_patterns(self, event: RawEvent) -> RawEvent:
        if event.event_type != EventType.WEB_REQUEST:
            return event

        path = event.extra.get("path", "")
        method = event.extra.get("method", "")

        severity_order = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}

        for pattern in SQLI_PATTERNS:
            combined = f"{path} {method}"
            if pattern.search(combined):
                event.extra["attack_detected"] = "sql_injection"
                event.severity = Severity.HIGH
                break

        for pattern in CMDI_PATTERNS:
            combined = f"{path} {method}"
            if pattern.search(combined):
                event.extra["attack_detected"] = "command_injection"
                event.severity = Severity.HIGH
                break

        for pattern in SUSPICIOUS_PATHS:
            if pattern.search(path):
                event.extra["suspicious_path"] = True
                if severity_order[event.severity] < severity_order[Severity.MEDIUM]:
                    event.severity = Severity.MEDIUM
                break

        return event

    def _normalize_event_type(self, event: RawEvent) -> RawEvent:
        if event.event_type == EventType.UNKNOWN:
            msg = event.message.lower()
            if "password" in msg or "auth" in msg:
                if "fail" in msg or "invalid" in msg or "denied" in msg:
                    event.event_type = EventType.AUTH_FAILURE
                elif "accept" in msg or "success" in msg:
                    event.event_type = EventType.AUTH_SUCCESS
            elif "error" in msg or "warn" in msg:
                event.event_type = EventType.APP_LOG
            elif any(w in msg for w in ("login", "logout", "session")):
                event.event_type = EventType.AUTH_SUCCESS
        return event

    def detect_scanning(self, events: list[RawEvent], threshold: int = 100) -> dict[str, Any] | None:
        if not events:
            return None

        ip_events: dict[str, list[RawEvent]] = {}
        for ev in events:
            if ev.source_ip:
                ip_events.setdefault(ev.source_ip, []).append(ev)

        for ip, evts in ip_events.items():
            unique_ports = set()
            for ev in evts:
                if ev.port:
                    unique_ports.add(ev.port)
            if len(unique_ports) >= threshold:
                return {
                    "type": "port_scan",
                    "source_ip": ip,
                    "unique_ports": len(unique_ports),
                    "event_count": len(evts),
                }
        return None
