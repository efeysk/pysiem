from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pysiem.logging_config import get_logger
from pysiem.models import EventType, RawEvent, Severity

logger = get_logger(__name__)


class LogParser:
    def __init__(self) -> None:
        self._patterns = self._build_patterns()

    def _build_patterns(self) -> dict[str, re.Pattern[str]]:
        return {
            "sshd_failed": re.compile(
                r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+"
                r"Failed password for (?:invalid user\s+)?(\S+) from (\S+) port (\d+)"
            ),
            "sshd_accepted": re.compile(
                r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+"
                r"Accepted password for (\S+) from (\S+) port (\d+)"
            ),
            "sshd_invalid_user": re.compile(
                r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+"
                r"Invalid user (\S+) from (\S+) port (\d+)"
            ),
            "sshd_connection_closed": re.compile(
                r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+"
                r"Connection closed by (?:invalid user\s+)?(\S+)?\s*from (\S+) port (\d+)"
            ),
            "sshd_disconnect": re.compile(
                r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+"
                r"Disconnected from (?:invalid user\s+)?(\S+)?\s*from (\S+) port (\d+)"
            ),
            "web_access": re.compile(
                r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d{3})\s+(\d+)'
            ),
            "web_error": re.compile(
                r"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"
                r"(ERROR|WARN|INFO)\s+(.*)"
            ),
            "app_log": re.compile(
                r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+"
                r"(ERROR|WARN|INFO|DEBUG|CRITICAL)\s+(.*)"
            ),
            "syslog": re.compile(
                r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)"
            ),
        }

    def _parse_timestamp(self, ts_str: str) -> datetime:
        current_year = datetime.now().year
        for fmt in ("%b %d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%b/%Y:%H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
            try:
                dt = datetime.strptime(ts_str.strip(), fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=current_year)
                return dt
            except ValueError:
                continue
        logger.warning("Gecersiz timestamp: %s", ts_str)
        return datetime.now()

    def parse_sshd_failed(self, line: str) -> RawEvent | None:
        m = self._patterns["sshd_failed"].match(line)
        if not m:
            return None
        return RawEvent(
            timestamp=self._parse_timestamp(m.group(1)),
            source="sshd",
            event_type=EventType.AUTH_FAILURE,
            username=m.group(3),
            source_ip=m.group(4),
            port=int(m.group(5)),
            status="failed",
            message=f"Basarisiz sifre denemesi: {m.group(3)}",
            severity=Severity.MEDIUM,
            raw_log=line,
            hostname=m.group(2),
            protocol="ssh",
        )

    def parse_sshd_accepted(self, line: str) -> RawEvent | None:
        m = self._patterns["sshd_accepted"].match(line)
        if not m:
            return None
        return RawEvent(
            timestamp=self._parse_timestamp(m.group(1)),
            source="sshd",
            event_type=EventType.AUTH_SUCCESS,
            username=m.group(3),
            source_ip=m.group(4),
            port=int(m.group(5)),
            status="success",
            message=f"Basarili sifre girisi: {m.group(3)}",
            severity=Severity.LOW,
            raw_log=line,
            hostname=m.group(2),
            protocol="ssh",
        )

    def parse_sshd_invalid_user(self, line: str) -> RawEvent | None:
        m = self._patterns["sshd_invalid_user"].match(line)
        if not m:
            return None
        return RawEvent(
            timestamp=self._parse_timestamp(m.group(1)),
            source="sshd",
            event_type=EventType.AUTH_FAILURE,
            username=m.group(3),
            source_ip=m.group(4),
            port=int(m.group(5)),
            status="invalid_user",
            message=f"Gecersiz kullanici denemesi: {m.group(3)}",
            severity=Severity.MEDIUM,
            raw_log=line,
            hostname=m.group(2),
            protocol="ssh",
        )

    def parse_web_access(self, line: str) -> RawEvent | None:
        m = self._patterns["web_access"].match(line)
        if not m:
            return None
        method = m.group(3)
        path = m.group(4)
        status_code = int(m.group(6))
        severity = Severity.LOW
        if status_code >= 500:
            severity = Severity.HIGH
        elif status_code >= 400:
            severity = Severity.MEDIUM
        return RawEvent(
            timestamp=self._parse_timestamp(m.group(2)),
            source="webserver",
            event_type=EventType.WEB_REQUEST,
            source_ip=m.group(1),
            status=str(status_code),
            message=f"{method} {path} - {status_code}",
            severity=severity,
            raw_log=line,
            hostname=m.group(1),
            protocol="http",
            extra={"method": method, "path": path, "response_code": status_code},
        )

    def parse_web_error(self, line: str) -> RawEvent | None:
        m = self._patterns["web_error"].match(line)
        if not m:
            return None
        level = m.group(3)
        severity = Severity.MEDIUM if level in ("ERROR", "CRITICAL") else Severity.LOW
        return RawEvent(
            timestamp=self._parse_timestamp(m.group(2)),
            source="webserver",
            event_type=EventType.APP_LOG,
            source_ip=m.group(1),
            status=level.lower(),
            message=m.group(4),
            severity=severity,
            raw_log=line,
            hostname=m.group(1),
        )

    def parse_app_log(self, line: str) -> RawEvent | None:
        m = self._patterns["app_log"].match(line)
        if not m:
            return None
        level = m.group(4)
        severity_map = {
            "DEBUG": Severity.LOW,
            "INFO": Severity.LOW,
            "WARN": Severity.MEDIUM,
            "ERROR": Severity.HIGH,
            "CRITICAL": Severity.CRITICAL,
        }
        return RawEvent(
            timestamp=self._parse_timestamp(m.group(1)),
            source=m.group(3),
            event_type=EventType.APP_LOG,
            status=level.lower(),
            message=m.group(5),
            severity=severity_map.get(level, Severity.LOW),
            raw_log=line,
            hostname=m.group(2),
        )

    def parse_syslog(self, line: str) -> RawEvent | None:
        m = self._patterns["syslog"].match(line)
        if not m:
            return None
        return RawEvent(
            timestamp=self._parse_timestamp(m.group(1)),
            source=m.group(3),
            event_type=EventType.SYSTEM_EVENT,
            status="info",
            message=m.group(4),
            severity=Severity.LOW,
            raw_log=line,
            hostname=m.group(2),
        )

    def parse_line(self, line: str) -> RawEvent | None:
        if not line or not line.strip():
            return None

        parsers = [
            self.parse_sshd_failed,
            self.parse_sshd_invalid_user,
            self.parse_sshd_accepted,
            self.parse_web_access,
            self.parse_web_error,
            self.parse_app_log,
            self.parse_syslog,
        ]

        for parser in parsers:
            try:
                result = parser(line)
                if result is not None:
                    return result
            except Exception as exc:
                logger.debug("Parser hatasi: %s - %s", parser.__name__, exc)
                continue

        return RawEvent(
            timestamp=datetime.now(),
            source="unknown",
            event_type=EventType.UNKNOWN,
            message=line.strip(),
            severity=Severity.LOW,
            raw_log=line,
        )

    def parse_lines(self, lines: list[str]) -> list[RawEvent]:
        events: list[RawEvent] = []
        for line in lines:
            event = self.parse_line(line)
            if event is not None:
                events.append(event)
        logger.info("%d / %d satir basariyla ayristirildi.", len(events), len(lines))
        return events
