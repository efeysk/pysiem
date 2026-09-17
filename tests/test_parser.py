"""Tests for the log parser module."""

from datetime import datetime

import pytest

from pysiem.parser import LogParser
from pysiem.models import EventType, Severity


@pytest.fixture
def parser() -> LogParser:
    return LogParser()


class TestSSHDParsers:
    def test_parse_failed_password(self, parser: LogParser) -> None:
        line = "Sep 16 18:31:22 server sshd[1234]: Failed password for root from 192.168.1.50 port 43122 ssh2"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.AUTH_FAILURE
        assert event.source_ip == "192.168.1.50"
        assert event.username == "root"
        assert event.port == 43122
        assert event.protocol == "ssh"
        assert event.source == "sshd"
        assert "Failed password" in event.raw_log

    def test_parse_accepted_password(self, parser: LogParser) -> None:
        line = "Sep 16 18:32:10 server sshd[1235]: Accepted password for admin from 192.168.1.20 port 45122 ssh2"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.AUTH_SUCCESS
        assert event.source_ip == "192.168.1.20"
        assert event.username == "admin"
        assert event.port == 45122
        assert event.status == "success"

    def test_parse_invalid_user(self, parser: LogParser) -> None:
        line = "Sep 16 18:33:00 server sshd[1236]: Invalid user testuser from 10.0.0.1 port 46000 ssh2"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.AUTH_FAILURE
        assert event.username == "testuser"
        assert event.status == "invalid_user"
        assert event.source_ip == "10.0.0.1"

    def test_parse_failed_password_for_invalid_user(self, parser: LogParser) -> None:
        line = "Sep 16 18:34:00 server sshd[1237]: Failed password for invalid user hacker from 203.0.113.50 port 47000 ssh2"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.AUTH_FAILURE
        assert event.username == "hacker"
        assert event.source_ip == "203.0.113.50"


class TestWebParsers:
    def test_parse_web_access(self, parser: LogParser) -> None:
        line = '192.168.1.10 - - [16/Sep/2026:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 5120'
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.WEB_REQUEST
        assert event.source_ip == "192.168.1.10"
        assert event.status == "200"
        assert event.extra.get("method") == "GET"
        assert event.extra.get("path") == "/index.html"

    def test_parse_web_404(self, parser: LogParser) -> None:
        line = '10.0.0.50 - - [16/Sep/2026:08:06:01 +0000] "GET /admin/ HTTP/1.1" 403 512'
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.WEB_REQUEST
        assert event.status == "403"

    def test_parse_web_500(self, parser: LogParser) -> None:
        line = '203.0.113.50 - - [16/Sep/2026:09:15:03 +0000] "POST /api/run HTTP/1.1" 500 512'
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.WEB_REQUEST
        assert event.status == "500"


class TestAppLogParser:
    def test_parse_app_log(self, parser: LogParser) -> None:
        line = "Sep 16 08:10:00 app-server application[2001]: ERROR Database connection timeout after 30 seconds"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.APP_LOG
        assert event.status == "error"
        assert "Database connection timeout" in event.message
        assert event.severity == Severity.HIGH

    def test_parse_app_log_info(self, parser: LogParser) -> None:
        line = "Sep 16 08:00:00 app-server application[2001]: INFO Application started successfully"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.APP_LOG
        assert event.status == "info"
        assert event.severity == Severity.LOW


class TestSyslogParser:
    def test_parse_syslog(self, parser: LogParser) -> None:
        line = "Sep 16 08:00:01 web-server systemd[1]: Started PySIEM Collector Service"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.SYSTEM_EVENT
        assert event.hostname == "web-server"


class TestEdgeCases:
    def test_empty_line(self, parser: LogParser) -> None:
        assert parser.parse_line("") is None

    def test_whitespace_only(self, parser: LogParser) -> None:
        assert parser.parse_line("   ") is None

    def test_unknown_format(self, parser: LogParser) -> None:
        line = "This is a completely unknown log format"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.UNKNOWN

    def test_parse_lines_batch(self, parser: LogParser) -> None:
        lines = [
            "Sep 16 08:00:01 server sshd[1001]: Failed password for root from 192.168.1.50 port 43122 ssh2",
            "Sep 16 08:01:00 server sshd[1002]: Accepted password for admin from 192.168.1.20 port 44100 ssh2",
            "",
            "random garbage line",
        ]
        events = parser.parse_lines(lines)
        assert len(events) >= 2
        assert all(e is not None for e in events)

    def test_malformed_sshd_line(self, parser: LogParser) -> None:
        line = "Sep 16 server sshd[]: Failed password for root"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.UNKNOWN

    def test_parse_syslog_kernel(self, parser: LogParser) -> None:
        line = "Sep 16 08:00:02 web-server kernel: [    1.234567] EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.SYSTEM_EVENT
        assert event.hostname == "web-server"
