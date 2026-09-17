"""Tests for the event normalizer module."""

import pytest

from pysiem.normalizer import EventNormalizer
from pysiem.models import EventType, RawEvent, Severity
from datetime import datetime


@pytest.fixture
def normalizer() -> EventNormalizer:
    return EventNormalizer()


def _make_event(**kwargs) -> RawEvent:
    defaults = dict(
        timestamp=datetime(2026, 9, 16, 8, 0, 0),
        source="sshd",
        event_type=EventType.AUTH_FAILURE,
        username="root",
        source_ip="192.168.1.50",
        port=43122,
        status="failed",
        message="Basarisiz sifre denemesi",
        severity=Severity.MEDIUM,
        raw_log="test log line",
        hostname="server",
        protocol="ssh",
    )
    defaults.update(kwargs)
    return RawEvent(**defaults)


class TestNormalization:
    def test_basic_normalization(self, normalizer: EventNormalizer) -> None:
        event = _make_event()
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].source_ip == "192.168.1.50"

    def test_invalid_ip_cleared(self, normalizer: EventNormalizer) -> None:
        event = _make_event(source_ip="not-an-ip")
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].source_ip == ""

    def test_empty_ip_preserved(self, normalizer: EventNormalizer) -> None:
        event = _make_event(source_ip="")
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].source_ip == ""

    def test_valid_ipv6_preserved(self, normalizer: EventNormalizer) -> None:
        event = _make_event(source_ip="::1")
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].source_ip == "::1"

    def test_empty_list(self, normalizer: EventNormalizer) -> None:
        results = normalizer.normalize([])
        assert results == []

    def test_none_filter(self, normalizer: EventNormalizer) -> None:
        event = _make_event()
        results = normalizer.normalize([event])
        assert len(results) == 1


class TestSQLInjectionDetection:
    def test_sqli_union_select(self, normalizer: EventNormalizer) -> None:
        event = _make_event(
            event_type=EventType.WEB_REQUEST,
            message="GET /search?q=' UNION SELECT username,password FROM users --",
            extra={"method": "GET", "path": "/search?q=' UNION SELECT username,password FROM users --"},
        )
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH
        assert results[0].extra.get("attack_detected") == "sql_injection"

    def test_sqli_or_1_equals_1(self, normalizer: EventNormalizer) -> None:
        event = _make_event(
            event_type=EventType.WEB_REQUEST,
            message="GET /login?user=admin' OR 1=1 --",
            extra={"method": "GET", "path": "/login?user=admin' OR 1=1 --"},
        )
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH

    def test_sqli_drop_table(self, normalizer: EventNormalizer) -> None:
        event = _make_event(
            event_type=EventType.WEB_REQUEST,
            message="POST /api/query HTTP/1.1",
            extra={"method": "POST", "path": "/api/query?id=1; DROP TABLE users;"},
        )
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH


class TestCommandInjectionDetection:
    def test_cmdi_semicolon(self, normalizer: EventNormalizer) -> None:
        event = _make_event(
            event_type=EventType.WEB_REQUEST,
            message="GET /exec?cmd=cat /etc/passwd",
            extra={"method": "GET", "path": "/exec?cmd=cat /etc/passwd"},
        )
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH
        assert results[0].extra.get("attack_detected") == "command_injection"

    def test_cmdi_pipe(self, normalizer: EventNormalizer) -> None:
        event = _make_event(
            event_type=EventType.WEB_REQUEST,
            message="GET /shell?cmd=ls | bash",
            extra={"method": "GET", "path": "/shell?cmd=ls | bash"},
        )
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH


class TestSuspiciousPath:
    def test_etc_passwd_access(self, normalizer: EventNormalizer) -> None:
        event = _make_event(
            event_type=EventType.WEB_REQUEST,
            message="GET /etc/passwd",
            extra={"method": "GET", "path": "/etc/passwd"},
        )
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].extra.get("suspicious_path") is True

    def test_git_directory_access(self, normalizer: EventNormalizer) -> None:
        event = _make_event(
            event_type=EventType.WEB_REQUEST,
            message="GET /.git/config",
            extra={"method": "GET", "path": "/.git/config"},
        )
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].extra.get("suspicious_path") is True


class TestSeverityEnrichment:
    def test_root_login_high_severity(self, normalizer: EventNormalizer) -> None:
        event = _make_event(
            event_type=EventType.AUTH_FAILURE,
            message="Basarisiz root girisi",
            source_ip="10.0.0.50",
        )
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH

    def test_web_500_high_severity(self, normalizer: EventNormalizer) -> None:
        event = _make_event(
            event_type=EventType.WEB_REQUEST,
            status="500",
            message="Internal Server Error",
        )
        results = normalizer.normalize([event])
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH


class TestPortScanDetection:
    def test_port_scan_detected(self, normalizer: EventNormalizer) -> None:
        events = []
        for port in range(1, 110):
            events.append(
                _make_event(
                    event_type=EventType.WEB_REQUEST,
                    source_ip="10.0.0.50",
                    port=port,
                )
            )
        result = normalizer.detect_scanning(events, threshold=100)
        assert result is not None
        assert result["type"] == "port_scan"
        assert result["source_ip"] == "10.0.0.50"

    def test_no_port_scan(self, normalizer: EventNormalizer) -> None:
        events = [
            _make_event(event_type=EventType.WEB_REQUEST, source_ip="10.0.0.50", port=80),
            _make_event(event_type=EventType.WEB_REQUEST, source_ip="10.0.0.50", port=443),
        ]
        result = normalizer.detect_scanning(events, threshold=100)
        assert result is None
