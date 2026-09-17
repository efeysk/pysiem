"""Tests for the detection engine module."""

from datetime import datetime, timedelta

import pytest

from pysiem.detection import DetectionEngine
from pysiem.models import DetectionRule, EventType, RawEvent, Severity


@pytest.fixture
def rules() -> list[DetectionRule]:
    return [
        DetectionRule(
            id="BRUTE-FORCE-SSH",
            name="SSH Brute Force",
            description="Brute force detection",
            severity=Severity.HIGH,
            threshold=5,
            time_window=300,
            mitre_technique="T1110",
            rule_type="brute_force",
            enabled=True,
        ),
        DetectionRule(
            id="FAILED-THEN-SUCCESS",
            name="Failed Then Success",
            description="Failed login pattern",
            severity=Severity.HIGH,
            threshold=3,
            time_window=300,
            mitre_technique="T1110.001",
            rule_type="failed_then_success",
            enabled=True,
        ),
        DetectionRule(
            id="SQLI-DETECT",
            name="SQL Injection",
            description="SQL injection pattern",
            severity=Severity.CRITICAL,
            threshold=1,
            time_window=60,
            mitre_technique="T1190",
            rule_type="pattern_match",
            enabled=True,
            pattern=r"(?i)(union\s+select|select\s+\*\s+from|drop\s+table)",
        ),
        DetectionRule(
            id="WEB-SCANNING",
            name="Web Scanning",
            description="Directory scanning",
            severity=Severity.MEDIUM,
            threshold=10,
            time_window=300,
            mitre_technique="T1595.003",
            rule_type="web_scanning",
            enabled=True,
        ),
        DetectionRule(
            id="SUSPICIOUS-AUTH",
            name="Suspicious Auth",
            description="Suspicious authentication",
            severity=Severity.MEDIUM,
            threshold=2,
            time_window=300,
            mitre_technique="T1078",
            rule_type="suspicious_auth",
            enabled=True,
        ),
        DetectionRule(
            id="MULTI-FAILED",
            name="Multiple Failed Auth",
            description="Multiple failed authentication attempts",
            severity=Severity.HIGH,
            threshold=3,
            time_window=300,
            mitre_technique="T1110.003",
            rule_type="multi_failed_auth",
            enabled=True,
        ),
        DetectionRule(
            id="PRIV-ESC",
            name="Privilege Escalation",
            description="Privilege escalation detection",
            severity=Severity.HIGH,
            threshold=1,
            time_window=60,
            mitre_technique="T1068",
            rule_type="privilege_escalation",
            enabled=True,
        ),
    ]


@pytest.fixture
def engine(rules: list[DetectionRule]) -> DetectionEngine:
    return DetectionEngine(rules)


def _make_event(**kwargs) -> RawEvent:
    defaults = dict(
        timestamp=datetime(2026, 9, 16, 8, 0, 0),
        source="sshd",
        event_type=EventType.AUTH_FAILURE,
        username="root",
        source_ip="192.168.1.50",
        port=43122,
        status="failed",
        message="Failed login",
        severity=Severity.MEDIUM,
        raw_log="test log",
        hostname="server",
        protocol="ssh",
    )
    defaults.update(kwargs)
    return RawEvent(**defaults)


class TestBruteForceDetection:
    def test_brute_force_detected(self, engine: DetectionEngine) -> None:
        events = [
            _make_event(source_ip="10.0.0.50", timestamp=datetime(2026, 9, 16, 8, 0, i))
            for i in range(6)
        ]
        results = engine.evaluate(events)
        brute_force = [r for r in results if r.rule_id == "BRUTE-FORCE-SSH"]
        assert len(brute_force) >= 1
        assert brute_force[0].source_ip == "10.0.0.50"

    def test_brute_force_not_triggered_below_threshold(
        self, engine: DetectionEngine
    ) -> None:
        events = [
            _make_event(source_ip="10.0.0.50", timestamp=datetime(2026, 9, 16, 8, 0, i))
            for i in range(4)
        ]
        results = engine.evaluate(events)
        brute_force = [r for r in results if r.rule_id == "BRUTE-FORCE-SSH"]
        assert len(brute_force) == 0

    def test_brute_force_multiple_ips(self, engine: DetectionEngine) -> None:
        events = [
            _make_event(source_ip="10.0.0.50", timestamp=datetime(2026, 9, 16, 8, 0, i))
            for i in range(6)
        ] + [
            _make_event(source_ip="10.0.0.99", timestamp=datetime(2026, 9, 16, 9, 0, i))
            for i in range(6)
        ]
        results = engine.evaluate(events)
        brute_force = [r for r in results if r.rule_id == "BRUTE-FORCE-SSH"]
        assert len(brute_force) >= 2


class TestFailedThenSuccess:
    def test_failed_then_success_detected(self, engine: DetectionEngine) -> None:
        events = []
        for i in range(4):
            events.append(
                _make_event(
                    source_ip="10.0.0.50",
                    event_type=EventType.AUTH_FAILURE,
                    timestamp=datetime(2026, 9, 16, 8, 0, i),
                )
            )
        events.append(
            _make_event(
                source_ip="10.0.0.50",
                event_type=EventType.AUTH_SUCCESS,
                username="admin",
                timestamp=datetime(2026, 9, 16, 8, 0, 10),
            )
        )
        results = engine.evaluate(events)
        pattern = [r for r in results if r.rule_id == "FAILED-THEN-SUCCESS"]
        assert len(pattern) >= 1

    def test_success_without_failures_no_alert(
        self, engine: DetectionEngine
    ) -> None:
        events = [
            _make_event(
                source_ip="10.0.0.50",
                event_type=EventType.AUTH_SUCCESS,
                timestamp=datetime(2026, 9, 16, 8, 0, 0),
            )
        ]
        results = engine.evaluate(events)
        pattern = [r for r in results if r.rule_id == "FAILED-THEN-SUCCESS"]
        assert len(pattern) == 0


class TestPatternMatch:
    def test_sql_injection_detected(self, engine: DetectionEngine) -> None:
        events = [
            _make_event(
                event_type=EventType.WEB_REQUEST,
                raw_log="GET /search?q=' UNION SELECT username,password FROM users --",
                message="GET /search?q=' UNION SELECT username,password FROM users --",
                source_ip="203.0.113.50",
                timestamp=datetime(2026, 9, 16, 9, 15, 0),
            )
        ]
        results = engine.evaluate(events)
        sqli = [r for r in results if r.rule_id == "SQLI-DETECT"]
        assert len(sqli) >= 1
        assert sqli[0].severity == Severity.CRITICAL

    def test_no_pattern_match(self, engine: DetectionEngine) -> None:
        events = [
            _make_event(
                event_type=EventType.WEB_REQUEST,
                raw_log="GET /index.html HTTP/1.1",
                message="GET /index.html HTTP/1.1",
                source_ip="192.168.1.10",
            )
        ]
        results = engine.evaluate(events)
        sqli = [r for r in results if r.rule_id == "SQLI-DETECT"]
        assert len(sqli) == 0


class TestWebScanning:
    def test_web_scanning_detected(self, engine: DetectionEngine) -> None:
        events = [
            _make_event(
                event_type=EventType.WEB_REQUEST,
                source_ip="10.0.0.50",
                extra={"path": f"/dir{i}"},
                timestamp=datetime(2026, 9, 16, 8, 0, i),
            )
            for i in range(15)
        ]
        results = engine.evaluate(events)
        scanning = [r for r in results if r.rule_id == "WEB-SCANNING"]
        assert len(scanning) >= 1


class TestDisabledRule:
    def test_disabled_rule_not_evaluated(self) -> None:
        disabled_rules = [
            DetectionRule(
                id="DISABLED-RULE",
                name="Disabled",
                rule_type="brute_force",
                enabled=False,
            )
        ]
        engine = DetectionEngine(disabled_rules)
        events = [
            _make_event(source_ip="10.0.0.50", timestamp=datetime(2026, 9, 16, 8, 0, i))
            for i in range(10)
        ]
        results = engine.evaluate(events)
        assert len(results) == 0


class TestEdgeCases:
    def test_empty_events(self, engine: DetectionEngine) -> None:
        results = engine.evaluate([])
        assert results == []

    def test_no_rules(self) -> None:
        engine = DetectionEngine([])
        events = [_make_event() for _ in range(10)]
        results = engine.evaluate(events)
        assert results == []

    def test_events_no_source_ip(self, engine: DetectionEngine) -> None:
        events = [
            _make_event(source_ip="", event_type=EventType.AUTH_FAILURE)
            for _ in range(10)
        ]
        results = engine.evaluate(events)
        brute_force = [r for r in results if r.rule_id == "BRUTE-FORCE-SSH"]
        assert len(brute_force) == 0
