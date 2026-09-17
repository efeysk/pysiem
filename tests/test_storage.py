"""Tests for the storage / database module."""

import tempfile
from pathlib import Path

import pytest

from pysiem.models import Alert, AlertStatus, EventType, RawEvent, Severity
from pysiem.storage import DatabaseManager


@pytest.fixture
def db_manager() -> DatabaseManager:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        mgr = DatabaseManager(db_path)
        mgr.initialize()
        yield mgr
        mgr.close()


def _make_event(**kwargs) -> RawEvent:
    defaults = dict(
        timestamp=__import__("datetime").datetime(2026, 9, 16, 8, 0, 0),
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


def _make_alert(**kwargs) -> Alert:
    defaults = dict(
        id="test-alert-001",
        detection_id="det-001",
        rule_id="BRUTE-FORCE",
        rule_name="SSH Brute Force",
        severity=Severity.HIGH,
        status=AlertStatus.NEW,
        source_ip="10.0.0.50",
        description="Brute force detected",
        mitre_technique="T1110",
    )
    defaults.update(kwargs)
    return Alert(**defaults)


class TestEventOperations:
    def test_insert_and_get_event(self, db_manager: DatabaseManager) -> None:
        event = _make_event()
        eid = db_manager.insert_event(event)
        assert eid is not None
        events = db_manager.get_events(limit=10)
        assert len(events) == 1
        assert events[0]["source_ip"] == "192.168.1.50"

    def test_insert_events_bulk(self, db_manager: DatabaseManager) -> None:
        events = [_make_event(source_ip=f"10.0.0.{i}") for i in range(10)]
        ids = db_manager.insert_events(events)
        assert len(ids) == 10
        assert db_manager.count_events() == 10

    def test_get_events_with_filter(self, db_manager: DatabaseManager) -> None:
        db_manager.insert_event(_make_event(source_ip="10.0.0.1", event_type=EventType.AUTH_FAILURE))
        db_manager.insert_event(_make_event(source_ip="10.0.0.2", event_type=EventType.AUTH_SUCCESS))
        failures = db_manager.get_events(event_type="auth_failure")
        assert len(failures) == 1
        assert failures[0]["source_ip"] == "10.0.0.1"

    def test_count_events(self, db_manager: DatabaseManager) -> None:
        assert db_manager.count_events() == 0
        db_manager.insert_event(_make_event())
        assert db_manager.count_events() == 1

    def test_get_events_by_ip(self, db_manager: DatabaseManager) -> None:
        db_manager.insert_event(_make_event(source_ip="10.0.0.1"))
        db_manager.insert_event(_make_event(source_ip="10.0.0.2"))
        db_manager.insert_event(_make_event(source_ip="10.0.0.1"))
        ip_events = db_manager.get_events_by_ip("10.0.0.1")
        assert len(ip_events) == 2


class TestAlertOperations:
    def test_insert_and_get_alert(self, db_manager: DatabaseManager) -> None:
        alert = _make_alert()
        aid = db_manager.insert_alert(alert)
        assert aid is not None
        alerts = db_manager.get_alerts(limit=10)
        assert len(alerts) == 1
        assert alerts[0]["source_ip"] == "10.0.0.50"

    def test_update_alert_status(self, db_manager: DatabaseManager) -> None:
        alert = _make_alert()
        db_manager.insert_alert(alert)
        success = db_manager.update_alert_status("test-alert-001", "INVESTIGATING")
        assert success is True
        alerts = db_manager.get_alerts()
        assert alerts[0]["status"] == "INVESTIGATING"

    def test_update_nonexistent_alert(self, db_manager: DatabaseManager) -> None:
        success = db_manager.update_alert_status("nonexistent-id", "RESOLVED")
        assert success is False

    def test_alert_deduplication(self, db_manager: DatabaseManager) -> None:
        assert db_manager.alert_exists("RULE-1", "10.0.0.1") is False
        alert = _make_alert(rule_id="RULE-1", source_ip="10.0.0.1")
        db_manager.insert_alert(alert)
        assert db_manager.alert_exists("RULE-1", "10.0.0.1") is True

    def test_count_alerts(self, db_manager: DatabaseManager) -> None:
        assert db_manager.count_alerts() == 0
        db_manager.insert_alert(_make_alert())
        assert db_manager.count_alerts() == 1

    def test_get_alerts_by_severity(self, db_manager: DatabaseManager) -> None:
        db_manager.insert_alert(_make_alert(severity=Severity.HIGH))
        db_manager.insert_alert(_make_alert(id="a2", severity=Severity.CRITICAL))
        by_sev = db_manager.get_alerts_by_severity()
        assert by_sev.get("HIGH") == 1
        assert by_sev.get("CRITICAL") == 1


class TestRuleOperations:
    def test_insert_and_get_rules(self, db_manager: DatabaseManager) -> None:
        rule = {
            "id": "TEST-RULE",
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "MEDIUM",
            "threshold": 5,
            "time_window": 300,
            "mitre_technique": "T1110",
            "rule_type": "brute_force",
            "enabled": True,
            "pattern": "",
            "fields": {},
        }
        db_manager.insert_rule(rule)
        rules = db_manager.get_rules()
        assert len(rules) == 1
        assert rules[0]["id"] == "TEST-RULE"


class TestStatistics:
    def test_get_event_stats(self, db_manager: DatabaseManager) -> None:
        db_manager.insert_event(_make_event())
        db_manager.insert_alert(_make_alert())
        stats = db_manager.get_event_stats()
        assert stats["total_events"] == 1
        assert stats["total_alerts"] == 1


class TestEdgeCases:
    def test_empty_database_queries(self, db_manager: DatabaseManager) -> None:
        assert db_manager.get_events() == []
        assert db_manager.get_alerts() == []
        assert db_manager.get_rules() == []
        assert db_manager.count_events() == 0
        assert db_manager.count_alerts() == 0
