"""Tests for the alert management module."""

import tempfile
from pathlib import Path
from datetime import datetime

import pytest

from pysiem.alert import AlertManager
from pysiem.config import AppConfig
from pysiem.models import DetectionResult, Severity
from pysiem.storage import DatabaseManager


@pytest.fixture
def infrastructure() -> tuple[DatabaseManager, AlertManager, AppConfig]:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config = AppConfig(
            database_path=db_path,
            dedup_window=60,
        )
        db = DatabaseManager(db_path)
        db.initialize()
        alert_mgr = AlertManager(db, config)
        yield db, alert_mgr, config
        db.close()


def _make_detection(**kwargs) -> DetectionResult:
    defaults = dict(
        rule_id="BRUTE-FORCE-SSH",
        rule_name="SSH Brute Force",
        description="Brute force from 10.0.0.50",
        severity=Severity.HIGH,
        source_ip="10.0.0.50",
        timestamp=datetime(2026, 9, 16, 8, 0, 0),
        mitre_technique="T1110",
        related_events=["log line 1", "log line 2"],
        details={"failure_count": 10},
    )
    defaults.update(kwargs)
    return DetectionResult(**defaults)


class TestAlertCreation:
    def test_create_alerts_from_detections(
        self, infrastructure: tuple
    ) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [_make_detection()]
        alerts = alert_mgr.process_detections(detections)
        assert len(alerts) == 1
        assert alerts[0].rule_name == "SSH Brute Force"
        assert alerts[0].severity == Severity.HIGH

    def test_multiple_detections_create_multiple_alerts(
        self, infrastructure: tuple
    ) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [
            _make_detection(rule_id="RULE-1", source_ip="10.0.0.1"),
            _make_detection(rule_id="RULE-2", source_ip="10.0.0.2"),
        ]
        alerts = alert_mgr.process_detections(detections)
        assert len(alerts) == 2

    def test_alert_stored_in_database(
        self, infrastructure: tuple
    ) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [_make_detection()]
        alert_mgr.process_detections(detections)
        stored = db.get_alerts()
        assert len(stored) == 1
        assert stored[0]["rule_name"] == "SSH Brute Force"


class TestDeduplication:
    def test_duplicate_alert_suppressed(
        self, infrastructure: tuple
    ) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [_make_detection()]
        alerts1 = alert_mgr.process_detections(detections)
        alerts2 = alert_mgr.process_detections(detections)
        assert len(alerts1) == 1
        assert len(alerts2) == 0

    def test_different_source_ip_not_deduplicated(
        self, infrastructure: tuple
    ) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [
            _make_detection(source_ip="10.0.0.1"),
            _make_detection(source_ip="10.0.0.2"),
        ]
        alerts = alert_mgr.process_detections(detections)
        assert len(alerts) == 2


class TestAlertListing:
    def test_list_alerts(self, infrastructure: tuple) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [_make_detection()]
        alert_mgr.process_detections(detections)
        alerts = alert_mgr.list_alerts()
        assert len(alerts) == 1

    def test_filter_by_severity(self, infrastructure: tuple) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [
            _make_detection(rule_id="R1", severity=Severity.HIGH),
            _make_detection(rule_id="R2", severity=Severity.LOW),
        ]
        alert_mgr.process_detections(detections)
        high_alerts = alert_mgr.list_alerts(severity="HIGH")
        assert len(high_alerts) == 1

    def test_filter_by_source_ip(self, infrastructure: tuple) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [
            _make_detection(rule_id="R1", source_ip="10.0.0.1"),
            _make_detection(rule_id="R2", source_ip="10.0.0.2"),
        ]
        alert_mgr.process_detections(detections)
        ip_alerts = alert_mgr.list_alerts(source_ip="10.0.0.1")
        assert len(ip_alerts) == 1


class TestAlertStatusUpdate:
    def test_update_status(self, infrastructure: tuple) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [_make_detection()]
        alerts = alert_mgr.process_detections(detections)
        alert_id = alerts[0].id
        success = alert_mgr.update_status(alert_id, "INVESTIGATING")
        assert success is True
        updated = db.get_alerts()
        assert updated[0]["status"] == "INVESTIGATING"

    def test_invalid_status_rejected(self, infrastructure: tuple) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [_make_detection()]
        alerts = alert_mgr.process_detections(detections)
        alert_id = alerts[0].id
        success = alert_mgr.update_status(alert_id, "INVALID_STATUS")
        assert success is False


class TestAlertSummary:
    def test_summary(self, infrastructure: tuple) -> None:
        db, alert_mgr, _ = infrastructure
        detections = [
            _make_detection(rule_id="R1", severity=Severity.HIGH),
            _make_detection(rule_id="R2", severity=Severity.CRITICAL),
        ]
        alert_mgr.process_detections(detections)
        summary = alert_mgr.get_summary()
        assert summary["total_alerts"] == 2
        assert summary["by_severity"]["HIGH"] == 1
        assert summary["by_severity"]["CRITICAL"] == 1


class TestEdgeCases:
    def test_empty_detections(self, infrastructure: tuple) -> None:
        db, alert_mgr, _ = infrastructure
        alerts = alert_mgr.process_detections([])
        assert alerts == []

    def test_empty_alert_list(self, infrastructure: tuple) -> None:
        db, alert_mgr, _ = infrastructure
        alerts = alert_mgr.list_alerts()
        assert alerts == []
