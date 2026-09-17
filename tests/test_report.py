"""Tests for pysiem.report module."""

from __future__ import annotations

from pathlib import Path

import json

import pytest

from pysiem.models import Alert, AlertStatus, EventType, RawEvent, Severity
from pysiem.report import ReportGenerator
from pysiem.storage import DatabaseManager


@pytest.fixture
def db(tmp_path: Path) -> DatabaseManager:
    db_path = tmp_path / "test_report.db"
    manager = DatabaseManager(db_path)
    manager.initialize()
    yield manager
    manager.close()


@pytest.fixture
def reports_path(tmp_path: Path) -> Path:
    rp = tmp_path / "reports"
    rp.mkdir()
    return rp


@pytest.fixture
def report_gen(db: DatabaseManager, reports_path: Path) -> ReportGenerator:
    return ReportGenerator(db, reports_path)


class TestReportGeneration:
    def test_empty_report(self, report_gen: ReportGenerator) -> None:
        report = report_gen.generate_full_report()
        assert report["summary"]["total_events"] == 0
        assert report["summary"]["total_alerts"] == 0

    def test_report_with_data(self, db: DatabaseManager, report_gen: ReportGenerator) -> None:
        ev = RawEvent(
            timestamp=__import__("datetime").datetime(2026, 9, 16, 8, 0, 0),
            source="test",
            event_type=EventType.AUTH_FAILURE,
            source_ip="10.0.0.1",
            message="test",
            severity=Severity.HIGH,
            raw_log="raw",
        )
        db.insert_event(ev)
        alert = Alert(
            rule_id="R1",
            rule_name="Test",
            severity=Severity.HIGH,
            status=AlertStatus.NEW,
            source_ip="10.0.0.1",
            description="test alert",
        )
        db.insert_alert(alert)
        report = report_gen.generate_full_report()
        assert report["summary"]["total_events"] == 1
        assert report["summary"]["total_alerts"] == 1


class TestJSONExport:
    def test_export_json(self, report_gen: ReportGenerator, reports_path: Path) -> None:
        path = report_gen.export_json("test_report.json")
        assert path.exists()
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert "report_title" in data
        assert "summary" in data


class TestCSVExport:
    def test_export_csv_alerts_empty(self, report_gen: ReportGenerator, reports_path: Path) -> None:
        path = report_gen.export_csv_alerts("empty_alerts.csv")
        assert path.parent.exists()

    def test_export_csv_events_empty(self, report_gen: ReportGenerator, reports_path: Path) -> None:
        path = report_gen.export_csv_events("empty_events.csv")
        assert path.parent.exists()


class TestTextReport:
    def test_text_report(self, report_gen: ReportGenerator) -> None:
        text = report_gen.format_text_report()
        assert "PySIEM" in text
        assert "GUVENLIK RAPORU" in text
