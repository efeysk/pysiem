"""Tests for the correlation engine module."""

from datetime import datetime, timedelta

import pytest

from pysiem.config import AppConfig
from pysiem.correlation import CorrelationEngine
from pysiem.models import EventType, RawEvent, Severity


@pytest.fixture
def config() -> AppConfig:
    return AppConfig(
        brute_force_threshold=5,
        correlation_time_window=300,
        failed_login_threshold=3,
    )


@pytest.fixture
def engine(config: AppConfig) -> CorrelationEngine:
    return CorrelationEngine(config)


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


class TestFailedThenSuccessCorrelation:
    def test_correlate_failed_then_success(
        self, engine: CorrelationEngine
    ) -> None:
        events = []
        for i in range(4):
            events.append(
                _make_event(
                    source_ip="10.0.0.50",
                    event_type=EventType.AUTH_FAILURE,
                    timestamp=datetime(2026, 9, 16, 8, 0, i * 10),
                )
            )
        events.append(
            _make_event(
                source_ip="10.0.0.50",
                event_type=EventType.AUTH_SUCCESS,
                username="admin",
                timestamp=datetime(2026, 9, 16, 8, 1, 0),
            )
        )
        results = engine.analyze(events)
        assert any("Basarisiz" in r.rule_name for r in results)

    def test_no_correlation_with_single_failure(
        self, engine: CorrelationEngine
    ) -> None:
        events = [
            _make_event(
                source_ip="10.0.0.50",
                event_type=EventType.AUTH_FAILURE,
                timestamp=datetime(2026, 9, 16, 8, 0, 0),
            ),
            _make_event(
                source_ip="10.0.0.50",
                event_type=EventType.AUTH_SUCCESS,
                username="admin",
                timestamp=datetime(2026, 9, 16, 8, 0, 10),
            ),
        ]
        results = engine.analyze(events)
        failed_then = [r for r in results if "FAILED-THEN-SUCCESS" in r.rule_id]
        assert len(failed_then) == 0


class TestBruteForceCorrelation:
    def test_brute_force_in_window(self, engine: CorrelationEngine) -> None:
        events = [
            _make_event(
                source_ip="10.0.0.99",
                event_type=EventType.AUTH_FAILURE,
                timestamp=datetime(2026, 9, 16, 8, 0, min(i * 25, 59)),
            )
            for i in range(6)
        ]
        results = engine.analyze(events)
        assert any("Brute Force" in r.rule_name for r in results)

    def test_brute_force_outside_window(
        self, engine: CorrelationEngine
    ) -> None:
        events = [
            _make_event(
                source_ip="10.0.0.99",
                event_type=EventType.AUTH_FAILURE,
                timestamp=datetime(2026, 9, 16, 8, 0, 0),
            ),
            _make_event(
                source_ip="10.0.0.99",
                event_type=EventType.AUTH_FAILURE,
                timestamp=datetime(2026, 9, 16, 10, 0, 0),
            ),
        ]
        results = engine.analyze(events)
        bf = [r for r in results if "TIMED" in r.rule_id]
        assert len(bf) == 0


class TestLateralMovement:
    def test_lateral_movement_detected(
        self, engine: CorrelationEngine
    ) -> None:
        users = ["alice", "bob", "charlie", "diana"]
        events = [
            _make_event(
                source_ip="10.0.0.100",
                event_type=EventType.AUTH_SUCCESS,
                username=user,
                protocol="ssh",
                timestamp=datetime(2026, 9, 16, 8, 0, i),
            )
            for i, user in enumerate(users)
        ]
        results = engine.analyze(events)
        assert any("Lateral Movement" in r.rule_name for r in results)

    def test_lateral_movement_not_triggered_with_few_users(
        self, engine: CorrelationEngine
    ) -> None:
        events = [
            _make_event(
                source_ip="10.0.0.100",
                event_type=EventType.AUTH_SUCCESS,
                username="alice",
                protocol="ssh",
                timestamp=datetime(2026, 9, 16, 8, 0, 0),
            ),
            _make_event(
                source_ip="10.0.0.100",
                event_type=EventType.AUTH_SUCCESS,
                username="bob",
                protocol="ssh",
                timestamp=datetime(2026, 9, 16, 8, 0, 1),
            ),
        ]
        results = engine.analyze(events)
        assert not any("Lateral Movement" in r.rule_name for r in results)


class TestEdgeCases:
    def test_empty_events(self, engine: CorrelationEngine) -> None:
        results = engine.analyze([])
        assert results == []

    def test_single_event(self, engine: CorrelationEngine) -> None:
        events = [_make_event()]
        results = engine.analyze(events)
        assert isinstance(results, list)

    def test_multiple_ips(self, engine: CorrelationEngine) -> None:
        events = []
        for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
            for i in range(4):
                events.append(
                    _make_event(
                        source_ip=ip,
                        event_type=EventType.AUTH_FAILURE,
                        timestamp=datetime(2026, 9, 16, 8, 0, i),
                    )
                )
                events.append(
                    _make_event(
                        source_ip=ip,
                        event_type=EventType.AUTH_SUCCESS,
                        username="admin",
                        timestamp=datetime(2026, 9, 16, 8, 1, 0),
                    )
                )
        results = engine.analyze(events)
        assert len(results) >= 3
