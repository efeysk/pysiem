from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from pysiem.config import AppConfig
from pysiem.logging_config import get_logger
from pysiem.models import DetectionResult, EventType, RawEvent, Severity

logger = get_logger(__name__)


class CorrelationEngine:
    def __init__(self, config: AppConfig) -> None:
        self.time_window = config.correlation_time_window
        self.brute_force_threshold = config.brute_force_threshold
        self.failed_login_threshold = config.failed_login_threshold

    def analyze(self, events: list[RawEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        results.extend(self._correlate_failed_then_success(events))
        results.extend(self._correlate_brute_force_with_correlation(events))
        results.extend(self._correlate_lateral_movement(events))
        logger.info("%d korelasyon sonucu uretildi.", len(results))
        return results

    def _correlate_failed_then_success(
        self, events: list[RawEvent]
    ) -> list[DetectionResult]:
        ip_auth_events: dict[str, list[RawEvent]] = defaultdict(list)
        for ev in events:
            if ev.event_type in (EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS):
                if ev.source_ip:
                    ip_auth_events[ev.source_ip].append(ev)

        results: list[DetectionResult] = []
        for ip, evts in ip_auth_events.items():
            sorted_evts = sorted(evts, key=lambda e: e.timestamp)
            window_events: list[RawEvent] = []
            for ev in sorted_evts:
                window_events = [
                    w for w in window_events
                    if (ev.timestamp - w.timestamp).total_seconds() <= self.time_window
                ]
                window_events.append(ev)

                fail_count = sum(
                    1 for w in window_events if w.event_type == EventType.AUTH_FAILURE
                )
                has_success = any(
                    w.event_type == EventType.AUTH_SUCCESS for w in window_events
                )

                if fail_count >= self.failed_login_threshold and has_success:
                    fail_evts = [
                        w for w in window_events
                        if w.event_type == EventType.AUTH_FAILURE
                    ]
                    succ_evts = [
                        w for w in window_events
                        if w.event_type == EventType.AUTH_SUCCESS
                    ]
                    results.append(
                        DetectionResult(
                            rule_id="CORR-FAILED-THEN-SUCCESS",
                            rule_name="Basarisiz Denemeler Sonrasi Basarili Giris",
                            description=(
                                f"{ip} adresinden {fail_count} basarisiz deneme "
                                f"sonrasi basarili giris tespit edildi. "
                                f"Olasi hesap ele gecirme."
                            ),
                            severity=Severity.HIGH,
                            source_ip=ip,
                            timestamp=succ_evts[-1].timestamp,
                            mitre_technique="T1110.001",
                            related_events=[w.raw_log for w in window_events],
                            details={
                                "failure_count": fail_count,
                                "success_count": len(succ_evts),
                                "usernames": list(
                                    {w.username for w in window_events if w.username}
                                ),
                            },
                        )
                    )
                    window_events = []
        return results

    def _correlate_brute_force_with_correlation(
        self, events: list[RawEvent]
    ) -> list[DetectionResult]:
        ip_failure_windows: dict[str, list[RawEvent]] = defaultdict(list)
        for ev in events:
            if ev.event_type == EventType.AUTH_FAILURE and ev.source_ip:
                ip_failure_windows[ev.source_ip].append(ev)

        results: list[DetectionResult] = []
        for ip, all_failures in ip_failure_windows.items():
            sorted_failures = sorted(all_failures, key=lambda e: e.timestamp)
            window: list[RawEvent] = []
            for ev in sorted_failures:
                window = [
                    w for w in window
                    if (ev.timestamp - w.timestamp).total_seconds() <= self.time_window
                ]
                window.append(ev)

                if len(window) >= self.brute_force_threshold:
                    usernames = list({w.username for w in window if w.username})
                    results.append(
                        DetectionResult(
                            rule_id="CORR-BRUTE-FORCE-TIMED",
                            rule_name="Zaman Penceresi Icinde Brute Force",
                            description=(
                                f"{ip} adresinden {self.time_window} saniye icinde "
                                f"{len(window)} basarisiz giris denemesi. "
                                f"Brute force saldirisi."
                            ),
                            severity=Severity.CRITICAL,
                            source_ip=ip,
                            timestamp=ev.timestamp,
                            mitre_technique="T1110",
                            related_events=[w.raw_log for w in window],
                            details={
                                "window_seconds": self.time_window,
                                "failure_count": len(window),
                                "usernames_tried": usernames,
                            },
                        )
                    )
                    break
        return results

    def _correlate_lateral_movement(
        self, events: list[RawEvent]
    ) -> list[DetectionResult]:
        ip_ssh_success: dict[str, list[RawEvent]] = defaultdict(list)
        for ev in events:
            if (
                ev.event_type == EventType.AUTH_SUCCESS
                and ev.protocol == "ssh"
                and ev.source_ip
            ):
                ip_ssh_success[ev.source_ip].append(ev)

        results: list[DetectionResult] = []
        for ip, evts in ip_ssh_success.items():
            sorted_evts = sorted(evts, key=lambda e: e.timestamp)
            unique_users = {e.username for e in sorted_evts if e.username}
            if len(unique_users) >= 3:
                results.append(
                    DetectionResult(
                        rule_id="CORR-LATERAL-MOVEMENT",
                        rule_name="Lateral Movement Tespiti",
                        description=(
                            f"{ip} adresinden {len(unique_users)} farkli "
                            f"kullaniciyla basarili SSH girisi. "
                            f"Olasi lateral movement."
                        ),
                        severity=Severity.HIGH,
                        source_ip=ip,
                        timestamp=sorted_evts[-1].timestamp,
                        mitre_technique="T1021.004",
                        related_events=[e.raw_log for e in sorted_evts],
                        details={
                            "unique_users": list(unique_users),
                            "total_connections": len(sorted_evts),
                        },
                    )
                )
        return results
