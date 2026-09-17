from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from pysiem.logging_config import get_logger
from pysiem.models import DetectionResult, DetectionRule, EventType, RawEvent, Severity

logger = get_logger(__name__)


class DetectionEngine:
    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules = rules or []
        self._patterns: dict[str, re.Pattern[str]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        for rule in self.rules:
            if rule.pattern:
                try:
                    self._patterns[rule.id] = re.compile(rule.pattern, re.IGNORECASE)
                except re.error as exc:
                    logger.error("Kural deseni derlenemedi [%s]: %s", rule.id, exc)

    def load_rules(self, rules: list[DetectionRule]) -> None:
        self.rules = rules
        self._compile_patterns()
        logger.info("%d tespit kurali yuklendi.", len(rules))

    def evaluate(self, events: list[RawEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                detections = self._evaluate_rule(rule, events)
                results.extend(detections)
            except Exception as exc:
                logger.error("Kural degerlendirme hatasi [%s]: %s", rule.id, exc)
        logger.info("%d tespit sonucu uretildi.", len(results))
        return results

    def _evaluate_rule(
        self, rule: DetectionRule, events: list[RawEvent]
    ) -> list[DetectionResult]:
        handler = {
            "brute_force": self._rule_brute_force,
            "failed_then_success": self._rule_failed_then_success,
            "pattern_match": self._rule_pattern_match,
            "suspicious_auth": self._rule_suspicious_auth,
            "web_scanning": self._rule_web_scanning,
            "multi_failed_auth": self._rule_multi_failed,
            "privilege_escalation": self._rule_privilege_escalation,
        }.get(rule.rule_type)

        if handler is None:
            logger.warning("Bilinmeyen kural tipi: %s", rule.rule_type)
            return []

        return handler(rule, events)

    def _rule_brute_force(
        self, rule: DetectionRule, events: list[RawEvent]
    ) -> list[DetectionResult]:
        ip_failures: dict[str, list[RawEvent]] = defaultdict(list)
        for ev in events:
            if ev.event_type == EventType.AUTH_FAILURE and ev.source_ip:
                ip_failures[ev.source_ip].append(ev)

        results: list[DetectionResult] = []
        for ip, fail_events in ip_failures.items():
            if len(fail_events) >= rule.threshold:
                timestamps = [e.timestamp for e in fail_events]
                time_range = (max(timestamps) - min(timestamps)).total_seconds()
                if rule.time_window <= 0 or time_range <= rule.time_window:
                    results.append(
                        DetectionResult(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            description=(
                                f"{ip} adresinden {len(fail_events)} basarisiz "
                                f"giris denemesi tespit edildi."
                            ),
                            severity=rule.severity,
                            source_ip=ip,
                            timestamp=max(timestamps),
                            mitre_technique=rule.mitre_technique,
                            related_events=[e.raw_log for e in fail_events[-10:]],
                            details={
                                "failure_count": len(fail_events),
                                "time_range_seconds": time_range,
                                "usernames_tried": list(
                                    {e.username for e in fail_events if e.username}
                                ),
                            },
                        )
                    )
        return results

    def _rule_failed_then_success(
        self, rule: DetectionRule, events: list[RawEvent]
    ) -> list[DetectionResult]:
        ip_events: dict[str, list[RawEvent]] = defaultdict(list)
        for ev in events:
            if ev.source_ip and ev.event_type in (
                EventType.AUTH_FAILURE,
                EventType.AUTH_SUCCESS,
            ):
                ip_events[ev.source_ip].append(ev)

        results: list[DetectionResult] = []
        for ip, evts in ip_events.items():
            sorted_evts = sorted(evts, key=lambda e: e.timestamp)
            consecutive_failures = 0
            for i, ev in enumerate(sorted_evts):
                if ev.event_type == EventType.AUTH_FAILURE:
                    consecutive_failures += 1
                else:
                    if consecutive_failures >= rule.threshold:
                        fail_events = sorted_evts[
                            i - consecutive_failures : i
                        ]
                        results.append(
                            DetectionResult(
                                rule_id=rule.id,
                                rule_name=rule.name,
                                description=(
                                    f"{ip} adresinden {consecutive_failures} basarisiz "
                                    f"giris denemesinden sonra basarili giris."
                                ),
                                severity=rule.severity,
                                source_ip=ip,
                                timestamp=ev.timestamp,
                                mitre_technique=rule.mitre_technique,
                                related_events=[e.raw_log for e in fail_events + [ev]],
                                details={
                                    "consecutive_failures": consecutive_failures,
                                    "successful_username": ev.username,
                                },
                            )
                        )
                    consecutive_failures = 0
        return results

    def _rule_pattern_match(
        self, rule: DetectionRule, events: list[RawEvent]
    ) -> list[DetectionResult]:
        if rule.id not in self._patterns:
            return []
        pattern = self._patterns[rule.id]
        results: list[DetectionResult] = []
        for ev in events:
            if pattern.search(ev.raw_log) or pattern.search(ev.message):
                results.append(
                    DetectionResult(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        description=f"{rule.description} - Kaynak: {ev.source_ip or 'bilinmiyor'}",
                        severity=rule.severity,
                        source_ip=ev.source_ip,
                        timestamp=ev.timestamp,
                        mitre_technique=rule.mitre_technique,
                        related_events=[ev.raw_log],
                        details={"matched_event_type": ev.event_type.value},
                    )
                )
        return results

    def _rule_suspicious_auth(
        self, rule: DetectionRule, events: list[RawEvent]
    ) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        suspicious_usernames = {
            "root", "admin", "administrator", "test", "guest",
            "oracle", "mysql", "postgres", "www-data", "nobody",
        }

        for ev in events:
            if ev.event_type != EventType.AUTH_FAILURE:
                continue
            reasons: list[str] = []
            if ev.username.lower() in suspicious_usernames:
                reasons.append(f"Sipheli kullanici adi: {ev.username}")
            if ev.source_ip:
                ip_failures = sum(
                    1
                    for e in events
                    if e.source_ip == ev.source_ip
                    and e.event_type == EventType.AUTH_FAILURE
                )
                if ip_failures >= rule.threshold:
                    reasons.append(f"Ayni IP'den {ip_failures} basarisiz deneme")

            if reasons:
                results.append(
                    DetectionResult(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        description=f"Supheli kimlik dogrulama aktivitesi: {'; '.join(reasons)}",
                        severity=rule.severity,
                        source_ip=ev.source_ip,
                        timestamp=ev.timestamp,
                        mitre_technique=rule.mitre_technique,
                        related_events=[ev.raw_log],
                        details={"reasons": reasons},
                    )
                )
        return results

    def _rule_web_scanning(
        self, rule: DetectionRule, events: list[RawEvent]
    ) -> list[DetectionResult]:
        ip_paths: dict[str, set[str]] = defaultdict(set)
        ip_events: dict[str, list[RawEvent]] = defaultdict(list)
        for ev in events:
            if ev.event_type == EventType.WEB_REQUEST and ev.source_ip:
                path = ev.extra.get("path", "")
                ip_paths[ev.source_ip].add(path)
                ip_events[ev.source_ip].append(ev)

        results: list[DetectionResult] = []
        for ip, paths in ip_paths.items():
            if len(paths) >= rule.threshold:
                evts = ip_events[ip]
                results.append(
                    DetectionResult(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        description=(
                            f"{ip} adresinden {len(paths)} farkli yol taranildi - "
                            f"olasi dizin taramasi."
                        ),
                        severity=rule.severity,
                        source_ip=ip,
                        timestamp=max(e.timestamp for e in evts),
                        mitre_technique=rule.mitre_technique,
                        related_events=[e.raw_log for e in evts[-10:]],
                        details={
                            "unique_paths": len(paths),
                            "sample_paths": list(paths)[:20],
                        },
                    )
                )
        return results

    def _rule_multi_failed(
        self, rule: DetectionRule, events: list[RawEvent]
    ) -> list[DetectionResult]:
        ip_users: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        ip_events_map: dict[str, list[RawEvent]] = defaultdict(list)
        for ev in events:
            if ev.event_type == EventType.AUTH_FAILURE and ev.source_ip:
                ip_users[ev.source_ip][ev.username] += 1
                ip_events_map[ev.source_ip].append(ev)

        results: list[DetectionResult] = []
        for ip, user_counts in ip_users.items():
            total_failures = sum(user_counts.values())
            if total_failures >= rule.threshold and len(user_counts) >= 2:
                evts = ip_events_map[ip]
                results.append(
                    DetectionResult(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        description=(
                            f"{ip} adresinden {len(user_counts)} farkli kullanicida "
                            f"{total_failures} basarisiz deneme."
                        ),
                        severity=rule.severity,
                        source_ip=ip,
                        timestamp=max(e.timestamp for e in evts),
                        mitre_technique=rule.mitre_technique,
                        related_events=[e.raw_log for e in evts[-10:]],
                        details={
                            "unique_users": list(user_counts.keys()),
                            "failure_counts": dict(user_counts),
                        },
                    )
                )
        return results

    def _rule_privilege_escalation(
        self, rule: DetectionRule, events: list[RawEvent]
    ) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for ev in events:
            if ev.event_type not in (
                EventType.AUTH_SUCCESS,
                EventType.APP_LOG,
                EventType.SYSTEM_EVENT,
            ):
                continue
            reasons: list[str] = []
            msg = ev.message.lower()
            if "sudo" in msg and ("root" in msg or "su " in msg):
                reasons.append("Sudo ile root erisimi denemesi")
            if ev.username == "root" and ev.event_type == EventType.AUTH_SUCCESS:
                if ev.source_ip and ev.source_ip not in ("127.0.0.1", "::1"):
                    reasons.append("Root hesabiyla uzak giris")
            if "su " in msg and ("root" in msg or "su -" in msg):
                reasons.append("Kullanici degistirme denemesi")
            if reasons:
                results.append(
                    DetectionResult(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        description=f"Supheli yetki yukseltme aktivitesi: {'; '.join(reasons)}",
                        severity=rule.severity,
                        source_ip=ev.source_ip,
                        timestamp=ev.timestamp,
                        mitre_technique=rule.mitre_technique,
                        related_events=[ev.raw_log],
                        details={"reasons": reasons},
                    )
                )
        return results
