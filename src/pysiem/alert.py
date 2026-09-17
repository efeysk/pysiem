from __future__ import annotations

from typing import Any

from pysiem.config import AppConfig
from pysiem.logging_config import get_logger
from pysiem.models import Alert, AlertStatus, DetectionResult, Severity
from pysiem.storage import DatabaseManager

logger = get_logger(__name__)


class AlertManager:
    def __init__(self, db: DatabaseManager, config: AppConfig) -> None:
        self.db = db
        self.config = config

    def process_detections(
        self, detections: list[DetectionResult]
    ) -> list[Alert]:
        alerts: list[Alert] = []
        for det in detections:
            if self.db.alert_exists(
                det.rule_id, det.source_ip, self.config.dedup_window
            ):
                logger.debug(
                    "Tekrarlanan alert atlandi: %s / %s",
                    det.rule_id,
                    det.source_ip,
                )
                continue

            alert = Alert(
                detection_id=str(hash(det.rule_id + det.source_ip)),
                rule_id=det.rule_id,
                rule_name=det.rule_name,
                severity=det.severity,
                status=AlertStatus.NEW,
                source_ip=det.source_ip,
                timestamp=det.timestamp,
                description=det.description,
                mitre_technique=det.mitre_technique,
                related_events=det.related_events,
                details=det.details,
            )
            self.db.insert_alert(alert)
            self.db.log_detection(det)
            alerts.append(alert)
            logger.info(
                "Yeni alert: [%s] %s - %s",
                alert.severity.value,
                alert.rule_name,
                alert.source_ip,
            )
        return alerts

    def list_alerts(
        self,
        limit: int = 100,
        severity: str | None = None,
        status: str | None = None,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.db.get_alerts(
            limit=limit, severity=severity, status=status, source_ip=source_ip
        )

    def update_status(self, alert_id: str, status: str) -> bool:
        valid_statuses = {s.value for s in AlertStatus}
        if status not in valid_statuses:
            logger.warning("Gecersiz alert durumu: %s", status)
            return False
        success = self.db.update_alert_status(alert_id, status)
        if success:
            logger.info("Alert durumu guncellendi: %s -> %s", alert_id, status)
        return success

    def get_summary(self) -> dict[str, Any]:
        total = self.db.count_alerts()
        by_severity = self.db.get_alerts_by_severity()
        return {
            "total_alerts": total,
            "by_severity": by_severity,
        }
