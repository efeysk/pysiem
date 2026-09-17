from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from pysiem.logging_config import get_logger
from pysiem.storage import DatabaseManager

logger = get_logger(__name__)


class ReportGenerator:
    def __init__(self, db: DatabaseManager, reports_path: Path) -> None:
        self.db = db
        self.reports_path = reports_path
        self.reports_path.mkdir(parents=True, exist_ok=True)

    def generate_full_report(self) -> dict[str, Any]:
        stats = self.db.get_event_stats()
        report: dict[str, Any] = {
            "report_title": "PySIEM Guvenlik Raporu",
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_events": stats.get("total_events", 0),
                "total_alerts": stats.get("total_alerts", 0),
            },
            "alerts_by_severity": stats.get("alerts_by_severity", {}),
            "events_by_type": stats.get("events_by_type", {}),
            "top_source_ips": stats.get("top_source_ips", {}),
            "top_alert_ips": stats.get("top_alert_ips", {}),
            "detections_by_rule": stats.get("detections_by_rule", {}),
            "mitre_distribution": stats.get("mitre_distribution", {}),
            "hourly_events": stats.get("hourly_events", {}),
        }
        return report

    def export_json(self, filename: str | None = None) -> Path:
        if filename is None:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{ts}.json"
        path = self.reports_path / filename
        report = self.generate_full_report()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        logger.info("JSON rapor olusturuldu: %s", path)
        return path

    def export_csv_alerts(self, filename: str | None = None) -> Path:
        if filename is None:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"alerts_{ts}.csv"
        path = self.reports_path / filename
        alerts = self.db.get_alerts(limit=10000)
        if not alerts:
            logger.warning("Disa aktarilacak alert bulunamadi.")
            return path
        fieldnames = list(alerts[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for alert in alerts:
                row = dict(alert)
                row["related_events"] = json.dumps(row.get("related_events", []))
                row["details"] = json.dumps(row.get("details", {}))
                writer.writerow(row)
        logger.info("CSV rapor olusturuldu: %s", path)
        return path

    def export_csv_events(self, filename: str | None = None) -> Path:
        if filename is None:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"events_{ts}.csv"
        path = self.reports_path / filename
        events = self.db.get_events(limit=10000)
        if not events:
            logger.warning("Disa aktarilacak olay bulunamadi.")
            return path
        fieldnames = list(events[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for ev in events:
                writer.writerow(ev)
        logger.info("CSV rapor olusturuldu: %s", path)
        return path

    def format_text_report(self) -> str:
        report = self.generate_full_report()
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("  PySIEM GUVENLIK RAPORU")
        lines.append(f"  Uretim Zamani: {report['generated_at']}")
        lines.append("=" * 60)
        lines.append("")

        s = report["summary"]
        lines.append(f"  Toplam Olay Sayisi      : {s['total_events']}")
        lines.append(f"  Toplam Alert Sayisi     : {s['total_alerts']}")
        lines.append("")

        lines.append("-" * 60)
        lines.append("  SEVERITY DAGILIMI")
        lines.append("-" * 60)
        for sev, cnt in report.get("alerts_by_severity", {}).items():
            lines.append(f"  {sev:12s} : {cnt}")
        lines.append("")

        lines.append("-" * 60)
        lines.append("  EN COK EVENTURETEN IP ADRESLERI")
        lines.append("-" * 60)
        for ip, cnt in report.get("top_source_ips", {}).items():
            lines.append(f"  {ip:20s} : {cnt}")
        lines.append("")

        lines.append("-" * 60)
        lines.append("  EN COK SALDIRI TESPIT EDILEN IP ADRESLERI")
        lines.append("-" * 60)
        for ip, cnt in report.get("top_alert_ips", {}).items():
            lines.append(f"  {ip:20s} : {cnt}")
        lines.append("")

        lines.append("-" * 60)
        lines.append("  DETECTION DAGILIMI")
        lines.append("-" * 60)
        for rule, cnt in report.get("detections_by_rule", {}).items():
            lines.append(f"  {rule:40s} : {cnt}")
        lines.append("")

        lines.append("-" * 60)
        lines.append("  MITRE ATT&CK DAGILIMI")
        lines.append("-" * 60)
        for tech, cnt in report.get("mitre_distribution", {}).items():
            lines.append(f"  {tech:20s} : {cnt}")
        lines.append("")

        lines.append("-" * 60)
        lines.append("  SAATLIK AKTIVITE DAGILIMI")
        lines.append("-" * 60)
        for hour, cnt in report.get("hourly_events", {}).items():
            bar = "#" * min(cnt, 50)
            lines.append(f"  {hour} : {cnt:5d} {bar}")
        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)
