from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from pysiem import __version__
from pysiem.alert import AlertManager
from pysiem.collector import LogCollector
from pysiem.config import AppConfig, load_config
from pysiem.correlation import CorrelationEngine
from pysiem.detection import DetectionEngine
from pysiem.logging_config import get_logger, setup_logging
from pysiem.normalizer import EventNormalizer
from pysiem.parser import LogParser
from pysiem.report import ReportGenerator
from pysiem.storage import DatabaseManager


def _load_rules_from_json(rules_path: Path) -> list[dict]:
    import json as _json

    rules: list[dict] = []
    if not rules_path.is_dir():
        return rules
    for rule_file in sorted(rules_path.glob("*.json")):
        try:
            with open(rule_file, "r", encoding="utf-8") as fh:
                data = _json.load(fh)
                if isinstance(data, list):
                    rules.extend(data)
                elif isinstance(data, dict):
                    rules.append(data)
        except Exception as exc:
            logger.warning("Kural dosyasi okunamadi [%s]: %s", rule_file, exc)
    return rules


logger = get_logger("pysiem.cli")


def _init_infra(config: AppConfig) -> tuple[DatabaseManager, DetectionEngine, AlertManager]:
    db = DatabaseManager(config.database_path)
    db.initialize()

    raw_rules = _load_rules_from_json(config.rules_path)
    from pysiem.models import DetectionRule, Severity

    rules = []
    for r in raw_rules:
        rules.append(
            DetectionRule(
                id=r.get("id", ""),
                name=r.get("name", ""),
                description=r.get("description", ""),
                severity=Severity(r.get("severity", "MEDIUM")),
                threshold=r.get("threshold", 5),
                time_window=r.get("time_window", 300),
                mitre_technique=r.get("mitre_technique", ""),
                rule_type=r.get("rule_type", ""),
                enabled=r.get("enabled", True),
                pattern=r.get("pattern", ""),
                fields=r.get("fields", {}),
            )
        )

    detection = DetectionEngine(rules)
    alert_mgr = AlertManager(db, config)
    return db, detection, alert_mgr


def cmd_ingest(args: argparse.Namespace) -> int:
    config = load_config()
    setup_logging(config.log_level, config.log_path / "pysiem.log")

    source = Path(args.source)
    print(f"[INFO] Log dosyasi okunuyor: {source}")

    collector = LogCollector()
    lines = collector.collect(source)
    if not lines:
        print("[HATA] Dosyadan hic satir okunamadi.")
        return 1

    print(f"[OK] {len(lines)} satir toplandi.")

    parser = LogParser()
    events = parser.parse_lines(lines)
    if not events:
        print("[HATA] Hic olay ayristirilamadi.")
        return 1

    print(f"[OK] {len(events)} olay ayristirildi.")

    normalizer = EventNormalizer()
    normalized = normalizer.normalize(events)
    print(f"[OK] {len(normalized)} olay normalize edildi.")

    db, detection_engine, alert_mgr = _init_infra(config)

    event_ids = db.insert_events(normalized)
    print(f"[OK] {len(event_ids)} olay veritabanina kaydedildi.")

    detections = detection_engine.evaluate(normalized)
    print(f"[OK] {len(detections)} tespit yapildi.")

    correlation_engine = CorrelationEngine(config)
    correlations = correlation_engine.analyze(normalized)
    print(f"[OK] {len(correlations)} korelasyon sonucu.")

    all_detections = detections + correlations
    alerts = alert_mgr.process_detections(all_detections)
    print(f"[OK] {len(alerts)} alert olusturuldu.")

    if alerts:
        high_alerts = [
            a for a in alerts if a.severity.value in ("HIGH", "CRITICAL")
        ]
        if high_alerts:
            print(f"\n[ALERT] {len(high_alerts)} yuksek oncelikli supheli aktivite tespit edildi!")
            for a in high_alerts[:10]:
                print(
                    f"  [{a.severity.value:8s}] {a.rule_name} "
                    f"- IP: {a.source_ip} - {a.description}"
                )

    print("\n[OK] Log ingest islemi tamamlandi.")
    db.close()
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    config = load_config()
    db = DatabaseManager(config.database_path)
    db.initialize()

    events = db.get_events(
        limit=args.limit,
        severity=getattr(args, "severity", None),
        event_type=getattr(args, "type", None),
        source_ip=getattr(args, "ip", None),
    )

    if not events:
        print("[INFO] Kayitli olay bulunamadi.")
        db.close()
        return 0

    print(f"[INFO] {len(events)} olay listeleniyor:\n")
    print(
        f"{'ZAMAN':20s} {'TIP':14s} {'SEVIYE':10s} "
        f"{'KAYNAK IP':18s} {'KULLANICI':15s} {'MESAJ'}"
    )
    print("-" * 110)
    for ev in events:
        ts = ev.get("timestamp", "")[:19]
        etype = ev.get("event_type", "")[:14]
        sev = ev.get("severity", "")[:10]
        sip = ev.get("source_ip", "")[:18]
        user = ev.get("username", "")[:15]
        msg = ev.get("message", "")[:40]
        print(f"{ts:20s} {etype:14s} {sev:10s} {sip:18s} {user:15s} {msg}")

    db.close()
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    config = load_config()
    db = DatabaseManager(config.database_path)
    db.initialize()
    alert_mgr = AlertManager(db, config)

    alerts = alert_mgr.list_alerts(
        limit=args.limit,
        severity=getattr(args, "severity", None),
        status=getattr(args, "status", None),
    )

    if not alerts:
        print("[INFO] Kayitli alert bulunamadi.")
        db.close()
        return 0

    print(f"[INFO] {len(alerts)} alert listeleniyor:\n")
    print(
        f"{'ID':38s} {'SEVIYE':10s} {'DURUM':16s} "
        f"{'KAYNAK IP':18s} {'KURAL'}"
    )
    print("-" * 110)
    for al in alerts:
        aid = al.get("id", "")[:38]
        sev = al.get("severity", "")[:10]
        status = al.get("status", "")[:16]
        sip = al.get("source_ip", "")[:18]
        rule = al.get("rule_name", "")[:40]
        print(f"{aid:38s} {sev:10s} {status:16s} {sip:18s} {rule}")

    db.close()
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    config = load_config()
    db = DatabaseManager(config.database_path)
    db.initialize()

    raw_events = db.get_events(limit=100000)
    if not raw_events:
        print("[INFO] Analiz edilecek olay bulunamadi.")
        db.close()
        return 0

    from pysiem.models import EventType, RawEvent, Severity
    from datetime import datetime

    events: list[RawEvent] = []
    for re_dict in raw_events:
        try:
            ev = RawEvent(
                timestamp=datetime.fromisoformat(re_dict["timestamp"]),
                source=re_dict.get("source", ""),
                event_type=EventType(re_dict.get("event_type", "unknown")),
                username=re_dict.get("username", ""),
                source_ip=re_dict.get("source_ip", ""),
                destination_ip=re_dict.get("destination_ip", ""),
                port=re_dict.get("port", 0),
                status=re_dict.get("status", ""),
                message=re_dict.get("message", ""),
                severity=Severity(re_dict.get("severity", "LOW")),
                raw_log=re_dict.get("raw_log", ""),
                hostname=re_dict.get("hostname", ""),
                protocol=re_dict.get("protocol", ""),
            )
            events.append(ev)
        except Exception:
            continue

    print(f"[INFO] {len(events)} olay uzerinde tespit calistiriliyor...")

    _, detection_engine, alert_mgr = _init_infra(config)

    detections = detection_engine.evaluate(events)
    correlation_engine = CorrelationEngine(config)
    correlations = correlation_engine.analyze(events)

    all_detections = detections + correlations
    print(f"[OK] {len(all_detections)} tespit sonucu.")

    if all_detections:
        alerts = alert_mgr.process_detections(all_detections)
        print(f"[OK] {len(alerts)} yeni alert olusturuldu.")
        for det in all_detections:
            print(
                f"\n  [{det.severity.value:8s}] {det.rule_name}"
                f"\n    IP: {det.source_ip}"
                f"\n    Aciklama: {det.description}"
                f"\n    MITRE: {det.mitre_technique}"
            )

    db.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    config = load_config()
    db = DatabaseManager(config.database_path)
    db.initialize()

    report_gen = ReportGenerator(db, config.reports_path)

    if getattr(args, "format", "text") == "json":
        path = report_gen.export_json()
        print(f"[OK] JSON rapor olusturuldu: {path}")
    elif getattr(args, "format", "text") == "csv":
        path = report_gen.export_csv_alerts()
        print(f"[OK] CSV rapor olusturuldu: {path}")
    else:
        print(report_gen.format_text_report())

    db.close()
    return 0


def cmd_alert_update(args: argparse.Namespace) -> int:
    config = load_config()
    db = DatabaseManager(config.database_path)
    db.initialize()
    alert_mgr = AlertManager(db, config)

    success = alert_mgr.update_status(args.alert_id, args.status)
    if success:
        print(f"[OK] Alert durumu guncellendi: {args.alert_id} -> {args.status}")
    else:
        print("[HATA] Alert guncellenemedi. ID veya durum gecersiz.")
    db.close()
    return 0 if success else 1


def cmd_rules(args: argparse.Namespace) -> int:
    config = load_config()
    raw_rules = _load_rules_from_json(config.rules_path)
    if not raw_rules:
        print("[INFO] Yuklenmis kural bulunamadi.")
        return 0

    print(f"[INFO] {len(raw_rules)} kural yuklendi:\n")
    print(f"{'ID':20s} {'ISIM':35s} {'SEVIYE':10s} {'MITRE':12s} {'TIP'}")
    print("-" * 100)
    for r in raw_rules:
        rid = r.get("id", "")[:20]
        name = r.get("name", "")[:35]
        sev = r.get("severity", "")[:10]
        mitre = r.get("mitre_technique", "")[:12]
        rtype = r.get("rule_type", "")
        print(f"{rid:20s} {name:35s} {sev:10s} {mitre:12s} {rtype}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    config = load_config()
    db = DatabaseManager(config.database_path)
    db.initialize()

    event_count = db.count_events()
    alert_count = db.count_alerts()
    rules = _load_rules_from_json(config.rules_path)

    print("=" * 50)
    print("  PySIEM SISTEM DURUMU")
    print("=" * 50)
    print(f"  Veritabani       : {config.database_path}")
    print(f"  Toplam Olay      : {event_count}")
    print(f"  Toplam Alert     : {alert_count}")
    print(f"  Yuklenen Kurallar: {len(rules)}")
    print(f"  Log Seviyesi     : {config.log_level}")
    print("=" * 50)

    db.close()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pysiem",
        description="PySIEM - Mini Security Information and Event Management",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", help="Komutlar")

    p_ingest = subparsers.add_parser(
        "ingest", help="Log dosyasini sisteme aktar"
    )
    p_ingest.add_argument("source", help="Log dosyasi veya dizin yolu")

    p_events = subparsers.add_parser("events", help="Olaylari listele")
    p_events.add_argument(
        "--limit", type=int, default=50, help="Maksimum olay sayisi"
    )
    p_events.add_argument("--severity", help="Seviye filtresi")
    p_events.add_argument("--type", help="Olay tipi filtresi")
    p_events.add_argument("--ip", help="Kaynak IP filtresi")

    p_alerts = subparsers.add_parser("alerts", help="Alertleri listele")
    p_alerts.add_argument(
        "--limit", type=int, default=50, help="Maksimum alert sayisi"
    )
    p_alerts.add_argument("--severity", help="Seviye filtresi")
    p_alerts.add_argument("--status", help="Durum filtresi")

    p_detect = subparsers.add_parser(
        "detect", help="Tum olaylar uzerinde tespit calistir"
    )

    p_report = subparsers.add_parser("report", help="Rapor olustur")
    p_report.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Rapor formati",
    )

    p_alert_upd = subparsers.add_parser(
        "alert-update", help="Alert durumunu guncelle"
    )
    p_alert_upd.add_argument("alert_id", help="Alert ID")
    p_alert_upd.add_argument(
        "status",
        choices=["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"],
        help="Yeni durum",
    )

    p_rules = subparsers.add_parser("rules", help="Yuklenen kurallari listele")

    p_status = subparsers.add_parser("status", help="Sistem durumunu goster")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    command_map = {
        "ingest": cmd_ingest,
        "events": cmd_events,
        "alerts": cmd_alerts,
        "detect": cmd_detect,
        "report": cmd_report,
        "alert-update": cmd_alert_update,
        "rules": cmd_rules,
        "status": cmd_status,
    }

    handler = command_map.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)
