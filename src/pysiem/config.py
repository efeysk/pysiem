from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AppConfig:
    database_path: Path = field(default_factory=lambda: Path("data/db/pysiem.db"))
    log_path: Path = field(default_factory=lambda: Path("data/logs"))
    rules_path: Path = field(default_factory=lambda: Path("rules"))
    samples_path: Path = field(default_factory=lambda: Path("data/samples"))
    reports_path: Path = field(default_factory=lambda: Path("reports"))
    log_level: str = "INFO"
    brute_force_threshold: int = 5
    correlation_time_window: int = 300
    failed_login_threshold: int = 3
    port_scan_threshold: int = 100
    web_scan_threshold: int = 20
    dedup_window: int = 60

    @classmethod
    def from_env(cls) -> AppConfig:
        base = Path(os.environ.get("PYSIEM_BASE_DIR", "."))
        return cls(
            database_path=Path(
                os.environ.get("PYSIEM_DB_PATH", str(base / "data" / "db" / "pysiem.db"))
            ),
            log_path=Path(
                os.environ.get("PYSIEM_LOG_PATH", str(base / "data" / "logs"))
            ),
            rules_path=Path(
                os.environ.get("PYSIEM_RULES_PATH", str(base / "rules"))
            ),
            samples_path=Path(
                os.environ.get("PYSIEM_SAMPLES_PATH", str(base / "data" / "samples"))
            ),
            reports_path=Path(
                os.environ.get("PYSIEM_REPORTS_PATH", str(base / "reports"))
            ),
            log_level=os.environ.get("PYSIEM_LOG_LEVEL", "INFO"),
            brute_force_threshold=int(
                os.environ.get("PYSIEM_BRUTE_FORCE_THRESHOLD", "5")
            ),
            correlation_time_window=int(
                os.environ.get("PYSIEM_CORRELATION_WINDOW", "300")
            ),
            failed_login_threshold=int(
                os.environ.get("PYSIEM_FAILED_LOGIN_THRESHOLD", "3")
            ),
            port_scan_threshold=int(
                os.environ.get("PYSIEM_PORT_SCAN_THRESHOLD", "100")
            ),
            web_scan_threshold=int(
                os.environ.get("PYSIEM_WEB_SCAN_THRESHOLD", "20")
            ),
            dedup_window=int(os.environ.get("PYSIEM_DEDUP_WINDOW", "60")),
        )

    def ensure_directories(self) -> None:
        for d in (
            self.database_path.parent,
            self.log_path,
            self.reports_path,
        ):
            d.mkdir(parents=True, exist_ok=True)


def load_config() -> AppConfig:
    cfg = AppConfig.from_env()
    cfg.ensure_directories()
    return cfg
