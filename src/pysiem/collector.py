from __future__ import annotations

from pathlib import Path

from pysiem.logging_config import get_logger

logger = get_logger(__name__)


class LogCollector:
    def __init__(self) -> None:
        self._lines: list[str] = []

    @property
    def lines(self) -> list[str]:
        return list(self._lines)

    def collect_file(self, path: Path | str) -> list[str]:
        path = Path(path)
        if not path.is_file():
            logger.error("Log dosyasi bulunamadi: %s", path)
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = [line.rstrip("\n") for line in fh if line.strip()]
            logger.info("Log dosyasi okundu: %s (%d satir)", path, len(lines))
            self._lines.extend(lines)
            return lines
        except Exception as exc:
            logger.error("Log dosyasi okunurken hata olustu [%s]: %s", path, exc)
            return []

    def collect_directory(self, directory: Path | str, pattern: str = "*.log") -> list[str]:
        directory = Path(directory)
        if not directory.is_dir():
            logger.error("Dizin bulunamadi: %s", directory)
            return []
        all_lines: list[str] = []
        for log_file in sorted(directory.glob(pattern)):
            all_lines.extend(self.collect_file(log_file))
        logger.info("Dizinden %d satir toplandi: %s", len(all_lines), directory)
        return all_lines

    def collect(self, source: Path | str) -> list[str]:
        source = Path(source)
        if source.is_file():
            return self.collect_file(source)
        elif source.is_dir():
            return self.collect_directory(source)
        else:
            logger.error("Gecerli bir dosya veya dizin degil: %s", source)
            return []

    def clear(self) -> None:
        self._lines.clear()
