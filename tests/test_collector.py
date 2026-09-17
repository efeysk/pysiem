"""Tests for pysiem.collector module."""

from __future__ import annotations

from pathlib import Path

import pytest

from pysiem.collector import LogCollector


@pytest.fixture
def collector() -> LogCollector:
    return LogCollector()


class TestCollectFile:
    def test_collect_valid_file(self, collector: LogCollector, tmp_path: Path) -> None:
        log_file = tmp_path / "test.log"
        log_file.write_text("line1\nline2\nline3\n", encoding="utf-8")
        lines = collector.collect_file(log_file)
        assert len(lines) == 3
        assert lines[0] == "line1"

    def test_collect_nonexistent_file(self, collector: LogCollector, tmp_path: Path) -> None:
        lines = collector.collect_file(tmp_path / "missing.log")
        assert lines == []

    def test_collect_empty_file(self, collector: LogCollector, tmp_path: Path) -> None:
        log_file = tmp_path / "empty.log"
        log_file.write_text("", encoding="utf-8")
        lines = collector.collect_file(log_file)
        assert lines == []

    def test_collect_skips_blank_lines(self, collector: LogCollector, tmp_path: Path) -> None:
        log_file = tmp_path / "mixed.log"
        log_file.write_text("line1\n\n\nline2\n\n", encoding="utf-8")
        lines = collector.collect_file(log_file)
        assert len(lines) == 2


class TestCollectDirectory:
    def test_collect_directory(self, collector: LogCollector, tmp_path: Path) -> None:
        (tmp_path / "a.log").write_text("line_a\n", encoding="utf-8")
        (tmp_path / "b.log").write_text("line_b\n", encoding="utf-8")
        lines = collector.collect_directory(tmp_path)
        assert len(lines) == 2

    def test_collect_directory_nonexistent(self, collector: LogCollector, tmp_path: Path) -> None:
        lines = collector.collect_directory(tmp_path / "missing_dir")
        assert lines == []


class TestCollectSource:
    def test_collect_file_source(self, collector: LogCollector, tmp_path: Path) -> None:
        log_file = tmp_path / "test.log"
        log_file.write_text("line1\n", encoding="utf-8")
        lines = collector.collect(log_file)
        assert len(lines) == 1

    def test_collect_directory_source(self, collector: LogCollector, tmp_path: Path) -> None:
        (tmp_path / "a.log").write_text("line_a\n", encoding="utf-8")
        lines = collector.collect(tmp_path)
        assert len(lines) == 1

    def test_collect_nonexistent_source(self, collector: LogCollector, tmp_path: Path) -> None:
        lines = collector.collect(tmp_path / "nothing")
        assert lines == []


class TestClear:
    def test_clear(self, collector: LogCollector, tmp_path: Path) -> None:
        log_file = tmp_path / "test.log"
        log_file.write_text("line1\nline2\n", encoding="utf-8")
        collector.collect_file(log_file)
        assert len(collector.lines) == 2
        collector.clear()
        assert len(collector.lines) == 0
