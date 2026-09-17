"""Tests for the CLI module."""

import tempfile
from pathlib import Path

import pytest

from pysiem.cli import main


class TestCLI:
    def test_no_command_shows_help(self, capsys: pytest.CaptureFixture) -> None:
        result = main([])
        assert result == 0

    def test_version(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "pysiem" in captured.out.lower() or "pysiem" in captured.out

    def test_ingest_nonexistent_file(self) -> None:
        result = main(["ingest", "/nonexistent/file.log"])
        assert result == 1

    def test_events_empty_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            import os
            os.environ["PYSIEM_DB_PATH"] = str(Path(tmpdir) / "test.db")
            os.environ["PYSIEM_RULES_PATH"] = str(Path(tmpdir) / "rules")
            os.environ["PYSIEM_LOG_PATH"] = str(Path(tmpdir) / "logs")
            os.environ["PYSIEM_REPORTS_PATH"] = str(Path(tmpdir) / "reports")
            os.environ["PYSIEM_SAMPLES_PATH"] = str(Path(tmpdir) / "samples")

            Path(tmpdir, "rules").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "logs").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "reports").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "samples").mkdir(parents=True, exist_ok=True)

            result = main(["events"])
            assert result == 0

    def test_alerts_empty_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            import os
            os.environ["PYSIEM_DB_PATH"] = str(Path(tmpdir) / "test.db")
            os.environ["PYSIEM_RULES_PATH"] = str(Path(tmpdir) / "rules")
            os.environ["PYSIEM_LOG_PATH"] = str(Path(tmpdir) / "logs")
            os.environ["PYSIEM_REPORTS_PATH"] = str(Path(tmpdir) / "reports")
            os.environ["PYSIEM_SAMPLES_PATH"] = str(Path(tmpdir) / "samples")

            Path(tmpdir, "rules").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "logs").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "reports").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "samples").mkdir(parents=True, exist_ok=True)

            result = main(["alerts"])
            assert result == 0

    def test_rules_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            import os
            os.environ["PYSIEM_DB_PATH"] = str(Path(tmpdir) / "test.db")
            os.environ["PYSIEM_RULES_PATH"] = str(Path(tmpdir) / "rules")
            os.environ["PYSIEM_LOG_PATH"] = str(Path(tmpdir) / "logs")
            os.environ["PYSIEM_REPORTS_PATH"] = str(Path(tmpdir) / "reports")
            os.environ["PYSIEM_SAMPLES_PATH"] = str(Path(tmpdir) / "samples")

            Path(tmpdir, "rules").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "logs").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "reports").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "samples").mkdir(parents=True, exist_ok=True)

            result = main(["rules"])
            assert result == 0

    def test_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            import os
            os.environ["PYSIEM_DB_PATH"] = str(Path(tmpdir) / "test.db")
            os.environ["PYSIEM_RULES_PATH"] = str(Path(tmpdir) / "rules")
            os.environ["PYSIEM_LOG_PATH"] = str(Path(tmpdir) / "logs")
            os.environ["PYSIEM_REPORTS_PATH"] = str(Path(tmpdir) / "reports")
            os.environ["PYSIEM_SAMPLES_PATH"] = str(Path(tmpdir) / "samples")

            Path(tmpdir, "rules").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "logs").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "reports").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "samples").mkdir(parents=True, exist_ok=True)

            result = main(["status"])
            assert result == 0

    def test_report_empty_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            import os
            os.environ["PYSIEM_DB_PATH"] = str(Path(tmpdir) / "test.db")
            os.environ["PYSIEM_RULES_PATH"] = str(Path(tmpdir) / "rules")
            os.environ["PYSIEM_LOG_PATH"] = str(Path(tmpdir) / "logs")
            os.environ["PYSIEM_REPORTS_PATH"] = str(Path(tmpdir) / "reports")
            os.environ["PYSIEM_SAMPLES_PATH"] = str(Path(tmpdir) / "samples")

            Path(tmpdir, "rules").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "logs").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "reports").mkdir(parents=True, exist_ok=True)
            Path(tmpdir, "samples").mkdir(parents=True, exist_ok=True)

            result = main(["report"])
            assert result == 0

    def test_invalid_command(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["nonexistent_command"])
        assert exc_info.value.code == 2
