"""Cancellation stops future work without pretending to undo firewall mutations."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from jame_firewall.core.cancellation import CancellationToken
from jame_firewall.core.exceptions import OperationCancelledError
from jame_firewall.infrastructure.container import AppContainer
from jame_firewall.infrastructure.os.filesystem import OSFileSystemAdapter
from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner


def test_close_prevents_any_further_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    token = CancellationToken()
    runner = SystemProcessRunner(cancellation=token)
    launch = MagicMock()
    monkeypatch.setattr(subprocess, "Popen", launch)
    token.cancel()
    with pytest.raises(OperationCancelledError):
        runner.run(["powershell", "-Command", "query"])
    launch.assert_not_called()


def test_cancellation_during_command_is_reported_before_any_next_command() -> None:
    class CancelAfterLaunch(CancellationToken):
        def __init__(self) -> None:
            super().__init__()
            self.checks = 0

        def check(self) -> None:
            self.checks += 1
            if self.checks >= 2:
                self.cancel()
            super().check()

    token = CancelAfterLaunch()
    runner = SystemProcessRunner(cancellation=token)
    with pytest.raises(OperationCancelledError):
        runner.run([sys.executable, "-c", "import time; time.sleep(0.2)"])
    with pytest.raises(OperationCancelledError):
        runner.run([sys.executable, "-c", "print('must not start')"])


def test_scanning_stops_between_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = CancellationToken()
    scanner = OSFileSystemAdapter(cancellation=token)

    first, second = MagicMock(), MagicMock()
    first.path = str(tmp_path / "first.exe")

    def cancel_on_stat(*args: object, **kwargs: object) -> object:
        token.cancel()
        return tmp_path.stat()

    first.stat.side_effect = cancel_on_stat
    read = MagicMock()
    read.return_value.__enter__.return_value = iter([first, second])
    monkeypatch.setattr("os.scandir", read)
    with pytest.raises(OperationCancelledError):
        scanner.find_executables([tmp_path])
    second.stat.assert_not_called()


def test_production_shares_cancellation_across_scan_and_processes(tmp_path: Path) -> None:
    container = AppContainer.create_production(config_path=tmp_path / "config.json")
    container.cancellation.cancel()
    with pytest.raises(OperationCancelledError):
        container.directory_scanner.find_executables([tmp_path])
    with pytest.raises(OperationCancelledError):
        container.process_runner.run(["anything"])
