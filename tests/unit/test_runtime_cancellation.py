"""Cancellation stops future work without pretending to undo firewall mutations."""

import subprocess
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
    monkeypatch.setattr(subprocess, "run", launch)
    token.cancel()
    with pytest.raises(OperationCancelledError):
        runner.run(["powershell", "-Command", "query"])
    launch.assert_not_called()


def test_cancellation_during_command_stops_next_command(monkeypatch: pytest.MonkeyPatch) -> None:
    token = CancellationToken()
    runner = SystemProcessRunner(cancellation=token)

    def finish_current(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        token.cancel()
        return subprocess.CompletedProcess([], 0, b"committed", b"")

    launch = MagicMock(side_effect=finish_current)
    monkeypatch.setattr(subprocess, "run", launch)
    assert runner.run(["command"])[0] == 0
    with pytest.raises(OperationCancelledError):
        runner.run(["next mutation"])
    assert launch.call_count == 1


def test_scanning_stops_between_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = CancellationToken()
    scanner = OSFileSystemAdapter(cancellation=token)

    def walk(root: Path) -> object:
        yield str(root), [], ["one.exe"]
        token.cancel()
        yield str(root), [], ["two.exe"]
        pytest.fail("scan continued after cancellation")

    monkeypatch.setattr("os.walk", walk)
    with pytest.raises(OperationCancelledError):
        scanner.find_executables([tmp_path])


def test_production_shares_cancellation_across_scan_and_processes(tmp_path: Path) -> None:
    container = AppContainer.create_production(config_path=tmp_path / "config.json")
    container.cancellation.cancel()
    with pytest.raises(OperationCancelledError):
        container.directory_scanner.find_executables([tmp_path])
    with pytest.raises(OperationCancelledError):
        container.process_runner.run(["anything"])
