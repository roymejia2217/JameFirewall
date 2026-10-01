"""Process outcomes and trusted launch policy for the bounded process runner."""

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from jame_firewall.core import entities
from jame_firewall.infrastructure.os import process_runner as module
from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner


def test_process_runner_executes_parameterized_args_without_shell_expansion() -> None:
    argument = "literal; $(echo expanded) & extra"
    result = SystemProcessRunner().run(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", argument]
    )

    assert result.status == entities.ProcessStatus.COMPLETED
    assert result.returncode == 0
    assert result.stdout == argument
    assert result.stderr == ""
    assert result.succeeded


def test_nonzero_exit_is_completed_but_unsuccessful() -> None:
    result = SystemProcessRunner().run(
        [sys.executable, "-c", "import sys; print('failure', file=sys.stderr); sys.exit(7)"]
    )

    assert result.status == entities.ProcessStatus.COMPLETED
    assert result.returncode == 7
    assert result.stderr == "failure"
    assert not result.succeeded


def test_process_runner_handles_execution_error(tmp_path: Path) -> None:
    result = SystemProcessRunner().run([str(tmp_path / "nonexistent-executable")])

    assert result.status == entities.ProcessStatus.START_FAILED
    assert result.returncode is None
    assert result.detail
    assert not result.succeeded


def test_windows_powershell_ignores_path_and_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system = tmp_path / "trusted-system"
    powershell = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    powershell.parent.mkdir(parents=True)
    powershell.touch()
    monkeypatch.setenv("PATH", str(tmp_path / "untrusted"))
    monkeypatch.setenv("SystemRoot", str(tmp_path / "untrusted"))
    monkeypatch.setenv("PSModulePath", str(tmp_path / "untrusted-modules"))
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(module, "_system_directory", lambda: system)
    args = ["powershell", "-NoProfile", "-Command", "Get-NetFirewallRule"]

    command, environment = module._prepare_command(args)

    assert args[0] == "powershell", "Preparation must not mutate caller arguments"
    assert command[0] == str(powershell)
    assert environment is not None
    assert environment["PSModulePath"] == str(powershell.parent / "Modules")
    assert command[-1].startswith("$env:PSModulePath = '")
    assert "Get-NetFirewallRule" in command[-1]


def test_windows_missing_system_powershell_never_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(module, "_system_directory", lambda: tmp_path)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0, raising=False)
    launch = MagicMock(side_effect=AssertionError("Missing trusted executable must not launch"))
    monkeypatch.setattr(subprocess, "Popen", launch)
    result = SystemProcessRunner().run(["powershell"])

    assert result.status == entities.ProcessStatus.START_FAILED
    assert result.returncode is None
    assert result.detail
    launch.assert_not_called()


@pytest.mark.parametrize("timeout", [None, 500.0, 30.0])
def test_process_deadline_cannot_be_disabled(timeout: float | None) -> None:
    assert module._bounded_timeout(timeout) == 30.0


def test_shorter_deadline_is_preserved() -> None:
    assert module._bounded_timeout(0.125) == 0.125


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("nan"), float("inf")])
def test_invalid_deadline_does_not_spawn(timeout: float, monkeypatch: pytest.MonkeyPatch) -> None:
    launch = MagicMock(side_effect=AssertionError("Invalid deadline must not launch"))
    monkeypatch.setattr(subprocess, "Popen", launch)
    result = SystemProcessRunner().run(
        [sys.executable, "-c", "raise AssertionError()"], timeout=timeout
    )

    assert result.status == entities.ProcessStatus.START_FAILED
    assert result.returncode is None
    assert not result.succeeded
    launch.assert_not_called()


@pytest.mark.parametrize("status_name", ["TIMED_OUT", "OUTPUT_LIMIT", "START_FAILED"])
def test_incomplete_result_is_never_successful_even_with_zero_code(status_name: str) -> None:
    status = getattr(entities.ProcessStatus, status_name)
    result = entities.ProcessResult(status=status, returncode=0)

    assert not result.succeeded


@pytest.mark.parametrize("limit", [0, -1, 8 * 1024 * 1024 + 1])
def test_output_budget_cannot_be_disabled_or_extended(limit: int) -> None:
    with pytest.raises(ValueError):
        SystemProcessRunner(max_output_bytes=limit)


def test_read_failure_releases_process_and_never_claims_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = MagicMock()
    process.read.side_effect = OSError("pipe unavailable")
    monkeypatch.setattr(module, "_launch", lambda *args: process)
    result = SystemProcessRunner().run(["fixture"])
    assert result.status == entities.ProcessStatus.IO_FAILED
    assert not result.succeeded
    process.close.assert_called_once()
