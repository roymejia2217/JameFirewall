"""Pruebas unitarias para SystemProcessRunner (ProcessRunnerPort)."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner


def test_process_runner_executes_parameterized_args(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = SystemProcessRunner()
    mock_run = MagicMock()
    mock_run.return_value = subprocess.CompletedProcess(
        args=["netsh", "advfirewall"],
        returncode=0,
        stdout=b"Command executed successfully\r\n",
        stderr=b"",
    )
    monkeypatch.setattr(subprocess, "run", mock_run)

    code, out, err = runner.run(["netsh", "advfirewall", "show", "rule"])
    assert code == 0
    assert out == "Command executed successfully"
    assert err == ""

    # Verificar que NO se utiliza shell=True
    assert mock_run.call_args.kwargs["shell"] is False


def test_process_runner_handles_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = SystemProcessRunner()
    mock_run = MagicMock(side_effect=subprocess.TimeoutExpired(cmd=["sleep"], timeout=1.0))
    monkeypatch.setattr(subprocess, "run", mock_run)

    code, _, err = runner.run(["sleep", "5"], timeout=1.0)
    assert code == -1
    assert "Timeout" in err


def test_process_runner_handles_execution_error(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = SystemProcessRunner()
    mock_run = MagicMock(side_effect=OSError("Executable not found"))
    monkeypatch.setattr(subprocess, "run", mock_run)

    code, _, err = runner.run(["non_existent_binary"])
    assert code == -1
    assert "Executable not found" in err


def test_windows_powershell_ignores_path_and_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from jame_firewall.infrastructure.os import process_runner as module

    system = tmp_path / "trusted-system"
    powershell = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    powershell.parent.mkdir(parents=True)
    powershell.touch()
    monkeypatch.setenv("PATH", str(tmp_path / "untrusted"))
    monkeypatch.setenv("SystemRoot", str(tmp_path / "untrusted"))
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(module, "_system_directory", lambda: system, raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0, raising=False)
    launch = MagicMock(return_value=subprocess.CompletedProcess([], 0, b"", b""))
    monkeypatch.setattr(subprocess, "run", launch)
    runner = SystemProcessRunner()
    assert runner.run(["powershell", "-NoProfile"])[0] == 0
    assert launch.call_args.args[0][0] == str(powershell)
    assert launch.call_args.kwargs["stdin"] == subprocess.DEVNULL
    assert launch.call_args.kwargs["env"]["PSModulePath"] == str(powershell.parent / "Modules")


def test_windows_missing_system_powershell_never_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from jame_firewall.infrastructure.os import process_runner as module

    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(module, "_system_directory", lambda: tmp_path, raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0, raising=False)
    launch = MagicMock()
    monkeypatch.setattr(subprocess, "run", launch)
    code, _, error = SystemProcessRunner().run(["powershell"])
    assert code == -1
    assert error
    launch.assert_not_called()


@pytest.mark.parametrize("timeout", [None, 500.0])
def test_process_deadline_cannot_be_disabled(
    timeout: float | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    launch = MagicMock(return_value=subprocess.CompletedProcess([], 0, b"", b""))
    monkeypatch.setattr(subprocess, "run", launch)
    assert SystemProcessRunner().run(["command"], timeout=timeout)[0] == 0
    assert launch.call_args.kwargs["timeout"] == 30.0


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("nan"), float("inf")])
def test_invalid_deadline_does_not_spawn(timeout: float, monkeypatch: pytest.MonkeyPatch) -> None:
    launch = MagicMock()
    monkeypatch.setattr(subprocess, "run", launch)
    assert SystemProcessRunner().run(["command"], timeout=timeout)[0] == -1
    launch.assert_not_called()
