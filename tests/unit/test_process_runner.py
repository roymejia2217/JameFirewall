"""Pruebas unitarias para SystemProcessRunner (ProcessRunnerPort)."""

import subprocess
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
