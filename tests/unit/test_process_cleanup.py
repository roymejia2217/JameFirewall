"""Retrying resource release must not restart the cleanup deadline."""

import os
import subprocess
import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from jame_firewall.infrastructure.os._process_io import PosixProcess
from jame_firewall.infrastructure.os._win32_process import Win32Process


def test_windows_close_does_not_restart_failed_cleanup_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = Win32Process.__new__(Win32Process)
    process._process, process._job = 1, 2
    process._assigned, process._finished = True, False
    process._handles = set()
    process._cleanup_deadline = None
    process._terminate_job = lambda *args: True
    process._wait = lambda *args: 0

    def active_job(job: object, info: object, output: Any, *args: object) -> bool:
        output._obj.active_processes = 1
        return True

    process._query_job = active_job
    ticks = iter([0.0, 6.0, 6.0, 6.0])
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    sleep = MagicMock(side_effect=AssertionError("Cleanup retry extended its expired deadline"))
    monkeypatch.setattr(time, "sleep", sleep)
    with pytest.raises(OSError, match="cleanup deadline"):
        process.finish()
    with pytest.raises(OSError, match="cleanup deadline"):
        process.close()
    sleep.assert_not_called()


def test_posix_close_does_not_restart_failed_cleanup_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = PosixProcess.__new__(PosixProcess)
    process._process = MagicMock()
    process._process.wait.side_effect = subprocess.TimeoutExpired("fixture", 5)
    process._streams = (MagicMock(), MagicMock())
    process._finished = False
    process._cleanup_deadline = None
    ticks = iter([0.0, 0.0, 6.0])
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks), raising=False)
    monkeypatch.setattr(os, "killpg", lambda *args: None)
    with pytest.raises(subprocess.TimeoutExpired):
        process.finish()
    with pytest.raises(subprocess.TimeoutExpired):
        process.close()
    assert [call.kwargs["timeout"] for call in process._process.wait.call_args_list] == [5.0, 0.0]
    for stream in process._streams:
        stream.close.assert_called_once()
