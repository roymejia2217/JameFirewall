"""Real Windows Job Object ownership, bounded output, and resource cleanup."""

from __future__ import annotations

import ctypes
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest

from jame_firewall.core.cancellation import CancellationToken
from jame_firewall.core.entities import ProcessStatus
from jame_firewall.core.exceptions import OperationCancelledError
from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(sys.platform != "win32", reason="requires Windows Job Objects"),
]

_CHILD = """import pathlib, sys, time
pidfile, marker = map(pathlib.Path, sys.argv[1:])
import os
pidfile.write_text(str(os.getpid()), encoding='ascii')
while True:
    marker.write_text(str(time.monotonic()), encoding='ascii')
    time.sleep(0.05)
"""

_PARENT = """import pathlib, subprocess, sys, time
child_code, pidfile, marker, mode = sys.argv[1:]
subprocess.Popen([sys.executable, '-u', '-c', child_code, pidfile, marker],
                 stdout=sys.stdout, stderr=sys.stderr)
deadline = time.monotonic() + 5
while not (pathlib.Path(pidfile).exists() and pathlib.Path(marker).exists()):
    if time.monotonic() > deadline:
        raise RuntimeError('Child fixture did not start')
    time.sleep(0.01)
print('CHILD_STARTED', flush=True)
if mode == 'normal':
    sys.exit(0)
if mode == 'overflow':
    for _ in range(4096):
        sys.stdout.write('x' * 4096)
        sys.stdout.flush()
    sys.stderr.write('y' * 4096)
    sys.stderr.flush()
time.sleep(60)
"""


def _kernel32() -> Any:
    loader = getattr(ctypes, "WinDLL", None)
    assert loader is not None
    return loader("kernel32", use_last_error=True)


def _child_handle(pid: int) -> tuple[Any, Any]:
    kernel = _kernel32()
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    handle = kernel.OpenProcess(0x100000 | 0x1000 | 0x0001, False, pid)
    return kernel, handle


def _assert_child_stopped(pidfile: Path, marker: Path) -> None:
    assert pidfile.exists(), "The descendant fixture must start before cleanup is tested"
    pid = int(pidfile.read_text(encoding="ascii"))
    kernel, handle = _child_handle(pid)
    if handle:
        try:
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.WaitForSingleObject.restype = wintypes.DWORD
            assert kernel.WaitForSingleObject(handle, 0) == 0, "Descendant survived runner cleanup"
        finally:
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle(handle)
    else:
        last_error = getattr(ctypes, "get_last_error", None)
        assert last_error is not None
        assert last_error() == 87
    assert marker.exists(), "Descendant must execute before cleanup is tested"
    previous = marker.read_bytes()
    threading.Event().wait(0.1)
    assert marker.read_bytes() == previous, "Descendant kept writing after cleanup"


def _cleanup_child(pidfile: Path) -> None:
    if not pidfile.exists():
        return
    kernel, handle = _child_handle(int(pidfile.read_text(encoding="ascii")))
    if handle:
        try:
            kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
            kernel.TerminateProcess(handle, 1)
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.WaitForSingleObject(handle, 5000)
        finally:
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle(handle)


def _command(tmp_path: Path, mode: str) -> tuple[list[str], Path, Path]:
    pidfile = tmp_path / "descendant.pid"
    marker = tmp_path / "descendant-marker.txt"
    return (
        [sys.executable, "-u", "-c", _PARENT, _CHILD, str(pidfile), str(marker), mode],
        pidfile,
        marker,
    )


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("timeout", ProcessStatus.TIMED_OUT),
        ("overflow", ProcessStatus.OUTPUT_LIMIT),
        ("normal", ProcessStatus.COMPLETED),
    ],
)
def test_native_runner_reaps_descendants_on_every_exit_path(
    tmp_path: Path, mode: str, expected: ProcessStatus
) -> None:
    command, pidfile, marker = _command(tmp_path, mode)
    try:
        started = time.monotonic()
        result = SystemProcessRunner(max_output_bytes=4096).run(command, timeout=3)
        assert time.monotonic() - started < 9, "Cleanup exceeded command plus cleanup budgets"
        assert result.status == expected, result
        assert len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")) <= 4096
        if mode == "normal":
            assert result.succeeded
            assert result.returncode == 0
            assert "CHILD_STARTED" in result.stdout
        else:
            assert not result.succeeded
        _assert_child_stopped(pidfile, marker)
    finally:
        _cleanup_child(pidfile)


def test_native_runner_cancellation_kills_started_descendant(tmp_path: Path) -> None:
    token = CancellationToken()
    command, pidfile, marker = _command(tmp_path, "timeout")
    fixture_started = threading.Event()

    def cancel_when_started() -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if pidfile.exists() and marker.exists():
                fixture_started.set()
                token.cancel()
                return
            threading.Event().wait(0.01)
        token.cancel()

    canceller = threading.Thread(target=cancel_when_started)
    canceller.start()
    try:
        with pytest.raises(OperationCancelledError):
            SystemProcessRunner(cancellation=token).run(command, timeout=10)
        assert fixture_started.is_set(), "Cancellation must occur after the real child starts"
        _assert_child_stopped(pidfile, marker)
    finally:
        canceller.join(timeout=6)
        assert not canceller.is_alive()
        _cleanup_child(pidfile)


def _handle_count() -> int:
    kernel = _kernel32()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetProcessHandleCount.restype = wintypes.BOOL
    count = wintypes.DWORD()
    assert kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(count))
    return int(count.value)


def test_native_repeated_runs_release_handles_and_reader_threads() -> None:
    runner = SystemProcessRunner(max_output_bytes=4096)
    command = [sys.executable, "-c", "print('bounded-output')"]
    assert runner.run(command).succeeded  # Warm up runtime facilities before the baseline.
    handles_before = _handle_count()
    threads_before = {thread.ident for thread in threading.enumerate()}
    for _ in range(4):
        result = runner.run(command, timeout=3)
        assert result.succeeded, result
        assert result.stdout == "bounded-output"
        timed_out = runner.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=0.05)
        assert timed_out.status == ProcessStatus.TIMED_OUT
        overflow = runner.run([sys.executable, "-c", "print('x' * 8192)"], timeout=3)
        assert overflow.status == ProcessStatus.OUTPUT_LIMIT
    assert _handle_count() <= handles_before + 4
    assert {thread.ident for thread in threading.enumerate()} <= threads_before


def test_failed_job_assignment_never_executes_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jame_firewall.infrastructure.os._win32_process import Win32Process

    initialize = Win32Process._initialize_api

    def deny_assignment(process: Win32Process) -> None:
        initialize(process)
        process._assign = lambda *args: 0

    marker = tmp_path / "must-not-execute"
    handles_before = _handle_count()
    monkeypatch.setattr(Win32Process, "_initialize_api", deny_assignment)
    result = SystemProcessRunner().run(
        [sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()", str(marker)]
    )
    assert result.status == ProcessStatus.START_FAILED
    assert not result.succeeded
    assert not marker.exists()
    assert _handle_count() <= handles_before + 4
