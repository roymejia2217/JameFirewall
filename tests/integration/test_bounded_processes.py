"""Real subprocesses prove bounded capture and process-tree reclamation."""

import contextlib
import os
import signal
import sys
import time
from pathlib import Path
from threading import Thread

import pytest

from jame_firewall.core import entities
from jame_firewall.core.cancellation import CancellationToken
from jame_firewall.core.exceptions import OperationCancelledError
from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner


def process_is_alive(pid: int) -> bool:
    status = Path(f"/proc/{pid}/stat")
    # A zombie cannot execute or keep inherited pipes open. The process may
    # disappear between checking the proc entry and reading its state.
    with contextlib.suppress(FileNotFoundError):
        if status.read_text().rsplit(")", 1)[1].split()[0] == "Z":
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def kill_fixture(pid_file: Path) -> None:
    if pid_file.exists():
        with contextlib.suppress(ProcessLookupError):
            os.kill(int(pid_file.read_text()), signal.SIGKILL)


def wait_for_marker(marker: Path) -> None:
    deadline = time.monotonic() + 5
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not marker.exists():
        raise AssertionError("child did not publish its startup marker")


def test_real_capture_drains_stdout_and_stderr() -> None:
    result = SystemProcessRunner().run(
        [sys.executable, "-c", "import sys; print('stdout'); print('stderr', file=sys.stderr)"]
    )

    assert result.status == entities.ProcessStatus.COMPLETED
    assert result.stdout == "stdout"
    assert result.stderr == "stderr"
    assert result.returncode == 0
    assert result.succeeded


def test_short_timeout_is_bounded_and_not_successful() -> None:
    started = time.monotonic()
    result = SystemProcessRunner().run(
        [sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.15
    )

    assert time.monotonic() - started < 3
    assert result.status == entities.ProcessStatus.TIMED_OUT
    assert not result.succeeded


def test_combined_output_budget_caps_both_pipes() -> None:
    cap = 4096
    result = SystemProcessRunner(max_output_bytes=cap).run(
        [
            sys.executable,
            "-c",
            "import os; "
            "os.write(1, b'A' * 3072); os.write(2, b'B' * 3072); "
            "os.write(1, b'C' * 262144)",
        ]
    )

    assert result.status == entities.ProcessStatus.OUTPUT_LIMIT
    assert not result.succeeded
    assert len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")) <= cap


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process group fixture")
@pytest.mark.parametrize("parent_exits", [False, True])
def test_timeout_reclaims_descendant_even_when_parent_exits(
    tmp_path: Path, parent_exits: bool
) -> None:
    pid_file = tmp_path / "descendant.pid"
    parent = (
        "import subprocess, sys, pathlib, time; "
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
        + ("sys.exit(0)" if parent_exits else "time.sleep(20)")
    )
    started = time.monotonic()
    try:
        result = SystemProcessRunner().run(
            [sys.executable, "-c", parent, str(pid_file)], timeout=0.3
        )
        assert time.monotonic() - started < 3
        assert pid_file.exists()
        assert not process_is_alive(int(pid_file.read_text())), (
            "descendant outlived bounded command"
        )
        if parent_exits:
            assert result.status == entities.ProcessStatus.COMPLETED
            assert result.returncode == 0
            assert result.succeeded
        else:
            assert not result.succeeded
            assert result.status == entities.ProcessStatus.TIMED_OUT
    finally:
        kill_fixture(pid_file)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process group fixture")
def test_cancellation_reclaims_tree_before_raising(tmp_path: Path) -> None:
    pid_file = tmp_path / "descendant.pid"
    parent_pid_file = tmp_path / "parent.pid"
    token = CancellationToken()
    thread_errors: list[Exception] = []

    def cancel_when_running() -> None:
        try:
            wait_for_marker(pid_file)
            token.cancel()
        except Exception as error:
            thread_errors.append(error)
            token.cancel()

    canceller = Thread(target=cancel_when_running)
    canceller.start()
    script = (
        "import os, subprocess, sys, pathlib, time; "
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']); "
        "pathlib.Path(sys.argv[2]).write_text(str(os.getpid())); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(2)"
    )
    started = time.monotonic()
    try:
        with pytest.raises(OperationCancelledError):
            SystemProcessRunner(cancellation=token).run(
                [sys.executable, "-c", script, str(pid_file), str(parent_pid_file)], timeout=3
            )
        assert time.monotonic() - started < 1.5
        assert not process_is_alive(int(pid_file.read_text()))
        assert not process_is_alive(int(parent_pid_file.read_text()))
    finally:
        token.cancel()
        canceller.join(timeout=6)
        kill_fixture(pid_file)
        kill_fixture(parent_pid_file)
    assert not canceller.is_alive()
    assert thread_errors == []
