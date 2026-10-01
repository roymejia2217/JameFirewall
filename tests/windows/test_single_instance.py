"""Native process races, crash recovery and security inspection on real Windows."""

import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from jame_firewall.core.exceptions import InstanceCoordinationError
from jame_firewall.infrastructure.os._win32_mutex import Win32MutexApi
from jame_firewall.infrastructure.os.instance_lock import WindowsInstanceLock

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native global Windows mutexes"),
]


def wait_ready(path: Path, process: subprocess.Popen[bytes]) -> str:
    deadline = time.monotonic() + 10
    while not path.exists():
        if process.poll() is not None:
            _, error = process.communicate(timeout=2)
            pytest.fail(f"Native probe exited before claiming ownership: {error!r}")
        if time.monotonic() >= deadline:
            pytest.fail("Native instance probe did not publish its result")
        time.sleep(0.01)
    return path.read_text(encoding="utf-8")


def launch_probe(name: str, ready: Path, stop: Path, start: Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("instance_probe.py")),
            name,
            str(ready),
            str(stop),
            str(start),
        ],
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def stop_probes(processes: list[subprocess.Popen[bytes]], stop: Path) -> None:
    stop.touch()
    for process in processes:
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


def test_two_native_processes_race_and_only_one_can_operate(tmp_path: Path) -> None:
    name = rf"Global\JameFirewall.Instance.tests.{uuid.uuid4().hex}"
    stop, start = tmp_path / "stop", tmp_path / "start"
    processes: list[subprocess.Popen[bytes]] = []
    try:
        ready = [tmp_path / "one", tmp_path / "two"]
        for marker in ready:
            processes.append(launch_probe(name, marker, stop, start))
        start.touch()
        results = [
            wait_ready(marker, process) for marker, process in zip(ready, processes, strict=True)
        ]
        assert sorted(results) == ["busy", "owned"]
        stop.touch()
        for process in processes:
            _, error = process.communicate(timeout=10)
            assert process.returncode == 0, error
        next_instance = WindowsInstanceLock(name)
        assert next_instance.acquire()
        next_instance.release()
    finally:
        stop_probes(processes, stop)


def test_abandoned_mutex_is_recovered_after_owner_is_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = rf"Global\JameFirewall.Instance.tests.{uuid.uuid4().hex}"
    ready, stop, start = tmp_path / "ready", tmp_path / "stop", tmp_path / "start"
    process = launch_probe(name, ready, stop, start)
    keeper: int | None = None
    api = Win32MutexApi()
    results: list[int] = []
    wait = api.wait

    def recorded_wait(handle: int) -> int:
        result = wait(handle)
        results.append(result)
        return result

    try:
        start.touch()
        assert wait_ready(ready, process) == "owned"
        # Keep the object alive so the next wait observes actual WAIT_ABANDONED.
        keeper = api.create(name)
        assert api.is_trusted(keeper)
        process.kill()
        process.communicate(timeout=10)
        monkeypatch.setattr(api, "wait", recorded_wait)
        recovered = WindowsInstanceLock(name, api=api)
        assert recovered.acquire()
        try:
            assert results == [0x80]
        finally:
            recovered.release()
    finally:
        if keeper is not None:
            api.close(keeper)
        stop_probes([process], stop)


def test_preexisting_mutex_with_an_unexpected_acl_is_not_a_valid_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from jame_firewall.infrastructure.os import _win32_mutex as native

    name = rf"Global\JameFirewall.Instance.tests.{uuid.uuid4().hex}"
    foreign = Win32MutexApi()
    # This producer grants WORLD access; the application must inspect the existing object.
    with monkeypatch.context() as altered_policy:
        altered_policy.setattr(native, "_MUTEX_SDDL", "O:BAD:P(A;;GA;;;WD)")
        handle = foreign.create(name)
    try:
        contender = WindowsInstanceLock(name)
        with pytest.raises(InstanceCoordinationError):
            contender.acquire()
    finally:
        foreign.close(handle)
