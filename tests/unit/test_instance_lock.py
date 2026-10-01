"""Mutex ownership and fail-closed startup without Windows or a display."""

import threading
from dataclasses import dataclass, field

import pytest

from jame_firewall.core.exceptions import InstanceCoordinationError
from jame_firewall.core.ports import InstanceLockPort
from jame_firewall.infrastructure.os._win32_mutex import _same_security_descriptor
from jame_firewall.infrastructure.os.instance_lock import WindowsInstanceLock


@dataclass
class MutexApi:
    """Stateful Win32 boundary double; a handle is never ownership by itself."""

    status: int = 0
    trusted: bool = True
    failure: str = ""
    events: list[str] = field(default_factory=list)

    def create(self, name: str) -> int:
        self.events.append("create")
        if self.failure == "create":
            raise InstanceCoordinationError("Access denied")
        return 42

    def is_trusted(self, handle: int) -> bool:
        self.events.append("trust")
        if self.failure == "trust":
            raise InstanceCoordinationError("Security query failed")
        return self.trusted

    def wait(self, handle: int) -> int:
        self.events.append("wait")
        return self.status

    def release(self, handle: int) -> None:
        self.events.append("release")
        if self.failure == "release":
            raise InstanceCoordinationError("Release failed")

    def close(self, handle: int) -> None:
        self.events.append("close")


@pytest.mark.parametrize("status", [0, 0x80])
def test_normal_and_abandoned_mutex_grant_ownership_once(status: int) -> None:
    api = MutexApi(status=status)
    lock = WindowsInstanceLock(api=api)
    assert isinstance(lock, InstanceLockPort)
    assert lock.acquire()
    assert lock.acquire()  # Must not recursively acquire the native mutex.
    assert api.events == ["create", "trust", "wait"]
    lock.release()
    lock.release()
    assert api.events == ["create", "trust", "wait", "release", "close"]


def test_busy_is_not_ownership_and_closes_handle() -> None:
    api = MutexApi(status=0x102)
    lock = WindowsInstanceLock(api=api)
    assert not lock.acquire()
    lock.release()
    assert api.events == ["create", "trust", "wait", "close"]


@pytest.mark.parametrize("status", [0xFFFFFFFF, 99])
def test_failed_or_unknown_wait_cannot_start_an_instance(status: int) -> None:
    api = MutexApi(status=status)
    with pytest.raises(InstanceCoordinationError):
        WindowsInstanceLock(api=api).acquire()
    assert api.events[-1] == "close"
    assert "release" not in api.events


def test_precreated_untrusted_mutex_is_rejected_before_waiting() -> None:
    api = MutexApi(trusted=False)
    with pytest.raises(InstanceCoordinationError):
        WindowsInstanceLock(api=api).acquire()
    assert api.events == ["create", "trust", "close"]


@pytest.mark.parametrize("failure", ["create", "trust"])
def test_coordination_error_never_looks_like_a_duplicate(failure: str) -> None:
    api = MutexApi(failure=failure)
    with pytest.raises(InstanceCoordinationError):
        WindowsInstanceLock(api=api).acquire()
    assert "wait" not in api.events
    if failure == "trust":
        assert api.events[-1] == "close"


def test_release_error_still_closes_native_handle() -> None:
    api = MutexApi(failure="release")
    lock = WindowsInstanceLock(api=api)
    assert lock.acquire()
    with pytest.raises(InstanceCoordinationError):
        lock.release()
    assert api.events[-2:] == ["release", "close"]


def test_ownership_cannot_be_released_from_another_thread() -> None:
    api = MutexApi()
    lock = WindowsInstanceLock(api=api)
    assert lock.acquire()
    errors: list[Exception] = []

    def release() -> None:
        try:
            lock.release()
        except InstanceCoordinationError as error:
            errors.append(error)

    thread = threading.Thread(target=release)
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert errors
    assert "release" not in api.events
    lock.release()
    assert api.events[-2:] == ["release", "close"]


@pytest.mark.parametrize(
    "actual",
    [
        "O:BAD:P(A;;0x120001;;;WD)",
        "O:SYD:P(A;;0x120001;;;SY)(A;;0x120001;;;BA)",
        "O:BAD:NO_ACCESS_CONTROL",
        "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)",
        "",
    ],
)
def test_mutex_security_cannot_gain_additional_principals_or_access(actual: str) -> None:
    expected = "O:BAD:P(A;;0x120001;;;SY)(A;;0x120001;;;BA)"
    assert not _same_security_descriptor(actual, expected)


def test_kernel_acl_protection_flag_does_not_change_owner_or_permissions() -> None:
    expected = "O:BAD:P(A;;0x120001;;;SY)(A;;0x120001;;;BA)"
    assert _same_security_descriptor(expected.replace("D:P", "D:"), expected)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "Local\\JameFirewall.Instance",
        "Global\\Other",
        "Global\\JameFirewall.Instance\\Extra",
        "Global\\JameFirewall.Instance\x00extra",
        "Global\\JameFirewall." + "x" * 260,
    ],
)
def test_mutex_name_cannot_change_scope_or_truncate(name: str) -> None:
    with pytest.raises(ValueError):
        WindowsInstanceLock(name)
