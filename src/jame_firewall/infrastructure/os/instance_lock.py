"""Machine-wide Windows exclusion with explicit ownership and checked security."""

import sys
from threading import get_ident
from typing import Protocol

from jame_firewall.core.exceptions import InstanceCoordinationError
from jame_firewall.infrastructure.os._win32_mutex import Win32MutexApi

INSTANCE_MUTEX_NAME = r"Global\JameFirewall.Instance"


class _MutexApi(Protocol):
    def create(self, name: str) -> int: ...
    def is_trusted(self, handle: int) -> bool: ...
    def wait(self, handle: int) -> int: ...
    def release(self, handle: int) -> None: ...
    def close(self, handle: int) -> None: ...


class WindowsInstanceLock:
    """Hold the global mutex on the main thread until workers and the window exit."""

    def __init__(self, name: str = INSTANCE_MUTEX_NAME, *, api: _MutexApi | None = None) -> None:
        if (
            not name.startswith(r"Global\JameFirewall.")
            or len(name) >= 260
            or "\x00" in name
            or "\\" in name.removeprefix("Global\\")
        ):
            raise ValueError("Invalid instance mutex namespace")
        self._name = name
        self._api = api
        self._handle: int | None = None
        self._owner_thread: int | None = None

    def acquire(self) -> bool:
        """Reject contention immediately; accept abandonment and require a fresh audit."""
        if self._handle is not None:
            self._check_thread()
            return True
        if self._api is None and sys.platform == "win32":
            self._api = Win32MutexApi()
        if self._api is None:
            # Development imports and portable tests do not provide Windows exclusion.
            self._handle = 0
            self._owner_thread = get_ident()
            return True
        handle = self._api.create(self._name)
        acquired = False
        try:
            if not self._api.is_trusted(handle):
                raise InstanceCoordinationError("Instance mutex has an unexpected owner or ACL")
            result = self._api.wait(handle)
            if result == 0x102:  # WAIT_TIMEOUT: another thread owns it.
                return False
            if result not in (0, 0x80):  # WAIT_OBJECT_0, WAIT_ABANDONED
                raise InstanceCoordinationError(f"Instance mutex wait failed: {result:#x}")
            acquired = True
        finally:
            if not acquired:
                self._api.close(handle)
        self._handle = handle
        self._owner_thread = get_ident()
        return True

    def _check_thread(self) -> None:
        if self._owner_thread != get_ident():
            raise InstanceCoordinationError("Instance mutex must be released by its owning thread")

    def release(self) -> None:
        """Close every acquired handle, including after release errors."""
        if self._handle is None:
            return
        self._check_thread()
        handle, self._handle = self._handle, None
        self._owner_thread = None
        if self._api is not None:
            try:
                self._api.release(handle)
            finally:
                self._api.close(handle)
