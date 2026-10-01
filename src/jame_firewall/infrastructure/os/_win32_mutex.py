"""Small typed ctypes boundary for a mutex restricted to elevated administrators."""

import ctypes
from collections.abc import Callable
from typing import Any, ClassVar

from jame_firewall.core.exceptions import InstanceCoordinationError

# Owner: Administrators. Read security + synchronize + modify, for SYSTEM/Admins only.
_MUTEX_SDDL = "O:BAD:P(A;;0x120001;;;SY)(A;;0x120001;;;BA)"
_ACCESS = 0x120001
_OWNER_AND_DACL = 0x5


class _SecurityAttributes(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("length", ctypes.c_uint32),
        ("descriptor", ctypes.c_void_p),
        ("inherit", ctypes.c_int32),
    ]


def _same_security_descriptor(actual: str, expected: str) -> bool:
    # Kernel objects do not inherit ACLs; preserve owner and every ACE, ignoring only protection.
    return bool(expected) and actual.replace("D:P", "D:") == expected.replace("D:P", "D:")


def _bind(library: Any, name: str, arguments: list[Any], result: Any) -> Any:
    function = getattr(library, name)
    function.argtypes = arguments
    function.restype = result
    return function


class Win32MutexApi:
    """All pointers and allocated descriptors stay inside the native adapter."""

    def __init__(self) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise InstanceCoordinationError("Windows mutex API is unavailable")
        kernel = loader("kernel32", use_last_error=True, winmode=0x800)
        security = loader("advapi32", use_last_error=True, winmode=0x800)
        pointer = ctypes.c_void_p
        uint = ctypes.c_uint32
        boolean = ctypes.c_int32
        self._create = _bind(
            kernel,
            "CreateMutexExW",
            [ctypes.POINTER(_SecurityAttributes), ctypes.c_wchar_p, uint, uint],
            pointer,
        )
        self._wait = _bind(kernel, "WaitForSingleObject", [pointer, uint], uint)
        self._release = _bind(kernel, "ReleaseMutex", [pointer], boolean)
        self._close = _bind(kernel, "CloseHandle", [pointer], boolean)
        self._free = _bind(kernel, "LocalFree", [pointer], pointer)
        self._parse = _bind(
            security,
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            [ctypes.c_wchar_p, uint, ctypes.POINTER(pointer), ctypes.POINTER(uint)],
            boolean,
        )
        self._stringify = _bind(
            security,
            "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            [pointer, uint, uint, ctypes.POINTER(pointer), ctypes.POINTER(uint)],
            boolean,
        )
        self._get_security = _bind(
            security, "GetSecurityInfo", [pointer, uint, uint] + [ctypes.POINTER(pointer)] * 5, uint
        )
        self._get_error: Callable[[], int] = getattr(ctypes, "get_last_error", lambda: 0)
        self._expected = ""

    def _error(self, operation: str, code: int | None = None) -> InstanceCoordinationError:
        return InstanceCoordinationError(
            f"{operation} failed (Windows error {self._get_error() if code is None else code})"
        )

    def _sddl(self, descriptor: ctypes.c_void_p) -> str:
        text = ctypes.c_void_p()
        if not self._stringify(descriptor, 1, _OWNER_AND_DACL, ctypes.byref(text), None):
            raise self._error("Mutex security descriptor conversion")
        try:
            return ctypes.wstring_at(text)
        finally:
            self._free(text)

    def create(self, name: str) -> int:
        """Create/open with minimal access; never inherit the handle into child processes."""
        descriptor = ctypes.c_void_p()
        if not self._parse(_MUTEX_SDDL, 1, ctypes.byref(descriptor), None):
            raise self._error("Mutex security descriptor creation")
        try:
            self._expected = self._sddl(descriptor)
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, 0)
            handle: int | None = self._create(ctypes.byref(attributes), name, 0, _ACCESS)
            if handle is None:
                raise self._error("Instance mutex creation")
            return handle
        finally:
            self._free(descriptor)

    def is_trusted(self, handle: int) -> bool:
        """Inspect the opened handle, including objects that existed before this process."""
        descriptor = ctypes.c_void_p()
        code: int = self._get_security(
            handle, 6, _OWNER_AND_DACL, None, None, None, None, ctypes.byref(descriptor)
        )
        if code:
            raise self._error("Instance mutex security inspection", code)
        try:
            return _same_security_descriptor(self._sddl(descriptor), self._expected)
        finally:
            self._free(descriptor)

    def wait(self, handle: int) -> int:
        """Attempt ownership immediately; no GUI thread can wait on another instance."""
        result = int(self._wait(handle, 0))
        if result == 0xFFFFFFFF:
            raise self._error("Instance mutex wait")
        return result

    def release(self, handle: int) -> None:
        if not self._release(handle):
            raise self._error("Instance mutex release")

    def close(self, handle: int) -> None:
        if not self._close(handle):
            raise self._error("Instance mutex handle close")
