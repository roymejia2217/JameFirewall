"""Native storage location and protected administrator-only configuration ACLs."""

import ctypes
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, ClassVar

from jame_firewall.core.exceptions import ConfigStorageError

_DIRECTORY_SDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
_FILE_SDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
_OWNER_DACL = 5


class _SecurityAttributes(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("length", ctypes.c_uint32),
        ("descriptor", ctypes.c_void_p),
        ("inherit", ctypes.c_int32),
    ]


def _bind(library: Any, name: str, arguments: list[Any], result: Any) -> Any:
    function = getattr(library, name)
    function.argtypes, function.restype = arguments, result
    return function


class WindowsConfigSecurity:
    """Refuse untrusted existing storage; never repair another actor's permissions."""

    def __init__(self) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise ConfigStorageError("Windows configuration security API is unavailable")
        kernel = loader("kernel32", use_last_error=True, winmode=0x800)
        security = loader("advapi32", use_last_error=True, winmode=0x800)
        shell = loader("shell32", use_last_error=True, winmode=0x800)
        ole = loader("ole32", use_last_error=True, winmode=0x800)
        pointer, uint, boolean = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        self._free = _bind(kernel, "LocalFree", [pointer], pointer)
        self._task_free = _bind(ole, "CoTaskMemFree", [pointer], None)
        self._known_folder = _bind(
            shell,
            "SHGetKnownFolderPath",
            [pointer, uint, pointer, ctypes.POINTER(pointer)],
            boolean,
        )
        self._create_directory = _bind(
            kernel,
            "CreateDirectoryW",
            [ctypes.c_wchar_p, ctypes.POINTER(_SecurityAttributes)],
            boolean,
        )
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
        self._get = _bind(
            security,
            "GetNamedSecurityInfoW",
            [ctypes.c_wchar_p, uint, uint] + [ctypes.POINTER(pointer)] * 5,
            uint,
        )
        self._owner = _bind(
            security,
            "GetSecurityDescriptorOwner",
            [pointer, ctypes.POINTER(pointer), ctypes.POINTER(boolean)],
            boolean,
        )
        self._dacl = _bind(
            security,
            "GetSecurityDescriptorDacl",
            [pointer, ctypes.POINTER(boolean), ctypes.POINTER(pointer), ctypes.POINTER(boolean)],
            boolean,
        )
        self._set = _bind(
            security, "SetNamedSecurityInfoW", [ctypes.c_wchar_p, uint, uint] + [pointer] * 4, uint
        )

    @staticmethod
    def _error(operation: str, code: int | None = None) -> ConfigStorageError:
        if code is None:
            code = int(getattr(ctypes, "get_last_error", lambda: 0)())
        return ConfigStorageError(f"{operation} failed (Windows error {code})")

    @contextmanager
    def _descriptor(self, sddl: str) -> Iterator[ctypes.c_void_p]:
        descriptor = ctypes.c_void_p()
        if not self._parse(sddl, 1, ctypes.byref(descriptor), None):
            raise self._error("Configuration security descriptor creation")
        try:
            yield descriptor
        finally:
            self._free(descriptor)

    def _sddl(self, descriptor: ctypes.c_void_p) -> str:
        text = ctypes.c_void_p()
        if not self._stringify(descriptor, 1, _OWNER_DACL, ctypes.byref(text), None):
            raise self._error("Configuration security descriptor conversion")
        try:
            # Ignore the auto-inheritance metadata flag, preserving protection and every ACE.
            return ctypes.wstring_at(text).replace("D:PAI", "D:P")
        finally:
            self._free(text)

    def default_directory(self) -> Path:
        """Resolve FOLDERID_ProgramData through Windows, without trusting environment overrides."""
        folder_id = ctypes.create_string_buffer(
            uuid.UUID("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97").bytes_le, 16
        )
        text = ctypes.c_void_p()
        try:
            code: int = self._known_folder(folder_id, 0, None, ctypes.byref(text))
            if code or not text:
                raise self._error("ProgramData resolution", code)
            root = Path(ctypes.wstring_at(text))
            if not root.is_absolute() or str(root).startswith("\\\\"):
                raise ConfigStorageError("Configuration storage requires a local absolute folder")
            return root / "JameFirewall"
        finally:
            self._task_free(text)

    @staticmethod
    def _reject_reparse_points(path: Path) -> None:
        for component in (path, *path.parents):
            try:
                info = component.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ConfigStorageError(
                    f"Configuration storage cannot follow a reparse point: {component}"
                )

    def _verify(self, path: Path, sddl: str) -> None:
        self._reject_reparse_points(path)
        actual = ctypes.c_void_p()
        code: int = self._get(
            str(path), 1, _OWNER_DACL, None, None, None, None, ctypes.byref(actual)
        )
        if code:
            raise self._error("Configuration security inspection", code)
        try:
            with self._descriptor(sddl) as expected:
                if self._sddl(actual) != self._sddl(expected):
                    raise ConfigStorageError(
                        f"La configuración tiene propietario o permisos inesperados: {path}"
                    )
        finally:
            self._free(actual)

    def ensure_directory(self, path: Path) -> None:
        self._reject_reparse_points(path)
        with self._descriptor(_DIRECTORY_SDDL) as descriptor:
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, 0)
            if not self._create_directory(str(path), ctypes.byref(attributes)):
                code = int(getattr(ctypes, "get_last_error", lambda: 0)())
                if code != 183:  # ERROR_ALREADY_EXISTS must still pass validation.
                    raise self._error("Configuration directory creation", code)
        if not path.is_dir():
            raise ConfigStorageError("Configuration storage is not a directory")
        self._verify(path, _DIRECTORY_SDDL)

    def verify_file(self, path: Path) -> None:
        self._verify(path, _FILE_SDDL)

    def protect_file(self, path: Path) -> None:
        """Apply a protected owner/DACL to our temporary before publishing it."""
        self._reject_reparse_points(path)
        with self._descriptor(_FILE_SDDL) as descriptor:
            owner, dacl = ctypes.c_void_p(), ctypes.c_void_p()
            present, defaulted = ctypes.c_int32(), ctypes.c_int32()
            if not self._owner(descriptor, ctypes.byref(owner), ctypes.byref(defaulted)):
                raise self._error("Configuration owner extraction")
            if (
                not self._dacl(
                    descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
                )
                or not present
            ):
                raise self._error("Configuration ACL extraction")
            code: int = self._set(str(path), 1, 0x80000000 | _OWNER_DACL, owner, None, dacl, None)
            if code:
                raise self._error("Configuration file protection", code)
        self.verify_file(path)
