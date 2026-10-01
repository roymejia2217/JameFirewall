"""Contained native Windows launch: suspend, assign a private Job, then resume."""

import ctypes
import subprocess
import time
from collections.abc import Callable
from typing import Any, ClassVar

from jame_firewall.infrastructure.os._process_io import CLEANUP_TIMEOUT_SECONDS


class _SecurityAttributes(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("length", ctypes.c_uint32),
        ("descriptor", ctypes.c_void_p),
        ("inherit", ctypes.c_int32),
    ]


class _StartupInfo(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("cb", ctypes.c_uint32),
        ("reserved", ctypes.c_wchar_p),
        ("desktop", ctypes.c_wchar_p),
        ("title", ctypes.c_wchar_p),
        ("x", ctypes.c_uint32),
        ("y", ctypes.c_uint32),
        ("x_size", ctypes.c_uint32),
        ("y_size", ctypes.c_uint32),
        ("x_chars", ctypes.c_uint32),
        ("y_chars", ctypes.c_uint32),
        ("fill", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("show", ctypes.c_uint16),
        ("reserved_size", ctypes.c_uint16),
        ("reserved_bytes", ctypes.c_void_p),
        ("stdin", ctypes.c_void_p),
        ("stdout", ctypes.c_void_p),
        ("stderr", ctypes.c_void_p),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("startup", _StartupInfo),
        ("attributes", ctypes.c_void_p),
    ]


class _ProcessInformation(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("process", ctypes.c_void_p),
        ("thread", ctypes.c_void_p),
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
    ]


class _BasicLimit(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("process_time", ctypes.c_int64),
        ("job_time", ctypes.c_int64),
        ("flags", ctypes.c_uint32),
        ("min_working_set", ctypes.c_size_t),
        ("max_working_set", ctypes.c_size_t),
        ("active_processes", ctypes.c_uint32),
        ("affinity", ctypes.c_size_t),
        ("priority", ctypes.c_uint32),
        ("scheduling", ctypes.c_uint32),
    ]


class _IoCounters(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        (name, ctypes.c_uint64)
        for name in (
            "read_ops",
            "write_ops",
            "other_ops",
            "read_bytes",
            "write_bytes",
            "other_bytes",
        )
    ]


class _ExtendedLimit(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("basic", _BasicLimit),
        ("io", _IoCounters),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process_memory", ctypes.c_size_t),
        ("peak_job_memory", ctypes.c_size_t),
    ]


class _Accounting(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("user_time", ctypes.c_int64),
        ("kernel_time", ctypes.c_int64),
        ("period_user_time", ctypes.c_int64),
        ("period_kernel_time", ctypes.c_int64),
        ("page_faults", ctypes.c_uint32),
        ("total_processes", ctypes.c_uint32),
        ("active_processes", ctypes.c_uint32),
        ("terminated_processes", ctypes.c_uint32),
    ]


def _bind(library: Any, name: str, arguments: list[Any], result: Any) -> Any:
    function = getattr(library, name)
    function.argtypes, function.restype = arguments, result
    return function


class Win32Process:
    """Own all launch/Job/pipe handles; fail closed if containment cannot be established."""

    def __init__(self, args: list[str], environment: dict[str, str] | None) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise OSError("Windows process API is unavailable")
        self._kernel = loader("kernel32", use_last_error=True, winmode=0x800)
        self._handles: set[int] = set()
        self._process = self._job = 0
        self._finished = self._assigned = False
        self._streams: list[int] = []
        self._initialize_api()
        attributes = ctypes.c_void_p()
        initialized = False
        try:
            self._job = self._own(self._create_job(None, None))
            limit = _ExtendedLimit()
            limit.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, no breakaway.
            self._require(self._set_job(self._job, 9, ctypes.byref(limit), ctypes.sizeof(limit)))
            sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, 1)
            writers: list[int] = []
            for _ in range(2):
                reader, writer = ctypes.c_void_p(), ctypes.c_void_p()
                self._require(
                    self._pipe(ctypes.byref(reader), ctypes.byref(writer), ctypes.byref(sa), 0)
                )
                self._streams.append(self._own(reader.value))
                writers.append(self._own(writer.value))
                self._require(self._handle_info(reader, 1, 0))
            stdin = self._own(self._create_file("NUL", 0x80000000, 3, ctypes.byref(sa), 3, 0, None))
            size = ctypes.c_size_t()
            self._init_attributes(None, 1, 0, ctypes.byref(size))
            storage = ctypes.create_string_buffer(size.value)
            attributes = ctypes.cast(storage, ctypes.c_void_p)
            self._require(self._init_attributes(attributes, 1, 0, ctypes.byref(size)))
            initialized = True
            inherited = (ctypes.c_void_p * 3)(stdin, *writers)
            self._require(
                self._update_attributes(
                    attributes, 0, 0x20002, inherited, ctypes.sizeof(inherited), None, None
                )
            )
            startup = _StartupInfoEx()
            startup.startup.cb = ctypes.sizeof(startup)
            startup.startup.flags = 0x100  # STARTF_USESTDHANDLES.
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = stdin, *writers
            startup.attributes = attributes
            information = _ProcessInformation()
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline(args))
            env_buffer = None
            if environment is not None:
                entries = [
                    f"{key}={value}"
                    for key, value in sorted(environment.items(), key=lambda item: item[0].upper())
                ]
                env_buffer = ctypes.create_unicode_buffer("\0".join(entries) + "\0\0")
            # CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT.
            self._require(
                self._create_process(
                    args[0],
                    command,
                    None,
                    None,
                    1,
                    0x08080404,
                    env_buffer,
                    None,
                    ctypes.byref(startup),
                    ctypes.byref(information),
                )
            )
            self._process = self._own(information.process)
            thread = self._own(information.thread)
            for handle in (*writers, stdin):
                self._release(handle)
            self._require(self._assign(self._job, self._process))
            self._assigned = True
            if self._resume(thread) == 0xFFFFFFFF:
                self._raise_error()
            self._release(thread)
        except BaseException:
            self.close()
            raise
        finally:
            if initialized:
                self._delete_attributes(attributes)

    def _initialize_api(self) -> None:
        k, p, u, b = self._kernel, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        bindings: dict[str, tuple[str, list[Any], Any]] = {
            "_close_handle": ("CloseHandle", [p], b),
            "_create_job": ("CreateJobObjectW", [p, ctypes.c_wchar_p], p),
            "_set_job": ("SetInformationJobObject", [p, u, p, u], b),
            "_query_job": ("QueryInformationJobObject", [p, u, p, u, p], b),
            "_terminate_job": ("TerminateJobObject", [p, u], b),
            "_assign": ("AssignProcessToJobObject", [p, p], b),
            "_pipe": ("CreatePipe", [p, p, p, u], b),
            "_handle_info": ("SetHandleInformation", [p, u, u], b),
            "_create_file": ("CreateFileW", [ctypes.c_wchar_p, u, u, p, u, u, p], p),
            "_init_attributes": ("InitializeProcThreadAttributeList", [p, u, u, p], b),
            "_update_attributes": (
                "UpdateProcThreadAttribute",
                [p, u, ctypes.c_size_t, p, ctypes.c_size_t, p, p],
                b,
            ),
            "_delete_attributes": ("DeleteProcThreadAttributeList", [p], None),
            "_create_process": (
                "CreateProcessW",
                [ctypes.c_wchar_p, p, p, p, b, u, p, ctypes.c_wchar_p, p, p],
                b,
            ),
            "_resume": ("ResumeThread", [p], u),
            "_wait": ("WaitForSingleObject", [p, u], u),
            "_exit_code": ("GetExitCodeProcess", [p, p], b),
            "_terminate_process": ("TerminateProcess", [p, u], b),
            "_peek": ("PeekNamedPipe", [p, p, u, p, p, p], b),
            "_read_file": ("ReadFile", [p, p, u, p, p], b),
        }
        for attribute, (name, arguments, result) in bindings.items():
            setattr(self, attribute, _bind(k, name, arguments, result))

    # Bindings are dynamic ctypes functions, confined to this module.
    _close_handle: Any
    _create_job: Any
    _set_job: Any
    _query_job: Any
    _terminate_job: Any
    _assign: Any
    _pipe: Any
    _handle_info: Any
    _create_file: Any
    _init_attributes: Any
    _update_attributes: Any
    _delete_attributes: Any
    _create_process: Any
    _resume: Any
    _wait: Any
    _exit_code: Any
    _terminate_process: Any
    _peek: Any
    _read_file: Any

    @staticmethod
    def _raise_error() -> None:
        get_error: Callable[[], int] = getattr(ctypes, "get_last_error", lambda: 0)
        raise OSError(get_error(), "Windows process resource operation failed")

    def _require(self, success: object) -> None:
        if not success:
            self._raise_error()

    def _own(self, handle: int | None) -> int:
        if not handle or handle == ctypes.c_void_p(-1).value:
            self._raise_error()
        if handle is None:
            raise OSError("Missing Windows handle")
        self._handles.add(handle)
        return handle

    def _release(self, handle: int) -> None:
        self._require(self._close_handle(handle))
        self._handles.remove(handle)

    def poll(self) -> int | None:
        status = self._wait(self._process, 0)
        if status == 0x102:
            return None
        if status != 0:
            self._raise_error()
        code = ctypes.c_uint32()
        self._require(self._exit_code(self._process, ctypes.byref(code)))
        return int(code.value)

    def read(self, stream: int, size: int) -> bytes | None:
        available = ctypes.c_uint32()
        if not self._peek(self._streams[stream], None, 0, None, ctypes.byref(available), None):
            get_error: Callable[[], int] = getattr(ctypes, "get_last_error", lambda: 0)
            if get_error() in (109, 232):  # ERROR_BROKEN_PIPE / ERROR_NO_DATA.
                return b""
            self._raise_error()
        if not available.value:
            return None
        buffer = ctypes.create_string_buffer(min(size, available.value))
        read = ctypes.c_uint32()
        self._require(
            self._read_file(self._streams[stream], buffer, len(buffer), ctypes.byref(read), None)
        )
        return buffer.raw[: read.value]

    def finish(self) -> None:
        if self._finished or not self._process:
            return
        if self._assigned:
            self._require(self._terminate_job(self._job, 1))
        else:
            self._require(self._terminate_process(self._process, 1))
        deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        while True:
            root_done = self._wait(self._process, 0) == 0
            accounting = _Accounting()
            if self._assigned:
                self._require(
                    self._query_job(
                        self._job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None
                    )
                )
            if root_done and accounting.active_processes == 0:
                self._finished = True
                return
            if time.monotonic() >= deadline:
                raise OSError("Windows process cleanup deadline exceeded")
            time.sleep(0.01)

    def close(self) -> None:
        try:
            self.finish()
        finally:
            # Closing the last non-inheritable Job handle also kills contained processes.
            error: OSError | None = None
            for handle in tuple(self._handles):
                try:
                    self._release(handle)
                except OSError as ex:
                    error = error or ex
            if error is not None:
                raise error
