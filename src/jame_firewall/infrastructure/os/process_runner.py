"""Bounded process execution; cancellation returns only after reclaiming owned resources."""

import ctypes
import math
import os
import sys
import time
from pathlib import Path

from jame_firewall.core.cancellation import CancellationToken
from jame_firewall.core.entities import ProcessResult, ProcessStatus
from jame_firewall.core.exceptions import FirewallExecutionError
from jame_firewall.core.execution import remaining_operation_seconds
from jame_firewall.infrastructure.os._process_io import PosixProcess, ProcessIO
from jame_firewall.infrastructure.os._win32_process import Win32Process

MAX_OUTPUT_BYTES = 8 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 30.0


def _system_directory() -> Path:
    """Ask Windows itself; elevated commands must not trust PATH or SystemRoot."""
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise OSError("Windows API is unavailable")
    kernel32 = loader("kernel32", use_last_error=True, winmode=0x800)
    get_directory = kernel32.GetSystemDirectoryW
    get_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    get_directory.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_directory(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise OSError("Windows system directory lookup failed")
    return Path(buffer.value)


def _bounded_timeout(timeout: float | None) -> float:
    if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("Invalid command timeout")
    return COMMAND_TIMEOUT_SECONDS if timeout is None else min(timeout, COMMAND_TIMEOUT_SECONDS)


def _prepare_command(args: list[str]) -> tuple[list[str], dict[str, str] | None]:
    if not args:
        raise ValueError("Missing executable")
    command = list(args)
    environment = None
    if sys.platform == "win32" and Path(command[0]).name.lower() in {
        "powershell",
        "powershell.exe",
    }:
        powershell = _system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if not powershell.is_file():
            raise OSError("System Windows PowerShell executable is unavailable")
        command[0] = str(powershell)
        environment = os.environ.copy()
        modules = str(powershell.parent / "Modules")
        environment["PSModulePath"] = modules
        # Windows PowerShell may augment PSModulePath at startup. Reset before autoload.
        if "-Command" in command:
            position = command.index("-Command") + 1
            if position < len(command):
                literal = "'" + modules.replace("'", "''") + "'"
                command[position] = f"$env:PSModulePath = {literal}; " + command[position]
    return command, environment


def _launch(args: list[str], environment: dict[str, str] | None) -> ProcessIO:
    if sys.platform == "win32":
        return Win32Process(args, environment)
    return PosixProcess(args, environment)


class SystemProcessRunner:
    """No shell or unbounded communicate buffer; one contained tree per command."""

    def __init__(
        self,
        cancellation: CancellationToken | None = None,
        *,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
    ) -> None:
        if not isinstance(max_output_bytes, int) or not 0 < max_output_bytes <= MAX_OUTPUT_BYTES:
            raise ValueError("Output limit must be a positive integer no greater than 8 MiB")
        self._cancellation = cancellation or CancellationToken()
        self._max_output_bytes = max_output_bytes

    def run(
        self, args: list[str], timeout: float | None = COMMAND_TIMEOUT_SECONDS
    ) -> ProcessResult:
        """Bound both streams together; clean up the tree before returning or raising."""
        self._cancellation.check()
        remaining = remaining_operation_seconds()
        try:
            duration = _bounded_timeout(timeout)
            if remaining is not None:
                duration = min(duration, remaining)
            command, environment = _prepare_command(args)
        except (OSError, ValueError) as ex:
            return ProcessResult(ProcessStatus.START_FAILED, None, detail=str(ex)[:1024])
        deadline = time.monotonic() + duration
        try:
            process = _launch(command, environment)
        except (OSError, ValueError) as ex:
            return ProcessResult(ProcessStatus.START_FAILED, None, detail=str(ex)[:1024])
        buffers = (bytearray(), bytearray())
        retained = 0
        open_streams = {0, 1}
        code: int | None = None
        status = ProcessStatus.COMPLETED
        detail = ""
        try:
            while True:
                self._cancellation.check()
                if time.monotonic() >= deadline:
                    status, detail = (
                        ProcessStatus.TIMED_OUT,
                        "Timeout expired during command execution",
                    )
                    break
                read_any = False
                for stream in tuple(open_streams):
                    chunk = process.read(stream, min(32768, self._max_output_bytes - retained + 1))
                    if chunk is None:
                        continue
                    if not chunk:
                        open_streams.remove(stream)
                        continue
                    read_any = True
                    if retained + len(chunk) > self._max_output_bytes:
                        status, detail = (
                            ProcessStatus.OUTPUT_LIMIT,
                            "Combined process output limit exceeded",
                        )
                        break
                    buffers[stream].extend(chunk)
                    retained += len(chunk)
                if status != ProcessStatus.COMPLETED:
                    break
                if code is None:
                    code = process.poll()
                    if code is not None:
                        # A successful parent must not leave descendants holding the pipes open.
                        process.finish()
                if code is not None and not open_streams:
                    break
                if not read_any:
                    time.sleep(0.01)
        except OSError as ex:
            status, detail = ProcessStatus.IO_FAILED, str(ex)[:1024]
        finally:
            try:
                process.close()
            except OSError as ex:
                raise FirewallExecutionError(
                    "No se pudo confirmar la liberación de los recursos del comando. "
                    "Los cambios ya aplicados no se revierten."
                ) from ex
        return ProcessResult(
            status,
            code if status == ProcessStatus.COMPLETED else None,
            buffers[0].decode("utf-8", errors="replace").strip(),
            buffers[1].decode("utf-8", errors="replace").strip(),
            detail,
        )
