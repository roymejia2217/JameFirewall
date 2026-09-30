"""Ejecutor de subprocesos seguro y parametrizado para Windows y Linux."""

import ctypes
import math
import os
import subprocess
import sys
from pathlib import Path

from jame_firewall.core.cancellation import CancellationToken


def _system_directory() -> Path:
    """Ask Windows itself; elevated commands must not trust PATH or SystemRoot."""
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise OSError("Windows API is unavailable")
    kernel32 = loader("kernel32", use_last_error=True)
    get_directory = kernel32.GetSystemDirectoryW
    get_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    get_directory.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_directory(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise OSError("Windows system directory lookup failed")
    return Path(buffer.value)


class SystemProcessRunner:
    """Implementación de ProcessRunnerPort sin shell=True y con banderas seguras."""

    def __init__(self, cancellation: CancellationToken | None = None) -> None:
        self._cancellation = cancellation or CancellationToken()
        self._creationflags = 0
        if sys.platform == "win32":
            self._creationflags = subprocess.CREATE_NO_WINDOW

    def run(self, args: list[str], timeout: float | None = 30.0) -> tuple[int, str, str]:
        """Ejecuta un proceso parametrizado suprimiendo consolas en Windows."""
        self._cancellation.check()
        if not args:
            return -1, "", "Missing executable"
        if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
            return -1, "", "Invalid command timeout"
        deadline = 30.0 if timeout is None else min(timeout, 30.0)
        try:
            command = list(args)
            environment = None
            if sys.platform == "win32" and Path(command[0]).name.lower() in {
                "powershell",
                "powershell.exe",
            }:
                system = _system_directory()
                powershell = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
                if not powershell.is_file():
                    raise OSError("System Windows PowerShell executable is unavailable")
                command[0] = str(powershell)
                environment = os.environ.copy()
                modules = str(powershell.parent / "Modules")
                environment["PSModulePath"] = modules
                # Windows PowerShell may augment PSModulePath at startup. Reset it before autoload.
                if "-Command" in command:
                    position = command.index("-Command") + 1
                    if position < len(command):
                        literal = "'" + modules.replace("'", "''") + "'"
                        command[position] = f"$env:PSModulePath = {literal}; " + command[position]
            result = subprocess.run(
                command,
                shell=False,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                env=environment,
                creationflags=self._creationflags,
                timeout=deadline,
                check=False,
            )
            stdout = result.stdout.decode("utf-8", errors="replace").strip()
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout expired during command execution"
        except OSError as ex:
            return -1, "", str(ex)
