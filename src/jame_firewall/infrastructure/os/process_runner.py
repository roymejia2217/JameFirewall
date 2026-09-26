"""Ejecutor de subprocesos seguro y parametrizado para Windows y Linux."""

import subprocess
import sys


class SystemProcessRunner:
    """Implementación de ProcessRunnerPort sin shell=True y con banderas seguras."""

    def __init__(self) -> None:
        self._creationflags = 0
        if sys.platform == "win32":
            self._creationflags = subprocess.CREATE_NO_WINDOW

    def run(self, args: list[str], timeout: float | None = 30.0) -> tuple[int, str, str]:
        """Ejecuta un proceso parametrizado suprimiendo consolas en Windows."""
        try:
            result = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                creationflags=self._creationflags,
                timeout=timeout,
                check=False,
            )
            stdout = result.stdout.decode("utf-8", errors="replace").strip()
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout expired during command execution"
        except OSError as ex:
            return -1, "", str(ex)
