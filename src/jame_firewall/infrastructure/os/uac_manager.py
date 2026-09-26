"""Gestor de elevación de privilegios UAC para Windows."""

import os
import sys
from typing import Any


class WindowsUACAdapter:
    """Implementación de UACPort con detección nativa y guardas multiplataforma."""

    def is_admin(self) -> bool:
        """Determina si el proceso cuenta con privilegios administrativos."""
        if sys.platform != "win32":
            return True
        try:
            import ctypes

            windll: Any = getattr(ctypes, "windll", None)
            if windll and hasattr(windll, "shell32"):
                return bool(windll.shell32.IsUserAnAdmin() != 0)
            return False
        except (AttributeError, OSError):
            return False

    def request_elevation(self) -> bool:
        """Solicita elevación UAC relanzando el proceso actual con 'runas'."""
        if sys.platform != "win32":
            return True
        try:
            import ctypes

            script_path = os.path.abspath(sys.argv[0])
            working_dir = os.path.dirname(script_path)
            args = " ".join([f'"{arg}"' for arg in sys.argv[1:]])

            if getattr(sys, "frozen", False):
                executable = sys.executable
                params = args
            else:
                executable = sys.executable
                params = f'"{script_path}" {args}'

            windll: Any = getattr(ctypes, "windll", None)
            if windll and hasattr(windll, "shell32"):
                code = windll.shell32.ShellExecuteW(
                    None, "runas", executable, params, working_dir, 1
                )
                return bool(code > 32)
            return False
        except (AttributeError, OSError):
            return False
