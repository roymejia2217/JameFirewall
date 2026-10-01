"""Descubrimiento automático de instalaciones en Registro de Windows y rutas estándar."""

import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from jame_firewall.core.cancellation import CancellationToken


class DiscoveryError(RuntimeError):
    """Discovery could not finish; callers must preserve their previous draft."""


class WindowsRegistryAdapter:
    """Implementación de RegistryDiscoveryPort con inspección segura de Registro."""

    def __init__(
        self,
        cancellation: CancellationToken | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._cancellation = cancellation or CancellationToken()
        self._clock = clock

    def discover_creative_paths(self) -> list[Path]:
        """Detecta rutas de suites y software creativo instalado."""
        found_paths: set[Path] = set()
        start = self._clock()
        subkeys_seen = 0

        def check() -> None:
            self._cancellation.check()
            if self._clock() - start >= 30.0:
                raise DiscoveryError("Autodetección incompleta: límite de duración alcanzado")

        def add(value: object) -> None:
            check()
            if not isinstance(value, str) or not value:
                return
            if len(value) > 32767:
                raise DiscoveryError("Autodetección incompleta: ruta demasiado larga")
            path = Path(os.path.abspath(value))
            # Preserve reparse paths for the scanner's explicit validation.
            if path.is_dir():
                if path not in found_paths and len(found_paths) >= 256:
                    raise DiscoveryError("Autodetección incompleta: límite de rutas alcanzado")
                found_paths.add(path)

        def registry_error(error: OSError) -> None:
            if isinstance(error, FileNotFoundError) or getattr(error, "winerror", None) in (2, 3):
                return
            raise DiscoveryError("Autodetección incompleta: Registro inaccesible") from error

        check()

        # 1. Búsqueda en Registro de Windows (HKLM y HKCU)
        try:
            import winreg

            reg: Any = winreg

            registry_roots = [
                (reg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Adobe"),
                (reg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Adobe"),
                (reg.HKEY_CURRENT_USER, r"Software\Adobe"),
            ]

            for hkey, subkey in registry_roots:
                check()
                try:
                    with reg.OpenKey(hkey, subkey) as root_key:
                        num_subkeys = reg.QueryInfoKey(root_key)[0]
                        if subkeys_seen + num_subkeys > 4096:
                            raise DiscoveryError(
                                "Autodetección incompleta: límite de claves alcanzado"
                            )
                        subkeys_seen += num_subkeys
                        for i in range(num_subkeys):
                            check()
                            app_name = reg.EnumKey(root_key, i)
                            for potential in ("InstallPath", "AMS", "Setup"):
                                check()
                                full_sub = f"{subkey}\\{app_name}\\{potential}"
                                try:
                                    with reg.OpenKey(hkey, full_sub) as handle:
                                        for name in ("", "Path"):
                                            check()
                                            try:
                                                value, _ = reg.QueryValueEx(handle, name)
                                                add(value)
                                            except OSError as ex:
                                                registry_error(ex)
                                except OSError as ex:
                                    registry_error(ex)
                except OSError as ex:
                    registry_error(ex)
        except ImportError:
            pass

        # 2. Rutas estándar del sistema
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pf_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        pdata = os.environ.get("ProgramData", r"C:\ProgramData")
        appdata = os.environ.get("APPDATA", "")
        local_appdata = os.environ.get("LOCALAPPDATA", "")

        candidates = [
            Path(pf) / "Adobe",
            Path(pf) / "Common Files" / "Adobe",
            Path(pf_x86) / "Adobe",
            Path(pf_x86) / "Common Files" / "Adobe",
            Path(pdata) / "Adobe",
        ]
        if appdata:
            candidates.append(Path(appdata) / "Adobe")
        if local_appdata:
            candidates.append(Path(local_appdata) / "Adobe")

        for candidate in candidates:
            add(str(candidate))

        return sorted(found_paths)
