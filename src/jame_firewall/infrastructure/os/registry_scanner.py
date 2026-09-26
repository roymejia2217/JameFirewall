"""Descubrimiento automático de instalaciones en Registro de Windows y rutas estándar."""

import os
from pathlib import Path
from typing import Any


class WindowsRegistryAdapter:
    """Implementación de RegistryDiscoveryPort con inspección segura de Registro."""

    def discover_creative_paths(self) -> list[Path]:
        """Detecta rutas de suites y software creativo instalado."""
        found_paths: set[Path] = set()

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
                try:
                    with reg.OpenKey(hkey, subkey) as root_key:
                        num_subkeys = reg.QueryInfoKey(root_key)[0]
                        for i in range(num_subkeys):
                            try:
                                app_name = reg.EnumKey(root_key, i)
                                app_key_path = f"{subkey}\\{app_name}"
                                for potential in ["InstallPath", "AMS", "Setup"]:
                                    full_sub = f"{app_key_path}\\{potential}"
                                    try:
                                        with reg.OpenKey(hkey, full_sub) as handle:
                                            val, _ = reg.QueryValueEx(handle, "")
                                            if val and isinstance(val, str) and os.path.exists(val):
                                                found_paths.add(Path(val).resolve())
                                            try:
                                                val2, _ = reg.QueryValueEx(handle, "Path")
                                                if val2 and isinstance(val2, str) and os.path.exists(val2):
                                                    found_paths.add(Path(val2).resolve())
                                            except OSError:
                                                pass
                                    except OSError:
                                        pass
                            except OSError:
                                continue
                except OSError:
                    pass
        except (ImportError, AttributeError):
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
            if candidate.exists() and candidate.is_dir():
                found_paths.add(candidate.resolve())

        return sorted(found_paths)
