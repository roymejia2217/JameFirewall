"""Persistencia JSON con sustitución y expansión portable de variables de entorno."""

import json
import os
import sys
from pathlib import Path

DEFAULT_CONFIG_FILENAME = "jamefirewall_config.json"


class JsonConfigAdapter:
    """Implementación de ConfigRepositoryPort con serialización portable en JSON."""

    def __init__(self, config_path: Path | None = None) -> None:
        self.config_path = config_path or self._resolve_default_config_path()

    def _resolve_default_config_path(self) -> Path:
        """Determina la ruta base de configuración compatible con PyInstaller."""
        if getattr(sys, "frozen", False):
            base_dir = Path(sys.executable).parent
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent.parent
        return base_dir / DEFAULT_CONFIG_FILENAME

    def _get_dynamic_default_paths(self) -> list[Path]:
        """Genera rutas por defecto basadas en variables de entorno del sistema."""
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pf_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        pdata = os.environ.get("ProgramData", r"C:\ProgramData")

        defaults = [
            Path(pf) / "Adobe",
            Path(pf) / "Common Files" / "Adobe",
            Path(pf_x86) / "Adobe",
            Path(pf_x86) / "Common Files" / "Adobe",
            Path(pf) / "Maxon Cinema 4D R25",
            Path(pf) / "Red Giant",
            Path(pdata) / "Adobe",
        ]
        return [p.resolve() for p in defaults if p.exists()] or [Path(pf) / "Adobe"]

    def _sanitize_path_for_storage(self, path: Path) -> str:
        """Reemplaza raíces específicas del usuario con variables de entorno (%VAR%)."""
        path_str = str(path.resolve())

        env_keys = [
            "LOCALAPPDATA",
            "APPDATA",
            "USERPROFILE",
            "ProgramFiles(x86)",
            "ProgramFiles",
            "ProgramData",
        ]

        for key in env_keys:
            val = os.environ.get(key)
            if val:
                val_resolved = str(Path(val).resolve())
                if path_str.lower().startswith(val_resolved.lower()):
                    relative = path_str[len(val_resolved) :]
                    if relative.startswith(os.sep) or relative.startswith("/"):
                        relative = relative[1:]
                    return f"%{key}%{os.sep}{relative}"

        return path_str

    def _expand_path_from_storage(self, raw_str: str) -> Path:
        """Expande variables de entorno (%VAR% y $VAR) a objetos Path absolutos."""
        # Soporte cross-platform para variables tipo %VAR% en Linux y Windows
        for key, val in os.environ.items():
            token = f"%{key}%"
            if token.lower() in raw_str.lower():
                # Reemplazo insensible a mayúsculas
                idx = raw_str.lower().find(token.lower())
                raw_str = raw_str[:idx] + val + raw_str[idx + len(token) :]

        expanded = os.path.expandvars(raw_str)
        return Path(expanded).resolve()

    def load_paths(self) -> list[Path]:
        """Carga los directorios configurados desde JSON o genera los predeterminados."""
        if self.config_path.exists():
            try:
                raw_data = self.config_path.read_text(encoding="utf-8")
                parsed = json.loads(raw_data)
                stored_strings = parsed.get("directories", [])
                loaded_paths = [self._expand_path_from_storage(s) for s in stored_strings]
                if loaded_paths:
                    return loaded_paths
            except (json.JSONDecodeError, OSError):
                pass

        return self._get_dynamic_default_paths()

    def save_paths(self, paths: list[Path]) -> bool:
        """Guarda la lista de directorios en JSON aplicando sanitización portable."""
        try:
            sanitized = [self._sanitize_path_for_storage(p) for p in paths]
            data = {"directories": sanitized}
            self.config_path.write_text(json.dumps(data, indent=4), encoding="utf-8")
            return True
        except OSError:
            return False
