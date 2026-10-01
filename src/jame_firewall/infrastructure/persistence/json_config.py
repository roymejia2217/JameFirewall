"""Persistencia JSON con sustitución y expansión portable de variables de entorno."""

import contextlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

from jame_firewall.core.exceptions import ConfigStorageError

DEFAULT_CONFIG_FILENAME = "jamefirewall_config.json"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_DIRECTORIES = 256
MAX_PATH_CHARS = 32767
ENV_ROOTS = (
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
    "ProgramFiles(x86)",
    "ProgramFiles",
    "ProgramData",
)
_ROOT_TOKEN = re.compile(r"^(?:%([^%]+)%|\$\{([^}]+)\}|\$([\w()]+))(?=[\\/]|$)")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate configuration key")
        result[key] = value
    return result


def _check_regular_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or getattr(info, "st_file_attributes", 0) & 0x400
    ):
        raise ConfigStorageError(f"La configuración no es un archivo regular seguro: {path}")
    return True


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

        for key in ENV_ROOTS:
            val = os.environ.get(key)
            if val:
                val_resolved = str(Path(val).resolve())
                if os.path.normcase(path_str) == os.path.normcase(val_resolved) or os.path.normcase(
                    path_str
                ).startswith(os.path.normcase(val_resolved + os.sep)):
                    relative = path_str[len(val_resolved) :]
                    if relative.startswith(os.sep) or relative.startswith("/"):
                        relative = relative[1:]
                    return f"%{key}%{os.sep}{relative}"

        return path_str

    def _expand_path_from_storage(self, raw_str: str) -> Path:
        """Expand only documented root variables, then require an absolute bounded path."""
        if not raw_str or len(raw_str) > MAX_PATH_CHARS or any(ord(c) < 32 for c in raw_str):
            raise ValueError("Invalid directory path")
        token = _ROOT_TOKEN.match(raw_str)
        if token:
            name = next(group for group in token.groups() if group is not None)
            key = next((key for key in ENV_ROOTS if key.casefold() == name.casefold()), None)
            value = os.environ.get(key) if key else None
            if not value:
                raise ValueError("Unknown or unavailable root variable")
            raw_str = value + raw_str[token.end() :]
        path = Path(raw_str)
        if not path.is_absolute() or len(raw_str) > MAX_PATH_CHARS:
            raise ValueError("Directory must be an absolute path")
        return path.resolve()

    def _read_paths(self, path: Path) -> list[Path] | None:
        if not _check_regular_file(path):
            return None
        with path.open("rb") as source:
            data = source.read(MAX_CONFIG_BYTES + 1)
        if len(data) > MAX_CONFIG_BYTES:
            raise ValueError("Configuration exceeds 1 MiB")
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(parsed, dict) or set(parsed) != {"directories"}:
            raise ValueError("Expected an object containing only directories")
        directories = parsed["directories"]
        if not isinstance(directories, list) or len(directories) > MAX_DIRECTORIES:
            raise ValueError("Expected at most 256 directories")
        if any(not isinstance(directory, str) for directory in directories):
            raise ValueError("Directories must be strings")
        return list(
            dict.fromkeys(self._expand_path_from_storage(directory) for directory in directories)
        )

    def load_paths(self) -> list[Path]:
        """Carga los directorios configurados desde JSON o genera los predeterminados."""
        try:
            paths = self._read_paths(self.config_path)
            return self._get_dynamic_default_paths() if paths is None else paths
        except (OSError, ValueError, RecursionError) as ex:
            raise ConfigStorageError(
                f"No se pudo cargar {self.config_path}. El archivo se conserva; "
                "corrija su contenido o muévalo para restablecer la configuración."
            ) from ex

    def save_paths(self, paths: list[Path]) -> bool:
        """Guarda la lista de directorios en JSON aplicando sanitización portable."""
        temporary: Path | None = None
        try:
            if len(paths) > MAX_DIRECTORIES:
                return False
            _check_regular_file(self.config_path)
            sanitized = [self._sanitize_path_for_storage(p) for p in paths]
            for value in sanitized:
                self._expand_path_from_storage(value)
            data = {"directories": sanitized}
            payload = json.dumps(data, indent=4).encode("utf-8")
            if len(payload) > MAX_CONFIG_BYTES:
                return False
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self.config_path.parent,
                prefix=".jamefirewall-",
                suffix=".tmp",
                delete=False,
            ) as target:
                temporary = Path(target.name)
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.config_path)
            return True
        except (OSError, ValueError, ConfigStorageError):
            return False
        finally:
            if temporary is not None:
                with contextlib.suppress(OSError):
                    temporary.unlink(missing_ok=True)
