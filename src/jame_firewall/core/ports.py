"""Protocolos e Interfaces (Ports) abstractos para JameFirewall."""

from pathlib import Path
from typing import Protocol, runtime_checkable

from jame_firewall.core.entities import RuleDirection


@runtime_checkable
class ProcessRunnerPort(Protocol):
    """Abstracción para la ejecución de procesos del sistema operativo."""

    def run(self, args: list[str], timeout: float | None = 30.0) -> tuple[int, str, str]:
        """Ejecuta un subproceso devolviendo (returncode, stdout, stderr)."""
        ...


@runtime_checkable
class FirewallPort(Protocol):
    """Abstracción de operaciones sobre el Firewall de Windows."""

    def add_rule(self, rule_name: str, program_path: Path, direction: RuleDirection) -> bool:
        """Crea una regla de bloqueo de tráfico."""
        ...

    def delete_rule(self, rule_name: str) -> bool:
        """Elimina una regla por nombre."""
        ...

    def list_rules_with_suffix(self, suffix: str) -> list[str]:
        """Lista todas las reglas registradas que contienen el sufijo especificado."""
        ...


@runtime_checkable
class DirectoryScannerPort(Protocol):
    """Abstracción para escaneo del sistema de archivos y poda algorítmica."""

    def find_executables(self, search_roots: list[Path]) -> list[Path]:
        """Escanea recursivamente los directorios buscando binarios ejecutables (.exe)."""
        ...

    def prune_redundant_paths(self, candidates: list[Path]) -> list[Path]:
        """Elimina subdirectorios redundantes si su directorio contenedor ya está presente."""
        ...


@runtime_checkable
class ConfigRepositoryPort(Protocol):
    """Abstracción para la persistencia y lectura de directorios de búsqueda."""

    def load_paths(self) -> list[Path]:
        """Carga las rutas configuradas con expansión de variables de entorno."""
        ...

    def save_paths(self, paths: list[Path]) -> bool:
        """Persiste las rutas configuradas sustituyendo variables de entorno."""
        ...


@runtime_checkable
class RegistryDiscoveryPort(Protocol):
    """Abstracción para la inspección del Registro de Windows."""

    def discover_creative_paths(self) -> list[Path]:
        """Detecta rutas de suites instaladas en el Registro de Windows."""
        ...


@runtime_checkable
class UACPort(Protocol):
    """Abstracción para la verificación y elevación de privilegios UAC."""

    def is_admin(self) -> bool:
        """Determina si el proceso cuenta con privilegios administrativos."""
        ...

    def request_elevation(self) -> bool:
        """Solicita la elevación del proceso mediante UAC."""
        ...
