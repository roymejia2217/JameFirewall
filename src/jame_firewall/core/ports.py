"""Protocolos e Interfaces (Ports) abstractos para JameFirewall."""

from pathlib import Path
from typing import Protocol, runtime_checkable

from jame_firewall.core.entities import (
    FirewallInventory,
    FirewallRule,
    ProcessResult,
    RuleDirection,
    ScanResult,
)


@runtime_checkable
class ProcessRunnerPort(Protocol):
    """Abstracción para la ejecución de procesos del sistema operativo."""

    def run(self, args: list[str], timeout: float | None = 30.0) -> ProcessResult:
        """Return bounded output and explicit completion; cancellation raises after cleanup."""
        ...


MAX_INVENTORY_RULES = 2048


@runtime_checkable
class FirewallPort(Protocol):
    """Abstracción de operaciones sobre el Firewall de Windows."""

    def add_rule(self, rule_name: str, program_path: Path, direction: RuleDirection) -> bool:
        """Crea una regla de bloqueo de tráfico."""
        ...

    def delete_rule(self, rule: FirewallRule) -> bool:
        """Elimina una regla propia por identidad y atributos verificados."""
        ...

    def add_rules(self, rules: list[FirewallRule]) -> tuple[bool, ...]:
        """Apply bounded sequential batches; aligned results are not proof of effective policy.

        Invalid identities raise before execution; incomplete processes abort subsequent batches.
        Known per-rule failures return false. Already applied changes are never rolled back.
        """
        ...

    def delete_rules(self, rules: list[FirewallRule]) -> tuple[bool, ...]:
        """Remove revalidated owned rules in bounded batches with the same result contract."""
        ...

    def list_inventory(self, suffixes: list[str]) -> FirewallInventory:
        """Return a complete inventory of at most MAX_INVENTORY_RULES candidates; errors raise."""
        ...


@runtime_checkable
class DirectoryScannerPort(Protocol):
    """Abstracción para escaneo del sistema de archivos y poda algorítmica."""

    def find_executables(self, search_roots: list[Path]) -> ScanResult:
        """Return bounded targets and omissions together; cancellation raises."""
        ...

    def prune_redundant_paths(self, candidates: list[Path]) -> list[Path]:
        """Elimina subdirectorios redundantes si su directorio contenedor ya está presente."""
        ...


@runtime_checkable
class ConfigRepositoryPort(Protocol):
    """Abstracción para la persistencia y lectura de directorios de búsqueda."""

    def load_paths(self) -> list[Path]:
        """Load validated paths; missing uses defaults, invalid raises ConfigStorageError."""
        ...

    def save_paths(self, paths: list[Path]) -> bool:
        """Replace the complete configuration; false preserves the previous file."""
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


@runtime_checkable
class InstanceLockPort(Protocol):
    """Lifetime exclusion between application processes, owned by the startup thread."""

    def acquire(self) -> bool:
        """Acquire without waiting; false means busy, coordination failures raise."""
        ...

    def release(self) -> None:
        """Release on the acquiring thread; harmless when not acquired."""
        ...
