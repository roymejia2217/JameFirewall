"""Entidades de dominio y objetos de valor para JameFirewall."""

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class RuleDirection(StrEnum):
    """Dirección del tráfico de red en Windows Firewall."""

    IN = "in"
    OUT = "out"


class SystemStatus(StrEnum):
    """Estado del sistema respecto a la protección del firewall."""

    LOADING = "Cargando..."
    PROTECTED = "Habilitado"
    UNPROTECTED = "Deshabilitado"
    PARTIAL = "Parcial"
    ERROR = "Error"
    NO_ADMIN_PRIVILEGES = "Sin Privilegios"


@dataclass(frozen=True)
class FirewallRule:
    """Representa una regla en Windows Defender Firewall."""

    name: str
    program_path: Path
    direction: RuleDirection
    action: str = "block"
    display_name: str = ""
    group: str = ""
    enabled: bool = True
    profiles: str = "Any"
    effective: bool = True


@dataclass(frozen=True)
class FirewallInventory:
    """Reglas locales y condiciones de aplicación de la política activa."""

    rules: tuple[FirewallRule, ...]
    profiles_enabled: bool = True
    local_rules_allowed: bool = True


@dataclass(frozen=True)
class ExecutableTarget:
    """Representa un archivo binario ejecutable (.exe) escaneado."""

    name: str
    path: Path


@dataclass(frozen=True)
class ScanIssue:
    """One bounded diagnostic about an unexamined portion of the configured scope."""

    path: Path
    reason: str


@dataclass(frozen=True)
class ScanResult:
    """Observed targets and completeness travel together across every scan consumer."""

    executables: tuple[Path, ...]
    issues: tuple[ScanIssue, ...] = ()
    visited_directories: int = 0
    visited_entries: int = 0

    @property
    def complete(self) -> bool:
        return not self.issues

    @property
    def detail(self) -> str:
        if self.complete:
            return ""
        samples = "; ".join(f"{issue.reason}: {str(issue.path)[:256]}" for issue in self.issues[:3])
        return f"Escaneo incompleto ({len(self.issues)} incidencias); {samples}"


@dataclass(frozen=True)
class BlockSummary:
    """Resumen inmutable de una operación de bloqueo de ejecutables."""

    blocked_count: int
    skipped_count: int
    failed_count: int
    errors: list[str] = field(default_factory=list)
    scan_complete: bool = True


@dataclass(frozen=True)
class UnblockSummary:
    """Resumen inmutable de una operación de desbloqueo."""

    removed_count: int
    failed_count: int
    errors: list[str] = field(default_factory=list)
    retained_legacy_count: int = 0


@dataclass(frozen=True)
class StatusSnapshot:
    """Captura del estado actual de protección del sistema."""

    status: SystemStatus
    rule_count: int
    detail: str = ""
