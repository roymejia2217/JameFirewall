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
    ERROR = "Error"
    NO_ADMIN_PRIVILEGES = "Sin Privilegios"


@dataclass(frozen=True)
class FirewallRule:
    """Representa una regla en Windows Defender Firewall."""

    name: str
    program_path: Path
    direction: RuleDirection
    action: str = "block"


@dataclass(frozen=True)
class ExecutableTarget:
    """Representa un archivo binario ejecutable (.exe) escaneado."""

    name: str
    path: Path


@dataclass(frozen=True)
class BlockSummary:
    """Resumen inmutable de una operación de bloqueo de ejecutables."""

    blocked_count: int
    skipped_count: int
    failed_count: int
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class UnblockSummary:
    """Resumen inmutable de una operación de desbloqueo."""

    removed_count: int
    failed_count: int
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StatusSnapshot:
    """Captura del estado actual de protección del sistema."""

    status: SystemStatus
    rule_count: int
    detail: str = ""
