"""Caso de uso para la auditoría del estado de protección del Firewall."""

from pathlib import Path

from jame_firewall.core.entities import StatusSnapshot, SystemStatus
from jame_firewall.core.exceptions import FirewallExecutionError
from jame_firewall.core.execution import check_operation_budget, operation_budget
from jame_firewall.core.ports import DirectoryScannerPort, FirewallPort, UACPort
from jame_firewall.core.rule_identity import (
    covered_programs,
    is_legacy_rule,
    is_managed_rule,
    program_key,
)


class AuditFirewallStatusUseCase:
    """Audita el Firewall de Windows para determinar el estado de protección."""

    def __init__(
        self,
        firewall: FirewallPort,
        uac: UACPort,
        scanner: DirectoryScannerPort,
        primary_suffix: str = "jame-block",
        legacy_suffixes: list[str] | None = None,
    ) -> None:
        self._scanner = scanner
        self._firewall = firewall
        self._uac = uac
        self._primary_suffix = primary_suffix
        self._legacy_suffixes = legacy_suffixes or []

    def execute(self, search_directories: list[Path]) -> StatusSnapshot:
        """Determina el estado del sistema y conteo de reglas activas."""
        with operation_budget():
            result = self._execute(search_directories)
            check_operation_budget()
            return result

    def _execute(self, search_directories: list[Path]) -> StatusSnapshot:
        """Determina el estado del sistema y conteo de reglas activas."""
        if not self._uac.is_admin():
            return StatusSnapshot(
                status=SystemStatus.NO_ADMIN_PRIVILEGES,
                rule_count=0,
                detail="Se requieren privilegios administrativos.",
            )

        suffixes = [self._primary_suffix, *self._legacy_suffixes]
        try:
            check_operation_budget()
            inventory = self._firewall.list_inventory(suffixes)
        except FirewallExecutionError as ex:
            return StatusSnapshot(SystemStatus.ERROR, 0, str(ex))
        managed = [r for r in inventory.rules if is_managed_rule(r, self._primary_suffix)]
        legacy_count = sum(is_legacy_rule(r, suffixes) for r in inventory.rules)
        scan = self._scanner.find_executables(search_directories)
        targets = {program_key(path) for path in scan.executables}
        covered = covered_programs(inventory, self._primary_suffix)
        count = len(managed)
        detail = f"Reglas: {count}; ejecutables cubiertos: {len(targets & covered)}/{len(targets)}"
        if legacy_count:
            detail += f"; reglas antiguas sin migrar: {legacy_count}"
        if not scan.complete:
            return StatusSnapshot(SystemStatus.PARTIAL, count, detail + "; " + scan.detail)
        if not inventory.profiles_enabled or not inventory.local_rules_allowed:
            return StatusSnapshot(
                SystemStatus.PARTIAL, count, detail + "; la política impide el bloqueo completo"
            )
        if targets and targets <= covered and not legacy_count:
            return StatusSnapshot(SystemStatus.PROTECTED, count, detail)
        if managed or legacy_count:
            return StatusSnapshot(SystemStatus.PARTIAL, count, detail)
        return StatusSnapshot(SystemStatus.UNPROTECTED, 0, detail)
