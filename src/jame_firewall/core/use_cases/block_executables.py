"""Caso de uso para la reconciliación del bloqueo de ejecutables en el Firewall."""

from collections.abc import Callable
from pathlib import Path

from jame_firewall.core.entities import BlockSummary, RuleDirection
from jame_firewall.core.exceptions import PrivilegesRequiredError
from jame_firewall.core.ports import DirectoryScannerPort, FirewallPort, UACPort
from jame_firewall.core.rule_identity import (
    covered_programs,
    is_blocking_rule,
    managed_rule_name,
    program_key,
)


class BlockExecutablesUseCase:
    """Orquesta la búsqueda, deduplicación y creación de reglas de bloqueo."""

    def __init__(
        self,
        firewall: FirewallPort,
        scanner: DirectoryScannerPort,
        uac: UACPort,
        primary_suffix: str = "jame-block",
        on_progress: Callable[[str, str], None] | None = None,
    ) -> None:
        self._firewall = firewall
        self._scanner = scanner
        self._uac = uac
        self._suffix = primary_suffix
        self._on_progress = on_progress

    def execute(
        self,
        search_directories: list[Path],
        *,
        on_progress: Callable[[str, str], None] | None = None,
    ) -> BlockSummary:
        """Ejecuta el proceso completo de escaneo y bloqueo de binarios."""
        progress = on_progress if on_progress is not None else self._on_progress
        if not self._uac.is_admin():
            raise PrivilegesRequiredError(
                "Se requieren privilegios de administrador para crear reglas."
            )

        scan = self._scanner.find_executables(search_directories)
        if not scan.complete:
            message = scan.detail + "; no se crearon reglas"
            if progress:
                progress(message, "err")
            return BlockSummary(0, 0, 0, [message], scan_complete=False)
        inventory = self._firewall.list_inventory([self._suffix])
        covered = covered_programs(inventory, self._suffix)
        usable_names = {
            rule.name for rule in inventory.rules if is_blocking_rule(rule, self._suffix)
        }
        targets = {program_key(path): path for path in scan.executables}
        pending = {key: path for key, path in targets.items() if key not in covered}
        errors: list[str] = []
        for path in pending.values():
            if progress:
                progress(f"+ {path.stem}", "info")
            for direction in RuleDirection:
                name = managed_rule_name(path, direction, self._suffix)
                if name in usable_names:
                    continue
                self._firewall.add_rule(name, path, direction)

        # Un timeout no demuestra si hubo cambios: verificar el resultado observado.
        if pending:
            inventory = self._firewall.list_inventory([self._suffix])
            covered = covered_programs(inventory, self._suffix)
        for key, path in pending.items():
            if key not in covered:
                message = f"Bloqueo incompleto o no efectivo para: {path}"
                errors.append(message)
                if progress:
                    progress(message, "err")
        return BlockSummary(
            blocked_count=len(pending) - len(errors),
            skipped_count=len(targets) - len(pending),
            failed_count=len(errors),
            errors=errors,
        )
