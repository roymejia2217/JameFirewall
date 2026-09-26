"""Caso de uso para el bloqueo transaccional de ejecutables en el Firewall."""

from collections.abc import Callable
from pathlib import Path

from jame_firewall.core.entities import BlockSummary, RuleDirection
from jame_firewall.core.exceptions import PrivilegesRequiredError
from jame_firewall.core.ports import DirectoryScannerPort, FirewallPort, UACPort


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

    def execute(self, search_directories: list[Path]) -> BlockSummary:
        """Ejecuta el proceso completo de escaneo y bloqueo de binarios."""
        if not self._uac.is_admin():
            raise PrivilegesRequiredError("Se requieren privilegios de administrador para crear reglas.")

        # 1. Obtener reglas existentes para evitar duplicaciones
        existing_rules = self._firewall.list_rules_with_suffix(self._suffix)
        existing_base_names = {
            r.replace(f" {self._suffix}", "").lower()
            for r in existing_rules
            if r.lower().endswith(f" {self._suffix}".lower())
        }

        # 2. Escanear ejecutables
        discovered_exes = self._scanner.find_executables(search_directories)
        if not discovered_exes:
            return BlockSummary(blocked_count=0, skipped_count=0, failed_count=0)

        blocked = 0
        skipped = 0
        failed = 0
        errors: list[str] = []

        for exe_path in discovered_exes:
            exe_name = exe_path.stem
            if exe_name.lower() in existing_base_names:
                skipped += 1
                continue

            rule_name = f"{exe_name} {self._suffix}"
            if self._on_progress:
                self._on_progress(f"+ {exe_name}", "info")

            ok_out = self._firewall.add_rule(rule_name, exe_path, RuleDirection.OUT)
            ok_in = self._firewall.add_rule(rule_name, exe_path, RuleDirection.IN)

            if ok_out and ok_in:
                blocked += 1
                existing_base_names.add(exe_name.lower())
            else:
                failed += 1
                err_msg = f"Error al crear reglas para: {exe_name}"
                errors.append(err_msg)
                if self._on_progress:
                    self._on_progress(err_msg, "err")

        return BlockSummary(
            blocked_count=blocked,
            skipped_count=skipped,
            failed_count=failed,
            errors=errors,
        )
