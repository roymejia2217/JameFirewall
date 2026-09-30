"""Caso de uso para el desbloqueo de reglas propias del Firewall."""

from collections.abc import Callable

from jame_firewall.core.entities import UnblockSummary
from jame_firewall.core.exceptions import PrivilegesRequiredError
from jame_firewall.core.ports import FirewallPort, UACPort
from jame_firewall.core.rule_identity import is_legacy_rule, is_managed_rule


class UnblockRulesUseCase:
    """Elimina reglas propias y conserva las antiguas para revisión."""

    def __init__(
        self,
        firewall: FirewallPort,
        uac: UACPort,
        primary_suffix: str = "jame-block",
        legacy_suffixes: list[str] | None = None,
        on_progress: Callable[[str, str], None] | None = None,
    ) -> None:
        self._firewall = firewall
        self._uac = uac
        self._primary_suffix = primary_suffix
        self._legacy_suffixes = legacy_suffixes or []
        self._on_progress = on_progress

    def execute(
        self,
        *,
        on_progress: Callable[[str, str], None] | None = None,
    ) -> UnblockSummary:
        """Elimina identidades propias verificadas y comunica reglas antiguas retenidas."""
        progress = on_progress if on_progress is not None else self._on_progress
        if not self._uac.is_admin():
            raise PrivilegesRequiredError(
                "Se requieren privilegios de administrador para eliminar reglas."
            )

        suffixes = [self._primary_suffix, *self._legacy_suffixes]
        inventory = self._firewall.list_inventory(suffixes)
        owned = [rule for rule in inventory.rules if is_managed_rule(rule, self._primary_suffix)]
        legacy_count = sum(is_legacy_rule(rule, suffixes) for rule in inventory.rules)
        errors: list[str] = []
        for rule in owned:
            if progress:
                progress(f"- {rule.program_path} ({rule.direction})", "info")
            self._firewall.delete_rule(rule)
        remaining = self._firewall.list_inventory(suffixes) if owned else inventory
        remaining_names = {rule.name for rule in remaining.rules}
        failed_names = {rule.name for rule in owned if rule.name in remaining_names}
        for name in sorted(failed_names):
            errors.append(f"La regla sigue presente: {name}")
        if progress:
            for message in errors:
                progress(message, "err")
        return UnblockSummary(
            removed_count=len(owned) - len(failed_names),
            failed_count=len(failed_names),
            errors=errors,
            retained_legacy_count=legacy_count,
        )
