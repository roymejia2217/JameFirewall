"""Caso de uso para el desbloqueo y migración de reglas legacy del Firewall."""

from collections.abc import Callable

from jame_firewall.core.entities import UnblockSummary
from jame_firewall.core.exceptions import PrivilegesRequiredError
from jame_firewall.core.ports import FirewallPort, UACPort


class UnblockRulesUseCase:
    """Orquesta la eliminación atómica de reglas oficiales y legacy."""

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

    def execute(self) -> UnblockSummary:
        """Elimina todas las reglas asociadas a JameFirewall y sufijos anteriores."""
        if not self._uac.is_admin():
            raise PrivilegesRequiredError(
                "Se requieren privilegios de administrador para eliminar reglas."
            )

        # Recolectar reglas de todos los sufijos auditados
        all_suffixes = [self._primary_suffix, *self._legacy_suffixes]
        rules_to_delete: set[str] = set()

        for suffix in all_suffixes:
            found = self._firewall.list_rules_with_suffix(suffix)
            rules_to_delete.update(found)

        if not rules_to_delete:
            return UnblockSummary(removed_count=0, failed_count=0)

        removed = 0
        failed = 0
        errors: list[str] = []

        for rule_name in sorted(rules_to_delete):
            if self._on_progress:
                self._on_progress(f"- {rule_name}", "info")

            if self._firewall.delete_rule(rule_name):
                removed += 1
            else:
                failed += 1
                err_msg = f"Error al eliminar la regla: {rule_name}"
                errors.append(err_msg)
                if self._on_progress:
                    self._on_progress(err_msg, "err")

        return UnblockSummary(removed_count=removed, failed_count=failed, errors=errors)
