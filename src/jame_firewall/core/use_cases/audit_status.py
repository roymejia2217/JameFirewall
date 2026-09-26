"""Caso de uso para la auditoría del estado de protección del Firewall."""

from jame_firewall.core.entities import StatusSnapshot, SystemStatus
from jame_firewall.core.ports import FirewallPort, UACPort


class AuditFirewallStatusUseCase:
    """Audita el Firewall de Windows para determinar el estado de protección."""

    def __init__(
        self,
        firewall: FirewallPort,
        uac: UACPort,
        primary_suffix: str = "jame-block",
        legacy_suffixes: list[str] | None = None,
    ) -> None:
        self._firewall = firewall
        self._uac = uac
        self._primary_suffix = primary_suffix
        self._legacy_suffixes = legacy_suffixes or []

    def execute(self) -> StatusSnapshot:
        """Determina el estado del sistema y conteo de reglas activas."""
        if not self._uac.is_admin():
            return StatusSnapshot(
                status=SystemStatus.NO_ADMIN_PRIVILEGES,
                rule_count=0,
                detail="Se requieren privilegios administrativos.",
            )

        all_suffixes = [self._primary_suffix, *self._legacy_suffixes]
        rules: set[str] = set()

        for suffix in all_suffixes:
            found = self._firewall.list_rules_with_suffix(suffix)
            rules.update(found)

        count = len(rules)
        if count > 0:
            return StatusSnapshot(
                status=SystemStatus.PROTECTED,
                rule_count=count,
                detail=f"{count} reglas activas",
            )

        return StatusSnapshot(
            status=SystemStatus.UNPROTECTED,
            rule_count=0,
            detail="0 reglas activas",
        )
