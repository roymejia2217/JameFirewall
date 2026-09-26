"""Doble de prueba en memoria para FirewallPort."""

from pathlib import Path

from jame_firewall.core.entities import FirewallRule, RuleDirection


class InMemoryFirewallAdapter:
    """Implementación en memoria de FirewallPort para pruebas deterministas."""

    def __init__(self) -> None:
        # Clave: (rule_name, direction)
        self.rules: dict[tuple[str, str], FirewallRule] = {}
        self.add_should_fail: bool = False
        self.delete_should_fail: bool = False
        self.list_should_fail: bool = False

    def add_rule(self, rule_name: str, program_path: Path, direction: RuleDirection) -> bool:
        if self.add_should_fail:
            return False
        key = (rule_name, direction.value)
        self.rules[key] = FirewallRule(
            name=rule_name,
            program_path=program_path,
            direction=direction,
            action="block",
        )
        return True

    def delete_rule(self, rule_name: str) -> bool:
        if self.delete_should_fail:
            return False
        keys_to_delete = [k for k in self.rules if k[0] == rule_name]
        if not keys_to_delete:
            return False
        for k in keys_to_delete:
            del self.rules[k]
        return True

    def list_rules_with_suffix(self, suffix: str) -> list[str]:
        if self.list_should_fail:
            return []
        matching_names: set[str] = set()
        for rule_name, _ in self.rules:
            if suffix in rule_name:
                matching_names.add(rule_name)
        return sorted(matching_names)

    def has_rule(self, rule_name: str) -> bool:
        """Helper de verificación para aserciones de pruebas."""
        return any(k[0] == rule_name for k in self.rules)

    def clear(self) -> None:
        """Limpia el estado en memoria."""
        self.rules.clear()
