"""Doble de prueba en memoria para FirewallPort."""

from pathlib import Path

from jame_firewall.core.entities import FirewallInventory, FirewallRule, RuleDirection
from jame_firewall.core.exceptions import FirewallExecutionError
from jame_firewall.core.execution import check_operation_budget
from jame_firewall.core.rule_identity import MANAGED_GROUP, managed_rule_name


class InMemoryFirewallAdapter:
    """Implementación en memoria de FirewallPort para pruebas deterministas."""

    def __init__(self) -> None:
        # Clave: (rule_name, direction)
        self.rules: dict[tuple[str, str], FirewallRule] = {}
        self.add_should_fail: bool = False
        self.delete_should_fail: bool = False
        self.list_should_fail: bool = False
        self.profiles_enabled = True
        self.local_rules_allowed = True

    def add_rule(self, rule_name: str, program_path: Path, direction: RuleDirection) -> bool:
        if self.add_should_fail:
            return False
        key = (rule_name, direction.value)
        self.rules[key] = FirewallRule(
            name=rule_name,
            program_path=program_path,
            direction=direction,
            action="block",
            display_name=rule_name,
            group=MANAGED_GROUP if ":v1:" in rule_name else "",
        )
        return True

    def delete_rule(self, rule: FirewallRule) -> bool:
        if self.delete_should_fail:
            return False
        suffix = rule.name.split(":v1:", 1)[0]
        if rule.group != MANAGED_GROUP or rule.name != managed_rule_name(
            rule.program_path, rule.direction, suffix
        ):
            return False
        key = (rule.name, rule.direction.value)
        if self.rules.get(key) != rule:
            return False
        del self.rules[key]
        return True

    def add_rules(self, rules: list[FirewallRule]) -> tuple[bool, ...]:
        results = []
        for rule in rules:
            check_operation_budget()
            results.append(self.add_rule(rule.name, rule.program_path, rule.direction))
        return tuple(results)

    def delete_rules(self, rules: list[FirewallRule]) -> tuple[bool, ...]:
        results = []
        for rule in rules:
            check_operation_budget()
            results.append(self.delete_rule(rule))
        return tuple(results)

    def list_inventory(self, suffixes: list[str]) -> FirewallInventory:
        if self.list_should_fail:
            raise FirewallExecutionError("Inventory unavailable")
        rules = tuple(
            rule
            for rule in self.rules.values()
            if rule.group == MANAGED_GROUP
            or any(rule.name.startswith(f"{s}:v1:") for s in suffixes)
            or any(rule.display_name.casefold().endswith(f" {s}".casefold()) for s in suffixes)
        )
        return FirewallInventory(rules, self.profiles_enabled, self.local_rules_allowed)

    def has_rule(self, rule_name: str) -> bool:
        """Helper de verificación para aserciones de pruebas."""
        return any(k[0] == rule_name for k in self.rules)

    def clear(self) -> None:
        """Limpia el estado en memoria."""
        self.rules.clear()
