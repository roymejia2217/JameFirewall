"""Identidad estable de reglas por ruta Windows y dirección."""

import hashlib
import ntpath
import re
from pathlib import PurePath

from jame_firewall.core.entities import FirewallInventory, FirewallRule, RuleDirection

MANAGED_GROUP = "JameFirewall.v1"


def program_key(path: PurePath) -> str:
    """Normaliza separadores y mayúsculas con semántica Windows."""
    return ntpath.normcase(ntpath.normpath(str(path)))


def managed_rule_name(path: PurePath, direction: RuleDirection, suffix: str = "jame-block") -> str:
    """Identificador de proveedor; el nombre visible no determina la propiedad."""
    if not re.fullmatch(r"[a-z0-9-]+", suffix):
        raise ValueError("Invalid firewall namespace")
    digest = hashlib.sha256(program_key(path).encode("utf-8")).hexdigest()
    return f"{suffix}:v1:{digest}:{direction.value}"


def is_managed_rule(rule: FirewallRule, suffix: str = "jame-block") -> bool:
    """Comprueba grupo y vínculo entre identificador, ruta y dirección."""
    if not re.fullmatch(r"[a-z0-9-]+", suffix):
        return False
    return rule.group == MANAGED_GROUP and rule.name == managed_rule_name(
        rule.program_path, rule.direction, suffix
    )


def is_legacy_rule(rule: FirewallRule, suffixes: list[str]) -> bool:
    """Reconoce candidatos antiguos únicamente para advertir de su presencia."""
    return (
        any(rule.display_name.casefold().endswith(f" {suffix}".casefold()) for suffix in suffixes)
        and rule.group != MANAGED_GROUP
    )


def is_blocking_rule(rule: FirewallRule, suffix: str) -> bool:
    """Regla propia habilitada, sin restricciones y aplicada por Windows."""
    return (
        is_managed_rule(rule, suffix)
        and rule.enabled
        and rule.action.casefold() == "block"
        and rule.profiles.casefold() == "any"
        and rule.effective
    )


def covered_programs(inventory: FirewallInventory, suffix: str) -> set[str]:
    """Rutas con ambas reglas completas y presentes en la política activa."""
    if not inventory.profiles_enabled or not inventory.local_rules_allowed:
        return set()
    directions: dict[str, set[RuleDirection]] = {}
    for rule in inventory.rules:
        if is_blocking_rule(rule, suffix):
            directions.setdefault(program_key(rule.program_path), set()).add(rule.direction)
    return {path for path, found in directions.items() if found == set(RuleDirection)}
