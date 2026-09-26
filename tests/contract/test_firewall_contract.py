"""Pruebas de contrato para FirewallPort y sus adaptadores."""

from pathlib import Path

from tests.fakes.fake_firewall import InMemoryFirewallAdapter

from jame_firewall.core.entities import RuleDirection
from jame_firewall.core.ports import FirewallPort


def test_fake_firewall_satisfies_protocol() -> None:
    adapter = InMemoryFirewallAdapter()
    assert isinstance(adapter, FirewallPort)


def test_firewall_port_lifecycle() -> None:
    adapter = InMemoryFirewallAdapter()

    # 1. Agregar reglas
    added_out = adapter.add_rule("app jame-block", Path("C:/app.exe"), RuleDirection.OUT)
    added_in = adapter.add_rule("app jame-block", Path("C:/app.exe"), RuleDirection.IN)
    assert added_out is True
    assert added_in is True

    # 2. Listar reglas
    rules = adapter.list_rules_with_suffix("jame-block")
    assert "app jame-block" in rules
    assert len(rules) == 1

    # 3. Eliminar regla
    deleted = adapter.delete_rule("app jame-block")
    assert deleted is True
    assert len(adapter.list_rules_with_suffix("jame-block")) == 0
