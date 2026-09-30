"""Pruebas de contrato para FirewallPort y sus adaptadores."""

from pathlib import Path

from tests.fakes.fake_firewall import InMemoryFirewallAdapter

from jame_firewall.core.entities import RuleDirection
from jame_firewall.core.ports import FirewallPort
from jame_firewall.core.rule_identity import managed_rule_name


def test_fake_firewall_satisfies_protocol() -> None:
    adapter = InMemoryFirewallAdapter()
    assert isinstance(adapter, FirewallPort)


def test_firewall_port_lifecycle() -> None:
    adapter = InMemoryFirewallAdapter()

    path = Path("C:/app.exe")
    for direction in RuleDirection:
        assert adapter.add_rule(managed_rule_name(path, direction), path, direction)
    inventory = adapter.list_inventory(["jame-block"])
    assert len(inventory.rules) == 2
    assert {r.direction for r in inventory.rules} == set(RuleDirection)
    for rule in inventory.rules:
        assert adapter.delete_rule(rule)
    assert not adapter.list_inventory(["jame-block"]).rules
