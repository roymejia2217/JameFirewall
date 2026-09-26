"""Pruebas unitarias para WindowsNetshAdapter."""

from pathlib import Path
from unittest.mock import MagicMock

from jame_firewall.core.entities import RuleDirection
from jame_firewall.infrastructure.firewall.netsh_adapter import WindowsNetshAdapter


def test_netsh_adapter_add_rule() -> None:
    runner_mock = MagicMock()
    runner_mock.run.return_value = (0, "Ok.", "")
    adapter = WindowsNetshAdapter(runner=runner_mock)

    success = adapter.add_rule(
        rule_name="photoshop jame-block",
        program_path=Path("C:/app/photoshop.exe"),
        direction=RuleDirection.OUT,
    )
    assert success is True
    call_args = runner_mock.run.call_args[0][0]
    assert call_args[0] == "netsh"
    assert "name=photoshop jame-block" in call_args
    assert "dir=out" in call_args
    assert f"program={Path('C:/app/photoshop.exe')}" in call_args
    assert "action=block" in call_args


def test_netsh_adapter_delete_rule() -> None:
    runner_mock = MagicMock()
    runner_mock.run.return_value = (0, "Deleted 1 rule(s).", "")
    adapter = WindowsNetshAdapter(runner=runner_mock)

    success = adapter.delete_rule("photoshop jame-block")
    assert success is True
    call_args = runner_mock.run.call_args[0][0]
    assert call_args == [
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        "name=photoshop jame-block",
    ]


def test_netsh_adapter_list_rules_with_suffix() -> None:
    runner_mock = MagicMock()
    # Simular salida de PowerShell
    runner_mock.run.return_value = (
        0,
        "Photoshop jame-block\nIllustrator jame-block\nInDesign other-rule\n",
        "",
    )
    adapter = WindowsNetshAdapter(runner=runner_mock)

    rules = adapter.list_rules_with_suffix("jame-block")
    assert len(rules) == 2
    assert "Photoshop jame-block" in rules
    assert "Illustrator jame-block" in rules


def test_empty_successful_powershell_result_does_not_fallback() -> None:
    """An empty successful PowerShell query is an authoritative empty rule set."""
    runner_mock = MagicMock()
    runner_mock.run.return_value = (0, "", "")
    adapter = WindowsNetshAdapter(runner=runner_mock)

    rules = adapter.list_rules_with_suffix("jame-block")

    assert rules == []
    runner_mock.run.assert_called_once()


def test_failed_powershell_query_falls_back_to_netsh() -> None:
    """netsh remains available only when the primary PowerShell query fails."""
    runner_mock = MagicMock()
    runner_mock.run.side_effect = [
        (1, "", "PowerShell failure"),
        (0, "Rule Name: Photoshop jame-block\n", ""),
    ]
    adapter = WindowsNetshAdapter(runner=runner_mock)

    rules = adapter.list_rules_with_suffix("jame-block")

    assert rules == ["Photoshop jame-block"]
    assert runner_mock.run.call_count == 2
