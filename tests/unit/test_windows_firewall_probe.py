"""Contracts for the bounded native Windows Firewall E2E probe."""

from __future__ import annotations

from pathlib import PureWindowsPath

from tests.windows.firewall_probe import build_probe_script, managed_rule_names

from jame_firewall.core.entities import RuleDirection
from jame_firewall.core.rule_identity import managed_rule_name


def test_managed_rule_names_are_exact_and_deterministic() -> None:
    programs = {
        PureWindowsPath(r"C:\Program Files\7-Zip\7z.exe"),
        PureWindowsPath(r"C:\Program Files\7-Zip\7zFM.exe"),
        PureWindowsPath(r"C:\Program Files\7-Zip\7zG.exe"),
    }

    expected = {managed_rule_name(p, d) for p in programs for d in RuleDirection}
    assert set(managed_rule_names(programs)) == expected
    assert len(expected) == 6


def test_probe_script_queries_exact_names_without_global_wildcard() -> None:
    script = build_probe_script(("7z jame-block", "7zFM jame-block"))

    assert "Get-NetFirewallRule -Name $name" in script
    assert "$names = @(" in script
    assert "'7z jame-block'" in script
    assert "'7zFM jame-block'" in script
    assert "'* jame-block'" not in script
    assert '"* jame-block"' not in script


def test_probe_script_escapes_powershell_single_quotes() -> None:
    script = build_probe_script(("vendor's tool jame-block",))

    assert "'vendor''s tool jame-block'" in script
