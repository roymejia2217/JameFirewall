"""Bounded Windows Defender Firewall probe for native system tests."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Collection, Iterable
from pathlib import PurePath
from typing import TypedDict, cast

from jame_firewall.core.entities import RuleDirection
from jame_firewall.core.rule_identity import managed_rule_name


class FirewallRuleSnapshot(TypedDict):
    """Native firewall rule state relevant to the JameFirewall system contract."""

    DisplayName: str
    Direction: str
    Action: str
    Enabled: str
    Program: str


def managed_rule_names(
    programs: Iterable[PurePath],
    suffix: str = "jame-block",
) -> tuple[str, ...]:
    """Derive the exact display names JameFirewall creates for executable paths."""
    names = {
        managed_rule_name(program, direction, suffix)
        for program in programs
        for direction in RuleDirection
    }
    return tuple(sorted(names, key=str.casefold))


def _powershell_single_quote(value: str) -> str:
    return value.replace("'", "''")


def build_probe_script(rule_names: Collection[str]) -> str:
    """Build a NetSecurity query restricted to exact managed display names."""
    literals = "\n".join(
        f"    '{_powershell_single_quote(name)}'" for name in sorted(rule_names, key=str.casefold)
    )
    return f"""$names = @(
{literals}
)
$items = foreach ($name in $names) {{
    $rules = @(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)
    foreach ($rule in $rules) {{
        $filters = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule)
        foreach ($filter in $filters) {{
            [PSCustomObject]@{{
                DisplayName = [string]$rule.DisplayName
                Direction = [string]$rule.Direction
                Action = [string]$rule.Action
                Enabled = [string]$rule.Enabled
                Program = [string]$filter.Program
            }}
        }}
    }}
}}
if ($items) {{
    $items | ConvertTo-Json -Compress
}} else {{
    '[]'
}}
"""


def probe_firewall_rules(
    rule_names: Collection[str],
    *,
    timeout_seconds: float = 30.0,
) -> list[FirewallRuleSnapshot]:
    """Read exact JameFirewall rules through the native Windows NetSecurity API."""
    if not rule_names:
        return []

    script = build_probe_script(rule_names)
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        names = ", ".join(sorted(rule_names, key=str.casefold))
        raise TimeoutError(
            f"Windows Firewall exact-name probe timed out after {timeout_seconds}s: {names}"
        ) from exc

    raw: object = json.loads(completed.stdout)
    if isinstance(raw, dict):
        raw = [raw]
    return cast(list[FirewallRuleSnapshot], raw)
