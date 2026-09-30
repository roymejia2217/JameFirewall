"""Adaptador de Windows Defender Firewall mediante NetSecurity y JSON tipado."""

import json
from pathlib import Path
from typing import Any

from jame_firewall.core.entities import FirewallInventory, FirewallRule, RuleDirection
from jame_firewall.core.exceptions import FirewallExecutionError
from jame_firewall.core.ports import ProcessRunnerPort
from jame_firewall.core.rule_identity import MANAGED_GROUP, is_managed_rule


def _literal(value: str) -> str:
    """Literal PowerShell, incluso para rutas con apóstrofes."""
    return "'" + value.replace("'", "''") + "'"


_INVENTORY_SCRIPT = r"""
function Test-Any($value) {
    $values = @($value)
    return ($values.Count -eq 1 -and [string]$values[0] -eq 'Any')
}
function Test-Unrestricted($rule, $application) {
    $port = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule)
    $address = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule)
    $service = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule)
    $interface = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule)
    $type = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule)
    $security = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule)
    if ($port.Count -ne 1 -or $address.Count -ne 1 -or $service.Count -ne 1 -or
        $interface.Count -ne 1 -or $type.Count -ne 1 -or $security.Count -ne 1) {
        throw 'Incomplete traffic filter'
    }
    return (
        [string]$port[0].Protocol -in @('Any', '256') -and
        (Test-Any $port[0].LocalPort) -and (Test-Any $port[0].RemotePort) -and
        (Test-Any $port[0].IcmpType) -and (Test-Any $port[0].DynamicTarget) -and
        (Test-Any $address[0].LocalAddress) -and (Test-Any $address[0].RemoteAddress) -and
        (Test-Any $service[0].Service) -and (Test-Any $interface[0].InterfaceAlias) -and
        (Test-Any $type[0].InterfaceType) -and
        [string]$security[0].Authentication -eq 'NotRequired' -and
        [string]$security[0].Encryption -eq 'NotRequired' -and
        [string]$security[0].LocalUser -in @('', 'Any') -and
        [string]$security[0].RemoteUser -in @('', 'Any') -and
        [string]$security[0].RemoteMachine -in @('', 'Any') -and
        [string]$application.Package -in @('', 'Any') -and
        @($rule.Platform | Where-Object { $_ }).Count -eq 0 -and
        @($rule.RemoteDynamicKeywordAddresses | Where-Object { $_ }).Count -eq 0 -and
        [string]$rule.PolicyAppId -eq ''
    )
}
$local = @(Get-NetFirewallRule -PolicyStore PersistentStore)
$active = @{}
foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore)) {
    if ($r.Group -eq $group) { $active[$r.Name] = $r }
}
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
if ($profiles.Count -ne 3) { throw 'Incomplete firewall profile inventory' }
$enabled = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' }).Count -eq 0
$allowed = @($profiles | Where-Object {
    [string]$_.AllowLocalFirewallRules -eq 'False'
}).Count -eq 0
$items = @(foreach ($r in $local) {
    $candidate = $r.Group -eq $group
    foreach ($suffix in $suffixes) {
        if ($r.Name.StartsWith($suffix + ':v1:', [StringComparison]::Ordinal) -or
            $r.DisplayName.EndsWith(' ' + $suffix, [StringComparison]::OrdinalIgnoreCase)) {
            $candidate = $true
        }
    }
    if (-not $candidate) { continue }
    $filter = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r)
    if ($filter.Count -ne 1) { throw 'Incomplete application filter' }
    $program = [Environment]::ExpandEnvironmentVariables([string]$filter[0].Program)
    $effective = $false
    $a = $active[$r.Name]
    if ($null -ne $a) {
        $af = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $a)
        if ($af.Count -ne 1) { throw 'Incomplete active application filter' }
        $ap = [Environment]::ExpandEnvironmentVariables([string]$af[0].Program)
        $effective = (
            $a.Group -eq $group -and
            [string]$a.Enabled -eq 'True' -and
            [string]$a.Action -eq 'Block' -and
            [string]$a.Profile -eq 'Any' -and
            [string]$a.PrimaryStatus -eq 'OK' -and
            @($a.EnforcementStatus).Count -gt 0 -and
            @($a.EnforcementStatus | Where-Object { [string]$_ -notin @('Full', '1') }).Count -eq 0 -and
            (Test-Unrestricted $a $af[0]) -and
            $a.Direction -eq $r.Direction -and
            [string]::Equals($ap.Replace('/', '\'), $program.Replace('/', '\'),
                [StringComparison]::OrdinalIgnoreCase)
        )
    }
    [PSCustomObject]@{
        Name = [string]$r.Name; DisplayName = [string]$r.DisplayName
        Program = $program; Direction = [string]$r.Direction
        Action = [string]$r.Action; Group = [string]$r.Group
        Enabled = ([string]$r.Enabled -eq 'True')
        Profile = [string]$r.Profile; Effective = [bool]$effective
    }
})
[PSCustomObject]@{
    Rules = @($items); ProfilesEnabled = [bool]$enabled; LocalRulesAllowed = [bool]$allowed
} | ConvertTo-Json -Depth 4 -Compress
"""

# Revalidar el objeto local evita operar sobre una regla ajena con un nombre visible igual.
_LOOKUP_SCRIPT = r"""
$found = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -eq $name })
if ($found.Count -gt 1) { throw 'Ambiguous rule identity' }
if ($found.Count -eq 1) {
    $r = $found[0]
    $filter = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r)
    if ($filter.Count -ne 1) { throw 'Incomplete application filter' }
    $actual = [Environment]::ExpandEnvironmentVariables([string]$filter[0].Program)
    if ($r.Group -ne $group -or [string]$r.Direction -ne $direction -or
        -not [string]::Equals($actual.Replace('/', '\'), $program.Replace('/', '\'),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Rule identity does not belong to this application'
    }
}
"""


class WindowsNetshAdapter:
    """FirewallPort; NetSecurity conserva identidades y evita interpretar texto localizado."""

    def __init__(self, runner: ProcessRunnerPort) -> None:
        self._runner = runner

    def _run(self, script: str) -> tuple[int, str, str]:
        command = (
            "$ErrorActionPreference = 'Stop'; "
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); "
            "try {\n"
            + script
            + "\n} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
        )
        return self._runner.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
        )

    def _rule_variables(self, name: str, path: Path, direction: RuleDirection) -> str:
        native_direction = "Inbound" if direction == RuleDirection.IN else "Outbound"
        return (
            f"$name = {_literal(name)}; $program = {_literal(str(path))}; "
            f"$direction = {_literal(native_direction)}; $group = {_literal(MANAGED_GROUP)};\n"
        )

    def add_rule(self, rule_name: str, program_path: Path, direction: RuleDirection) -> bool:
        """Crea o repara una regla propia; el llamador verifica la política resultante."""
        suffix = rule_name.split(":v1:", 1)[0]
        candidate = FirewallRule(rule_name, program_path, direction, group=MANAGED_GROUP)
        if not is_managed_rule(candidate, suffix):
            return False
        script = self._rule_variables(rule_name, program_path, direction) + _LOOKUP_SCRIPT
        script += """
if ($found.Count -eq 1) {
    Remove-NetFirewallRule -InputObject $r
}
New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name `
        -Group $group -Program $program -Direction $direction -Action Block `
        -Enabled True -Profile Any -Protocol Any -LocalAddress Any -RemoteAddress Any `
        -InterfaceType Any -Service Any | Out-Null
"""
        code, _, _ = self._run(script)
        return code == 0

    def delete_rule(self, rule: FirewallRule) -> bool:
        """Elimina solamente una identidad propia revalidada en PersistentStore."""
        suffix = rule.name.split(":v1:", 1)[0]
        if not is_managed_rule(rule, suffix):
            return False
        script = self._rule_variables(rule.name, rule.program_path, rule.direction)
        script += (
            _LOOKUP_SCRIPT + "\nif ($found.Count -eq 1) { Remove-NetFirewallRule -InputObject $r }"
        )
        code, _, _ = self._run(script)
        return code == 0

    def list_inventory(self, suffixes: list[str]) -> FirewallInventory:
        """Lee reglas locales, presencia en ActiveStore y perfiles; falla de forma explícita."""
        literals = ", ".join(_literal(suffix) for suffix in suffixes)
        script = f"$group = {_literal(MANAGED_GROUP)}; $suffixes = @({literals});\n"
        code, stdout, stderr = self._run(script + _INVENTORY_SCRIPT)
        if code != 0:
            raise FirewallExecutionError(f"No se pudo consultar el firewall: {stderr}")
        try:
            raw: object = json.loads(stdout)
            if not isinstance(raw, dict) or not isinstance(raw.get("Rules"), list):
                raise ValueError("Invalid inventory schema")
            enabled = self._boolean(raw, "ProfilesEnabled")
            allowed = self._boolean(raw, "LocalRulesAllowed")
            rules = tuple(self._parse_rule(item) for item in raw["Rules"])
            if len({r.name for r in rules}) != len(rules):
                raise ValueError("Duplicate native identities")
            return FirewallInventory(rules, enabled, allowed)
        except (ValueError, KeyError, TypeError) as ex:
            raise FirewallExecutionError("Respuesta de firewall inválida") from ex

    @staticmethod
    def _boolean(raw: dict[str, Any], key: str) -> bool:
        value: object = raw[key]
        if not isinstance(value, bool):
            raise ValueError(f"Invalid boolean: {key}")
        return value

    @classmethod
    def _parse_rule(cls, item: object) -> FirewallRule:
        if not isinstance(item, dict):
            raise ValueError("Invalid rule")
        for key in ("Name", "DisplayName", "Program", "Direction", "Action", "Group", "Profile"):
            if not isinstance(item.get(key), str):
                raise ValueError(f"Invalid rule field: {key}")
        directions = {"Inbound": RuleDirection.IN, "Outbound": RuleDirection.OUT}
        if not item["Name"] or not item["Program"]:
            raise ValueError("Missing rule identity or program")
        return FirewallRule(
            name=item["Name"],
            display_name=item["DisplayName"],
            program_path=Path(item["Program"]),
            direction=directions[item["Direction"]],
            action=item["Action"].casefold(),
            group=item["Group"],
            enabled=cls._boolean(item, "Enabled"),
            profiles=item["Profile"],
            effective=cls._boolean(item, "Effective"),
        )
