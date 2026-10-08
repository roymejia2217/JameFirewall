"""Adaptador de Windows Defender Firewall mediante NetSecurity y JSON tipado."""

import json
import re
from pathlib import Path
from typing import Any

from jame_firewall.core.entities import (
    FirewallInventory,
    FirewallRule,
    ProcessStatus,
    RuleDirection,
)
from jame_firewall.core.exceptions import FirewallExecutionError
from jame_firewall.core.execution import (
    OPERATION_TIMEOUT_SECONDS,
    check_operation_budget,
    remaining_operation_seconds,
    renew_operation_budget,
)
from jame_firewall.core.ports import ProcessRunnerPort
from jame_firewall.core.rule_identity import MANAGED_GROUP, is_managed_rule
from jame_firewall.infrastructure.firewall._inventory import (
    _INVENTORY_SCRIPT,
    MAX_SUFFIX_LENGTH,
    MAX_SUFFIXES,
)


def _literal(value: str) -> str:
    """Literal PowerShell, incluso para rutas con apóstrofes."""
    return "'" + value.replace("'", "''") + "'"


# Revalidar el objeto local evita operar sobre una regla ajena con un nombre visible igual.
_LOOKUP_SCRIPT = r"""
$found = @()
try {
    $found = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop)
} catch {
    if ($_.CategoryInfo.Category -eq 'ObjectNotFound' -and
        $_.FullyQualifiedErrorId -eq 'CmdletizationQuery_NotFound_InstanceID,Get-NetFirewallRule') {
        $found = @()
    } else { throw }
}
if ($found.Count -gt 1) { throw 'Ambiguous rule identity' }
$owned = $true
if ($found.Count -eq 1) {
    $r = $found[0]
    $filter = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r)
    if ($filter.Count -ne 1) { throw 'Incomplete application filter' }
    $actual = [Environment]::ExpandEnvironmentVariables([string]$filter[0].Program)
    if ($r.Group -ne $group -or [string]$r.Direction -ne $direction -or
        -not [string]::Equals($actual.Replace('/', '\'), $program.Replace('/', '\'),
            [StringComparison]::OrdinalIgnoreCase)) {
        $owned = $false
    }
}
"""


_BATCH_LOOKUP_SCRIPT = r"""
# Read each native catalog once per bounded batch, then revalidate exact ownership.
# Both catalog queries are fail-closed: missing/duplicate filter identities abort the batch.
$requestedNames = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
foreach ($request in $requests) {
    if (-not $requestedNames.Add([string]$request.Name)) {
        throw 'Duplicate batch rule identity'
    }
}
$foundByName = @{}
Get-NetFirewallRule -PolicyStore PersistentStore -All -ErrorAction Stop | ForEach-Object {
    $key = [string]$_.Name
    if ($requestedNames.Contains($key)) {
        if ($foundByName.ContainsKey($key)) { throw 'Ambiguous rule identity' }
        $foundByName[$key] = $_
    }
}
$filtersByName = @{}
if ($foundByName.Count -gt 0) {
    Get-NetFirewallApplicationFilter -PolicyStore PersistentStore -All -ErrorAction Stop |
        ForEach-Object {
            $key = [string]$_.InstanceID
            if ($foundByName.ContainsKey($key)) {
                if ($filtersByName.ContainsKey($key)) { throw 'Ambiguous application filter' }
                $filtersByName[$key] = $_
            }
        }
    if ($filtersByName.Count -ne $foundByName.Count) {
        throw 'Incomplete application filter catalog'
    }
}
"""

_BATCH_VALIDATE_SCRIPT = r"""
$owned = $true
$found = @()
if ($foundByName.ContainsKey($name)) {
    $r = $foundByName[$name]
    $found = @($r)
    if (-not $filtersByName.ContainsKey($name)) {
        throw 'Incomplete application filter'
    }
    $filter = $filtersByName[$name]
    $actual = [Environment]::ExpandEnvironmentVariables([string]$filter.Program)
    if ($r.Group -ne $group -or [string]$r.Direction -ne $direction -or
        -not [string]::Equals($actual.Replace('/', '\'), $program.Replace('/', '\'),
            [StringComparison]::OrdinalIgnoreCase)) {
        $owned = $false
    }
}
"""

_PAYLOAD_LIMIT = 8000  # UTF-16 bytes after quoting; leaves room for script and runner prefix.
_CREATE_SCRIPT = """
if ($owned) {
    if ($found.Count -eq 1) { Remove-NetFirewallRule -InputObject $r | Out-Null }
    New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name `
        -Group $group -Program $program -Direction $direction -Action Block `
        -Enabled True -Profile Any -Protocol Any -LocalAddress Any -RemoteAddress Any `
        -InterfaceType Any -Service Any | Out-Null
}
"""


class WindowsNetshAdapter:
    """FirewallPort; NetSecurity conserva identidades y evita interpretar texto localizado."""

    def __init__(self, runner: ProcessRunnerPort) -> None:
        self._runner = runner

    def _run(self, script: str, *, timeout: float | None = None) -> tuple[int, str, str]:
        command = (
            "$ErrorActionPreference = 'Stop'; "
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); "
            "try {\n"
            + script
            + "\n} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
        )
        args = ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
        effective_timeout = timeout
        if effective_timeout is None:
            remaining = remaining_operation_seconds()
            effective_timeout = remaining if remaining is not None else OPERATION_TIMEOUT_SECONDS
        result = self._runner.run(args, timeout=effective_timeout)
        if result.status != ProcessStatus.COMPLETED or result.returncode is None:
            detail = result.detail or result.stderr[:1024] or result.status.value
            raise FirewallExecutionError(
                f"Comando de firewall incompleto ({result.status.value}): {detail}. "
                "Los cambios ya aplicados no se revierten; actualice el estado antes de reintentar."
            )
        return result.returncode, result.stdout, result.stderr

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
if (-not $owned) { exit 2 }
if ($found.Count -eq 1) {
    Remove-NetFirewallRule -InputObject $r
}
New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name `
        -Group $group -Program $program -Direction $direction -Action Block `
        -Enabled True -Profile Any -Protocol Any -LocalAddress Any -RemoteAddress Any `
        -InterfaceType Any -Service Any | Out-Null
"""
        code, _, _ = self._run(script)
        if code == 0:
            renew_operation_budget()
        return code == 0

    def delete_rule(self, rule: FirewallRule) -> bool:
        """Elimina solamente una identidad propia revalidada en PersistentStore."""
        suffix = rule.name.split(":v1:", 1)[0]
        if not is_managed_rule(rule, suffix):
            return False
        script = self._rule_variables(rule.name, rule.program_path, rule.direction)
        script += (
            _LOOKUP_SCRIPT
            + "\nif (-not $owned) { exit 2 }\n"
            + "if ($found.Count -eq 1) { Remove-NetFirewallRule -InputObject $r }"
        )
        code, _, _ = self._run(script)
        if code == 0:
            renew_operation_budget()
        return code == 0

    def add_rules(self, rules: list[FirewallRule]) -> tuple[bool, ...]:
        """Create or repair in bounded sequential batches; final inventory proves coverage."""
        return self._mutate_rules(rules, delete=False)

    def delete_rules(self, rules: list[FirewallRule]) -> tuple[bool, ...]:
        """Delete only revalidated owned rules; incomplete execution aborts remaining batches."""
        return self._mutate_rules(rules, delete=True)

    def _mutate_rules(self, rules: list[FirewallRule], *, delete: bool) -> tuple[bool, ...]:
        if len({r.name for r in rules}) != len(rules) or any(
            not is_managed_rule(r, r.name.split(":v1:", 1)[0]) for r in rules
        ):
            raise FirewallExecutionError("Identidades de lote inválidas o duplicadas")
        results: list[bool] = []
        batch: list[FirewallRule] = []
        for rule in rules:
            check_operation_budget()
            candidate = [*batch, rule]
            if self._payload_size(candidate) > _PAYLOAD_LIMIT:
                if batch:
                    results.extend(self._run_batch(batch, delete=delete))
                    batch = []
                check_operation_budget()
                if self._payload_size([rule]) > _PAYLOAD_LIMIT:
                    raise FirewallExecutionError("Ruta demasiado larga para el lote de firewall")
            batch.append(rule)
        if batch:
            results.extend(self._run_batch(batch, delete=delete))
        check_operation_budget()
        return tuple(results)

    @staticmethod
    def _payload(rules: list[FirewallRule]) -> str:
        return _literal(
            json.dumps(
                [
                    {
                        "Name": r.name,
                        "Program": str(r.program_path),
                        "Direction": "Inbound" if r.direction == RuleDirection.IN else "Outbound",
                    }
                    for r in rules
                ],
                ensure_ascii=True,
                separators=(",", ":"),
            )
        )

    @classmethod
    def _payload_size(cls, rules: list[FirewallRule]) -> int:
        return len(cls._payload(rules).encode("utf-16-le"))

    def _run_batch(self, rules: list[FirewallRule], *, delete: bool) -> list[bool]:
        check_operation_budget()
        action = (
            "if ($found.Count -eq 1) { Remove-NetFirewallRule -InputObject $r | Out-Null }"
            if delete
            else _CREATE_SCRIPT
        )
        script = (
            f"$group = {_literal(MANAGED_GROUP)};\n"
            f"$requests = ConvertFrom-Json {self._payload(rules)};\n"
            + _BATCH_LOOKUP_SCRIPT
            + "$results = @(foreach ($request in $requests) {\n"
            "$name = [string]$request.Name; $program = [string]$request.Program;\n"
            "$direction = [string]$request.Direction; $success = $false;\n"
            + _BATCH_VALIDATE_SCRIPT
            + "\nif ($owned) {\n"
            + action
            + "\n$success = $true\n}\n"
            "[PSCustomObject]@{ Name = $name; Succeeded = [bool]$success }\n"
            "});\n[PSCustomObject]@{ Results = @($results) } | ConvertTo-Json -Depth 3 -Compress"
        )
        code, stdout, stderr = self._run(script)
        if code != 0:
            raise FirewallExecutionError(f"Lote de firewall incompleto: {stderr[:1024]}")
        try:
            raw: object = json.loads(stdout)
            if not isinstance(raw, dict) or not isinstance(raw.get("Results"), list):
                raise ValueError("Invalid batch schema")
            items = raw["Results"]
            if len(items) != len(rules):
                raise ValueError("Incomplete batch results")
            results = []
            for rule, item in zip(rules, items, strict=True):
                if not isinstance(item, dict) or item.get("Name") != rule.name:
                    raise ValueError("Mismatched batch identity")
                results.append(self._boolean(item, "Succeeded"))
            renew_operation_budget()
            return results
        except (ValueError, KeyError, TypeError) as ex:
            raise FirewallExecutionError("Respuesta de lote inválida; actualice el estado") from ex

    def list_inventory(self, suffixes: list[str]) -> FirewallInventory:
        """Lee reglas locales, presencia en ActiveStore y perfiles; falla de forma explícita."""
        if len(suffixes) > MAX_SUFFIXES or any(
            not re.fullmatch(r"[a-z0-9-]{1," + str(MAX_SUFFIX_LENGTH) + "}", suffix)
            for suffix in suffixes
        ):
            raise FirewallExecutionError("Ámbito de inventario inválido o demasiado amplio")
        check_operation_budget()
        literals = ", ".join(_literal(suffix) for suffix in dict.fromkeys(suffixes))
        script = f"$group = {_literal(MANAGED_GROUP)}; $suffixes = @({literals});\n"
        code, stdout, stderr = self._run(script + _INVENTORY_SCRIPT)
        if code != 0:
            raise FirewallExecutionError(f"No se pudo consultar el firewall: {stderr}")
        try:
            raw: object = json.loads(stdout)
            if not isinstance(raw, dict) or not isinstance(raw.get("Rules"), list):
                raise ValueError("Invalid inventory schema")
            if not self._boolean(raw, "Complete"):
                raise ValueError("Incomplete inventory")
            enabled = self._boolean(raw, "ProfilesEnabled")
            allowed = self._boolean(raw, "LocalRulesAllowed")
            rules = tuple(self._parse_rule(item) for item in raw["Rules"])
            if len({r.name.casefold() for r in rules}) != len(rules):
                raise ValueError("Duplicate native identities")
            check_operation_budget()
            renew_operation_budget()
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
        states: object = item["EnforcementStates"]
        if not isinstance(states, list) or any(not isinstance(state, str) for state in states):
            raise ValueError("Invalid enforcement states")
        # Inactive profiles coexist with the enforced profile; rejection states never count.
        enforced = bool(set(states) & {"Enforced", "Full"}) and set(states) <= {
            "Enforced",
            "Full",
            "ProfileInactive",
        }
        return FirewallRule(
            name=item["Name"],
            display_name=item["DisplayName"],
            program_path=Path(item["Program"]),
            direction=directions[item["Direction"]],
            action=item["Action"].casefold(),
            group=item["Group"],
            enabled=cls._boolean(item, "Enabled"),
            profiles=item["Profile"],
            effective=cls._boolean(item, "Effective") and enforced,
        )
