"""Native scoped inventory completeness, provider faults and catalog pressure."""

import json
import shutil
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import psutil
import pytest

from jame_firewall.core.entities import FirewallRule, RuleDirection, SystemStatus
from jame_firewall.core.exceptions import FirewallExecutionError
from jame_firewall.core.rule_identity import managed_rule_name, program_key
from jame_firewall.core.use_cases.audit_status import AuditFirewallStatusUseCase
from jame_firewall.core.use_cases.unblock_rules import UnblockRulesUseCase
from jame_firewall.infrastructure.firewall._inventory import _INVENTORY_SCRIPT
from jame_firewall.infrastructure.firewall.netsh_adapter import WindowsNetshAdapter
from jame_firewall.infrastructure.os.filesystem import OSFileSystemAdapter
from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner
from jame_firewall.infrastructure.os.uac_manager import WindowsUACAdapter

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows Firewall"),
]


def test_scoped_inventory_with_unrelated_rules_and_legacy_collision(
    tmp_path: Path,
    record_testsuite_property: Callable[[str, object], None],
) -> None:
    assert WindowsUACAdapter().is_admin()
    suffix = "jame-inv-" + uuid.uuid4().hex[:12]
    fixture_group = "fixture-" + suffix
    path = tmp_path / "O'Brien_á.exe"
    shutil.copy2(sys.executable, path)
    escaped_path = str(path).replace("'", "''")
    runner = SystemProcessRunner()
    firewall = WindowsNetshAdapter(runner)
    from jame_firewall.core.rule_identity import MANAGED_GROUP, managed_rule_name

    owned = [
        FirewallRule(managed_rule_name(path, d, suffix), path, d, group=MANAGED_GROUP)
        for d in RuleDirection
    ]
    collision = managed_rule_name(tmp_path / "foreign.exe", RuleDirection.OUT, suffix)

    def native(script: str) -> str:
        result = runner.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference = 'Stop'; " + script,
            ]
        )
        assert result.succeeded, result
        return result.stdout

    try:
        # Unrelated catalog entries must not enter the scoped inventory DTO.
        native(
            f"1..128 | ForEach-Object {{ New-NetFirewallRule -Name ('{suffix}-unrelated-' + $_) -DisplayName ('Unrelated ' + $_) -Group '{fixture_group}' -Program '{escaped_path}' -Direction Outbound -Action Allow | Out-Null }}"
        )
        native(
            f"New-NetFirewallRule -Name '{suffix}-legacy' -DisplayName 'Legacy ADOBE-BLOCK' -Group '{fixture_group}' -Program '{escaped_path}' -Direction Outbound -Action Allow | Out-Null; New-NetFirewallRule -Name '{collision}' -DisplayName 'Foreign collision' -Group '{fixture_group}' -Program '{escaped_path}' -Direction Outbound -Action Allow | Out-Null"
        )
        assert firewall.add_rules(owned) == (True, True)
        full = json.loads(
            native(
                "$watch = [Diagnostics.Stopwatch]::StartNew(); $local = @(Get-NetFirewallRule -PolicyStore PersistentStore); $active = @(Get-NetFirewallRule -PolicyStore ActiveStore); $watch.Stop(); [PSCustomObject]@{ LocalCount = $local.Count; ActiveCount = $active.Count; Seconds = $watch.Elapsed.TotalSeconds } | ConvertTo-Json -Compress"
            )
        )
        start = time.monotonic()
        inventory = firewall.list_inventory([suffix, "adobe-block"])
        scoped_seconds = time.monotonic() - start
        assert {r.name for r in inventory.rules} == {
            *(r.name for r in owned),
            collision,
            suffix + "-legacy",
        }
        assert all(r.effective for r in inventory.rules if r.name in {r.name for r in owned})
        assert not next(r for r in inventory.rules if r.name == collision).effective
        assert full["LocalCount"] >= 132 and full["ActiveCount"] >= 132
        record_testsuite_property("inventory_full_local_rows", full["LocalCount"])
        record_testsuite_property("inventory_full_active_rows", full["ActiveCount"])
        record_testsuite_property("inventory_scoped_candidates", len(inventory.rules))
        record_testsuite_property("inventory_full_catalog_seconds", round(full["Seconds"], 3))
        record_testsuite_property("inventory_scoped_verified_seconds", round(scoped_seconds, 3))
        audit = AuditFirewallStatusUseCase(
            firewall,
            WindowsUACAdapter(),
            OSFileSystemAdapter(),
            primary_suffix=suffix,
            legacy_suffixes=["adobe-block"],
        )
        assert audit.execute([tmp_path]).status == SystemStatus.PARTIAL
        removed = UnblockRulesUseCase(
            firewall, WindowsUACAdapter(), primary_suffix=suffix, legacy_suffixes=["adobe-block"]
        ).execute()
        assert removed.removed_count == 2 and removed.retained_legacy_count == 1
        assert {r.name for r in firewall.list_inventory([suffix, "adobe-block"]).rules} == {
            collision,
            suffix + "-legacy",
        }
    finally:
        firewall.delete_rules(owned)
        native(
            f"Get-NetFirewallRule -PolicyStore PersistentStore -Group '{fixture_group}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
        )
    assert firewall.list_inventory([suffix, "adobe-block"]).rules == ()


@pytest.mark.parametrize("fault", ["duplicate", "changed", "access", "fake-absence"])
def test_native_inventory_rejects_ambiguous_or_failed_provider_queries_before_filters(
    fault: str,
) -> None:
    # Real Windows PowerShell executes the inventory control flow with deterministic provider
    # records; provider failures do not require native OS mutations.
    runner = SystemProcessRunner()
    firewall = WindowsNetshAdapter(runner)
    if fault in {"access", "fake-absence"}:
        category = "PermissionDenied" if fault == "access" else "ObjectNotFound"
        provider = f"$record = [System.Management.Automation.ErrorRecord]::new([Exception]::new('fixture failure'), 'FixtureFailure', [System.Management.Automation.ErrorCategory]::{category}, $null); throw $record"
    else:
        provider = "$script:calls++; "
        if fault == "duplicate":
            provider += "1..2 | ForEach-Object { [PSCustomObject]@{ Name = 'same' } }"
        elif fault == "changed":
            provider += "[PSCustomObject]@{ Name = 'same'; DisplayName = [string]$script:calls }"
        else:
            provider += "[PSCustomObject]@{ Name = 'same' }"
    mock = (
        "$script:calls = 0; function Get-NetFirewallRule { "
        + provider
        + " }; function Get-NetFirewallApplicationFilter { throw 'EXPENSIVE_FILTER_WAS_REACHED' }; "
    )
    scope = "$group = 'fixture'; $suffixes = @('jame'); "
    with pytest.raises(FirewallExecutionError) as exc:
        code, _, stderr = firewall._run(mock + scope + _INVENTORY_SCRIPT)
        if code:
            raise FirewallExecutionError(stderr)
    assert "EXPENSIVE_FILTER_WAS_REACHED" not in str(exc.value)
    expected = {
        "duplicate": "Ambiguous",
        "changed": "changed",
        "access": "fixture failure",
        "fake-absence": "fixture failure",
    }
    assert expected[fault] in str(exc.value)


@pytest.mark.parametrize(
    ("parameter", "value", "property"),
    [
        ("-Group", "absent-jame-group-", "RuleGroup"),
        ("-Name", "absent-jame-name-", "InstanceID"),
    ],
)
def test_native_empty_selector_uses_cim_property_identity(
    parameter: str, value: str, property: str
) -> None:
    runner = SystemProcessRunner()
    missing = value + uuid.uuid4().hex
    script = (
        "$ErrorActionPreference = 'Stop'; try { "
        f"Get-NetFirewallRule -PolicyStore PersistentStore {parameter} '{missing}' | Out-Null; "
        "throw 'Expected exact missing-group error' } catch { "
        "[PSCustomObject]@{ Id = $_.FullyQualifiedErrorId; "
        "Category = [string]$_.CategoryInfo.Category } | ConvertTo-Json -Compress }"
    )
    result = runner.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
    assert result.succeeded, result
    assert json.loads(result.stdout) == {
        "Id": f"CmdletizationQuery_NotFound_{property},Get-NetFirewallRule",
        "Category": "ObjectNotFound",
    }
    if parameter == "-Group":
        # Production must accept absence and still retrieve all profiles, not hide other errors.
        assert WindowsNetshAdapter(runner).list_inventory([missing]).rules == ()


@pytest.mark.windows_load
def test_inventory_load_with_128_owned_rules_is_complete_and_effective(
    tmp_path: Path,
    benchmark: Any,
    record_testsuite_property: Callable[[str, object], None],
) -> None:
    """Measure the production refresh path against 128 real effective native rules."""
    assert WindowsUACAdapter().is_admin()
    suffix = "jame-load-" + uuid.uuid4().hex[:12]
    programs = [tmp_path / f"program-{index:03d}.exe" for index in range(64)]
    for program in programs:
        shutil.copy2(sys.executable, program)
    runner = SystemProcessRunner()
    firewall = WindowsNetshAdapter(runner)
    uac = WindowsUACAdapter()
    scanner = OSFileSystemAdapter()
    audit = AuditFirewallStatusUseCase(firewall, uac, scanner, primary_suffix=suffix)
    rules = [
        {
            "Name": managed_rule_name(program, direction, suffix),
            "Program": str(program),
            "Direction": "Inbound" if direction == RuleDirection.IN else "Outbound",
        }
        for program in programs
        for direction in RuleDirection
    ]
    payload_path = tmp_path / "inventory-load-rules.json"
    payload_path.write_text(json.dumps(rules, ensure_ascii=True), encoding="utf-8")
    payload_literal = str(payload_path).replace("'", "''")
    setup = (
        "$items = Get-Content -LiteralPath '"
        + payload_literal
        + "' -Raw | ConvertFrom-Json; foreach ($item in $items) { "
        + "New-NetFirewallRule -PolicyStore PersistentStore -Name $item.Name "
        + "-DisplayName $item.Name -Group 'JameFirewall.v1' -Program $item.Program "
        + "-Direction $item.Direction -Action Block -Enabled True -Profile Any "
        + "-Protocol Any -LocalAddress Any -RemoteAddress Any -InterfaceType Any "
        + "-Service Any | Out-Null }"
    )
    cleanup = (
        "$prefix = '" + suffix + ":v1:'; "
        "Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { "
        "$_.Group -eq 'JameFirewall.v1' -and $_.Name.StartsWith($prefix, "
        "[StringComparison]::Ordinal) } | Remove-NetFirewallRule"
    )
    process = psutil.Process()
    rss_before = process.memory_info().rss
    try:
        result = runner.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", setup])
        assert result.succeeded, result

        inventory = benchmark.pedantic(
            firewall.list_inventory,
            args=([suffix],),
            iterations=1,
            rounds=1,
            warmup_rounds=0,
        )
        by_name = {rule.name: rule for rule in inventory.rules}
        assert len(by_name) == 128
        assert all(rule.effective for rule in inventory.rules)
        # Unique paths prove batched provider output remains associated with its rule.
        for program in programs:
            for direction in RuleDirection:
                rule = by_name[managed_rule_name(program, direction, suffix)]
                assert program_key(rule.program_path) == program_key(program)
        audit_started = time.monotonic()
        assert audit.execute([tmp_path]).status == SystemStatus.PROTECTED
        audit_seconds = time.monotonic() - audit_started
        result = runner.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cleanup])
        assert result.succeeded, result
        assert not firewall.list_inventory([suffix]).rules
        assert audit.execute([tmp_path]).status == SystemStatus.UNPROTECTED

        record_testsuite_property("inventory_load_owned_rules", len(inventory.rules))
        record_testsuite_property("inventory_load_audit_seconds", round(audit_seconds, 3))
        record_testsuite_property("inventory_load_benchmark_seconds", benchmark.stats.stats.mean)
        record_testsuite_property("inventory_load_rss_before_bytes", rss_before)
        record_testsuite_property("inventory_load_rss_after_bytes", process.memory_info().rss)
    finally:
        runner.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cleanup])
