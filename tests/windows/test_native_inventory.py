"""Native scoped inventory completeness, provider faults and catalog pressure."""

import json
import shutil
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path

import pytest

from jame_firewall.core.entities import FirewallRule, RuleDirection, SystemStatus
from jame_firewall.core.exceptions import FirewallExecutionError
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
        # A real unrelated catalog must not consume the scoped candidate quota or enter the DTO.
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


@pytest.mark.parametrize(
    "fault", ["candidate", "rows", "duplicate", "changed", "access", "fake-absence"]
)
def test_native_inventory_rejects_provider_limits_and_faults_before_filter_queries(
    fault: str,
) -> None:
    # Real Windows PowerShell executes the inventory control flow with deterministic provider
    # records; large quotas and error paths do not require thousands of OS mutations.
    runner = SystemProcessRunner()
    firewall = WindowsNetshAdapter(runner)
    if fault in {"access", "fake-absence"}:
        category = "PermissionDenied" if fault == "access" else "ObjectNotFound"
        provider = f"$record = [System.Management.Automation.ErrorRecord]::new([Exception]::new('fixture failure'), 'FixtureFailure', [System.Management.Automation.ErrorCategory]::{category}, $null); throw $record"
    else:
        provider = "$script:calls++; "
        if fault == "candidate":
            provider += "1..3 | ForEach-Object { [PSCustomObject]@{ Name = ('rule' + $_) } }"
        elif fault == "duplicate":
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
    cap = (
        "$maxCandidates = 2; $maxRows = "
        + ("1" if fault == "rows" else "100")
        + "; $group = 'fixture'; $suffixes = @('jame'); "
    )
    with pytest.raises(FirewallExecutionError) as exc:
        code, _, stderr = firewall._run(mock + cap + _INVENTORY_SCRIPT)
        if code:
            raise FirewallExecutionError(stderr)
    assert "EXPENSIVE_FILTER_WAS_REACHED" not in str(exc.value)
    expected = {
        "candidate": "candidate limit",
        "rows": "row limit",
        "duplicate": "Ambiguous",
        "changed": "changed",
        "access": "fixture failure",
        "fake-absence": "fixture failure",
    }
    assert expected[fault] in str(exc.value)
