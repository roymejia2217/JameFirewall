"""Native payload-batch scale, measured command cost and foreign-rule isolation."""

import json
import shutil
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path

import pytest

from jame_firewall.core.entities import FirewallRule, ProcessResult, RuleDirection, SystemStatus
from jame_firewall.core.rule_identity import MANAGED_GROUP, managed_rule_name
from jame_firewall.core.use_cases.audit_status import AuditFirewallStatusUseCase
from jame_firewall.core.use_cases.block_executables import BlockExecutablesUseCase
from jame_firewall.core.use_cases.unblock_rules import UnblockRulesUseCase
from jame_firewall.infrastructure.firewall.netsh_adapter import WindowsNetshAdapter
from jame_firewall.infrastructure.os.filesystem import OSFileSystemAdapter
from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner
from jame_firewall.infrastructure.os.uac_manager import WindowsUACAdapter

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows Firewall"),
]


class CountingRunner(SystemProcessRunner):
    def __init__(self) -> None:
        super().__init__()
        self.commands = 0

    def run(self, args: list[str], timeout: float | None = 30.0) -> ProcessResult:
        self.commands += 1
        return super().run(args, timeout)


def test_multi_batch_native_round_trip_and_command_baseline(
    tmp_path: Path,
    record_testsuite_property: Callable[[str, object], None],
) -> None:
    assert WindowsUACAdapter().is_admin()
    suffix = "jame-batch-" + uuid.uuid4().hex[:12]
    paths = []
    for i in range(10):
        path = tmp_path / f"helper{i}.exe"
        shutil.copy2(sys.executable, path)
        paths.append(path)
    rules = [
        FirewallRule(managed_rule_name(path, d, suffix), path, d, group=MANAGED_GROUP)
        for path in paths
        for d in RuleDirection
    ]
    runner = CountingRunner()
    firewall = WindowsNetshAdapter(runner)
    scanner = OSFileSystemAdapter()
    uac = WindowsUACAdapter()
    block = BlockExecutablesUseCase(firewall, scanner, uac, primary_suffix=suffix)
    unblock = UnblockRulesUseCase(firewall, uac, primary_suffix=suffix)
    audit = AuditFirewallStatusUseCase(firewall, uac, scanner, primary_suffix=suffix)
    try:
        start = time.monotonic()
        for rule in rules:
            assert firewall.add_rule(rule.name, rule.program_path, rule.direction)
        for rule in rules:
            assert firewall.delete_rule(rule)
        serial_seconds = time.monotonic() - start
        serial_commands = runner.commands
        assert serial_commands == 40
        assert not firewall.list_inventory([suffix]).rules

        before = runner.commands
        start = time.monotonic()
        summary = block.execute([tmp_path])
        assert summary.blocked_count == 10 and summary.failed_count == 0
        block_commands = runner.commands - before
        assert 3 <= block_commands < 5  # Two inventories plus payload-sized mutation batches.
        assert audit.execute([tmp_path]).status == SystemStatus.PROTECTED
        repeated = block.execute([tmp_path])
        assert repeated.skipped_count == 10 and repeated.blocked_count == 0
        before = runner.commands
        removed = unblock.execute()
        assert removed.removed_count == 20 and removed.failed_count == 0
        unblock_commands = runner.commands - before
        assert 3 <= unblock_commands < 5
        assert audit.execute([tmp_path]).status == SystemStatus.UNPROTECTED
        batch_seconds = time.monotonic() - start
        record_testsuite_property("firewall_serial_mutation_commands", serial_commands)
        record_testsuite_property(
            "firewall_batch_mutation_commands", block_commands + unblock_commands - 4
        )
        record_testsuite_property("firewall_serial_mutation_seconds", round(serial_seconds, 3))
        # Includes scan, inventories, repeat activation and independent follow-up audits.
        record_testsuite_property("firewall_batch_full_cycle_seconds", round(batch_seconds, 3))
    finally:
        unblock.execute()


@pytest.mark.windows_load
def test_native_reconciliation_scales_past_small_rule_sets(
    tmp_path: Path,
    record_testsuite_property: Callable[[str, object], None],
) -> None:
    """Exercise the production scan, inventory, mutation and verification over 128 rules."""
    assert WindowsUACAdapter().is_admin()
    suffix = "jame-scale-" + uuid.uuid4().hex[:12]
    programs = [tmp_path / f"scale-{index:03d}.exe" for index in range(64)]
    for program in programs:
        shutil.copy2(sys.executable, program)
    firewall = WindowsNetshAdapter(SystemProcessRunner())
    uac = WindowsUACAdapter()
    block = BlockExecutablesUseCase(firewall, OSFileSystemAdapter(), uac, primary_suffix=suffix)
    unblock = UnblockRulesUseCase(firewall, uac, primary_suffix=suffix)
    try:
        started = time.monotonic()
        summary = block.execute([tmp_path])
        activation_seconds = time.monotonic() - started
        assert summary.blocked_count == len(programs)
        assert summary.failed_count == 0
        active = firewall.list_inventory([suffix]).rules
        assert len(active) == len(programs) * len(RuleDirection)
        assert {rule.program_path for rule in active} == set(programs)

        started = time.monotonic()
        removed = unblock.execute()
        deactivation_seconds = time.monotonic() - started
        assert removed.removed_count == len(active)
        assert removed.failed_count == 0
        assert firewall.list_inventory([suffix]).rules == ()
        record_testsuite_property("firewall_scale_program_count", len(programs))
        record_testsuite_property("firewall_scale_rule_count", len(active))
        record_testsuite_property("firewall_scale_activation_seconds", round(activation_seconds, 3))
        record_testsuite_property(
            "firewall_scale_deactivation_seconds", round(deactivation_seconds, 3)
        )
    finally:
        unblock.execute()


def test_native_batch_failure_preserves_foreign_rule_and_continues(tmp_path: Path) -> None:
    suffix = "jame-batch-" + uuid.uuid4().hex[:12]
    paths = [tmp_path / f"probe{i}.exe" for i in range(3)]
    rules = [
        FirewallRule(
            managed_rule_name(p, RuleDirection.OUT, suffix),
            p,
            RuleDirection.OUT,
            group=MANAGED_GROUP,
        )
        for p in paths
    ]
    collision = rules[1].name
    runner = SystemProcessRunner()
    firewall = WindowsNetshAdapter(runner)

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
        native(
            f"New-NetFirewallRule -Name '{collision}' -DisplayName 'Foreign fixture' -Group 'Foreign fixture' -Program '{sys.executable}' -Direction Outbound -Action Allow | Out-Null"
        )
        assert firewall.add_rules(rules) == (True, False, True)
        assert firewall.delete_rules(rules) == (True, False, True)
        raw = json.loads(
            native(
                f"Get-NetFirewallRule -PolicyStore PersistentStore -Name '{collision}' | ForEach-Object {{ [PSCustomObject]@{{ Name = [string]$_.Name; Group = [string]$_.Group; Action = [string]$_.Action }} }} | ConvertTo-Json -Compress"
            )
        )
        assert raw == {"Name": collision, "Group": "Foreign fixture", "Action": "Allow"}
        inventory = firewall.list_inventory([suffix])
        assert {r.name for r in inventory.rules} == {collision}
    finally:
        # Only this test's known foreign fixture is removed explicitly; product must retain it.
        native(
            f"Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {{ $_.Name -eq '{collision}' }} | Remove-NetFirewallRule"
        )
        firewall.delete_rules([rules[0], rules[2]])
