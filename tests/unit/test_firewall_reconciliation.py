"""Regression coverage for complete, path-specific and owned firewall rules."""

from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from tests.fakes.fake_firewall import InMemoryFirewallAdapter
from tests.fakes.fake_uac import FakeUACAdapter

from jame_firewall.core.cancellation import CancellationToken
from jame_firewall.core.entities import (
    FirewallInventory,
    FirewallRule,
    RuleDirection,
    ScanIssue,
    ScanResult,
    StatusSnapshot,
    SystemStatus,
)
from jame_firewall.core.exceptions import FirewallExecutionError, OperationCancelledError
from jame_firewall.core.rule_identity import MANAGED_GROUP, managed_rule_name
from jame_firewall.core.use_cases.audit_status import AuditFirewallStatusUseCase
from jame_firewall.core.use_cases.block_executables import BlockExecutablesUseCase
from jame_firewall.core.use_cases.unblock_rules import UnblockRulesUseCase


def scanner_for(*paths: Path) -> MagicMock:
    scanner = MagicMock()
    scanner.find_executables.return_value = ScanResult(executables=tuple(paths))
    return scanner


def add_managed_rule(
    firewall: InMemoryFirewallAdapter, path: Path, direction: RuleDirection
) -> FirewallRule:
    name = managed_rule_name(path, direction)
    firewall.add_rule(name, path, direction)
    return firewall.rules[(name, direction.value)]


def audit(firewall: InMemoryFirewallAdapter, *paths: Path) -> StatusSnapshot:
    return AuditFirewallStatusUseCase(
        firewall=firewall, uac=FakeUACAdapter(), scanner=scanner_for(*paths)
    ).execute([Path("C:/")])


def test_equal_names_in_distinct_directories_receive_both_directions() -> None:
    firewall = InMemoryFirewallAdapter()
    paths = [Path("C:/AppA/helper.exe"), Path("C:/AppB/helper.exe")]
    summary = BlockExecutablesUseCase(firewall, scanner_for(*paths), FakeUACAdapter()).execute(
        [Path("C:/")]
    )
    assert summary.blocked_count == 2
    assert summary.skipped_count == 0
    assert {(rule.program_path, rule.direction) for rule in firewall.rules.values()} == {
        (path, direction) for path in paths for direction in RuleDirection
    }


def test_repeated_block_repairs_missing_inbound_direction() -> None:
    firewall = InMemoryFirewallAdapter()
    path = Path("C:/AppA/helper.exe")
    add_managed_rule(firewall, path, RuleDirection.OUT)
    summary = BlockExecutablesUseCase(firewall, scanner_for(path), FakeUACAdapter()).execute(
        [path.parent]
    )
    assert summary.skipped_count == 0
    assert {(rule.program_path, rule.direction) for rule in firewall.rules.values()} >= {
        (path, RuleDirection.IN),
        (path, RuleDirection.OUT),
    }


def test_audit_never_reports_single_direction_as_protected() -> None:
    firewall = InMemoryFirewallAdapter()
    path = Path("C:/AppA/helper.exe")
    add_managed_rule(firewall, path, RuleDirection.OUT)
    snapshot = audit(firewall, path)
    assert snapshot.status == SystemStatus.PARTIAL


def test_failed_inventory_is_reported_as_error() -> None:
    firewall = InMemoryFirewallAdapter()
    firewall.list_should_fail = True
    snapshot = audit(firewall, Path("C:/AppA/helper.exe"))
    assert snapshot.status == SystemStatus.ERROR


def test_unblock_preserves_foreign_rules_with_matching_suffix() -> None:
    firewall = InMemoryFirewallAdapter()
    name = "Corporate jame-block policy"
    firewall.add_rule(name, Path("C:/Corporate/helper.exe"), RuleDirection.OUT)
    summary = UnblockRulesUseCase(firewall, FakeUACAdapter()).execute()
    assert summary.removed_count == 0
    assert firewall.has_rule(name)


def test_complete_block_is_idempotent_and_counts_individual_rules() -> None:
    firewall = InMemoryFirewallAdapter()
    path = Path("C:/AppA/helper.exe")
    block = BlockExecutablesUseCase(firewall, scanner_for(path), FakeUACAdapter())
    assert block.execute([path.parent]).blocked_count == 1
    summary = block.execute([path.parent])
    assert (summary.blocked_count, summary.skipped_count, summary.failed_count) == (0, 1, 0)
    snapshot = audit(firewall, path)
    assert snapshot.status == SystemStatus.PROTECTED
    assert snapshot.rule_count == 2


def test_case_and_separator_variants_refer_to_one_windows_target() -> None:
    firewall = InMemoryFirewallAdapter()
    paths = [Path("C:/Apps/Helper.exe"), Path(r"c:\apps\HELPER.exe")]
    summary = BlockExecutablesUseCase(firewall, scanner_for(*paths), FakeUACAdapter()).execute(
        [Path("C:/Apps")]
    )
    assert summary.blocked_count == 1
    assert len(firewall.rules) == 2


@pytest.mark.parametrize(
    "changes",
    [
        {"enabled": False},
        {"action": "allow"},
        {"effective": False},
        {"profiles": "Domain"},
        {"program_path": Path("C:/Other/helper.exe")},
        {"group": "Corporate"},
    ],
)
def test_audit_rejects_incomplete_or_ineffective_rule(changes: dict[str, Any]) -> None:
    firewall = InMemoryFirewallAdapter()
    path = Path("C:/AppA/helper.exe")
    add_managed_rule(firewall, path, RuleDirection.IN)
    rule = add_managed_rule(firewall, path, RuleDirection.OUT)
    firewall.rules[(rule.name, rule.direction.value)] = replace(rule, **changes)
    assert audit(firewall, path).status != SystemStatus.PROTECTED


@pytest.mark.parametrize("changes", [{"profiles_enabled": False}, {"local_rules_allowed": False}])
def test_audit_rejects_system_policy_preventing_local_blocks(changes: dict[str, bool]) -> None:
    firewall = InMemoryFirewallAdapter()
    path = Path("C:/AppA/helper.exe")
    for direction in RuleDirection:
        add_managed_rule(firewall, path, direction)
    inventory = FirewallInventory(rules=tuple(firewall.rules.values()), **changes)
    firewall_mock = MagicMock()
    firewall_mock.list_inventory.return_value = inventory
    snapshot = AuditFirewallStatusUseCase(
        firewall=firewall_mock, uac=FakeUACAdapter(), scanner=scanner_for(path)
    ).execute([path.parent])
    assert snapshot.status != SystemStatus.PROTECTED


def test_audit_requires_every_configured_executable_to_be_covered() -> None:
    firewall = InMemoryFirewallAdapter()
    first, second = Path("C:/AppA/helper.exe"), Path("C:/AppB/helper.exe")
    for direction in RuleDirection:
        add_managed_rule(firewall, first, direction)
    assert audit(firewall, first, second).status == SystemStatus.PARTIAL


def test_audit_without_targets_does_not_claim_protection_from_stale_rules() -> None:
    firewall = InMemoryFirewallAdapter()
    for direction in RuleDirection:
        add_managed_rule(firewall, Path("C:/Old/helper.exe"), direction)
    assert audit(firewall).status != SystemStatus.PROTECTED


def test_unblock_retains_legacy_names_and_deletes_only_owned_identity() -> None:
    firewall = InMemoryFirewallAdapter()
    legacy = "helper adobe-block"
    firewall.add_rule(legacy, Path("C:/Old/helper.exe"), RuleDirection.OUT)
    path = Path("C:/AppA/helper.exe")
    for direction in RuleDirection:
        add_managed_rule(firewall, path, direction)
    summary = UnblockRulesUseCase(
        firewall, FakeUACAdapter(), legacy_suffixes=["adobe-block"]
    ).execute()
    assert summary.removed_count == 2
    assert summary.retained_legacy_count == 1
    assert firewall.has_rule(legacy)


def test_unblock_preserves_same_group_with_forged_identity() -> None:
    firewall = InMemoryFirewallAdapter()
    path = Path("C:/AppA/helper.exe")
    rule = add_managed_rule(firewall, path, RuleDirection.OUT)
    firewall.rules[(rule.name, rule.direction.value)] = replace(
        rule, program_path=Path("C:/Corporate/helper.exe"), group=MANAGED_GROUP
    )
    summary = UnblockRulesUseCase(firewall, FakeUACAdapter()).execute()
    assert summary.removed_count == 0
    assert firewall.has_rule(rule.name)


def test_repeated_block_repairs_disabled_owned_rule() -> None:
    firewall = InMemoryFirewallAdapter()
    path = Path("C:/AppA/helper.exe")
    add_managed_rule(firewall, path, RuleDirection.IN)
    rule = add_managed_rule(firewall, path, RuleDirection.OUT)
    firewall.rules[(rule.name, rule.direction.value)] = replace(rule, enabled=False)
    summary = BlockExecutablesUseCase(firewall, scanner_for(path), FakeUACAdapter()).execute(
        [path.parent]
    )
    assert summary.blocked_count == 1
    assert summary.failed_count == 0
    assert audit(firewall, path).status == SystemStatus.PROTECTED


def test_failed_inventory_prevents_block_mutations() -> None:
    firewall = MagicMock()
    firewall.list_inventory.side_effect = FirewallExecutionError("Query unavailable")
    path = Path("C:/AppA/helper.exe")
    block = BlockExecutablesUseCase(firewall, scanner_for(path), FakeUACAdapter())
    with pytest.raises(FirewallExecutionError):
        block.execute([path.parent])
    firewall.add_rules.assert_not_called()
    firewall.delete_rules.assert_not_called()


def test_failed_inventory_prevents_unblock_mutations() -> None:
    firewall = MagicMock()
    firewall.list_inventory.side_effect = FirewallExecutionError("Query unavailable")
    with pytest.raises(FirewallExecutionError):
        UnblockRulesUseCase(firewall, FakeUACAdapter()).execute()
    firewall.delete_rules.assert_not_called()


class TimedOutDeletionFirewall(InMemoryFirewallAdapter):
    """Provider mutation succeeds but the acknowledgement is lost."""

    def delete_rule(self, rule: FirewallRule) -> bool:
        super().delete_rule(rule)
        return False


class ReassignedRuleFirewall(InMemoryFirewallAdapter):
    """An administrator changes ownership between inventory and deletion."""

    def delete_rule(self, rule: FirewallRule) -> bool:
        key = (rule.name, rule.direction.value)
        self.rules[key] = replace(self.rules[key], group="Corporate")
        return False


def test_unblock_verifies_deletion_after_lost_provider_acknowledgement() -> None:
    firewall = TimedOutDeletionFirewall()
    add_managed_rule(firewall, Path("C:/AppA/helper.exe"), RuleDirection.OUT)
    summary = UnblockRulesUseCase(firewall, FakeUACAdapter()).execute()
    assert summary.removed_count == 1
    assert summary.failed_count == 0
    assert summary.errors == []


def test_unblock_reports_surviving_rule_after_ownership_reassignment() -> None:
    firewall = ReassignedRuleFirewall()
    rule = add_managed_rule(firewall, Path("C:/AppA/helper.exe"), RuleDirection.OUT)
    summary = UnblockRulesUseCase(firewall, FakeUACAdapter()).execute()
    assert summary.removed_count == 0
    assert summary.failed_count == 1
    assert summary.errors
    assert firewall.has_rule(rule.name)
    inventory = firewall.list_inventory(["jame-block"])
    assert len(inventory.rules) == 1
    assert inventory.rules[0].group == "Corporate"


def test_distinct_unicode_windows_paths_do_not_share_rule_identity() -> None:
    first = Path("C:/Apps/Straße.exe")
    second = Path("C:/Apps/Strasse.exe")
    assert managed_rule_name(first, RuleDirection.OUT) != managed_rule_name(
        second, RuleDirection.OUT
    )


def test_audit_with_covered_targets_and_scan_issue_reports_partial() -> None:
    firewall = InMemoryFirewallAdapter()
    path = Path("C:/AppA/helper.exe")
    for direction in RuleDirection:
        add_managed_rule(firewall, path, direction)
    scanner = scanner_for(path)
    scanner.find_executables.return_value = ScanResult(
        executables=(path,), issues=(ScanIssue(Path("C:/AppA/private"), "Acceso denegado"),)
    )
    snapshot = AuditFirewallStatusUseCase(firewall, FakeUACAdapter(), scanner).execute(
        [path.parent]
    )
    assert snapshot.status == SystemStatus.PARTIAL
    assert "Escaneo incompleto" in snapshot.detail


def test_audit_without_targets_and_scan_issue_does_not_report_unprotected() -> None:
    scanner = scanner_for()
    scanner.find_executables.return_value = ScanResult(
        executables=(), issues=(ScanIssue(Path("C:/AppA"), "Acceso denegado"),)
    )
    snapshot = AuditFirewallStatusUseCase(
        InMemoryFirewallAdapter(), FakeUACAdapter(), scanner
    ).execute([Path("C:/AppA")])
    assert snapshot.status == SystemStatus.PARTIAL
    assert "Escaneo incompleto" in snapshot.detail


@pytest.mark.parametrize("found_paths", [(), (Path("C:/AppA/helper.exe"),)])
def test_incomplete_scan_prevents_all_firewall_mutations(found_paths: tuple[Path, ...]) -> None:
    firewall = MagicMock()
    firewall.list_inventory.return_value = FirewallInventory(rules=())
    scanner = scanner_for()
    scanner.find_executables.return_value = ScanResult(
        executables=found_paths,
        issues=(ScanIssue(Path("C:/AppA/private"), "Acceso denegado"),),
    )
    summary = BlockExecutablesUseCase(firewall, scanner, FakeUACAdapter()).execute(
        [Path("C:/AppA")]
    )
    assert not summary.scan_complete
    assert summary.blocked_count == 0
    assert summary.errors
    assert any("Escaneo incompleto" in message for message in summary.errors)
    firewall.add_rules.assert_not_called()
    firewall.delete_rules.assert_not_called()


def test_complete_scan_preserves_successful_block_result() -> None:
    path = Path("C:/AppA/helper.exe")
    summary = BlockExecutablesUseCase(
        InMemoryFirewallAdapter(), scanner_for(path), FakeUACAdapter()
    ).execute([path.parent])
    assert summary.scan_complete
    assert summary.blocked_count == 1
    assert summary.failed_count == 0
    assert not summary.errors


@pytest.mark.parametrize("operation", ["block", "unblock"])
def test_resource_failure_stops_further_mutations_and_verification_queries(operation: str) -> None:
    path = Path("C:/Apps/helper.exe")
    rules = tuple(
        FirewallRule(managed_rule_name(path, direction), path, direction, group=MANAGED_GROUP)
        for direction in RuleDirection
    )
    firewall = MagicMock()
    firewall.list_inventory.return_value = FirewallInventory(
        rules=rules if operation == "unblock" else ()
    )
    failure = FirewallExecutionError("Process TIMED_OUT; incomplete mutation")
    firewall.add_rules.side_effect = failure
    firewall.delete_rules.side_effect = failure
    with pytest.raises(FirewallExecutionError, match="TIMED_OUT"):
        if operation == "block":
            BlockExecutablesUseCase(firewall, scanner_for(path), FakeUACAdapter()).execute(
                [path.parent]
            )
        else:
            UnblockRulesUseCase(firewall, FakeUACAdapter()).execute()
    assert firewall.list_inventory.call_count == 1
    if operation == "block":
        assert firewall.add_rules.call_count == 1
        firewall.delete_rules.assert_not_called()
    else:
        assert firewall.delete_rules.call_count == 1
        firewall.add_rules.assert_not_called()


def test_application_shutdown_cancellation_stops_next_fake_firewall_mutation() -> None:
    token = CancellationToken()
    firewall = MagicMock()
    firewall.list_inventory.return_value = FirewallInventory(rules=())
    path = Path("C:/Apps/helper.exe")
    committed: list[RuleDirection] = []

    def mutation(rules: list[FirewallRule]) -> tuple[bool, ...]:
        for rule in rules:
            token.check()
            committed.append(rule.direction)
            token.cancel()
        return (True,) * len(rules)

    firewall.add_rules.side_effect = mutation
    with pytest.raises(OperationCancelledError):
        BlockExecutablesUseCase(firewall, scanner_for(path), FakeUACAdapter()).execute(
            [path.parent]
        )
    assert len(committed) == 1
    assert firewall.list_inventory.call_count == 1
