"""Operation-wide deadlines must survive nesting and stop additional side effects."""

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.fakes.fake_uac import FakeUACAdapter

from jame_firewall.core.entities import (
    FirewallInventory,
    FirewallRule,
    RuleDirection,
    ScanResult,
    SystemStatus,
)
from jame_firewall.core.exceptions import OperationDeadlineExceeded
from jame_firewall.core.execution import (
    OPERATION_TIMEOUT_SECONDS,
    check_operation_budget,
    operation_budget,
    remaining_operation_seconds,
)
from jame_firewall.core.rule_identity import MANAGED_GROUP, managed_rule_name
from jame_firewall.core.use_cases.audit_status import AuditFirewallStatusUseCase
from jame_firewall.core.use_cases.block_executables import BlockExecutablesUseCase
from jame_firewall.core.use_cases.unblock_rules import UnblockRulesUseCase


@dataclass
class FakeClock:
    now: float = 0.0

    def __call__(self) -> float:
        return self.now


def scanner_for(path: Path) -> MagicMock:
    scanner = MagicMock()
    scanner.find_executables.return_value = ScanResult(executables=(path,))
    return scanner


def test_no_active_operation_has_no_deadline() -> None:
    assert remaining_operation_seconds() is None
    check_operation_budget()


def test_default_deadline_is_120_seconds_and_context_resets() -> None:
    clock = FakeClock()
    assert OPERATION_TIMEOUT_SECONDS == 120.0
    with operation_budget(clock=clock):
        assert remaining_operation_seconds() == pytest.approx(120)
        clock.now = 119
        assert remaining_operation_seconds() == pytest.approx(1)
        check_operation_budget()
        clock.now = 120
        with pytest.raises(OperationDeadlineExceeded):
            check_operation_budget()
    assert remaining_operation_seconds() is None


def test_nested_budget_does_not_reset_or_extend_parent_deadline() -> None:
    clock = FakeClock()
    with operation_budget(10, clock=clock):
        clock.now = 4
        with operation_budget(120, clock=FakeClock()):
            assert remaining_operation_seconds() == pytest.approx(6)
            clock.now = 10
            with pytest.raises(OperationDeadlineExceeded):
                check_operation_budget()
        with pytest.raises(OperationDeadlineExceeded):
            check_operation_budget()
    assert remaining_operation_seconds() is None


def test_context_cleanup_on_exception_does_not_leak_deadline() -> None:
    with pytest.raises(ValueError), operation_budget(10, clock=FakeClock()):
        raise ValueError("operation failed")
    assert remaining_operation_seconds() is None


def test_block_stops_before_verification_when_batch_exhausts_shared_budget() -> None:
    clock = FakeClock()
    path = Path("C:/Apps/helper.exe")
    firewall = MagicMock()
    firewall.list_inventory.return_value = FirewallInventory(rules=())

    def slow_mutation(_rules: list[FirewallRule]) -> tuple[bool, ...]:
        clock.now = 10
        return (True, True)

    firewall.add_rules.side_effect = slow_mutation
    with operation_budget(10, clock=clock), pytest.raises(OperationDeadlineExceeded):
        BlockExecutablesUseCase(firewall, scanner_for(path), FakeUACAdapter()).execute(
            [path.parent]
        )
    assert firewall.add_rules.call_count == 1
    assert firewall.list_inventory.call_count == 1


def test_unblock_stops_before_verification_when_batch_exhausts_shared_budget() -> None:
    clock = FakeClock()
    path = Path("C:/Apps/helper.exe")
    rules = tuple(
        FirewallRule(managed_rule_name(path, direction), path, direction, group=MANAGED_GROUP)
        for direction in RuleDirection
    )
    firewall = MagicMock()
    firewall.list_inventory.return_value = FirewallInventory(rules=rules)

    def slow_delete(_rules: list[FirewallRule]) -> tuple[bool, ...]:
        clock.now = 10
        return (True, True)

    firewall.delete_rules.side_effect = slow_delete
    with operation_budget(10, clock=clock), pytest.raises(OperationDeadlineExceeded):
        UnblockRulesUseCase(firewall, FakeUACAdapter()).execute()
    assert firewall.delete_rules.call_count == 1
    assert firewall.list_inventory.call_count == 1


def test_block_does_not_query_firewall_after_scan_exhausts_budget() -> None:
    clock = FakeClock()
    path = Path("C:/Apps/helper.exe")
    scanner = scanner_for(path)

    def slow_scan(_directories: list[Path]) -> ScanResult:
        clock.now = 10
        return ScanResult(executables=(path,))

    scanner.find_executables.side_effect = slow_scan
    firewall = MagicMock()
    firewall.list_inventory.return_value = FirewallInventory(rules=())
    with operation_budget(10, clock=clock), pytest.raises(OperationDeadlineExceeded):
        BlockExecutablesUseCase(firewall, scanner, FakeUACAdapter()).execute([path.parent])
    firewall.list_inventory.assert_not_called()
    firewall.add_rules.assert_not_called()


def test_audit_expired_budget_never_queries_firewall_or_claims_protected() -> None:
    clock = FakeClock()
    path = Path("C:/Apps/helper.exe")
    firewall = MagicMock()
    firewall.list_inventory.return_value = FirewallInventory(rules=())
    with operation_budget(10, clock=clock):
        clock.now = 10
        # Audit may return its established ERROR snapshot or propagate the typed
        # deadline for the UI worker to report; neither may execute another query.
        try:
            snapshot = AuditFirewallStatusUseCase(
                firewall, FakeUACAdapter(), scanner_for(path)
            ).execute([path.parent])
        except OperationDeadlineExceeded:
            pass
        else:
            assert snapshot.status == SystemStatus.ERROR
    firewall.list_inventory.assert_not_called()


def test_audit_does_not_publish_snapshot_after_scan_exhausts_budget() -> None:
    clock = FakeClock()
    path = Path("C:/Apps/helper.exe")
    firewall = MagicMock()
    firewall.list_inventory.return_value = FirewallInventory(rules=())
    scanner = scanner_for(path)

    def slow_scan(_directories: list[Path]) -> ScanResult:
        clock.now = 10
        return ScanResult(executables=(path,))

    scanner.find_executables.side_effect = slow_scan
    with operation_budget(10, clock=clock), pytest.raises(OperationDeadlineExceeded):
        AuditFirewallStatusUseCase(firewall, FakeUACAdapter(), scanner).execute([path.parent])
