"""Pruebas unitarias para entidades de dominio y objetos de valor."""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from jame_firewall.core.entities import (
    BlockSummary,
    ExecutableTarget,
    FirewallRule,
    RuleDirection,
    StatusSnapshot,
    SystemStatus,
    UnblockSummary,
)


def test_firewall_rule_immutability() -> None:
    rule = FirewallRule(
        name="photoshop jame-block",
        program_path=Path("C:/app/photoshop.exe"),
        direction=RuleDirection.OUT,
    )
    assert rule.name == "photoshop jame-block"
    assert rule.direction == RuleDirection.OUT
    assert rule.action == "block"

    with pytest.raises(FrozenInstanceError):
        rule.name = "new_name"  # type: ignore[misc]


def test_executable_target_properties() -> None:
    target = ExecutableTarget(name="illustrator", path=Path("C:/Adobe/illustrator.exe"))
    assert target.name == "illustrator"
    assert target.path == Path("C:/Adobe/illustrator.exe")


def test_block_summary_structure() -> None:
    summary = BlockSummary(blocked_count=5, skipped_count=2, failed_count=0, errors=[])
    assert summary.blocked_count == 5
    assert summary.skipped_count == 2
    assert summary.failed_count == 0
    assert len(summary.errors) == 0


def test_unblock_summary_structure() -> None:
    summary = UnblockSummary(removed_count=10, failed_count=1, errors=["Access denied"])
    assert summary.removed_count == 10
    assert summary.failed_count == 1
    assert "Access denied" in summary.errors


def test_status_snapshot_structure() -> None:
    snapshot = StatusSnapshot(status=SystemStatus.PROTECTED, rule_count=4)
    assert snapshot.status == SystemStatus.PROTECTED
    assert snapshot.rule_count == 4
