"""Pruebas unitarias para BlockExecutablesUseCase."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.fakes.fake_firewall import InMemoryFirewallAdapter
from tests.fakes.fake_uac import FakeUACAdapter

from jame_firewall.core.entities import RuleDirection, ScanResult
from jame_firewall.core.exceptions import PrivilegesRequiredError
from jame_firewall.core.rule_identity import managed_rule_name
from jame_firewall.core.use_cases.block_executables import BlockExecutablesUseCase


def test_block_executables_skips_already_blocked_and_blocks_new(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    # 1. Configurar regla previa
    fake_firewall.add_rule(
        managed_rule_name(Path("C:/Adobe/photoshop.exe"), RuleDirection.OUT),
        Path("C:/Adobe/photoshop.exe"),
        RuleDirection.OUT,
    )
    fake_firewall.add_rule(
        managed_rule_name(Path("C:/Adobe/photoshop.exe"), RuleDirection.IN),
        Path("C:/Adobe/photoshop.exe"),
        RuleDirection.IN,
    )

    progress_events: list[tuple[str, str]] = []

    scanner_mock = MagicMock()
    scanner_mock.find_executables.return_value = ScanResult(
        executables=(
            Path("C:/Adobe/photoshop.exe"),
            Path("C:/Adobe/illustrator.exe"),
        )
    )

    use_case = BlockExecutablesUseCase(
        firewall=fake_firewall,
        scanner=scanner_mock,
        uac=fake_uac,
        primary_suffix="jame-block",
        on_progress=lambda msg, lvl: progress_events.append((msg, lvl)),
    )

    summary = use_case.execute([Path("C:/Adobe")])

    assert summary.blocked_count == 1
    assert summary.skipped_count == 1
    assert summary.failed_count == 0
    assert fake_firewall.has_rule(
        managed_rule_name(Path("C:/Adobe/illustrator.exe"), RuleDirection.OUT)
    )
    assert any("+ illustrator" in msg for msg, _ in progress_events)


def test_block_executables_handles_addition_failure(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    fake_firewall.add_should_fail = True
    scanner_mock = MagicMock()
    scanner_mock.find_executables.return_value = ScanResult(
        executables=(Path("C:/Adobe/illustrator.exe"),)
    )

    use_case = BlockExecutablesUseCase(
        firewall=fake_firewall,
        scanner=scanner_mock,
        uac=fake_uac,
    )

    summary = use_case.execute([Path("C:/Adobe")])
    assert summary.failed_count == 1
    assert len(summary.errors) == 1


def test_block_executables_empty_list(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    scanner_mock = MagicMock()
    scanner_mock.find_executables.return_value = ScanResult(executables=())

    use_case = BlockExecutablesUseCase(
        firewall=fake_firewall,
        scanner=scanner_mock,
        uac=fake_uac,
    )

    summary = use_case.execute([Path("C:/Adobe")])
    assert summary.blocked_count == 0


def test_block_executables_requires_admin(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    fake_uac.admin_status = False  # Sin privilegios
    scanner_mock = MagicMock()

    use_case = BlockExecutablesUseCase(
        firewall=fake_firewall,
        scanner=scanner_mock,
        uac=fake_uac,
    )

    with pytest.raises(PrivilegesRequiredError):
        use_case.execute([Path("C:/Adobe")])
