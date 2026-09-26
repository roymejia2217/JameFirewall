"""Pruebas unitarias para UnblockRulesUseCase y migración de reglas legacy."""

from pathlib import Path

import pytest
from tests.fakes.fake_firewall import InMemoryFirewallAdapter
from tests.fakes.fake_uac import FakeUACAdapter

from jame_firewall.core.entities import RuleDirection
from jame_firewall.core.exceptions import PrivilegesRequiredError
from jame_firewall.core.use_cases.unblock_rules import UnblockRulesUseCase


def test_unblock_rules_cleans_both_current_and_legacy(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    # Agregar regla con sufijo nuevo y regla con sufijo legacy
    fake_firewall.add_rule("photoshop jame-block", Path("C:/photoshop.exe"), RuleDirection.OUT)
    fake_firewall.add_rule("afterfx adobe-block", Path("C:/afterfx.exe"), RuleDirection.OUT)

    events: list[tuple[str, str]] = []

    use_case = UnblockRulesUseCase(
        firewall=fake_firewall,
        uac=fake_uac,
        primary_suffix="jame-block",
        legacy_suffixes=["adobe-block"],
        on_progress=lambda msg, lvl: events.append((msg, lvl)),
    )

    summary = use_case.execute()
    assert summary.removed_count == 2
    assert summary.failed_count == 0
    assert len(fake_firewall.list_rules_with_suffix("jame-block")) == 0
    assert len(fake_firewall.list_rules_with_suffix("adobe-block")) == 0
    assert len(events) == 2


def test_unblock_rules_empty(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    use_case = UnblockRulesUseCase(
        firewall=fake_firewall,
        uac=fake_uac,
    )
    summary = use_case.execute()
    assert summary.removed_count == 0


def test_unblock_rules_handles_deletion_failure(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    fake_firewall.add_rule("photoshop jame-block", Path("C:/photoshop.exe"), RuleDirection.OUT)
    fake_firewall.delete_should_fail = True

    use_case = UnblockRulesUseCase(
        firewall=fake_firewall,
        uac=fake_uac,
    )
    summary = use_case.execute()
    assert summary.failed_count == 1
    assert len(summary.errors) == 1


def test_unblock_rules_requires_admin(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    fake_uac.admin_status = False

    use_case = UnblockRulesUseCase(
        firewall=fake_firewall,
        uac=fake_uac,
    )

    with pytest.raises(PrivilegesRequiredError):
        use_case.execute()
