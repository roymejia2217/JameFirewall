"""Pruebas unitarias para AuditFirewallStatusUseCase."""

from pathlib import Path

from tests.fakes.fake_firewall import InMemoryFirewallAdapter
from tests.fakes.fake_uac import FakeUACAdapter

from jame_firewall.core.entities import RuleDirection, SystemStatus
from jame_firewall.core.use_cases.audit_status import AuditFirewallStatusUseCase


def test_audit_status_reports_protected_when_rules_exist(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    fake_firewall.add_rule("photoshop jame-block", Path("C:/photoshop.exe"), RuleDirection.OUT)
    use_case = AuditFirewallStatusUseCase(
        firewall=fake_firewall,
        uac=fake_uac,
        primary_suffix="jame-block",
        legacy_suffixes=["adobe-block"],
    )

    snapshot = use_case.execute()
    assert snapshot.status == SystemStatus.PROTECTED
    assert snapshot.rule_count == 1


def test_audit_status_reports_unprotected_when_no_rules(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    use_case = AuditFirewallStatusUseCase(
        firewall=fake_firewall,
        uac=fake_uac,
        primary_suffix="jame-block",
        legacy_suffixes=["adobe-block"],
    )

    snapshot = use_case.execute()
    assert snapshot.status == SystemStatus.UNPROTECTED
    assert snapshot.rule_count == 0


def test_audit_status_reports_no_admin(
    fake_firewall: InMemoryFirewallAdapter, fake_uac: FakeUACAdapter
) -> None:
    fake_uac.admin_status = False
    use_case = AuditFirewallStatusUseCase(
        firewall=fake_firewall,
        uac=fake_uac,
        primary_suffix="jame-block",
        legacy_suffixes=["adobe-block"],
    )

    snapshot = use_case.execute()
    assert snapshot.status == SystemStatus.NO_ADMIN_PRIVILEGES
