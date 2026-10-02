"""Provider contracts for identity, policy visibility and safe firewall mutations."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from jame_firewall.core.entities import FirewallRule, ProcessResult, ProcessStatus, RuleDirection
from jame_firewall.core.exceptions import FirewallExecutionError
from jame_firewall.core.execution import OPERATION_TIMEOUT_SECONDS, operation_budget
from jame_firewall.core.rule_identity import MANAGED_GROUP, managed_rule_name
from jame_firewall.infrastructure.firewall.netsh_adapter import WindowsNetshAdapter


def inventory_json(rules: list[object] | None = None, **flags: bool) -> str:
    return json.dumps(
        {
            "Complete": True,
            "Rules": rules or [],
            "ProfilesEnabled": True,
            "LocalRulesAllowed": True,
            **flags,
        },
        ensure_ascii=False,
    )


def rule_json() -> dict[str, Any]:
    path = Path("C:/Aplicación/ayudante.exe")
    return {
        "Name": managed_rule_name(path, RuleDirection.OUT),
        "DisplayName": "Ayudante — JameFirewall",
        "Program": str(path),
        "Direction": "Outbound",
        "Action": "Block",
        "Group": MANAGED_GROUP,
        "Enabled": True,
        "Profile": "Any",
        "Effective": True,
        "EnforcementStates": ["ProfileInactive", "Enforced"],
    }


def adapter_with_response(output: str = "", code: int = 0) -> tuple[WindowsNetshAdapter, MagicMock]:
    runner = MagicMock()
    runner.run.return_value = ProcessResult(
        ProcessStatus.COMPLETED, code, output, "provider error" if code else ""
    )
    return WindowsNetshAdapter(runner=runner), runner


def command_script(runner: MagicMock) -> str:
    command = runner.run.call_args[0][0]
    assert "-NoProfile" in command
    assert "-NonInteractive" in command
    script: object = command[-1]
    assert isinstance(script, str)
    return script


def test_inventory_keeps_native_identity_separate_from_display_name() -> None:
    dto = rule_json()
    adapter, runner = adapter_with_response(inventory_json([dto]))
    inventory = adapter.list_inventory(["jame-block"])
    assert len(inventory.rules) == 1
    rule = inventory.rules[0]
    assert rule.name == dto["Name"]
    assert rule.display_name == dto["DisplayName"]
    assert rule.program_path == Path(dto["Program"])
    assert rule.direction == RuleDirection.OUT
    assert rule.action.casefold() == "block"
    assert rule.group == MANAGED_GROUP
    assert rule.enabled and rule.effective
    assert rule.profiles == "Any"
    assert inventory.profiles_enabled and inventory.local_rules_allowed
    runner.run.assert_called_once()


def test_inventory_returns_authoritative_empty_set_without_fallback() -> None:
    adapter, runner = adapter_with_response(inventory_json())
    assert adapter.list_inventory(["jame-block"]).rules == ()
    runner.run.assert_called_once()


def test_firewall_provider_timeout_uses_operation_window_instead_of_fixed_30_seconds() -> None:
    adapter, runner = adapter_with_response(inventory_json())
    adapter.list_inventory(["jame-block"])
    assert runner.run.call_args.kwargs["timeout"] == OPERATION_TIMEOUT_SECONDS

    runner.reset_mock()
    with operation_budget(75.0, clock=lambda: 10.0):
        adapter.list_inventory(["jame-block"])
    assert runner.run.call_args.kwargs["timeout"] == pytest.approx(75.0)


def test_inventory_preserves_disabled_policy_and_ineffective_rule_flags() -> None:
    dto = {**rule_json(), "Enabled": False, "Effective": False, "Direction": "Inbound"}
    adapter, _ = adapter_with_response(
        inventory_json([dto], ProfilesEnabled=False, LocalRulesAllowed=False)
    )
    inventory = adapter.list_inventory(["jame-block"])
    assert not inventory.profiles_enabled
    assert not inventory.local_rules_allowed
    assert not inventory.rules[0].enabled
    assert not inventory.rules[0].effective
    assert inventory.rules[0].direction == RuleDirection.IN


def test_failed_inventory_query_raises_without_fallback() -> None:
    adapter, runner = adapter_with_response(code=1)
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(["jame-block"])
    runner.run.assert_called_once()


@pytest.mark.parametrize(
    "output",
    [
        "",
        "Not JSON",
        "null",
        "[]",
        "{}",
        json.dumps({"Rules": {}, "ProfilesEnabled": True, "LocalRulesAllowed": True}),
        json.dumps({"Rules": [], "ProfilesEnabled": "True", "LocalRulesAllowed": True}),
        json.dumps({"Rules": [], "ProfilesEnabled": True, "LocalRulesAllowed": 1}),
        inventory_json([{}]),
        inventory_json([42]),
    ],
)
def test_inventory_rejects_malformed_or_incomplete_provider_response(output: str) -> None:
    adapter, runner = adapter_with_response(output)
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(["jame-block"])
    runner.run.assert_called_once()


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("Enabled", "False"),
        ("Effective", 1),
        ("Name", None),
        ("Name", ""),
        ("Program", []),
        ("Program", ""),
        ("Direction", "Sideways"),
        ("Action", True),
        ("Group", 2),
        ("DisplayName", {}),
        ("Profile", []),
    ],
)
def test_inventory_rejects_invalid_rule_attribute(attribute: str, value: object) -> None:
    dto = {**rule_json(), attribute: value}
    adapter, _ = adapter_with_response(inventory_json([dto]))
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(["jame-block"])


def test_inventory_reads_active_policy_and_program_filters() -> None:
    adapter, runner = adapter_with_response(inventory_json())
    adapter.list_inventory(["jame-block", "adobe-block"])
    script = command_script(runner)
    assert "ActiveStore" in script
    assert "PersistentStore" in script
    assert "Get-NetFirewallApplicationFilter" in script
    assert "EnforcementStatus" in script
    for provider_filter in (
        "Get-NetFirewallPortFilter",
        "Get-NetFirewallAddressFilter",
        "Get-NetFirewallServiceFilter",
        "Get-NetFirewallInterfaceFilter",
        "Get-NetFirewallInterfaceTypeFilter",
        "Get-NetFirewallSecurityFilter",
    ):
        assert provider_filter in script
    assert "Get-NetFirewallProfile" in script
    assert "ConvertTo-Json" in script


def test_inventory_rejects_duplicate_native_names_as_ambiguous() -> None:
    dto = rule_json()
    adapter, _ = adapter_with_response(inventory_json([dto, dto]))
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(["jame-block"])


def test_add_uses_canonical_native_name_and_escapes_program_path() -> None:
    adapter, runner = adapter_with_response()
    path = Path("C:/O'Brien/Aplicación.exe")
    name = managed_rule_name(path, RuleDirection.OUT)
    assert adapter.add_rule(name, path, RuleDirection.OUT)
    script = command_script(runner)
    assert name in script
    assert MANAGED_GROUP in script
    assert "O''Brien" in script
    assert "Outbound" in script
    assert "New-NetFirewallRule" in script
    assert "Block" in script


def test_repair_recreates_verified_owned_rule_to_restore_unrestricted_scope() -> None:
    adapter, runner = adapter_with_response()
    path = Path("C:/helper.exe")
    assert adapter.add_rule(managed_rule_name(path, RuleDirection.IN), path, RuleDirection.IN)
    script = command_script(runner)
    assert "Remove-NetFirewallRule -InputObject $r" in script
    assert "New-NetFirewallRule" in script
    assert "Set-NetFirewallRule" not in script
    assert script.index("if (-not $owned) { exit 2 }") < script.index("Remove-NetFirewallRule")


def test_add_refuses_noncanonical_name_without_invoking_provider() -> None:
    adapter, runner = adapter_with_response()
    assert not adapter.add_rule("helper jame-block", Path("C:/helper.exe"), RuleDirection.OUT)
    runner.run.assert_not_called()


def test_add_returns_failure_when_provider_rejects_mutation() -> None:
    adapter, _ = adapter_with_response(code=1)
    path = Path("C:/helper.exe")
    assert not adapter.add_rule(managed_rule_name(path, RuleDirection.IN), path, RuleDirection.IN)


def test_delete_checks_current_ownership_and_removes_provider_object() -> None:
    adapter, runner = adapter_with_response()
    path = Path("C:/O'Brien/helper.exe")
    name = managed_rule_name(path, RuleDirection.IN)
    rule = FirewallRule(
        name=name,
        program_path=path,
        direction=RuleDirection.IN,
        group=MANAGED_GROUP,
        display_name="Shared corporate display name",
    )
    assert adapter.delete_rule(rule)
    script = command_script(runner)
    assert name in script
    assert MANAGED_GROUP in script
    assert "O''Brien" in script
    assert "Inbound" in script
    assert "PersistentStore" in script
    assert "Remove-NetFirewallRule -InputObject" in script
    assert "Shared corporate display name" not in script


@pytest.mark.parametrize("group", ["", "Corporate"])
def test_delete_refuses_foreign_group_without_invoking_provider(group: str) -> None:
    adapter, runner = adapter_with_response()
    path = Path("C:/helper.exe")
    rule = FirewallRule(
        name=managed_rule_name(path, RuleDirection.IN),
        program_path=path,
        direction=RuleDirection.IN,
        group=group,
    )
    assert not adapter.delete_rule(rule)
    runner.run.assert_not_called()


def test_delete_refuses_mismatched_program_identity_without_invoking_provider() -> None:
    adapter, runner = adapter_with_response()
    rule = FirewallRule(
        name=managed_rule_name(Path("C:/AppA/helper.exe"), RuleDirection.OUT),
        program_path=Path("C:/AppB/helper.exe"),
        direction=RuleDirection.OUT,
        group=MANAGED_GROUP,
    )
    assert not adapter.delete_rule(rule)
    runner.run.assert_not_called()


def test_delete_reports_provider_failure() -> None:
    adapter, _ = adapter_with_response(code=1)
    path = Path("C:/helper.exe")
    rule = FirewallRule(
        name=managed_rule_name(path, RuleDirection.OUT),
        program_path=path,
        direction=RuleDirection.OUT,
        group=MANAGED_GROUP,
    )
    assert not adapter.delete_rule(rule)


@pytest.mark.parametrize(
    ("states", "effective"),
    [
        (["ProfileInactive", "Enforced"], True),
        (["Enforced"], True),
        (["Full"], True),
        (["ProfileInactive"], False),
        ([], False),
        (["Enforced", "LocalFirewallRulesDisallowed"], False),
        (["Enforced", "DisabledObject"], False),
        (["Unknown"], False),
    ],
)
def test_inventory_checks_native_enforcement_states(states: list[str], effective: bool) -> None:
    dto = {**rule_json(), "EnforcementStates": states}
    adapter, _ = adapter_with_response(inventory_json([dto]))
    assert adapter.list_inventory(["jame-block"]).rules[0].effective is effective


@pytest.mark.parametrize("states", [None, "Enforced", {}, [1]])
def test_inventory_rejects_invalid_enforcement_states(states: object) -> None:
    dto = {**rule_json(), "EnforcementStates": states}
    adapter, _ = adapter_with_response(inventory_json([dto]))
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(["jame-block"])


@pytest.mark.parametrize(
    "status", [ProcessStatus.TIMED_OUT, ProcessStatus.OUTPUT_LIMIT, ProcessStatus.START_FAILED]
)
def test_incomplete_process_never_parses_inventory_even_with_valid_partial_json(
    status: ProcessStatus,
) -> None:
    adapter, runner = adapter_with_response()
    runner.run.return_value = ProcessResult(
        status, 0, inventory_json([rule_json()]), "partial output"
    )
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(["jame-block"])
    runner.run.assert_called_once()


@pytest.mark.parametrize(
    "status", [ProcessStatus.TIMED_OUT, ProcessStatus.OUTPUT_LIMIT, ProcessStatus.START_FAILED]
)
@pytest.mark.parametrize("operation", ["add", "delete"])
def test_incomplete_mutation_process_aborts_instead_of_returning_false_or_success(
    status: ProcessStatus, operation: str
) -> None:
    adapter, runner = adapter_with_response()
    runner.run.return_value = ProcessResult(status, 0, "", "incomplete process")
    path = Path("C:/Apps/helper.exe")
    name = managed_rule_name(path, RuleDirection.OUT)
    with pytest.raises(FirewallExecutionError):
        if operation == "add":
            adapter.add_rule(name, path, RuleDirection.OUT)
        else:
            adapter.delete_rule(FirewallRule(name, path, RuleDirection.OUT, group=MANAGED_GROUP))
    runner.run.assert_called_once()


@pytest.mark.parametrize(
    ("status", "code", "expected"),
    [
        (ProcessStatus.COMPLETED, 0, True),
        (ProcessStatus.COMPLETED, 1, False),
        (ProcessStatus.COMPLETED, None, False),
        (ProcessStatus.TIMED_OUT, 0, False),
        (ProcessStatus.OUTPUT_LIMIT, 0, False),
        (ProcessStatus.START_FAILED, 0, False),
    ],
)
def test_process_result_success_requires_completed_zero_exit(
    status: ProcessStatus, code: int | None, expected: bool
) -> None:
    assert ProcessResult(status, code).succeeded is expected
