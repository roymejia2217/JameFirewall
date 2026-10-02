"""Incomplete, oversized and invalid-scope inventories never establish protection."""

import json

import pytest
from tests.unit.test_netsh_adapter import adapter_with_response, inventory_json, rule_json

from jame_firewall.core.exceptions import FirewallExecutionError


@pytest.mark.parametrize(
    "suffixes", [["*"], ["jame'; throw 'x"], ["X"], ["x" * 65], [f"ns-{i}" for i in range(9)]]
)
def test_invalid_or_excessive_namespace_scope_never_launches_provider(suffixes: list[str]) -> None:
    adapter, runner = adapter_with_response(inventory_json())
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(suffixes)
    runner.run.assert_not_called()


@pytest.mark.parametrize("complete", [None, False, 1, "True"])
def test_response_requires_explicit_complete_inventory(complete: object) -> None:
    raw = json.loads(inventory_json([rule_json()]))
    raw.pop("Complete", None)
    if complete is not None:
        raw["Complete"] = complete
    adapter, _ = adapter_with_response(json.dumps(raw))
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(["jame-block"])


def test_excessive_candidates_are_rejected_before_parsing_rules() -> None:
    # Invalid row contents must not mask the cardinality rejection.
    adapter, _ = adapter_with_response(inventory_json([None] * 2049))
    with pytest.raises(FirewallExecutionError, match="límite"):
        adapter.list_inventory(["jame-block"])


def test_inventory_queries_scope_and_bounds_before_expensive_filter_reads() -> None:
    adapter, runner = adapter_with_response(inventory_json())
    adapter.list_inventory(["jame-block", "adobe-block"])
    script: str = runner.run.call_args.args[0][-1]
    assert "Read-Candidates 'PersistentStore' 'Group' $group" in script
    assert "Read-Candidates 'PersistentStore' 'Name'" in script
    assert "Read-Candidates 'PersistentStore' 'DisplayName'" in script
    assert "Read-Candidates 'ActiveStore' 'Group' $group" in script
    assert "$maxCandidates = 2048" in script
    assert "$maxRows = 8192" in script
    assert "Get-NetFirewallRule -PolicyStore PersistentStore)" not in script
    assert "Get-NetFirewallRule -PolicyStore ActiveStore)" not in script
    assert script.index("Read-Candidates 'ActiveStore'") < script.index("$localApplications = @(")
    assert script.index("$localApplications = @(") < script.index("$activeApplications = @(")
    # Missing selectors are the sole empty-query exception; provider failures never fall back.
    assert "CmdletizationQuery_NotFound_" in script
    assert "ObjectNotFound" in script
    assert "SilentlyContinue" not in script


def test_activation_never_creates_more_rules_than_can_be_audited() -> None:
    from pathlib import Path
    from unittest.mock import MagicMock

    from tests.fakes.fake_uac import FakeUACAdapter
    from tests.unit.test_operation_budget import scanner_for

    from jame_firewall.core.entities import FirewallInventory, FirewallRule, RuleDirection
    from jame_firewall.core.use_cases.block_executables import BlockExecutablesUseCase

    path = Path("C:/New/helper.exe")
    firewall = MagicMock()
    firewall.list_inventory.return_value = FirewallInventory(
        rules=tuple(
            FirewallRule(f"legacy-{i}", Path(f"C:/Old/{i}.exe"), RuleDirection.OUT)
            for i in range(2048)
        )
    )
    with pytest.raises(FirewallExecutionError, match="no se crearon reglas"):
        BlockExecutablesUseCase(firewall, scanner_for(path), FakeUACAdapter()).execute(
            [path.parent]
        )
    firewall.add_rules.assert_not_called()


def test_duplicate_native_identity_case_is_rejected() -> None:
    dto = rule_json()
    adapter, _ = adapter_with_response(inventory_json([dto, {**dto, "Name": dto["Name"].upper()}]))
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(["jame-block"])
